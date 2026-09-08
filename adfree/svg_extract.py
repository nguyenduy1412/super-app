#!/usr/bin/env python3
"""
Trích SVG nhúng trong Hermes bytecode, đọc thẳng từ bytecode.

react-native-svg-transformer biến file .svg thành một component React, rồi Metro
và Hermes biên dịch component đó thành bytecode. Cây phần tử nằm trong các lời
gọi jsx(tag, props): props dựng bằng NewObjectWithBuffer, danh sách con bằng
NewArray + DefineOwnInDenseArray, và props.children trỏ vào danh sách đó — nên
đi tuần tự thân hàm là dựng lại được nguyên cấu trúc lồng nhau.

Cách này thay cho việc dò regex trên bản decompile: ở đó bộ decompile xuất
container thành `<G clipPath="url(#a)">{null}</G>` — mất hẳn quan hệ cha–con,
nên gradient và clip-path bị làm phẳng và hình hiển thị sai.

Cách dùng CLI:
    python3 svg_extract.py app.apk           # liệt kê SVG tìm được
    python3 svg_extract.py app.apk 26069     # in SVG của một hàm
"""
import ast
import re
import sys
import zipfile
from io import BytesIO
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from hermes_dec.parsers.hbc_file_parser import HBCReader
    from hermes_dec.parsers.hbc_bytecode_parser import parse_hbc_bytecode
    from hermes_dec.parsers.serialized_literal_parser import (
        TagType, unpack_slp_array,
    )
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

BUNDLE_ENTRY = "assets/index.android.bundle"
HBC_MAGIC = b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"
ROOT_MARKERS = ("xmlns", "viewBox")
JSX_NAMES = {"jsx", "jsxs", "jsxDEV", "jsxsDEV", "createElement"}
MAX_INSTRUCTIONS = 200_000
OBJECT_ASSIGN_BUILTIN = 46

# tên component của react-native-svg -> tên thẻ SVG
TAGS = {
    "default": "svg", "Svg": "svg", "Path": "path", "Circle": "circle",
    "Ellipse": "ellipse", "Rect": "rect", "Line": "line", "Polygon": "polygon",
    "Polyline": "polyline", "G": "g", "Defs": "defs", "Use": "use",
    "Symbol": "symbol", "ClipPath": "clipPath", "Mask": "mask",
    "Pattern": "pattern", "Image": "image", "Text": "text", "TSpan": "tspan",
    "TextPath": "textPath", "Marker": "marker", "ForeignObject": "foreignObject",
    "LinearGradient": "linearGradient", "RadialGradient": "radialGradient",
    "Stop": "stop", "Filter": "filter", "FeBlend": "feBlend",
    "FeColorMatrix": "feColorMatrix", "FeGaussianBlur": "feGaussianBlur",
    "FeOffset": "feOffset", "FeMerge": "feMerge", "FeMergeNode": "feMergeNode",
}
# thuộc tính giữ nguyên chữ hoa/thường thay vì đổi sang kebab-case
KEEP_CASE = {
    "viewBox", "preserveAspectRatio", "gradientTransform", "gradientUnits",
    "patternTransform", "patternUnits", "patternContentUnits", "clipPath",
    "clipPathUnits", "clipRule", "maskUnits", "maskContentUnits",
    "markerWidth", "markerHeight", "markerUnits", "refX", "refY",
    "spreadMethod", "textLength", "lengthAdjust", "startOffset",
    "baseFrequency", "numOctaves", "stdDeviation", "primitiveUnits",
    "filterUnits", "xlinkHref", "vectorEffect", "requiredExtensions",
}
SKIP_PROPS = {"children", "key", "ref"}
_CACHE = {}
_CACHE_LIMIT = 4


class Element:
    """Một phần tử JSX đã dựng lại."""
    __slots__ = ("tag", "props")

    def __init__(self, tag, props):
        self.tag = tag
        self.props = props


class PropRef:
    """Kết quả của GetById — cần tên thuộc tính để biết đây là jsx() hay thẻ nào."""
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name


class Obj(dict):
    __slots__ = ("shape",)


def _writes_register(ins):
    """Toán hạng đầu của lệnh có phải thanh ghi đích không."""
    operands = ins.inst.operands
    return bool(operands) and operands[0].operand_type.name.startswith("Reg")


def _bundle_bytes(apk_path):
    try:
        with zipfile.ZipFile(apk_path) as archive:
            data = archive.read(BUNDLE_ENTRY)
    except (KeyError, OSError, zipfile.BadZipFile):
        return None
    return data if data[:8] == HBC_MAGIC else None


def _shape_keys(reader, index):
    return [ast.literal_eval(k) for k in reader.object_shape_keys[index]]


def _literals(reader, offset, count):
    values = []
    for item in unpack_slp_array(reader.literal_values[offset:], count).items:
        if item.tag_type in (TagType.LongStringTag, TagType.ShortStringTag,
                             TagType.ByteStringTag):
            values.append(reader.strings[item.value])
        elif item.tag_type == TagType.NumberTag:
            values.append(int(item.value) if item.value.is_integer()
                          else item.value)
        else:
            values.append(item.value)
    return values


def _root_shapes(reader):
    """Shape của props thẻ <svg> gốc — dùng để dò nhanh hàm nào là SVG."""
    found = set()
    for index in range(len(reader.object_shape_keys)):
        try:
            keys = set(_shape_keys(reader, index))
        except (ValueError, SyntaxError):
            continue
        if "xmlns" in keys or {"viewBox", "fill"} <= keys:
            found.add(index)
    return found


def _interpret(reader, function_id, root_shapes, probe=False):
    """Chạy thân hàm, trả về phần tử <svg> gốc (hoặc True khi chỉ dò)."""
    registers = {}
    root = None
    for count, ins in enumerate(
            parse_hbc_bytecode(reader.function_headers[function_id], reader)):
        if count > MAX_INSTRUCTIONS:
            break
        name = ins.inst.name

        if name in ("NewObjectWithBuffer", "NewObjectWithBufferLong"):
            if probe:
                if ins.arg2 in root_shapes:
                    return True
                continue
            keys = _shape_keys(reader, ins.arg2)
            obj = Obj(zip(keys, _literals(reader, ins.arg3, len(keys))))
            obj.shape = keys
            registers[ins.arg1] = obj
        elif probe:
            continue
        elif name in ("NewArrayWithBuffer", "NewArrayWithBufferLong"):
            registers[ins.arg1] = _literals(reader, ins.arg4, ins.arg3)
        elif name == "NewArray":
            registers[ins.arg1] = [None] * ins.arg2
        elif name == "NewObject":
            obj = Obj()
            obj.shape = []
            registers[ins.arg1] = obj
        elif name in ("DefineOwnInDenseArray", "DefineOwnInDenseArrayL"):
            array = registers.get(ins.arg1)
            if isinstance(array, list):
                while len(array) <= ins.arg3:
                    array.append(None)
                array[ins.arg3] = registers.get(ins.arg2)
        elif name in ("PutOwnBySlotIdx", "PutOwnBySlotIdxLong"):
            obj = registers.get(ins.arg1)
            if isinstance(obj, Obj) and ins.arg3 < len(obj.shape):
                obj[obj.shape[ins.arg3]] = registers.get(ins.arg2)
        elif name in ("DefineOwnById", "DefineOwnByIdLong", "PutNewOwnById",
                      "PutNewOwnByIdLong", "PutByIdLoose", "PutByIdStrict",
                      "PutByIdLooseLong", "PutByIdStrictLong"):
            obj = registers.get(ins.arg1)
            if isinstance(obj, dict):
                obj[reader.strings[ins.arg4]] = registers.get(ins.arg2)
        elif name in ("GetById", "GetByIdShort", "GetByIdLong", "TryGetById",
                      "TryGetByIdLong"):
            registers[ins.arg1] = PropRef(reader.strings[ins.arg4])
        elif name.startswith("Call"):
            _apply_call(reader, registers, ins)
            result = registers.get(ins.arg1)
            if isinstance(result, Element) and result.tag == "svg":
                root = result
        elif name in ("Mov", "MovLong"):
            registers[ins.arg1] = registers.get(ins.arg2)
        elif name == "LoadConstZero":
            registers[ins.arg1] = 0
        elif name in ("LoadConstUInt8", "LoadConstInt"):
            registers[ins.arg1] = ins.arg2
        elif name == "LoadConstDouble":
            number = ins.arg2
            registers[ins.arg1] = (int(number) if float(number).is_integer()
                                   else number)
        elif name in ("LoadConstString", "LoadConstStringLongIndex"):
            registers[ins.arg1] = reader.strings[ins.arg2]
        elif name == "LoadConstTrue":
            registers[ins.arg1] = True
        elif name == "LoadConstFalse":
            registers[ins.arg1] = False
        elif name in ("LoadConstNull", "LoadConstUndefined", "LoadConstEmpty"):
            registers[ins.arg1] = None
        elif name in ("GetByIndex", "GetByVal", "GetByIndexLong"):
            container = registers.get(ins.arg2)
            index = ins.arg3 if name != "GetByVal" else registers.get(ins.arg3)
            value = None
            if isinstance(container, list) and isinstance(index, int) \
                    and 0 <= index < len(container):
                value = container[index]
            elif isinstance(container, dict):
                value = container.get(index)
            registers[ins.arg1] = value
        elif name in ("PutByValStrict", "PutByValLoose"):
            container = registers.get(ins.arg1)
            index = registers.get(ins.arg2)
            if isinstance(container, list) and isinstance(index, int) \
                    and 0 <= index:
                while len(container) <= index:
                    container.append(None)
                container[index] = registers.get(ins.arg3)
            elif isinstance(container, dict):
                container[index] = registers.get(ins.arg3)
        elif _writes_register(ins):
            # opcode khác (môi trường, số học…) — bỏ giá trị đích để khỏi dùng
            # lẫn dữ liệu cũ. Chỉ làm khi toán hạng đầu THỰC SỰ là thanh ghi:
            # với lệnh nhảy, toán hạng đầu là offset, xoá theo nó sẽ phá thanh
            # ghi đang giữ dữ liệu (offset 10 xoá mất r10).
            registers.pop(ins.arg1, None)
    return None if probe else root


def _apply_call(reader, registers, ins):
    """Mô phỏng lời gọi: chỉ quan tâm jsx()/jsxs() và Object.assign."""
    name = ins.inst.name
    if name == "CallBuiltin" or name == "CallBuiltinLong":
        # Object.assign(dst, src…) — giữ object đích, bỏ phần props lúc chạy
        if ins.arg2 == OBJECT_ASSIGN_BUILTIN:
            registers[ins.arg1] = registers.get(ins.arg1)
        else:
            registers.pop(ins.arg1, None)
        return
    callee = registers.get(getattr(ins, "arg2", None))
    if not (isinstance(callee, PropRef) and callee.name in JSX_NAMES):
        registers.pop(ins.arg1, None)
        return
    # Call<N> dst, callee, thisArg, arg1, arg2 …
    tag_ref = registers.get(getattr(ins, "arg4", None))
    props = registers.get(getattr(ins, "arg5", None))
    tag = TAGS.get(tag_ref.name) if isinstance(tag_ref, PropRef) else None
    if tag is None:
        registers.pop(ins.arg1, None)
        return
    registers[ins.arg1] = Element(tag, props if isinstance(props, dict) else {})


def _attr_name(name):
    if name in KEEP_CASE:
        return name
    if name == "xlinkHref":
        return "xlink:href"
    return re.sub(r"(?<!^)(?=[A-Z])", "-", name).lower()


def _escape(value):
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _render(element):
    if element is None:
        return ""
    if not isinstance(element, Element):
        return ""
    attrs = []
    children = []
    for key, value in (element.props or {}).items():
        if key in SKIP_PROPS:
            continue
        if value is None or value is True or isinstance(value, (dict, list)):
            continue
        attrs.append(f'{_attr_name(key)}="{_escape(value)}"')
    raw_children = (element.props or {}).get("children")
    if isinstance(raw_children, list):
        candidates = raw_children
    elif raw_children is not None:
        candidates = [raw_children]
    else:
        candidates = []
    for child in candidates:
        rendered = _render(child)
        if rendered:
            children.append(rendered)
    head = element.tag + ((" " + " ".join(attrs)) if attrs else "")
    if children:
        return f"<{head}>" + "".join(children) + f"</{element.tag}>"
    return f"<{head}/>"


def _svg_name(reader, function_id):
    """Tên hàm component, ví dụ SvgBellRing."""
    try:
        raw = reader.strings[reader.function_headers[function_id].functionName]
    except (IndexError, AttributeError):
        return ""
    return raw or ""


def _build(apk_path):
    empty = {"icons": [], "svg": {}}
    if not AVAILABLE:
        return empty
    data = _bundle_bytes(apk_path)
    if not data:
        return empty
    try:
        reader = HBCReader()
        reader.read_whole_file(BytesIO(data))
    except Exception:
        return empty
    root_shapes = _root_shapes(reader)
    if not root_shapes:
        return empty

    icons, sources = [], {}
    for function_id, header in enumerate(reader.function_headers):
        if header.bytecodeSizeInBytes < 32:
            continue
        try:
            if not _interpret(reader, function_id, root_shapes, probe=True):
                continue
            root = _interpret(reader, function_id, root_shapes)
        except Exception:
            continue
        if root is None:
            continue
        markup = _render(root)
        if not markup or "<" not in markup[1:]:
            continue  # thẻ <svg> rỗng, không có gì để vẽ
        sources[function_id] = markup
        icons.append({
            "function": function_id,
            "name": _svg_name(reader, function_id) or f"svg-{function_id}",
            "size": len(markup.encode("utf-8")),
            "nodes": markup.count("<") - markup.count("</"),
        })
    return {"icons": icons, "svg": sources}


def _cached(apk_path):
    path = Path(apk_path)
    try:
        stat = path.stat()
    except OSError:
        return {"icons": [], "svg": {}}
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    if key not in _CACHE:
        if len(_CACHE) >= _CACHE_LIMIT:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = _build(apk_path)
    return _CACHE[key]


def icons(apk_path):
    """Danh sách SVG nhúng trong Hermes bundle của APK."""
    return _cached(apk_path)["icons"]


def markup(apk_path, function_id):
    """Nội dung SVG của một hàm; chuỗi rỗng nếu không có."""
    try:
        function_id = int(function_id)
    except (TypeError, ValueError):
        return ""
    return _cached(apk_path)["svg"].get(function_id, "")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        for item in icons(sys.argv[1]):
            print(f"f{item['function']:<7} {item['name']:<34} "
                  f"{item['nodes']:>3} thẻ  {item['size']:>7} B")
    elif len(sys.argv) == 3:
        print(markup(sys.argv[1], sys.argv[2]))
    else:
        print(__doc__)
        sys.exit(1)
