#!/usr/bin/env python3
"""
Trích Lottie JSON nhúng trong Hermes bytecode, đọc thẳng từ bytecode.

Metro biên dịch file .json thành một module JS, rồi Hermes biên dịch module đó
thành bytecode chỉ gồm các lệnh dựng dữ liệu (NewObjectWithBuffer,
NewArrayWithBuffer, DefineOwnInDenseArray, PutOwnBySlotIdx…). Thân hàm là code
thẳng, không nhánh, nên thông dịch tuần tự là dựng lại được nguyên văn JSON.

Cách này thay cho việc decompile ra JS rồi eval lại: bộ decompile đặt tên biến
theo số thanh ghi, mà thanh ghi bị tái sử dụng cho nhiều mảng khác nhau trong
cùng một module, nên `assets`/`layers`/`markers` cùng trỏ vào giá trị cuối và
JSON dựng lại bị mất dữ liệu.

Cách dùng CLI:
    python3 lottie_extract.py app.apk              # liệt kê animation tìm được
    python3 lottie_extract.py app.apk 4596         # in JSON của một hàm
"""
import ast
import json
import logging
import struct
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
except ImportError:  # thiếu hermes_dec → caller tự fallback
    AVAILABLE = False

BUNDLE_ENTRY = "assets/index.android.bundle"
HBC_MAGIC = b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"
# Khoá bắt buộc ở gốc một file Lottie; asset precomp lồng bên trong chỉ có
# {id, nm, fr, layers} nên không trùng chữ ký này.
ROOT_KEYS = frozenset({"v", "fr", "ip", "op", "layers"})
MIN_BYTECODE_SIZE = 64          # hàm nhỏ hơn không thể chứa animation
MAX_INSTRUCTIONS = 4_000_000    # chặn hàm bất thường
STRING_TAGS = frozenset({
    TagType.LongStringTag, TagType.ShortStringTag, TagType.ByteStringTag,
}) if AVAILABLE else frozenset()

_CACHE = {}          # cache_key -> {"animations": [...], "json": {fid: str}}
_CACHE_LIMIT = 4     # số bundle giữ lại


class Unsupported(Exception):
    """Gặp opcode ngoài tập lệnh dựng dữ liệu — bỏ qua hàm này."""


class _Obj(dict):
    """Object kèm danh sách khoá theo shape, để giải nghĩa PutOwnBySlotIdx."""
    __slots__ = ("shape",)


class _Undefined:
    """undefined của JS — khác null, và JSON.stringify bỏ hẳn khoá mang nó."""
    __slots__ = ()

    def __repr__(self):
        return "undefined"


UNDEFINED = _Undefined()


def _drop_undefined(value):
    """Bỏ undefined đúng như JSON.stringify: mất khoá trong object, hoá null trong mảng."""
    if isinstance(value, dict):
        return {key: _drop_undefined(item) for key, item in value.items()
                if item is not UNDEFINED}
    if isinstance(value, list):
        return [None if item is UNDEFINED else _drop_undefined(item)
                for item in value]
    return value


def _bundle_bytes(apk_path):
    """Đọc Hermes bundle trong APK; None nếu không phải bundle Hermes."""
    try:
        with zipfile.ZipFile(apk_path) as archive:
            data = archive.read(BUNDLE_ENTRY)
    except (KeyError, OSError, zipfile.BadZipFile):
        return None
    return data if data[:8] == HBC_MAGIC else None


def _read_bundle(data):
    reader = HBCReader()
    reader.read_whole_file(BytesIO(data))
    return reader


def _shape_keys(reader, shape_index):
    """Khoá của một object shape (parser trả về dạng repr, cần bóc ngược)."""
    return [ast.literal_eval(key)
            for key in reader.object_shape_keys[shape_index]]


def _literals(reader, offset, count):
    """Giải mảng literal đã serialize thành giá trị Python."""
    values = []
    for item in unpack_slp_array(reader.literal_values[offset:], count).items:
        if item.tag_type in STRING_TAGS:
            values.append(reader.strings[item.value])
        elif item.tag_type == TagType.NumberTag:
            number = item.value
            values.append(int(number) if number.is_integer() else number)
        else:
            values.append(item.value)
    return values


def _lottie_shapes(reader):
    """Chỉ số các object shape mang chữ ký gốc của Lottie."""
    return {index for index, keys in enumerate(reader.object_shape_keys)
            if ROOT_KEYS <= set(_shape_keys(reader, index))}


def _interpret(reader, function_id, root_shapes, stop_at_first=False):
    """Chạy thân hàm, trả về object gốc Lottie đầu tiên dựng được (hoặc None).

    stop_at_first=True chỉ dò xem hàm có dựng object Lottie không, dừng ngay khi
    thấy — dùng cho bước quét cả bundle.
    """
    registers = {}
    root = None
    for count, ins in enumerate(
            parse_hbc_bytecode(reader.function_headers[function_id], reader)):
        if count > MAX_INSTRUCTIONS:
            raise Unsupported("hàm quá dài")
        name = ins.inst.name

        if name in ("NewObjectWithBuffer", "NewObjectWithBufferLong"):
            if stop_at_first:
                if ins.arg2 in root_shapes:
                    return True
                continue
            keys = _shape_keys(reader, ins.arg2)
            obj = _Obj(zip(keys, _literals(reader, ins.arg3, len(keys))))
            obj.shape = keys
            registers[ins.arg1] = obj
            if ins.arg2 in root_shapes and root is None:
                root = obj
        elif stop_at_first:
            continue
        elif name in ("NewArrayWithBuffer", "NewArrayWithBufferLong"):
            registers[ins.arg1] = _literals(reader, ins.arg4, ins.arg3)
        elif name == "NewArray":
            registers[ins.arg1] = [None] * ins.arg2
        elif name == "NewObject":
            obj = _Obj()
            obj.shape = []
            registers[ins.arg1] = obj
        elif name in ("DefineOwnInDenseArray", "DefineOwnInDenseArrayL"):
            array = registers[ins.arg1]
            if not isinstance(array, list):
                raise Unsupported("ghi phần tử vào giá trị không phải mảng")
            while len(array) <= ins.arg3:
                array.append(None)
            array[ins.arg3] = registers[ins.arg2]
        elif name in ("PutOwnBySlotIdx", "PutOwnBySlotIdxLong"):
            obj = registers[ins.arg1]
            if not isinstance(obj, _Obj) or ins.arg3 >= len(obj.shape):
                raise Unsupported("slot nằm ngoài shape")
            obj[obj.shape[ins.arg3]] = registers[ins.arg2]
        elif name in ("PutByIdLoose", "PutByIdStrict",
                      "PutByIdLooseLong", "PutByIdStrictLong"):
            pass  # gán vào exports/module — dữ liệu đã nắm qua root_shapes
        elif name in ("Mov", "MovLong"):
            registers[ins.arg1] = registers.get(ins.arg2)
        elif name in ("LoadParam", "LoadParamLong", "LoadConstUndefined",
                      "LoadConstEmpty"):
            registers[ins.arg1] = UNDEFINED
        elif name == "LoadConstNull":
            registers[ins.arg1] = None
        elif name == "LoadConstTrue":
            registers[ins.arg1] = True
        elif name == "LoadConstFalse":
            registers[ins.arg1] = False
        elif name == "LoadConstZero":
            registers[ins.arg1] = 0
        elif name in ("LoadConstInt", "LoadConstUInt8"):
            registers[ins.arg1] = ins.arg2
        elif name == "LoadConstDouble":
            number = ins.arg2
            registers[ins.arg1] = (int(number) if float(number).is_integer()
                                   else number)
        elif name in ("LoadConstString", "LoadConstStringLongIndex"):
            registers[ins.arg1] = reader.strings[ins.arg2]
        elif name == "Ret":
            break
        else:
            raise Unsupported(name)
    return None if stop_at_first else root


def _scan(reader):
    """Tìm mọi hàm dựng một object gốc Lottie."""
    root_shapes = _lottie_shapes(reader)
    if not root_shapes:
        return [], root_shapes
    found = []
    for function_id, header in enumerate(reader.function_headers):
        if header.bytecodeSizeInBytes < MIN_BYTECODE_SIZE:
            continue
        try:
            if _interpret(reader, function_id, root_shapes, stop_at_first=True):
                found.append(function_id)
        except (Unsupported, KeyError, IndexError, ValueError,
                NotImplementedError):
            continue
    return found, root_shapes


def _build(apk_path):
    """Quét bundle của APK, dựng sẵn JSON cho mọi animation tìm thấy."""
    empty = {"animations": [], "json": {}}
    if not AVAILABLE:
        return empty
    data = _bundle_bytes(apk_path)
    if not data:
        return empty
    # hermes_dec log cảnh báo với các bản bytecode mới; không cần trong web UI
    level = logging.getLogger().level
    logging.getLogger().setLevel(logging.ERROR)
    try:
        reader = _read_bundle(data)
        function_ids, root_shapes = _scan(reader)
        animations, sources = [], {}
        for function_id in function_ids:
            try:
                root = _interpret(reader, function_id, root_shapes)
            except (Unsupported, KeyError, IndexError, ValueError,
                    NotImplementedError):
                continue
            if not root or not isinstance(root.get("layers"), list):
                continue
            text = json.dumps(_drop_undefined(root), ensure_ascii=False,
                              separators=(",", ":"))
            sources[function_id] = text
            animations.append({
                "function": function_id,
                "name": str(root.get("nm") or f"animation-{function_id}"),
                "size": len(text.encode("utf-8")),
                "layers": len(root["layers"]),
            })
        return {"animations": animations, "json": sources}
    except (OSError, ValueError, IndexError, KeyError, NotImplementedError,
            AssertionError, struct.error):
        return empty
    finally:
        logging.getLogger().setLevel(level)


def _cached(apk_path):
    path = Path(apk_path)
    try:
        stat = path.stat()
    except OSError:
        return {"animations": [], "json": {}}
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    if key not in _CACHE:
        if len(_CACHE) >= _CACHE_LIMIT:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = _build(apk_path)
    return _CACHE[key]


def animations(apk_path):
    """Danh sách animation Lottie nhúng trong bundle Hermes của APK."""
    return _cached(apk_path)["animations"]


def animation_json(apk_path, function_id):
    """JSON của một animation; chuỗi rỗng nếu không có."""
    try:
        function_id = int(function_id)
    except (TypeError, ValueError):
        return ""
    return _cached(apk_path)["json"].get(function_id, "")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        for item in animations(sys.argv[1]):
            print(f"f{item['function']:<6} {item['name']:<45} "
                  f"{item['layers']:>3} layers  {item['size']:>9} B")
    elif len(sys.argv) == 3:
        print(animation_json(sys.argv[1], sys.argv[2]))
    else:
        print(__doc__)
        sys.exit(1)
