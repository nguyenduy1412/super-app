#!/usr/bin/env python3
"""
Trích danh sách API mà ứng dụng gọi, đọc thẳng từ Hermes bytecode và dex.

Với app React Native dùng Supabase, các lời gọi có dạng chuỗi phương thức
`.from("bảng").select("cột…").eq(…)`. Tên bảng và danh sách cột là hằng chuỗi
trong bytecode, và `this` của mỗi lời gọi trỏ về builder do `.from()` trả ra —
nên nối lại được nguyên chuỗi, biết bảng nào lấy những cột nào.

LƯU Ý VỀ "RESPONSE": APK chỉ chứa phía gọi, không chứa dữ liệu server trả về.
Cột liệt kê ở đây là cột ứng dụng YÊU CẦU (tham số của `.select`), tức hình dạng
response, chứ không phải giá trị thật. Muốn có response thật thì phải chạy app
và bắt gói tin.

Cách dùng CLI:
    python3 api_extract.py app.apk
"""
import ast
import json
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
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

BUNDLE_ENTRY = "assets/index.android.bundle"
HBC_MAGIC = b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"
GET_OPS = {"GetById", "GetByIdShort", "GetByIdLong", "TryGetById",
           "TryGetByIdLong"}
STR_OPS = {"LoadConstString", "LoadConstStringLongIndex"}
# phương thức mở đầu một chuỗi truy vấn
ROOTS = {"from": "table", "rpc": "rpc", "invoke": "function"}
# phương thức nối tiếp trong chuỗi PostgREST
CHAIN_OPS = {
    "select", "insert", "update", "upsert", "delete", "eq", "neq", "gt", "gte",
    "lt", "lte", "like", "ilike", "is", "in", "contains", "containedBy",
    "overlaps", "textSearch", "match", "not", "or", "filter", "order",
    "limit", "range", "single", "maybeSingle", "csv", "returns",
    "throwOnError", "abortSignal", "count", "head",
}
WRITE_VERBS = {"insert", "update", "upsert", "delete"}
# PostgREST/Supabase ánh xạ cố định phương thức -> HTTP, không phải suy đoán
HTTP_METHOD = {
    "select": "GET", "insert": "POST", "upsert": "POST", "update": "PATCH",
    "delete": "DELETE", "rpc": "POST", "invoke": "POST",
}
# opcode chỉ SỬA object/mảng sẵn có, không ghi đè thanh ghi đích
MUTATE_OPS = {
    "PutOwnBySlotIdx", "PutOwnBySlotIdxLong", "DefineOwnById",
    "DefineOwnByIdLong", "PutNewOwnById", "PutNewOwnByIdLong",
    "DefineOwnInDenseArray", "DefineOwnInDenseArrayL", "PutByValStrict",
    "PutByValLoose", "PutByIdLoose", "PutByIdStrict",
}
# host bỏ qua: hạ tầng/chuẩn, không phải API của app
SKIP_HOSTS = {
    "www.w3.org", "json-schema.org", "schemas.android.com", "localhost",
    "hostname", "127.0.0.1", "example.com", "www.example.com",
}
URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}")
MAX_COLUMN_TEXT = 2000
_CACHE = {}
_CACHE_LIMIT = 4


class Chain:
    """Một chuỗi truy vấn đang được dựng, ví dụ .from("posts").select(...)."""
    __slots__ = ("kind", "name", "ops", "params")

    def __init__(self, kind, name):
        self.kind = kind
        self.name = name
        self.ops = []
        self.params = []


NEW_OBJ_OPS = {"NewObjectWithBuffer", "NewObjectWithBufferLong"}


def _shape_keys(reader, index):
    try:
        return [ast.literal_eval(k) for k in reader.object_shape_keys[index]]
    except (ValueError, SyntaxError, IndexError):
        return []


def _writes_register(ins):
    operands = ins.inst.operands
    return bool(operands) and operands[0].operand_type.name.startswith("Reg")


def _bundle_bytes(apk_path):
    try:
        with zipfile.ZipFile(apk_path) as archive:
            data = archive.read(BUNDLE_ENTRY)
    except (KeyError, OSError, zipfile.BadZipFile):
        return b""
    return data if data[:8] == HBC_MAGIC else b""


def _clean_columns(text):
    """Gộp danh sách cột nhiều dòng thành một dòng gọn."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", text).strip()[:MAX_COLUMN_TEXT]


# Kiểu dữ liệu của zod tồn tại lúc chạy (z.string(), z.number()…), khác hẳn
# `type`/`interface` của TypeScript vốn bị xoá sạch khi biên dịch.
ZOD_TYPES = {
    "string", "number", "boolean", "date", "array", "object", "enum",
    "literal", "email", "url", "uuid", "int", "bigint", "any", "unknown",
    "record", "union", "tuple", "map", "set", "nativeEnum", "file",
    "instanceof", "coerce", "never", "null", "undefined", "symbol",
}
# phương thức nối thêm ràng buộc, giữ lại để biết giới hạn của trường
ZOD_REFINERS = {
    "min", "max", "length", "regex", "trim", "email", "url", "uuid", "int",
    "positive", "negative", "nonempty", "optional", "nullable", "nullish",
    "default", "refine", "superRefine", "transform", "describe", "catch",
    "brand", "readonly", "startsWith", "endsWith", "includes", "gte", "lte",
    "gt", "lt", "multipleOf", "finite", "safe", "toLowerCase", "toUpperCase",
}


class ZodShape:
    """Một lời gọi z.object({...}) đã dựng lại."""
    __slots__ = ("keys", "fields")

    def __init__(self, keys):
        self.keys = keys
        self.fields = {}


def _scan_zod(reader):
    """Các schema zod trong bundle: tên trường + kiểu + ràng buộc."""
    shapes = []
    for header in reader.function_headers:
        if header.bytecodeSizeInBytes < 12:
            continue
        registers = {}
        try:
            for ins in parse_hbc_bytecode(header, reader):
                name = ins.inst.name
                if name in GET_OPS:
                    registers[ins.arg1] = ("prop", reader.strings[ins.arg4])
                elif name in STR_OPS:
                    registers[ins.arg1] = ("str", reader.strings[ins.arg2])
                elif name in NEW_OBJ_OPS:
                    registers[ins.arg1] = (
                        "shape", ZodShape(_shape_keys(reader, ins.arg2)))
                elif name in ("PutOwnBySlotIdx", "PutOwnBySlotIdxLong"):
                    target = registers.get(ins.arg1)
                    value = registers.get(ins.arg2)
                    if (target and target[0] == "shape" and value
                            and value[0] == "zod"
                            and ins.arg3 < len(target[1].keys)):
                        key = target[1].keys[ins.arg3]
                        if isinstance(key, str):
                            target[1].fields[key] = value[1]
                elif name.startswith("Call"):
                    registers[ins.arg1] = _zod_call(registers, ins, shapes)
                    if registers[ins.arg1] is None:
                        registers.pop(ins.arg1, None)
                elif name in MUTATE_OPS:
                    pass
                elif name in ("Mov", "MovLong"):
                    registers[ins.arg1] = registers.get(ins.arg2)
                elif _writes_register(ins):
                    registers.pop(ins.arg1, None)
        except Exception:
            continue
    return shapes


def _zod_call(registers, ins, shapes):
    callee = registers.get(getattr(ins, "arg2", None))
    if not (callee and callee[0] == "prop"):
        return None
    method = callee[1]
    target = registers.get(getattr(ins, "arg3", None))
    first = registers.get(getattr(ins, "arg4", None))
    if method == "object" and first and first[0] == "shape":
        shapes.append(first[1])
        return ("zod", "object")
    if method in ZOD_TYPES and not (target and target[0] == "zod"):
        return ("zod", method)
    if target and target[0] == "zod" and method in ZOD_REFINERS:
        return ("zod", f"{target[1]}.{method}")
    return None


def _zod_rows(shapes):
    """Gộp schema trùng nhau, bỏ schema rỗng."""
    rows, seen = [], set()
    for shape in shapes:
        if not shape.fields:
            continue
        key = tuple(sorted(shape.fields.items()))
        if key in seen:
            continue
        seen.add(key)
        rows.append({"fields": [{"name": k, "type": v}
                                for k, v in shape.fields.items()]})
    return sorted(rows, key=lambda r: -len(r["fields"]))


def _scan_chains(reader):
    """Mọi chuỗi truy vấn Supabase tìm được trong bundle."""
    chains = []
    for header in reader.function_headers:
        if header.bytecodeSizeInBytes < 12:
            continue
        registers = {}
        try:
            for ins in parse_hbc_bytecode(header, reader):
                name = ins.inst.name
                if name in GET_OPS:
                    registers[ins.arg1] = ("prop", reader.strings[ins.arg4])
                elif name in STR_OPS:
                    registers[ins.arg1] = ("str", reader.strings[ins.arg2])
                elif name.startswith("Call"):
                    result = _apply_call(registers, ins, chains)
                    if result is None:
                        registers.pop(ins.arg1, None)
                    else:
                        registers[ins.arg1] = result
                elif name in NEW_OBJ_OPS:
                    registers[ins.arg1] = ("obj", tuple(
                        _shape_keys(reader, ins.arg2)))
                elif name in MUTATE_OPS:
                    pass          # sửa nội dung, thanh ghi vẫn giữ giá trị cũ
                elif name in ("Mov", "MovLong"):
                    registers[ins.arg1] = registers.get(ins.arg2)
                elif _writes_register(ins):
                    registers.pop(ins.arg1, None)
        except Exception:
            continue
    return chains


def _apply_call(registers, ins, chains):
    callee = registers.get(getattr(ins, "arg2", None))
    if not (callee and callee[0] == "prop"):
        return None
    method = callee[1]
    first = registers.get(getattr(ins, "arg4", None))
    text = first[1] if first and first[0] == "str" else None
    if method in ROOTS:
        if not text:
            return None
        chain = Chain(ROOTS[method], text)
        second = registers.get(getattr(ins, "arg5", None))
        if second and second[0] == "obj":
            chain.params = [k for k in second[1] if isinstance(k, str)]
        chains.append(chain)
        return ("chain", chain)
    target = registers.get(getattr(ins, "arg3", None))
    if method in CHAIN_OPS and target and target[0] == "chain":
        target[1].ops.append((method, text))
        return target
    return None


# host chỉ xuất hiện trong thông báo lỗi / tài liệu của thư viện
DOC_HOSTS = re.compile(
    r"(^|\.)(w3\.org|json-schema\.org|schemas\.android\.com|xmlpull\.org|"
    r"xml\.org|ns\.adobe\.com|slf4j\.org|opentelemetry\.io|dashif\.org|"
    r"github\.io|github\.com|reactnavigation\.org|react\.dev|expo\.fyi|"
    r"docs\..*|developer\..*|issuetracker\..*|youtrack\..*|openid\.net|"
    r"dev\.to|g\.co|goo\.gl|apps\.mapbox\.com|www\.mapbox\.com)$")
# "/auth/…" của googleapis.com là OAuth scope chứ không phải endpoint nên bỏ
API_PATH = re.compile(r"/(api|v\d|rest|graphql|geocoding|data|rpc|functions|"
                      r"push|oauth|token)(/|$|\?)")


def _looks_like_api(url):
    host = url.split("//", 1)[-1].split("/")[0].split(":")[0].lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", host):
        return False
    if host in SKIP_HOSTS or DOC_HOSTS.search(host):
        return False
    path = url.split("//", 1)[-1][len(host):]
    return host.startswith(("api.", "auth.")) or host == "exp.host" or bool(
        API_PATH.search(path))


def _urls(strings, dex_blobs):
    """URL của app. Bundle dùng bảng chuỗi đã parse chứ không quét byte thô:
    Hermes xếp các chuỗi liền nhau nên regex sẽ chạy lấn sang chuỗi kế tiếp và
    ghép ra những URL không hề tồn tại."""
    found, skipped = set(), 0
    candidates = [s for s in strings
                  if s.startswith(("http://", "https://"))]
    for blob in dex_blobs:
        for match in URL_RE.findall(blob):
            candidates.append(match.decode("utf-8", errors="replace"))
    for url in candidates:
        url = url.rstrip(".,);'\"")
        if _looks_like_api(url):
            found.add(url)
        else:
            skipped += 1
    return sorted(found), skipped


def _summarize(chains):
    """Gộp các chuỗi trùng nhau thành từng dòng cho bảng trên UI."""
    rows = {}
    for chain in chains:
        verb = "select"
        columns = ""
        filters = []
        for method, text in chain.ops:
            if method in WRITE_VERBS:
                verb = method
            elif method == "select":
                columns = _clean_columns(text) or columns or "*"
            elif method in ("eq", "neq", "gt", "gte", "lt", "lte", "like",
                            "ilike", "in", "match", "filter", "is"):
                if text:
                    filters.append(f"{method}({text})")
            elif method in ("single", "maybeSingle"):
                filters.append(method)
        if chain.kind == "rpc":
            verb = "rpc"
        elif chain.kind == "function":
            verb = "invoke"
        key = (chain.kind, chain.name, verb, columns)
        row = rows.setdefault(key, {
            "kind": chain.kind, "name": chain.name, "verb": verb,
            "http": HTTP_METHOD.get(verb, "?"),
            "columns": columns, "filters": [], "params": [], "count": 0,
        })
        for param in chain.params:
            if param not in row["params"]:
                row["params"].append(param)
        row["count"] += 1
        for item in filters:
            if item not in row["filters"]:
                row["filters"].append(item)
    order = {"table": 0, "rpc": 1, "function": 2}
    return sorted(rows.values(),
                  key=lambda r: (order.get(r["kind"], 3), r["name"], r["verb"]))


def _config_urls(apk_path):
    """URL lấy nguyên văn từ assets/app.config — cấu hình thật của app."""
    try:
        with zipfile.ZipFile(apk_path) as archive:
            config = json.loads(archive.read("assets/app.config"))
    except (KeyError, OSError, ValueError, zipfile.BadZipFile):
        return []
    found = set()

    def walk(node):
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, str) and node.startswith(("http://", "https://")):
            found.add(node)
    walk(config)
    return sorted(found)


def extract(apk_path):
    """Báo cáo API: bảng/RPC/edge function của Supabase + URL tuyệt đối."""
    report = {"rows": [], "urls": [], "config_urls": [], "schemas": [],
              "urls_skipped": 0, "note": ""}
    bundle = _bundle_bytes(apk_path)
    dex = []
    try:
        with zipfile.ZipFile(apk_path) as archive:
            for name in archive.namelist():
                if name.endswith(".dex"):
                    dex.append(archive.read(name))
    except (OSError, zipfile.BadZipFile):
        pass
    strings = []
    if AVAILABLE and bundle:
        try:
            reader = HBCReader()
            reader.read_whole_file(BytesIO(bundle))
            strings = reader.strings
            report["rows"] = _summarize(_scan_chains(reader))
            report["schemas"] = _zod_rows(_scan_zod(reader))
        except Exception:
            report["rows"] = []
    report["urls"], report["urls_skipped"] = _urls(strings, dex)
    report["config_urls"] = _config_urls(apk_path)
    if report["rows"] or report["urls"] or report["schemas"]:
        report["note"] = (
            "Phương thức HTTP và tham số gửi lên là dữ liệu thật đọc từ bytecode. "
            "Cột \"cột yêu cầu\" là tham số .select(), tức hình dạng response — "
            "APK không chứa dữ liệu server trả về, cũng không chứa type của "
            "TypeScript (bị xoá lúc biên dịch). Muốn response thật phải chạy app "
            "và bắt gói tin."
        )
    return report


def cached(apk_path):
    path = Path(apk_path)
    try:
        stat = path.stat()
    except OSError:
        return extract(apk_path)
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    if key not in _CACHE:
        if len(_CACHE) >= _CACHE_LIMIT:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = extract(apk_path)
    return _CACHE[key]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    print(json.dumps(extract(sys.argv[1]), indent=2, ensure_ascii=False))
