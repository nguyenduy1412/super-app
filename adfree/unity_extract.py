#!/usr/bin/env python3
"""
Trích ảnh (Texture2D) từ tài nguyên Unity trong APK.

Unity không để ảnh thành file rời mà gói vào container UnityFS (data.unity3d)
hoặc SerializedFile (*.assets). Module này tự đọc cả hai bằng thư viện chuẩn
Python: giải nén khối LZ4/LZMA, đọc bảng object, lấy Texture2D cùng dữ liệu
pixel nằm trong file .resS đi kèm.

Ảnh không nén được xuất thẳng ra PNG. Ảnh nén theo định dạng GPU (ASTC, ETC2,
DXT) xuất ra đúng dữ liệu khối kèm header chuẩn .astc/.dds — giải mã các định
dạng đó cần bộ giải riêng, chưa làm trong bản này.

Cách dùng CLI:
    python3 unity_extract.py app.apk            # liệt kê ảnh tìm được
    python3 unity_extract.py app.apk 3          # xuất ảnh thứ 3 ra stdout
"""
import io
import lzma
import math
import re
import struct
import sys
import zipfile
import zlib
from pathlib import Path

UNITY_DIRS = ("assets/bin/Data/", "assets/")
BUNDLE_MAGIC = b"UnityFS"
CLASS_TEXTURE2D = 28
MAX_BUNDLE = 512 * 1024 * 1024
_CACHE = {}
_CACHE_LIMIT = 2

# id định dạng của Unity -> (tên, kích thước khối, byte mỗi khối)
# khối 1x1 nghĩa là ảnh không nén, byte/khối là byte mỗi điểm ảnh
FORMATS = {
    1: ("Alpha8", 1, 1), 2: ("ARGB4444", 1, 2), 3: ("RGB24", 1, 3),
    4: ("RGBA32", 1, 4), 5: ("ARGB32", 1, 4), 7: ("RGB565", 1, 2),
    13: ("RGBA4444", 1, 2), 14: ("BGRA32", 1, 4), 62: ("RG16", 1, 2),
    63: ("R8", 1, 1),
    10: ("DXT1", 4, 8), 12: ("DXT5", 4, 16),
    34: ("ETC_RGB4", 4, 8), 45: ("ETC2_RGB", 4, 8),
    46: ("ETC2_RGBA1", 4, 8), 47: ("ETC2_RGBA8", 4, 16),
    48: ("ASTC_4x4", 4, 16), 49: ("ASTC_5x5", 5, 16), 50: ("ASTC_6x6", 6, 16),
    51: ("ASTC_8x8", 8, 16), 52: ("ASTC_10x10", 10, 16),
    53: ("ASTC_12x12", 12, 16),
}
# định dạng giải được ngay ra PNG bằng Python thuần
PLAIN = {"Alpha8", "R8", "RGB24", "RGBA32", "ARGB32", "BGRA32", "RGB565",
         "RGBA4444", "ARGB4444", "RG16"}


# ----------------------------------------------------------------- UnityFS
def _cstr(f):
    out = bytearray()
    while True:
        char = f.read(1)
        if not char or char == b"\0":
            break
        out += char
    return out.decode("utf-8", "replace")


def _be(f, size):
    return int.from_bytes(f.read(size), "big")


def lz4_decompress(src, out_size):
    """Giải nén khối LZ4 — viết tay để không cần thư viện ngoài."""
    dst = bytearray()
    pos, end = 0, len(src)
    while pos < end and len(dst) < out_size:
        token = src[pos]
        pos += 1
        length = token >> 4
        if length == 15:
            while True:
                extra = src[pos]
                pos += 1
                length += extra
                if extra != 255:
                    break
        dst += src[pos:pos + length]
        pos += length
        if pos >= end:
            break
        offset = src[pos] | (src[pos + 1] << 8)
        pos += 2
        match = token & 0xF
        if match == 15:
            while True:
                extra = src[pos]
                pos += 1
                match += extra
                if extra != 255:
                    break
        match += 4
        start = len(dst) - offset
        if start < 0:
            raise ValueError("offset LZ4 không hợp lệ")
        for index in range(match):
            dst.append(dst[start + index])
    return bytes(dst[:out_size])


def _unblock(raw, size, flags):
    kind = flags & 0x3F
    if kind == 0:
        return raw[:size]
    if kind in (2, 3):
        return lz4_decompress(raw, size)
    if kind == 1:
        return lzma.decompress(raw[:5] + size.to_bytes(8, "little") + raw[5:])
    raise ValueError(f"kiểu nén {kind} chưa hỗ trợ")


def read_bundle(data):
    """Giải container UnityFS thành {tên file con: bytes}."""
    stream = io.BytesIO(data)
    _cstr(stream)
    version = _be(stream, 4)
    _cstr(stream)
    revision = _cstr(stream)
    _be(stream, 8)
    packed = _be(stream, 4)
    unpacked = _be(stream, 4)
    flags = _be(stream, 4)
    if version >= 7:
        stream.seek((stream.tell() + 15) // 16 * 16)
    if flags & 0x80:                       # bảng khối nằm cuối file
        here = stream.tell()
        stream.seek(len(data) - packed)
        raw = stream.read(packed)
        stream.seek(here)
    else:
        raw = stream.read(packed)
    table = io.BytesIO(_unblock(raw, unpacked, flags))
    if flags & 0x200:                      # cần đệm 16 byte trước dữ liệu
        stream.seek((stream.tell() + 15) // 16 * 16)
    table.read(16)
    blocks = [(int.from_bytes(table.read(4), "big"),
               int.from_bytes(table.read(4), "big"),
               int.from_bytes(table.read(2), "big"))
              for _ in range(int.from_bytes(table.read(4), "big"))]
    nodes = []
    for _ in range(int.from_bytes(table.read(4), "big")):
        nodes.append((int.from_bytes(table.read(8), "big"),
                      int.from_bytes(table.read(8), "big"),
                      int.from_bytes(table.read(4), "big"),
                      _cstr(table)))
    body = bytearray()
    for size, packed_size, block_flags in blocks:
        body += _unblock(stream.read(packed_size), size, block_flags)
    return revision, {name: bytes(body[offset:offset + size])
                      for offset, size, _, name in nodes}


# ----------------------------------------------------------- SerializedFile
class Reader:
    def __init__(self, data, little=True):
        self.f = io.BytesIO(data)
        self.e = "<" if little else ">"

    def u8(self):
        return self.f.read(1)[0]

    def i16(self):
        return struct.unpack(self.e + "h", self.f.read(2))[0]

    def i32(self):
        return struct.unpack(self.e + "i", self.f.read(4))[0]

    def u32(self):
        return struct.unpack(self.e + "I", self.f.read(4))[0]

    def i64(self):
        return struct.unpack(self.e + "q", self.f.read(8))[0]

    def u64(self):
        return struct.unpack(self.e + "Q", self.f.read(8))[0]

    def cstr(self):
        return _cstr(self.f)

    def align(self, size=4):
        self.f.seek((self.f.tell() + size - 1) // size * size)

    def read(self, size):
        return self.f.read(size)

    def seek(self, pos):
        self.f.seek(pos)

    def tell(self):
        return self.f.tell()


def parse_serialized(data):
    """Đọc bảng object của một SerializedFile (*.assets, level*, resources)."""
    head = Reader(data, little=False)
    head.u32()
    head.u32()
    version = head.u32()
    data_offset = head.u32()
    little = True
    if version >= 9:
        little = head.u8() == 0
        head.read(3)
    if version >= 22:
        head.u32()
        head.i64()
        data_offset = head.i64()
        head.i64()
    reader = Reader(data, little=little)
    reader.seek(head.tell())
    unity = reader.cstr()
    reader.u32()                                  # targetPlatform
    has_tree = reader.u8() != 0 if version >= 13 else True
    types = []
    for _ in range(reader.i32()):
        class_id = reader.i32()
        if version >= 16:
            reader.u8()
        if version >= 17:
            reader.i16()
        if version >= 13:
            if (version < 16 and class_id < 0) or (version >= 16
                                                   and class_id == 114):
                reader.read(16)
            reader.read(16)
        if has_tree:
            node_count = reader.i32()
            buffer_size = reader.i32()
            reader.read(node_count * (32 if version >= 19 else 24))
            reader.read(buffer_size)
            if version >= 21:
                reader.read(4 * reader.i32())
        types.append(class_id)
    objects = []
    for _ in range(reader.i32()):
        if version >= 14:
            reader.align(4)
        reader.i64() if version >= 14 else reader.i32()
        start = reader.i64() if version >= 22 else reader.u32()
        size = reader.u32()
        type_index = reader.i32()
        objects.append((start, size, type_index))
    return {"version": version, "unity": unity, "little": little,
            "data_offset": data_offset, "types": types, "objects": objects}


def read_texture(data, meta, start, variant=0):
    """Đọc một Texture2D khi file không kèm type tree.

    Bố cục đổi giữa các đời Unity: bản 2017–2022 có cặp cờ
    m_DownscaleFallback/m_IsAlphaChannelOptional ngay sau m_ForcedFallbackFormat,
    Unity 6 thì không. Thay vì đoán theo chuỗi phiên bản (dễ sai), hàm này đọc
    theo một biến thể và bên gọi chỉ nhận kết quả khi kích thước dữ liệu tính ra
    khớp đúng số byte thật — sai bố cục thì gần như chắc chắn lệch.
    """
    reader = Reader(data, little=meta["little"])
    reader.seek(meta["data_offset"] + start)
    name_len = reader.u32()
    if not 0 < name_len < 512:
        return None
    name = reader.read(name_len).decode("utf-8", "replace")
    reader.align(4)
    reader.i32()                       # ForcedFallbackFormat
    if variant == 0:
        reader.read(2)                 # DownscaleFallback, IsAlphaChannelOptional
        reader.align(4)
    width = reader.i32()
    height = reader.i32()
    reader.i32()                       # CompleteImageSize
    reader.i32()                       # MipsStripped
    fmt = reader.i32()
    reader.i32()                       # MipCount
    reader.read(4)                     # 4 cờ bool
    reader.align(4)
    reader.i32()                       # StreamingMipmapsPriority
    reader.i32()                       # ImageCount
    reader.i32()                       # TextureDimension
    reader.read(4 * 6)                 # GLTextureSettings
    reader.i32()                       # LightmapFormat
    reader.i32()                       # ColorSpace
    reader.read(reader.i32())          # PlatformBlob
    reader.align(4)
    inline_size = reader.i32()
    inline_at = reader.tell()
    stream_offset = reader.u64()
    stream_size = reader.u32()
    path_len = reader.u32()
    path = (reader.read(path_len).decode("utf-8", "replace")
            if 0 < path_len < 512 else "")
    if not (0 < width <= 16384 and 0 < height <= 16384) or fmt not in FORMATS:
        return None
    label, block, unit = FORMATS[fmt]
    if block > 1:
        expected = (math.ceil(width / block) * math.ceil(height / block) * unit)
    else:
        expected = width * height * unit
    return {"name": name, "width": width, "height": height, "format": label,
            "block": block, "expected": expected, "inline_size": inline_size,
            "inline_at": inline_at, "stream_offset": stream_offset,
            "stream_size": stream_size, "stream_path": path}


# --------------------------------------------------------------- xuất ảnh
def png_bytes(width, height, rgba):
    """Ghi PNG 8-bit RGBA bằng zlib của thư viện chuẩn."""
    raw = bytearray()
    stride = width * 4
    for row in range(height):
        raw.append(0)                                 # filter None
        raw += rgba[row * stride:(row + 1) * stride]

    def chunk(tag, payload):
        return (len(payload).to_bytes(4, "big") + tag + payload
                + zlib.crc32(tag + payload).to_bytes(4, "big"))

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
            + chunk(b"IEND", b""))


def to_rgba(fmt, width, height, data):
    """Đổi ảnh không nén sang RGBA8; None nếu định dạng cần bộ giải GPU."""
    count = width * height
    out = bytearray(count * 4)
    if fmt in ("Alpha8", "R8"):
        for i in range(count):
            value = data[i]
            if fmt == "R8":
                out[i * 4:i * 4 + 4] = bytes((value, value, value, 255))
            else:
                out[i * 4:i * 4 + 4] = bytes((255, 255, 255, value))
    elif fmt == "RGB24":
        for i in range(count):
            out[i * 4:i * 4 + 4] = data[i * 3:i * 3 + 3] + b"\xff"
    elif fmt == "RGBA32":
        out[:] = data[:count * 4]
    elif fmt == "ARGB32":
        for i in range(count):
            a, r, g, b = data[i * 4:i * 4 + 4]
            out[i * 4:i * 4 + 4] = bytes((r, g, b, a))
    elif fmt == "BGRA32":
        for i in range(count):
            b, g, r, a = data[i * 4:i * 4 + 4]
            out[i * 4:i * 4 + 4] = bytes((r, g, b, a))
    elif fmt == "RGB565":
        for i in range(count):
            value = data[i * 2] | (data[i * 2 + 1] << 8)
            r = (value >> 11) & 0x1F
            g = (value >> 5) & 0x3F
            b = value & 0x1F
            out[i * 4:i * 4 + 4] = bytes(((r * 255) // 31, (g * 255) // 63,
                                          (b * 255) // 31, 255))
    elif fmt in ("RGBA4444", "ARGB4444"):
        for i in range(count):
            value = data[i * 2] | (data[i * 2 + 1] << 8)
            n = [(value >> 12) & 0xF, (value >> 8) & 0xF,
                 (value >> 4) & 0xF, value & 0xF]
            if fmt == "ARGB4444":
                a, r, g, b = n
            else:
                r, g, b, a = n
            out[i * 4:i * 4 + 4] = bytes((r * 17, g * 17, b * 17, a * 17))
    elif fmt == "RG16":
        for i in range(count):
            out[i * 4:i * 4 + 4] = bytes((data[i * 2], data[i * 2 + 1], 0, 255))
    else:
        return None
    return bytes(out)


def astc_file(width, height, block, data):
    """Bọc dữ liệu khối ASTC vào file .astc chuẩn để mở bằng công cụ khác."""
    header = bytearray(b"\x13\xab\xa1\x5c")
    header += bytes((block, block, 1))
    for value in (width, height, 1):
        header += bytes((value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF))
    return bytes(header) + data


# ------------------------------------------------------------ quét trong APK
def _looks_serialized(blob):
    """Nhận dạng sơ bộ SerializedFile để khỏi parse nhầm file của engine khác."""
    if len(blob) < 32:
        return False
    version = int.from_bytes(blob[8:12], "big")
    if not 5 <= version <= 30:
        return False
    file_size = int.from_bytes(blob[4:8], "big")
    # với ver>=22 trường này để 0 và kích thước thật nằm ở header mở rộng
    return file_size == 0 or file_size <= len(blob) + 64


def _sources(archive):
    """Các entry có thể chứa tài nguyên Unity."""
    found = []
    for info in archive.infolist():
        name = info.filename
        if not name.startswith("assets/"):
            continue
        if info.file_size > MAX_BUNDLE:
            continue
        tail = name.rsplit("/", 1)[-1]
        # "level" phải là scene của Unity (level0, level12…) — không phải mọi
        # file bắt đầu bằng "level" như level_complete.xml của game khác
        if (name.endswith((".unity3d", ".assets", ".bundle"))
                or tail in ("globalgamemanagers", "unity default resources")
                or re.fullmatch(r"level\d+", tail)):
            found.append(name)
    return found


def _collect(archive, names):
    """Gom mọi SerializedFile + file .resS, giải container nếu cần."""
    files = {}
    for name in names:
        try:
            blob = archive.read(name)
        except (OSError, KeyError, zipfile.BadZipFile):
            continue
        if blob[:7] == BUNDLE_MAGIC:
            try:
                _, inner = read_bundle(blob)
            except Exception:
                continue
            for key, value in inner.items():
                files.setdefault(key.rsplit("/", 1)[-1], value)
        else:
            files.setdefault(name.rsplit("/", 1)[-1], blob)
    return files


def _texture_data(texture, files, container):
    """Dữ liệu pixel: nằm trong .resS hay nhúng ngay trong object."""
    if texture["stream_path"] and texture["stream_size"]:
        key = texture["stream_path"].rsplit("/", 1)[-1]
        blob = files.get(key)
        if blob:
            start = texture["stream_offset"]
            return blob[start:start + texture["stream_size"]]
        return b""
    if texture["inline_size"]:
        start = texture["inline_at"]
        return container[start:start + texture["inline_size"]]
    return b""


def _build(apk_path):
    result = {"textures": [], "data": {}}
    try:
        with zipfile.ZipFile(apk_path) as archive:
            names = _sources(archive)
            if not names:
                return result
            files = _collect(archive, names)
    except (OSError, zipfile.BadZipFile):
        return result
    index = 0
    for name, blob in files.items():
        if not _looks_serialized(blob):
            continue
        try:
            meta = parse_serialized(blob)
        except Exception:
            continue
        for start, size, type_index in meta["objects"]:
            if not 0 <= type_index < len(meta["types"]):
                continue
            if meta["types"][type_index] != CLASS_TEXTURE2D:
                continue
            texture = payload = None
            for variant in (0, 1):
                try:
                    candidate = read_texture(blob, meta, start, variant)
                except Exception:
                    continue
                if not candidate:
                    continue
                blob_data = _texture_data(candidate, files, blob)
                if len(blob_data) == candidate["expected"]:
                    texture, payload = candidate, blob_data
                    break
            if not texture:
                continue                     # không bố cục nào khớp -> bỏ, không đoán
            texture["index"] = index
            texture["source"] = name
            texture["bytes"] = len(payload)
            texture["decodable"] = texture["format"] in PLAIN
            result["data"][index] = payload
            result["textures"].append(texture)
            index += 1
    return result


def _cached(apk_path):
    path = Path(apk_path)
    try:
        stat = path.stat()
    except OSError:
        return {"textures": [], "data": {}}
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    if key not in _CACHE:
        if len(_CACHE) >= _CACHE_LIMIT:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = _build(apk_path)
    return _CACHE[key]


def textures(apk_path):
    """Danh sách Texture2D tìm được trong tài nguyên Unity của APK."""
    return [{k: v for k, v in t.items() if k != "inline_at"}
            for t in _cached(apk_path)["textures"]]


def export(apk_path, index):
    """(bytes, mime, đuôi file) của một texture; PNG nếu giải được."""
    store = _cached(apk_path)
    try:
        index = int(index)
    except (TypeError, ValueError):
        return b"", "", ""
    texture = next((t for t in store["textures"] if t["index"] == index), None)
    payload = store["data"].get(index)
    if not texture or not payload:
        return b"", "", ""
    if texture["format"] in PLAIN:
        rgba = to_rgba(texture["format"], texture["width"], texture["height"],
                       payload)
        if rgba:
            return (png_bytes(texture["width"], texture["height"], rgba),
                    "image/png", ".png")
    if texture["format"].startswith("ASTC"):
        return (astc_file(texture["width"], texture["height"],
                          texture["block"], payload),
                "application/octet-stream", ".astc")
    return payload, "application/octet-stream", ".bin"


if __name__ == "__main__":
    if len(sys.argv) == 2:
        for item in textures(sys.argv[1]):
            flag = "PNG" if item["decodable"] else "thô"
            print(f"{item['index']:>4} {item['name'][:34]:<36} "
                  f"{item['width']:>5}x{item['height']:<5} "
                  f"{item['format']:<11} {item['bytes']:>9} B  {flag}")
    elif len(sys.argv) == 3:
        blob, mime, ext = export(sys.argv[1], sys.argv[2])
        sys.stdout.buffer.write(blob)
    else:
        print(__doc__)
        sys.exit(1)
