#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Đọc & GHI LẠI bảng chuỗi của Hermes bytecode (React Native bundle).

App React Native từ RN 0.70 trở đi biên dịch JS thành Hermes bytecode
(`assets/index.android.bundle`) — mọi text giao diện nằm trong *string table*
của file này, không nằm trong `res/values/`. Module này cho phép đọc danh sách
chuỗi, thay nội dung một số chuỗi rồi **dựng lại file bundle hợp lệ**.

Vì sao phải dựng lại cả file mà không vá tại chỗ: chuỗi tiếng Việt/Nhật cần
mã UTF-16 (2 byte/ký tự) nên gần như luôn dài hơn bản tiếng Anh 1 byte/ký tự.
Bảng chuỗi phình ra → mọi section phía sau bị dịch chỗ → phải cập nhật lại
`fileLength`, `debugInfoOffset` và **offset bytecode của từng function**.

Layout file (theo BytecodeFileFormat.h của Hermes — BSD):

    BytecodeFileHeader          ← đếm số lượng + kích thước từng section
    (đệm cho tròn 32 byte)
    SmallFunctionHeader × functionCount    ← có offset bytecode (tuyệt đối)
    StringKind::Entry × stringKindCount    ← RLE: chuỗi nào là String/Identifier
    identifierHash × identifierCount
    SmallStringTableEntry × stringCount    ← isUTF16:1 | offset:23 | length:8
    OverflowStringTableEntry × overflowStringCount   ← offset:u32, length:u32
    stringStorage (stringStorageSize byte)
    … (bigint, regexp, literal/array buffer, cjs, function source,
       bytecode của các function, LargeFunctionHeader, debug info) …
    BytecodeFileFooter          ← SHA1 của toàn bộ file phía trước

Chỉ dịch chuỗi có kind = String. Chuỗi kind = Identifier là tên thuộc tính /
biến trong JS (`onPress`, `flexDirection`…) — đổi là app hỏng ngay.

CLI:
    python3 hbc_strings.py list index.android.bundle [--all] [--limit N]
    python3 hbc_strings.py info index.android.bundle
'''

import hashlib
import struct
import sys
from pathlib import Path

HBC_MAGIC = bytes.fromhex("c61fbc03c103191f")
SHA1_LEN = 20

KIND_STRING, KIND_IDENTIFIER, KIND_PREDEFINED = 0, 1, 2

# Phiên bản đã kiểm chứng đọc/ghi. Version mới hơn vẫn thử (layout header
# được suy theo luật bên dưới) nhưng báo cảnh báo.
KNOWN_MAX_VERSION = 98
MIN_VERSION = 59


class HbcError(Exception):
    pass


def _align(n, to=4):
    return (n + to - 1) // to * to


def _header_fields(version):
    """Danh sách field u32 của BytecodeFileHeader theo version.

    Chỉ liệt kê phần u32 sau `sourceHash` — phần trước (magic u64, version
    u32, sourceHash 20 byte) là cố định ở mọi version.
    """
    f = ["fileLength", "globalCodeIndex", "functionCount", "stringKindCount",
         "identifierCount", "stringCount", "overflowStringCount",
         "stringStorageSize"]
    if version >= 87:
        f += ["bigIntCount", "bigIntStorageSize"]
    f += ["regExpCount", "regExpStorageSize"]
    if version < 97:
        f += ["arrayBufferSize", "objKeyBufferSize", "objValueBufferSize"]
    else:
        f += ["literalValueBufferSize", "objKeyBufferSize",
              "objShapeTableCount"]
        if version >= 98:
            f += ["numStringSwitchImms"]
    f += ["segmentID", "cjsModuleCount"]
    if version >= 84:
        f += ["functionSourceCount"]
    f += ["debugInfoOffset"]
    return f


def _small_func_header_size(version):
    """SmallFunctionHeader: 4 word ở version <97, 3 word từ 97 trở đi."""
    return 16 if version < 97 else 12


class HbcFile:
    """Bundle Hermes đã phân tích — đủ thông tin để dựng lại."""

    def __init__(self, data):
        self.data = data
        if data[:8] != HBC_MAGIC:
            raise HbcError("không phải file Hermes bytecode")
        self.version = struct.unpack_from("<I", data, 8)[0]
        if self.version < MIN_VERSION:
            raise HbcError(f"HBC version {self.version} quá cũ, chưa hỗ trợ")
        self.newer_than_known = self.version > KNOWN_MAX_VERSION

        # --- header ---
        self.field_off = {}
        pos = 8 + 4 + SHA1_LEN
        for name in _header_fields(self.version):
            self.field_off[name] = pos
            pos += 4
        pos += 1                      # byte cờ (staticBuiltins/…)
        self.header_size = _align(pos, 32)
        self.h = {n: struct.unpack_from("<I", data, o)[0]
                  for n, o in self.field_off.items()}
        if self.h["fileLength"] > len(data):
            raise HbcError("fileLength lớn hơn file — bundle bị cắt?")

        # --- vị trí từng section ---
        self.off_func_headers = self.header_size
        pos = self.off_func_headers + \
            self.h["functionCount"] * _small_func_header_size(self.version)
        self.off_kinds = pos = _align(pos)
        pos += self.h["stringKindCount"] * 4
        self.off_idhashes = pos = _align(pos)
        pos += self.h["identifierCount"] * 4
        self.off_small_table = pos = _align(pos)
        pos += self.h["stringCount"] * 4
        self.off_overflow = pos = _align(pos)
        pos += self.h["overflowStringCount"] * 8
        self.off_storage = pos = _align(pos)
        pos += self.h["stringStorageSize"]
        self.off_tail = _align(pos)
        if self.off_tail > len(data):
            raise HbcError("bảng chuỗi vượt quá kích thước file")

        self._read_kinds()
        self._read_strings()

    # ---------------------------------------------------------------- đọc
    def _read_kinds(self):
        """StringKind::Entry nén RLE: (count, kind) → bung thành list kind."""
        kinds = []
        bits = 31 if self.version >= 71 else 30
        mask = (1 << bits) - 1
        for i in range(self.h["stringKindCount"]):
            w = struct.unpack_from("<I", self.data,
                                   self.off_kinds + i * 4)[0]
            kinds += [w >> bits] * (w & mask)
        # Thiếu/thừa thì căn lại theo stringCount để không lệch chỉ số
        n = self.h["stringCount"]
        self.kinds = (kinds + [KIND_STRING] * n)[:n]

    def _entry(self, i):
        """(is_utf16, offset, length) của chuỗi thứ i (đã gộp overflow)."""
        w = struct.unpack_from("<I", self.data, self.off_small_table + i * 4)[0]
        is_utf16 = w & 1
        offset = (w >> 1) & 0x7FFFFF
        length = w >> 24
        if length == 0xFF:            # tràn: tra bảng overflow tại index=offset
            offset, length = struct.unpack_from(
                "<II", self.data, self.off_overflow + offset * 8)
        return is_utf16, offset, length

    def _read_strings(self):
        self.strings = []
        self.is_utf16 = []
        base = self.off_storage
        end = base + self.h["stringStorageSize"]
        for i in range(self.h["stringCount"]):
            u16, off, ln = self._entry(i)
            nbytes = ln * 2 if u16 else ln
            start = base + off
            if start + nbytes > end:
                raise HbcError(f"chuỗi #{i} nằm ngoài stringStorage")
            raw = self.data[start:start + nbytes]
            if u16:
                s = raw.decode("utf-16-le", errors="surrogatepass")
            else:
                s = raw.decode("latin-1")
            self.strings.append(s)
            self.is_utf16.append(bool(u16))

    # ------------------------------------------------------------- thông tin
    def counts_by_kind(self):
        out = {}
        for k in self.kinds:
            out[k] = out.get(k, 0) + 1
        return out

    def translatable_indices(self, pred=None):
        """Chỉ số các chuỗi kind=String (bỏ Identifier/Predefined).

        pred(text) tuỳ chọn để lọc thêm (chỉ lấy text giao diện chẳng hạn).
        """
        out = []
        for i, s in enumerate(self.strings):
            if self.kinds[i] != KIND_STRING:
                continue
            if pred is not None and not pred(s):
                continue
            out.append(i)
        return out


def parse(data_or_path):
    if isinstance(data_or_path, (bytes, bytearray)):
        return HbcFile(bytes(data_or_path))
    return HbcFile(Path(data_or_path).read_bytes())


# --------------------------------------------------------------------- ghi
def _encode(s):
    """Chuỗi → (bytes, is_utf16). Dùng latin-1 (1 byte) nếu vừa, không thì
    UTF-16LE như Hermes."""
    try:
        return s.encode("latin-1"), False
    except UnicodeEncodeError:
        return s.encode("utf-16-le", errors="surrogatepass"), True


def _flags_byte_offset(version):
    """Vị trí byte cờ trong SmallFunctionHeader (byte cuối)."""
    return _small_func_header_size(version) - 1


def rebuild(hbc, replacements, log=None):
    """Dựng lại bundle với các chuỗi đã thay.

    hbc          — HbcFile từ parse()
    replacements — {chỉ_số_chuỗi: text_mới}
    Trả về bytes của bundle mới.

    Ném HbcError nếu có function offset tràn 25 bit sau khi dịch chỗ (chưa
    hỗ trợ nâng cấp SmallFunctionHeader thành Large).
    """
    if log is None:
        log = []
    data = hbc.data
    version = hbc.version
    n = hbc.h["stringCount"]

    # 1) Gom nội dung mới cho mọi chuỗi, dựng storage mới.
    #    Chuỗi không đổi vẫn ghi lại — đơn giản và vẫn đúng offset.
    storage = bytearray()
    entries = []                       # (is_utf16, offset, length_ký_tự)
    seen = {}                          # gộp chuỗi trùng để đỡ phình file
    for i in range(n):
        text = replacements.get(i, hbc.strings[i])
        raw, u16 = _encode(text)
        key = (u16, bytes(raw))
        if key in seen:
            off = seen[key]
        else:
            if u16 and len(storage) % 2:
                storage += b"\x00"     # chuỗi UTF-16 phải căn 2 byte
            off = len(storage)
            storage += raw
            seen[key] = off
        entries.append((u16, off, len(raw) // 2 if u16 else len(raw)))

    # 2) Chuỗi nào không nhét được vào SmallStringTableEntry (offset >23 bit
    #    hoặc length ≥255) thì đẩy sang bảng overflow.
    small = bytearray()
    overflow = bytearray()
    n_overflow = 0
    for u16, off, ln in entries:
        if off <= 0x7FFFFF and ln < 0xFF:
            small += struct.pack("<I", (u16 & 1) | (off << 1) | (ln << 24))
        else:
            idx = n_overflow
            n_overflow += 1
            overflow += struct.pack("<II", off, ln)
            if idx > 0x7FFFFF:
                raise HbcError("quá nhiều chuỗi tràn bảng")
            small += struct.pack("<I", (u16 & 1) | (idx << 1) | (0xFF << 24))

    # 3) Tính độ dịch chỗ của toàn bộ phần phía sau bảng chuỗi
    old_prefix_end = hbc.off_tail
    new_off_overflow = _align(hbc.off_small_table + len(small))
    new_off_storage = _align(new_off_overflow + len(overflow))
    new_prefix_end = _align(new_off_storage + len(storage))
    delta = new_prefix_end - old_prefix_end
    if delta % 4:
        raise HbcError("độ dịch chỗ không chia hết cho 4")

    out = bytearray(data[:old_prefix_end])

    # 4) Sửa header
    def set_field(name, value):
        struct.pack_into("<I", out, hbc.field_off[name], value)

    set_field("overflowStringCount", n_overflow)
    set_field("stringStorageSize", len(storage))
    set_field("fileLength", hbc.h["fileLength"] + delta)
    if hbc.h.get("debugInfoOffset"):
        set_field("debugInfoOffset", hbc.h["debugInfoOffset"] + delta)

    # 5) Dịch offset bytecode của từng function (+ header tràn nếu có)
    hdr_size = _small_func_header_size(version)
    flag_off = _flags_byte_offset(version)
    large_ptrs = []                    # vị trí LargeFunctionHeader cần sửa
    for fi in range(hbc.h["functionCount"]):
        base = hbc.off_func_headers + fi * hdr_size
        w1 = struct.unpack_from("<I", out, base)[0]
        flags = out[base + flag_off]
        overflowed = (flags >> 5) & 1
        offset = w1 & 0x1FFFFFF
        if overflowed:
            # offset 25 bit thấp + phần cao nằm ở field khác → con trỏ tới
            # LargeFunctionHeader ở cuối file
            if version >= 98:
                hi_shift, hi_off, hi_mask = 24, base + 4, 0xFF
                w2 = struct.unpack_from("<I", out, base + 4)[0]
                hi = (w2 >> 14) & 0xFF
            elif version == 97:
                w2 = struct.unpack_from("<I", out, base + 4)[0]
                hi_shift, hi = 16, (w2 >> 14) & 0x3FFFF
            else:
                w3 = struct.unpack_from("<I", out, base + 8)[0]
                hi_shift, hi = 16, w3 & 0x1FFFFFF
            ptr = (hi << hi_shift) | offset
            new_ptr = ptr + delta
            large_ptrs.append(new_ptr)
            if new_ptr >> hi_shift > (0xFF if version >= 98 else 0x3FFFF):
                raise HbcError("con trỏ LargeFunctionHeader tràn")
            # ghi lại phần thấp 25 bit + phần cao
            struct.pack_into("<I", out, base,
                             (w1 & ~0x1FFFFFF) | (new_ptr & 0x1FFFFFF))
            if version >= 98:
                w2 = struct.unpack_from("<I", out, base + 4)[0]
                struct.pack_into("<I", out, base + 4,
                                 (w2 & ~(0xFF << 14))
                                 | (((new_ptr >> 24) & 0xFF) << 14))
            elif version == 97:
                w2 = struct.unpack_from("<I", out, base + 4)[0]
                struct.pack_into("<I", out, base + 4,
                                 (w2 & ~(0x3FFFF << 14))
                                 | (((new_ptr >> 16) & 0x3FFFF) << 14))
            else:
                w3 = struct.unpack_from("<I", out, base + 8)[0]
                struct.pack_into("<I", out, base + 8,
                                 (w3 & ~0x1FFFFFF)
                                 | ((new_ptr >> 16) & 0x1FFFFFF))
            continue
        new_offset = offset + delta
        if new_offset > 0x1FFFFFF:
            raise HbcError("offset bytecode tràn 25 bit sau khi dịch chỗ")
        struct.pack_into("<I", out, base, (w1 & ~0x1FFFFFF) | new_offset)
        if version < 97:
            w3 = struct.unpack_from("<I", out, base + 8)[0]
            info = w3 & 0x1FFFFFF
            if info:
                new_info = info + delta
                if new_info > 0x1FFFFFF:
                    raise HbcError("infoOffset tràn 25 bit sau khi dịch chỗ")
                struct.pack_into("<I", out, base + 8,
                                 (w3 & ~0x1FFFFFF) | new_info)

    # 6) Ghi bảng chuỗi mới + storage
    out = out[:hbc.off_small_table]
    out += small
    out += b"\x00" * (new_off_overflow - len(out))
    out += overflow
    out += b"\x00" * (new_off_storage - len(out))
    out += storage
    out += b"\x00" * (new_prefix_end - len(out))

    # 7) Phần đuôi giữ nguyên, chỉ sửa các LargeFunctionHeader bên trong
    tail_start = len(out)
    out += data[old_prefix_end:]
    for ptr in large_ptrs:
        # LargeFunctionHeader: offset u32, paramCount u32, … infoOffset u32
        # (chỉ hai field offset là địa chỉ tuyệt đối)
        p = ptr                      # ptr đã +delta → vị trí trong file mới
        if p + 8 > len(out):
            raise HbcError("LargeFunctionHeader nằm ngoài file")
        off = struct.unpack_from("<I", out, p)[0]
        struct.pack_into("<I", out, p, off + delta)
        if version < 97:
            # thứ tự: offset, paramCount, bytecodeSizeInBytes, functionName,
            # infoOffset → field thứ 5
            ioff = p + 16
            val = struct.unpack_from("<I", out, ioff)[0]
            struct.pack_into("<I", out, ioff, val + delta)
    assert tail_start == new_prefix_end

    # 8) Footer = SHA1 của toàn bộ phần trước nó
    if len(out) >= SHA1_LEN:
        body = bytes(out[:-SHA1_LEN])
        out[-SHA1_LEN:] = hashlib.sha1(body).digest()

    log.append(f"[hermes] dựng lại bundle: storage "
               f"{hbc.h['stringStorageSize']}→{len(storage)} byte "
               f"(dịch chỗ {delta:+} byte), {n_overflow} chuỗi tràn bảng, "
               f"{len(large_ptrs)} function header lớn")
    return bytes(out)


# --------------------------------------------------------------- kiểm chứng
def _func_ranges(x):
    """(offset, size) bytecode của từng function, gộp cả header lớn."""
    hs = _small_func_header_size(x.version)
    flag_off = _flags_byte_offset(x.version)
    out = []
    for fi in range(x.h["functionCount"]):
        base = x.off_func_headers + fi * hs
        w1, w2 = struct.unpack_from("<II", x.data, base)
        flags = x.data[base + flag_off]
        if (flags >> 5) & 1:
            if x.version >= 98:
                ptr = (((w2 >> 14) & 0xFF) << 24) | (w1 & 0x1FFFFFF)
            elif x.version == 97:
                ptr = (((w2 >> 14) & 0x3FFFF) << 16) | (w1 & 0x1FFFFFF)
            else:
                w3 = struct.unpack_from("<I", x.data, base + 8)[0]
                ptr = ((w3 & 0x1FFFFFF) << 16) | (w1 & 0x1FFFFFF)
            off, size = struct.unpack_from("<I", x.data, ptr)[0], \
                struct.unpack_from("<I", x.data, ptr + (12 if x.version >= 98
                                                        else 8))[0]
        else:
            off = w1 & 0x1FFFFFF
            size = (w2 & 0x3FFF) if x.version >= 98 else (w2 & 0x7FFF)
        out.append((off, size))
    return out


def verify(old, new_bytes, replacements):
    """Kiểm tra bundle vừa dựng lại có toàn vẹn không.

    · mọi chuỗi đọc lại đúng (kể cả chuỗi đã thay)
    · bytecode từng function giống nguyên bản từng byte, chỉ dịch chỗ
    · footer SHA1 và fileLength khớp

    Trả về (ok, thông_điệp). Pipeline PHẢI gọi hàm này trước khi ghi file —
    sai một offset là app crash ngay lúc mở.
    """
    try:
        new = HbcFile(new_bytes)
    except HbcError as e:
        return False, f"bundle dựng lại không đọc được: {e}"
    if new.h["stringCount"] != old.h["stringCount"]:
        return False, "số lượng chuỗi thay đổi"
    for i in range(old.h["stringCount"]):
        want = replacements.get(i, old.strings[i])
        if new.strings[i] != want:
            return False, f"chuỗi #{i} đọc lại sai"
    delta = len(new_bytes) - len(old.data)
    ra, rb = _func_ranges(old), _func_ranges(new)
    for fi, ((oa, sa), (ob, sb)) in enumerate(zip(ra, rb)):
        if ob != oa + delta or sb != sa:
            return False, f"function #{fi}: offset/size sai sau khi dịch chỗ"
        if old.data[oa:oa + sa] != new_bytes[ob:ob + sb]:
            return False, f"function #{fi}: bytecode bị đổi"
    if new.h["fileLength"] != len(new_bytes):
        return False, "fileLength không khớp kích thước file"
    if hashlib.sha1(new_bytes[:-SHA1_LEN]).digest() != new_bytes[-SHA1_LEN:]:
        return False, "footer SHA1 sai"
    return True, (f"OK — {len(replacements)} chuỗi đã thay, "
                  f"{old.h['functionCount']:,} function nguyên vẹn, "
                  f"file {delta:+,} byte")


# ------------------------------------------------------------------------ CLI
def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd, path = argv[0], argv[1]
    show_all = "--all" in argv
    limit = 40
    if "--limit" in argv:
        limit = int(argv[argv.index("--limit") + 1])
    hbc = parse(path)
    if cmd == "info":
        c = hbc.counts_by_kind()
        print(f"HBC version      : {hbc.version}"
              + ("  (mới hơn bản đã kiểm chứng!)" if hbc.newer_than_known
                 else ""))
        print(f"fileLength       : {hbc.h['fileLength']:,}")
        print(f"function         : {hbc.h['functionCount']:,}")
        print(f"chuỗi            : {hbc.h['stringCount']:,} "
              f"(String {c.get(0, 0):,} · Identifier {c.get(1, 0):,} · "
              f"Predefined {c.get(2, 0):,})")
        print(f"stringStorage    : {hbc.h['stringStorageSize']:,} byte")
        print(f"overflow         : {hbc.h['overflowStringCount']:,}")
        return 0
    if cmd == "list":
        idx = (range(len(hbc.strings)) if show_all
               else hbc.translatable_indices())
        for i in list(idx)[:limit]:
            print(f"{i:6} k={hbc.kinds[i]} {hbc.strings[i]!r}")
        print(f"… tổng {len(list(idx)):,} chuỗi")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
