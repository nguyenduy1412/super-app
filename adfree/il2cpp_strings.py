#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Dịch chuỗi literal của C# trong `global-metadata.dat` (Unity IL2CPP).

Game Unity build bằng IL2CPP biên dịch C# sang C++ nên **mọi chuỗi literal
trong code** (`"Bấm để chơi"`, `"Level %d"`) không nằm trong dex hay asset mà
trong file `assets/bin/Data/Managed/Metadata/global-metadata.dat`.

Cấu trúc (theo `Il2CppGlobalMetadataHeader` của Unity):

    int32 sanity = 0xFAB11BAF
    int32 version                     (bản chuẩn: 24, 27, 29, 31…)
    (int32 offset, int32 size) × N    ← bảng section, section đầu là literal
       [0] stringLiteral        → mảng {uint32 length; int32 dataIndex} × n
       [1] stringLiteralData    → byte UTF-8 của các chuỗi
       [2] string               → chuỗi metadata (tên class/method — KHÔNG dịch)
       …
    <dữ liệu các section, xếp nối tiếp>

Cách sửa: dựng lại vùng `stringLiteralData`, cập nhật `length`/`dataIndex`
trong bảng literal, rồi **dịch chỗ mọi section nằm sau nó** bằng cách cộng
delta vào offset trong header. Khác với Hermes, ở đây mọi địa chỉ đều nằm
trong header nên không phải sửa con trỏ nào bên trong dữ liệu.

An toàn:
  · chỉ nhận version chuẩn (bảng `KNOWN_VERSIONS`) và header đọc ra phải hợp
    lý (mọi section nằm trong file, xếp nối tiếp). Gặp thật: metadata của
    Duolingo khai version 39 — không phải version nào của Unity, tức là đã bị
    obfuscate → module này từ chối, không sửa bừa.
  · chỉ dịch chuỗi qua được `translator.natural_text` (bỏ khoá, đường dẫn,
    tên class, nhãn enum…) như bundle React Native.
  · `verify()` đọc lại file vừa dựng và so từng chuỗi + từng section trước
    khi ghi.

CLI:
    python3 il2cpp_strings.py info global-metadata.dat
    python3 il2cpp_strings.py list global-metadata.dat [--limit N]
'''

import struct
import sys
from pathlib import Path

import translator

SANITY = 0xFAB11BAF
# Các version metadata Unity đã phát hành (16→31). Version lạ = obfuscate.
KNOWN_VERSIONS = (16, 19, 20, 21, 22, 23, 24, 25, 27, 28, 29, 31)
LITERAL_ENTRY = 8          # {uint32 length; int32 dataIndex}
MAX_PAIRS = 128


class Il2CppError(Exception):
    pass


class Metadata:
    """global-metadata.dat đã phân tích đủ để dựng lại."""

    def __init__(self, data):
        self.data = data
        if len(data) < 64:
            raise Il2CppError("file quá nhỏ")
        sanity, version = struct.unpack_from("<Ii", data, 0)
        if sanity != SANITY:
            raise Il2CppError("không phải global-metadata.dat "
                              f"(sanity {sanity:#x})")
        self.version = version
        if version not in KNOWN_VERSIONS:
            raise Il2CppError(
                f"metadata version {version} không phải version chuẩn của "
                f"Unity ({', '.join(map(str, KNOWN_VERSIONS))}) — file có thể "
                f"đã bị obfuscate/mã hoá, không sửa để tránh phá game")
        self.pairs = self._read_pairs()
        self.header_size = min(o for o, s in self.pairs if s > 0)
        # section 0 = bảng literal, section 1 = dữ liệu literal
        (self.lit_off, self.lit_size), (self.data_off, self.data_size) = \
            self.pairs[0], self.pairs[1]
        if self.lit_size % LITERAL_ENTRY:
            raise Il2CppError("bảng string literal có kích thước lẻ")
        self.count = self.lit_size // LITERAL_ENTRY
        self._read_strings()

    def _read_pairs(self):
        """Đọc bảng section (offset, size).

        Header kết thúc ngay tại offset của section đầu tiên — dùng đúng mốc
        đó để dừng, nếu không sẽ đọc lố sang dữ liệu của section và coi nó là
        cặp (offset, size) giả.
        """
        n = len(self.data)
        pairs = []
        min_off = None
        for i in range(MAX_PAIRS):
            pos = 8 + i * 8
            if min_off is not None and pos + 8 > min_off:
                break                  # đã hết header
            if pos + 8 > n:
                break
            off, size = struct.unpack_from("<ii", self.data, pos)
            if off < 0 or size < 0 or off > n or off + size > n:
                break
            if size and off < 16:
                break
            pairs.append((off, size))
            if size > 0:
                min_off = off if min_off is None else min(min_off, off)
        if len(pairs) < 4:
            raise Il2CppError("không đọc được bảng section của metadata")
        # Header hợp lý: mọi section nằm sau header và trong file
        hdr = min(o for o, s in pairs if s > 0)
        if hdr < 8 + len(pairs) * 8 - 8 or hdr > 4096:
            raise Il2CppError(f"kích thước header vô lý ({hdr}) — "
                              f"metadata có thể đã bị obfuscate")
        return pairs

    def _read_strings(self):
        self.strings = []
        self.entries = []
        base = self.data_off
        end = base + self.data_size
        for i in range(self.count):
            length, idx = struct.unpack_from(
                "<Ii", self.data, self.lit_off + i * LITERAL_ENTRY)
            start = base + idx
            if idx < 0 or start + length > end:
                raise Il2CppError(f"literal #{i} nằm ngoài vùng dữ liệu")
            raw = self.data[start:start + length]
            self.entries.append((length, idx))
            self.strings.append(raw.decode("utf-8", "surrogateescape"))

    def translatable_indices(self, pred=None):
        out = []
        for i, s in enumerate(self.strings):
            if pred is not None and not pred(s):
                continue
            out.append(i)
        return out


def parse(data_or_path):
    if isinstance(data_or_path, (bytes, bytearray)):
        return Metadata(bytes(data_or_path))
    return Metadata(Path(data_or_path).read_bytes())


def rebuild(md, replacements, log=None):
    """Dựng lại metadata với các literal đã thay. Trả về bytes mới."""
    if log is None:
        log = []
    # 1) vùng dữ liệu literal mới
    blob = bytearray()
    entries = []
    seen = {}
    for i in range(md.count):
        text = replacements.get(i, md.strings[i])
        raw = text.encode("utf-8", "surrogateescape")
        key = bytes(raw)
        if key in seen:
            idx = seen[key]
        else:
            idx = len(blob)
            blob += raw
            seen[key] = idx
        entries.append((len(raw), idx))

    delta = len(blob) - md.data_size
    out = bytearray(md.data)

    # 2) bảng literal (kích thước không đổi)
    for i, (length, idx) in enumerate(entries):
        struct.pack_into("<Ii", out, md.lit_off + i * LITERAL_ENTRY,
                         length, idx)

    # 3) thay vùng dữ liệu + dịch chỗ mọi section phía sau
    start = md.data_off
    out[start:start + md.data_size] = blob
    for i, (off, size) in enumerate(md.pairs):
        pos = 8 + i * 8
        if i == 1:
            struct.pack_into("<ii", out, pos, off, len(blob))
        elif off > md.data_off:
            struct.pack_into("<ii", out, pos, off + delta, size)
    log.append(f"[il2cpp] dựng lại metadata: literal data "
               f"{md.data_size}→{len(blob)} byte (dịch chỗ {delta:+}), "
               f"{md.count} literal")
    return bytes(out)


def verify(old, new_bytes, replacements):
    """Kiểm file vừa dựng: mọi literal đọc lại đúng, các section còn nguyên."""
    try:
        new = Metadata(new_bytes)
    except Il2CppError as e:
        return False, f"metadata dựng lại không đọc được: {e}"
    if new.count != old.count:
        return False, "số literal thay đổi"
    for i in range(old.count):
        want = replacements.get(i, old.strings[i])
        if new.strings[i] != want:
            return False, f"literal #{i} đọc lại sai"
    delta = len(new_bytes) - len(old.data)
    for i, (off, size) in enumerate(old.pairs):
        noff, nsize = new.pairs[i]
        if i <= 1:
            continue
        if off <= old.data_off:
            if (noff, nsize) != (off, size):
                return False, f"section #{i} trước vùng literal bị đổi"
            if new_bytes[noff:noff + nsize] != old.data[off:off + size]:
                return False, f"nội dung section #{i} bị đổi"
        else:
            if noff != off + delta or nsize != size:
                return False, f"section #{i} không dịch chỗ đúng"
            if new_bytes[noff:noff + nsize] != old.data[off:off + size]:
                return False, f"nội dung section #{i} bị đổi"
    return True, (f"OK — {len(replacements)} literal đã thay, "
                  f"{len(old.pairs)} section nguyên vẹn, file {delta:+} byte")


def translate(data, lang, log=None, progress=None, preview=False):
    """Dịch literal trong metadata. Trả về (bytes mới | None, report)."""
    if log is None:
        log = []
    try:
        md = parse(data)
    except Il2CppError as e:
        return None, {"kind": "unity_il2cpp", "error": str(e)}
    texts = list(dict.fromkeys(md.strings))
    tr = translator.translate_texts(texts, lang, log, progress,
                                    label=f"literal C# (IL2CPP v{md.version})")
    repl = {i: tr[s] for i, s in enumerate(md.strings) if s in tr}
    rep = {"kind": "unity_il2cpp", "engine": f"IL2CPP metadata v{md.version}",
           "candidates": len(texts), "translated": len(repl),
           "samples": [{"from": md.strings[i], "to": repl[i]}
                       for i in list(repl)[:20]]}
    if preview or not repl:
        return None, rep
    out = rebuild(md, repl, log)
    ok, why = verify(md, out, repl)
    if not ok:
        log.append(f"[il2cpp] BỎ dịch — kiểm chứng thất bại: {why}")
        rep["error"] = why
        return None, rep
    log.append(f"[il2cpp] {why}")
    return out, rep


# ------------------------------------------------------------------------ CLI
def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd, path = argv[0], argv[1]
    limit = 40
    if "--limit" in argv:
        limit = int(argv[argv.index("--limit") + 1])
    try:
        md = parse(path)
    except Il2CppError as e:
        print("KHÔNG ĐỌC ĐƯỢC:", e)
        return 1
    if cmd == "info":
        print(f"metadata version : {md.version}")
        print(f"header           : {md.header_size} byte, "
              f"{len(md.pairs)} section")
        print(f"string literal   : {md.count:,} chuỗi, "
              f"{md.data_size:,} byte dữ liệu")
        return 0
    if cmd == "list":
        idx = md.translatable_indices(
            lambda s: translator.natural_text(s))
        for i in idx[:limit]:
            print(f"{i:6} {md.strings[i]!r}")
        print(f"… {len(idx):,}/{md.count:,} chuỗi trông như text hiển thị")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
