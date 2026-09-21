#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Test đọc/ghi `global-metadata.dat` của Unity IL2CPP.

Không có game Unity IL2CPP chuẩn trong máy để test, nên test này **tự sinh**
một file metadata đúng đặc tả (header + bảng section + literal + vài section
giả) rồi kiểm vòng tròn đọc → sửa → ghi → đọc lại. Cách này chứng minh phần
toán offset (thứ dễ sai nhất), không chứng minh tính tương thích với mọi bản
Unity thật.

Nếu có file thật thì truyền vào để test luôn:
    python3 test_il2cpp.py [global-metadata.dat]

Kiểm tra:
  · file tự sinh: đọc đủ literal, dựng lại + verify pass
  · thay chuỗi tiếng Việt (dài hơn bản gốc) → section sau bị dịch chỗ đúng
  · nội dung các section khác không đổi
  · từ chối file sai sanity / version lạ (obfuscate)
  · verify từ chối file bị sửa 1 byte
'''
import struct
import sys
from pathlib import Path

import il2cpp_strings as I


def build_fake(literals, version=29, n_extra=6):
    """Sinh một global-metadata.dat hợp lệ tối thiểu."""
    n_sections = 2 + n_extra
    header_size = 8 + n_sections * 8
    # dữ liệu literal
    blob = bytearray()
    entries = []
    for s in literals:
        raw = s.encode("utf-8")
        entries.append((len(raw), len(blob)))
        blob += raw
    lit_table = b"".join(struct.pack("<Ii", ln, idx) for ln, idx in entries)
    extras = [bytes([(i + 1) % 251]) * (100 + i * 37) for i in range(n_extra)]

    pos = header_size
    pairs = []
    body = bytearray()

    def add(chunk):
        nonlocal pos
        pairs.append((pos, len(chunk)))
        body.extend(chunk)
        pos += len(chunk)

    add(lit_table)
    add(bytes(blob))
    for e in extras:
        add(e)

    out = bytearray()
    out += struct.pack("<Ii", I.SANITY, version)
    for off, size in pairs:
        out += struct.pack("<ii", off, size)
    assert len(out) == header_size, (len(out), header_size)
    out += body
    return bytes(out), extras


def main(argv):
    ok_all = True

    def check(name, cond, extra=""):
        nonlocal ok_all
        print(("  ✅" if cond else "  ❌"), name, extra)
        ok_all = ok_all and cond

    lits = ["Tap to play", "Level %d", "Settings", "onClickHandler",
            "You have {0} coins", "com.example.Thing", "Game Over!"]
    data, extras = build_fake(lits)
    print(f"→ metadata tự sinh: {len(data):,} byte, {len(lits)} literal")

    md = I.parse(data)
    check("đọc đúng version", md.version == 29)
    check("đọc đủ literal", md.strings == lits, f"{len(md.strings)} chuỗi")

    # 1) dựng lại y nguyên
    out0 = I.rebuild(md, {})
    ok, why = I.verify(md, out0, {})
    check("dựng lại (không thay gì) verify pass", ok, why)

    # 2) thay chuỗi tiếng Việt (dài hơn → mọi section sau phải dịch chỗ)
    repl = {0: "Bấm để chơi ngay bây giờ", 2: "Cài đặt", 6: "Kết thúc ván!"}
    out1 = I.rebuild(md, repl)
    ok, why = I.verify(md, out1, repl)
    check("thay chuỗi dài hơn → verify pass", ok, why)
    md2 = I.parse(out1)
    check("chuỗi đã thay đọc lại đúng",
          all(md2.strings[i] == v for i, v in repl.items()))
    check("chuỗi không thay vẫn nguyên",
          all(md2.strings[i] == lits[i] for i in range(len(lits))
              if i not in repl))
    check("file dài ra đúng bằng phần thêm",
          len(out1) - len(data) == sum(
              len(v.encode()) for v in repl.values())
          - sum(len(lits[i].encode()) for i in repl))
    # các section phụ phải còn nguyên nội dung
    same = True
    for i, e in enumerate(extras):
        off, size = md2.pairs[2 + i]
        same = same and out1[off:off + size] == e
    check("section khác không đổi nội dung", same)

    # 3) từ chối file không chuẩn
    bad_ver = bytearray(data)
    struct.pack_into("<i", bad_ver, 4, 39)          # version Duolingo
    try:
        I.parse(bytes(bad_ver))
        check("từ chối version lạ (39)", False)
    except I.Il2CppError as e:
        check("từ chối version lạ (39)", "39" in str(e))
    bad_sanity = bytearray(data)
    struct.pack_into("<I", bad_sanity, 0, 0x12345678)
    try:
        I.parse(bytes(bad_sanity))
        check("từ chối sanity sai", False)
    except I.Il2CppError:
        check("từ chối sanity sai", True)

    # 4) verify bắt được file bị sửa
    broken = bytearray(out1)
    broken[-20] ^= 0xFF
    ok_bad, _ = I.verify(md, bytes(broken), repl)
    check("verify từ chối file bị sửa 1 byte", not ok_bad)

    # 5) file thật nếu có
    for cand in argv:
        p = Path(cand)
        if not p.is_file():
            continue
        print(f"\n→ file thật: {p}")
        try:
            real = I.parse(p)
            print(f"   version {real.version}, {real.count:,} literal")
            out = I.rebuild(real, {})
            ok, why = I.verify(real, out, {})
            check("file thật: dựng lại verify pass", ok, why)
        except I.Il2CppError as e:
            print(f"   (từ chối, đúng như mong đợi nếu file bị obfuscate): {e}")

    print("\n" + ("🎉 TẤT CẢ PASS" if ok_all else "💥 CÓ TEST FAIL"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
