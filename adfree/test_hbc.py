#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Test đọc/ghi bảng chuỗi Hermes trên một bundle THẬT.

Không tự sinh được file HBC hợp lệ (phải có hermesc), nên test cần một bundle
thật. Thứ tự tìm:

    1. tham số dòng lệnh: python3 test_hbc.py path/to/index.android.bundle
    2. biến môi trường ADFREE_TEST_BUNDLE
    3. tham số là file .apk → tự lấy bundle bên trong

Kiểm tra:
  · parse đọc được mọi chuỗi (offset/length hợp lệ)
  · dựng lại y nguyên (không thay gì) → verify pass, mọi chuỗi khớp
  · thay chuỗi có dấu tiếng Việt (buộc chuyển sang UTF-16) → verify pass
  · thay bằng chuỗi rất dài (>255 ký tự → phải đẩy sang bảng overflow)
  · bytecode từng function không đổi, footer SHA1 + fileLength đúng
  · verify PHẢI trả False khi file bị cắt/hỏng
'''
import os
import sys
import zipfile
from pathlib import Path

import hbc_strings as H


def find_bundle(argv):
    for cand in list(argv) + [os.environ.get("ADFREE_TEST_BUNDLE", "")]:
        if not cand:
            continue
        p = Path(cand)
        if not p.is_file():
            continue
        if p.suffix == ".apk":
            with zipfile.ZipFile(p) as z:
                for n in z.namelist():
                    if n.startswith("assets/") and n.endswith(
                            (".bundle", ".hbc")):
                        if z.open(n).read(8) == H.HBC_MAGIC:
                            out = Path("/tmp") / "adfree_test.bundle"
                            out.write_bytes(z.read(n))
                            return out
            continue
        return p
    return None


def main(argv):
    path = find_bundle(argv)
    if not path:
        print("⏭  BỎ QUA: chưa có bundle Hermes để test.\n"
              "   Dùng: python3 test_hbc.py <index.android.bundle | app.apk>")
        return 0

    ok_all = True

    def check(name, cond, extra=""):
        nonlocal ok_all
        print(("  ✅" if cond else "  ❌"), name, extra)
        ok_all = ok_all and cond

    print(f"→ bundle: {path} ({path.stat().st_size:,} byte)")
    hbc = H.parse(path)
    print(f"   HBC v{hbc.version} · {hbc.h['stringCount']:,} chuỗi · "
          f"{hbc.h['functionCount']:,} function")

    check("parse đọc đủ chuỗi",
          len(hbc.strings) == hbc.h["stringCount"])
    check("có chuỗi kind=String",
          hbc.counts_by_kind().get(H.KIND_STRING, 0) > 0)
    check("footer là SHA1 hợp lệ",
          __import__("hashlib").sha1(
              hbc.data[:-H.SHA1_LEN]).digest() == hbc.data[-H.SHA1_LEN:])

    # 1) dựng lại không thay gì
    out0 = H.rebuild(hbc, {})
    ok, why = H.verify(hbc, out0, {})
    check("dựng lại (không thay gì) verify pass", ok, why)
    b0 = H.parse(out0)
    check("mọi chuỗi khớp sau khi dựng lại",
          b0.strings == hbc.strings)

    # 2) thay chuỗi tiếng Việt (ASCII → UTF-16) + chuỗi dài (→ overflow)
    idx = hbc.translatable_indices(lambda s: 3 <= len(s) <= 40)[:50]
    if not idx:
        print("⏭  bundle không có chuỗi phù hợp để thay")
        return 0 if ok_all else 1
    repl = {i: "Tiếng Việt có dấu · " + hbc.strings[i] for i in idx[:40]}
    long_i = idx[-1]
    repl[long_i] = "Chuỗi rất dài để buộc đẩy sang bảng overflow " * 8
    out1 = H.rebuild(hbc, repl)
    ok, why = H.verify(hbc, out1, repl)
    check("thay chuỗi có dấu + chuỗi dài → verify pass", ok, why)
    b1 = H.parse(out1)
    check("chuỗi tiếng Việt đọc lại đúng",
          all(b1.strings[i] == repl[i] for i in repl))
    check("chuỗi dài >255 ký tự đọc lại đúng",
          len(b1.strings[long_i]) > 255
          and b1.strings[long_i] == repl[long_i])
    check("chuỗi không thay vẫn nguyên",
          all(b1.strings[i] == hbc.strings[i]
              for i in range(0, hbc.h["stringCount"], 97)
              if i not in repl))
    check("số chuỗi không đổi", b1.h["stringCount"] == hbc.h["stringCount"])
    check("fileLength khớp kích thước", b1.h["fileLength"] == len(out1))
    check("kind của chuỗi không đổi", b1.kinds == hbc.kinds)

    # 3) verify phải bắt được file hỏng
    ok_bad, _ = H.verify(hbc, out1[:len(out1) // 2], repl)
    check("verify từ chối file bị cắt", not ok_bad)
    broken = bytearray(out1)
    broken[len(broken) - 30] ^= 0xFF          # phá 1 byte trong đuôi
    ok_bad2, _ = H.verify(hbc, bytes(broken), repl)
    check("verify từ chối file bị sửa 1 byte", not ok_bad2)

    print("\n" + ("🎉 TẤT CẢ PASS" if ok_all else "💥 CÓ TEST FAIL"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
