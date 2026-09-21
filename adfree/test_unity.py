#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Test đọc/GHI LẠI asset Unity: sửa TextAsset → lưu → đọc lại phải khớp.

Cần một file asset/bundle Unity có TextAsset. Thứ tự tìm:
    1. tham số: python3 test_unity.py <file.bundle | app.apk>
    2. biến môi trường ADFREE_TEST_UNITY

Kiểm tra:
  · UnityPy mở được file, thấy TextAsset
  · sửa nội dung TextAsset (chèn text tiếng Việt) → lưu ra bytes mới
  · mở lại bytes mới: nội dung đúng như đã sửa
  · các object khác (số lượng, loại) không đổi
  · nội dung TextAsset không sửa vẫn nguyên
'''
import os
import sys
import zipfile
from pathlib import Path

import unity_strings


def find_target(argv):
    for cand in list(argv) + [os.environ.get("ADFREE_TEST_UNITY", "")]:
        if cand and Path(cand).is_file():
            return Path(cand)
    return None


def main(argv):
    target = find_target(argv)
    if not target:
        print("⏭  BỎ QUA: chưa có file asset Unity để test.\n"
              "   Dùng: python3 test_unity.py <file.bundle | app.apk>")
        return 0
    ok, err = unity_strings.ensure([])
    if not ok:
        print("⏭  BỎ QUA: không cài được UnityPy:", err)
        return 0

    import UnityPy
    from UnityPy.enums import ClassIDType

    # lấy dữ liệu: từ APK thì tìm file asset đầu tiên có TextAsset
    blobs = []
    if target.suffix == ".apk":
        with zipfile.ZipFile(target) as z:
            for name in unity_strings.unity_files(target):
                blobs.append((name, z.read(name)))
    else:
        blobs.append((target.name, target.read_bytes()))

    data = name = None
    for nm, blob in blobs:
        try:
            env = UnityPy.load(blob)
        except Exception:
            continue
        if any(o.type == ClassIDType.TextAsset for o in env.objects):
            name, data = nm, blob
            break
    if data is None:
        print("⏭  BỎ QUA: không tìm thấy TextAsset trong file đã cho")
        return 0

    ok_all = True

    def check(nm, cond, extra=""):
        nonlocal ok_all
        print(("  ✅" if cond else "  ❌"), nm, extra)
        ok_all = ok_all and cond

    print(f"→ asset: {name} ({len(data):,} byte)")
    env = UnityPy.load(data)
    objs = list(env.objects)
    tas = [o for o in objs if o.type == ClassIDType.TextAsset]
    kinds_before = sorted((o.type.name if hasattr(o.type, "name")
                           else str(o.type)) for o in objs)
    print(f"   {len(objs)} object · {len(tas)} TextAsset")
    check("mở được và có TextAsset", bool(tas))

    # sửa TextAsset đầu tiên
    first = tas[0].read()
    old_text = unity_strings._as_text(first.m_Script) or ""
    marker = "TIẾNG VIỆT có dấu — adfree test\n"
    first.m_Script = marker + old_text
    first.save()
    others = {}
    for o in tas[1:4]:
        d = o.read()
        others[d.m_Name] = unity_strings._as_text(d.m_Script)

    try:
        out = env.file.save(packer="original")
    except Exception:
        out = env.file.save()
    check("lưu ra được bytes mới", bool(out) and len(out) > 64,
          f"{len(data):,} → {len(out):,} byte")

    env2 = UnityPy.load(out)
    objs2 = list(env2.objects)
    tas2 = [o for o in objs2 if o.type == ClassIDType.TextAsset]
    kinds_after = sorted((o.type.name if hasattr(o.type, "name")
                          else str(o.type)) for o in objs2)
    check("số object không đổi", len(objs2) == len(objs),
          f"{len(objs)} → {len(objs2)}")
    check("loại object không đổi", kinds_after == kinds_before)

    got = None
    for o in tas2:
        d = o.read()
        if d.m_Name == first.m_Name:
            got = unity_strings._as_text(d.m_Script)
            break
    check("TextAsset đã sửa đọc lại đúng",
          got is not None and got.startswith(marker))
    same = True
    for o in tas2:
        d = o.read()
        if d.m_Name in others:
            same = same and (unity_strings._as_text(d.m_Script)
                             == others[d.m_Name])
    check("TextAsset không sửa vẫn nguyên", same)

    print("\n" + ("🎉 TẤT CẢ PASS" if ok_all else "💥 CÓ TEST FAIL"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
