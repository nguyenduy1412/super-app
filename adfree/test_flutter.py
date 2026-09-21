#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Test bộ tính năng Native Hook dịch ứng dụng Flutter.'''

import os
import sys
import tempfile
from pathlib import Path

import apptech
import flutter_translate

ROOT = Path(__file__).resolve().parent
SAMPLE_DIR = Path.home() / ".gemini/antigravity-ide/brain/e60af00a-829f-4124-a395-3f1026573d61/scratch/flutter_sample"
LIBFLUTTER_SO = SAMPLE_DIR / "lib/arm64-v8a/libflutter.so"
LIBAPP_SO = SAMPLE_DIR / "lib/arm64-v8a/libapp.so"


def test_prebuilt_binaries():
    print("→ 1. Kiểm tra file thư viện prebuilt libflutter_hook.so:")
    for abi in ("arm64-v8a", "armeabi-v7a"):
        p = ROOT / "prebuilt" / abi / "libflutter_hook.so"
        assert p.is_file(), f"Thiếu {p}"
        sz = p.stat().st_size
        assert sz > 50000, f"File {p} quá nhỏ ({sz} bytes)"
        print(f"  ✅ {abi}: {sz // 1024} KB hợp lệ")


def test_string_extraction():
    print("\n→ 2. Kiểm tra bộ trích xuất chuỗi từ libapp.so:")
    if not LIBAPP_SO.is_file():
        print("  ⏭ Bỏ qua (không có sample libapp.so)")
        return
    data = LIBAPP_SO.read_bytes()
    strings = flutter_translate.extract_strings_from_bytes(data)
    assert len(strings) > 100, f"Trích xuất được quá ít chuỗi: {len(strings)}"
    print(f"  ✅ Trích xuất thành công {len(strings)} chuỗi UI tự nhiên")
    # Kiểm tra không lẫn từ khóa Dart cơ bản
    for kw in ("bool", "void", "dynamic", "package:", "dart:"):
        assert kw not in strings, f"Từ khóa {kw} chưa bị lọc"
    print("  ✅ Đã lọc sạch từ khóa hệ thống Dart")


def test_apptech_inventory():
    print("\n→ 3. Kiểm tra nhận diện kho text Flutter trong apptech:")
    apk = SAMPLE_DIR / "split_config.arm64_v8a.apk"
    if not apk.is_file():
        print("  ⏭ Bỏ qua (không có sample APK)")
        return
    inv = apptech.inventory(apk)
    assert "Flutter" in inv["platform_names"], "Không nhận diện được Flutter"
    assert "flutter_aot" in inv["ready_kinds"], "flutter_aot chưa ở trạng thái ready"
    st = next(s for s in inv["stores"] if s["kind"] == "flutter_aot")
    assert st["status"] == "ready", "Status flutter_aot phải là ready"
    assert st["strings"] and st["strings"] > 0, "Chưa đếm được số chuỗi translatable"
    print(f"  ✅ Nhận diện đúng nền tảng Flutter (đếm được {st['strings']} chuỗi dịch được)")


def test_smali_injection():
    print("\n→ 4. Kiểm tra inject System.loadLibrary vào smali:")
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        manifest = tdp / "AndroidManifest.xml"
        manifest.write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">\n'
            '    <application android:name=".MainApp">\n'
            '    </application>\n'
            '</manifest>\n'
        )
        sdir = tdp / "smali/com/example/app"
        sdir.mkdir(parents=True)
        smali_file = sdir / "MainApp.smali"
        smali_file.write_text(
            '.class public Lcom/example/app/MainApp;\n'
            '.super Landroid/app/Application;\n\n'
            '.method public constructor <init>()V\n'
            '    .registers 1\n'
            '    invoke-direct {p0}, Landroid/app/Application;-><init>()V\n'
            '    return-void\n'
            '.end method\n'
        )
        ok = flutter_translate.inject_smali_loadlibrary(tdp, "flutter_hook")
        assert ok, "Inject smali thất bại"
        updated = smali_file.read_text()
        assert 'System;->loadLibrary(Ljava/lang/String;)V' in updated, "Chưa chèn loadLibrary"
        assert '"flutter_hook"' in updated, "Chưa chèn đúng tên library flutter_hook"
        print("  ✅ Chèn lệnh nạp thư viện vào smali thành công")


if __name__ == "__main__":
    test_prebuilt_binaries()
    test_string_extraction()
    test_apptech_inventory()
    test_smali_injection()
    print("\n🎉 TẤT CẢ CÁC BÀI TEST FLUTTER HOOK ĐỀU PASS!")
