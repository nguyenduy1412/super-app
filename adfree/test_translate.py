#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Test nhanh translator trên thư mục res giả lập (không cần APK thật).'''
import json
import shutil
import sys
from pathlib import Path

import translator

# Xóa cache để test từ đầu
translator._cache.clear()
translator._cache_loaded = True
if translator.CACHE_FILE.exists():
    translator.CACHE_FILE.unlink()

BASE = Path("/tmp/fake_res_test")
shutil.rmtree(BASE, ignore_errors=True)
res = BASE / "res"
(res / "values").mkdir(parents=True)
(res / "values-night").mkdir(parents=True)
(res / "values-en").mkdir(parents=True)
(res / "values-en-rUS").mkdir(parents=True)

(res / "values" / "strings.xml").write_text('''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <!-- comment giữ nguyên -->
    <string name="app_name">Super App</string>
    <string name="welcome">Welcome back, %1$s!</string>
    <string name="msg_count">You have <b>%d</b> new messages\\nPlease check your inbox.</string>
    <string name="home_url" translatable="false">https://example.com</string>
    <string name="link">Visit https://example.com/help for support</string>
    <string name="ref">@string/app_name</string>
    <string name="locked">Don\\'t panic — it\\'s fine &amp; safe</string>
    <string name="plain_braces">Choose {0} option</string>
</resources>''', "utf-8")

(res / "values" / "arrays.xml").write_text('''<resources>
    <string-array name="planets">
        <item>Mercury</item>
        <item>Venus</item>
    </string-array>
    <plurals name="songs">
        <item quantity="one">%d song</item>
        <item quantity="other">%d songs</item>
    </plurals>
    <integer-array name="nums">
        <item>1</item>
        <item>2</item>
    </integer-array>
</resources>''', "utf-8")

(res / "values-night" / "strings.xml").write_text(
    '<resources><string name="night_mode">Night mode is on</string></resources>',
    "utf-8")

# Locale override — nếu không gỡ, máy đặt tiếng Anh sẽ hiện text này
# thay vì bản dịch ở values/
(res / "values-en" / "strings.xml").write_text('''<resources>
    <string name="app_name">Super App</string>
    <string name="welcome">Welcome back, %1$s!</string>
</resources>''', "utf-8")

# color trong locale folder — phải giữ nguyên, KHÔNG bị đụng tới
(res / "values-night" / "colors.xml").write_text('''<resources>
    <color name="bg">#000000</color>
</resources>''', "utf-8")

log = []
rep = translator.apply(str(BASE), sys.argv[1] if len(sys.argv) > 1 else "vi", log)
print(json.dumps(rep, ensure_ascii=False, indent=1))
print("=" * 60)
for rel in ("values/strings.xml", "values/arrays.xml",
            "values-night/strings.xml", "values-en/strings.xml",
            "values-night/colors.xml"):
    print(f"--- {rel} ---")
    print((res / rel).read_text("utf-8"))
print("=" * 60)
print("\n".join(log))
