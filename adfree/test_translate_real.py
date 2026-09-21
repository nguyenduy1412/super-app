#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Test engine dịch OFFLINE thật (không mock): tự tải runtime/model nếu thiếu,
rồi dịch một thư mục res giả lập en→vi và kiểm tra placeholder/tag còn nguyên.

Cần mạng ở lần chạy đầu (tải ~60 MB runtime + ~80 MB model); các lần sau chạy
hoàn toàn offline.

    python3 test_translate_real.py [lang=vi]
'''
import json
import os
import re
import shutil
import sys
from pathlib import Path

os.environ["ADFREE_ENGINE"] = "offline"     # ép engine offline, bỏ Google

import offline_mt
import translator

LANG = (sys.argv[1] if len(sys.argv) > 1 else "vi").lower()

BASE = Path("/tmp/adfree_mt_real")
shutil.rmtree(BASE, ignore_errors=True)
res = BASE / "res"
(res / "values").mkdir(parents=True)
(res / "values-en").mkdir(parents=True)

(res / "values" / "strings.xml").write_text('''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Photo Editor</string>
    <string name="settings">Settings</string>
    <string name="welcome">Welcome back, %1$s!</string>
    <string name="msg_count">You have <b>%d</b> new messages\\nPlease check your inbox.</string>
    <string name="watch_ad">Watch a rewarded video to unlock this filter</string>
    <string name="storage" translatable="false">/sdcard/DCIM</string>
    <string name="site">https://example.com/help</string>
    <string name="ref">@string/app_name</string>
    <string name="percent">Loading… %d%%</string>
</resources>''', "utf-8")
(res / "values" / "arrays.xml").write_text('''<resources>
    <string-array name="tabs">
        <item>Camera</item>
        <item>Gallery</item>
    </string-array>
    <plurals name="photos">
        <item quantity="one">%d photo selected</item>
        <item quantity="other">%d photos selected</item>
    </plurals>
</resources>''', "utf-8")
(res / "values-en" / "strings.xml").write_text(
    '<resources><string name="settings">Settings</string></resources>', "utf-8")

log = []
print(f"→ chuẩn bị engine offline en→{LANG} (lần đầu sẽ tải model)…")
ok, err = offline_mt.ensure("en", LANG, log)
for line in log:
    print("  ", line)
if not ok:
    print("💥 không chuẩn bị được engine offline:", err)
    sys.exit(1)

# dịch từ đầu, không dùng cache cũ để chắc chắn engine thật chạy
translator._cache.clear()
translator._cache_loaded = True

log = []
rep = translator.apply(str(BASE), LANG, log)
print(json.dumps(rep, ensure_ascii=False, indent=1))
for line in log:
    print("  ", line)

s = (res / "values" / "strings.xml").read_text("utf-8")
a = (res / "values" / "arrays.xml").read_text("utf-8")
en = (res / "values-en" / "strings.xml").read_text("utf-8")
print("\n--- strings.xml sau khi dịch ---\n" + s)

ok_all = True


def check(name, cond):
    global ok_all
    print(("  ✅" if cond else "  ❌"), name)
    ok_all = ok_all and cond


def val(text, name):
    m = re.search(r'<string name="%s"[^>]*>(.*?)</string>' % name, text, re.S)
    return m.group(1) if m else ""


check("dùng đúng engine offline", rep.get("via_offline", 0) > 0
      and rep.get("via_google", 0) == 0)
check("có chuỗi được dịch", rep.get("translated", 0) >= 5)
check("settings đã đổi khác bản gốc", val(s, "settings") != "Settings")
check("welcome giữ %1$s", "%1$s" in val(s, "welcome"))
check("msg_count giữ <b>%d</b>", "<b>%d</b>" in val(s, "msg_count"))
check("msg_count giữ \\n", "\\n" in val(s, "msg_count"))
check("percent giữ %d%%", "%d%%" in val(s, "percent"))
check("translatable=false giữ nguyên", val(s, "storage") == "/sdcard/DCIM")
check("URL bỏ qua", val(s, "site") == "https://example.com/help")
check("@ref bỏ qua", val(s, "ref") == "@string/app_name")
check("string-array đã dịch", "Camera" not in a or "Gallery" not in a)
check("plurals giữ %d", a.count("%d") == 2)
check("values-en bị dọn để không override", "Settings" not in en)
check("XML không lỗi cú pháp",
      all(not re.search(r"[^\\]&(?!amp;|lt;|gt;|quot;|apos;|#)", t)
          for t in (s, a)))

print("\n" + ("🎉 TẤT CẢ PASS" if ok_all else "💥 CÓ TEST FAIL"))
sys.exit(0 if ok_all else 1)
