#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Test translator KHÔNG CẦN MẠNG: mock _translate_chunk trả bản dịch cứng.
Kiểm tra: tokenize/verify, ghi file, dọn locale override, giữ color.'''
import json
import shutil
import sys
from pathlib import Path

import translator

# plain (đã token hoá) -> bản dịch
CANNED = {
    "Super App": "Siêu ứng dụng",
    "Welcome back, {0}!": "Chào mừng trở lại, {0}!",
    "You have {0}{1}{2} new messages{3}Please check your inbox.":
        "Bạn có {0}{1}{2} tin nhắn mới{3}Hãy kiểm tra hộp thư.",
    "Don't panic — it's fine & safe": "Đừng hoảng sợ — mọi việc ổn & an toàn",
    "Mercury": "Thủy ngân", "Venus": "Sao Kim",
    "{0} song": "{0} bài hát", "{0} songs": "{0} bài hát",
    "Night mode is on": "Chế độ ban đêm đang bật",
}

calls = []
def fake_chunk(session, texts, target):
    calls.append(list(texts))
    return [CANNED.get(t) for t in texts]

translator._translate_chunk = fake_chunk
translator._cache.clear()
translator._cache_loaded = True      # chặn _load_cache đọc file cache cũ
translator.ENGINE = "google"         # test đường Google-mock (đã có CANNED)

BASE = Path("/tmp/fake_res_offline")
shutil.rmtree(BASE, ignore_errors=True)
res = BASE / "res"
for d in ("values", "values-night", "values-en"):
    (res / d).mkdir(parents=True)

(res / "values" / "strings.xml").write_text('''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Super App</string>
    <string name="welcome">Welcome back, %1$s!</string>
    <string name="msg_count">You have <b>%d</b> new messages\\nPlease check your inbox.</string>
    <string name="home_url" translatable="false">https://example.com</string>
    <string name="link">Visit https://example.com/help</string>
    <string name="ref">@string/app_name</string>
    <string name="locked">Don\\'t panic — it\\'s fine &amp; safe</string>
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
    </integer-array>
</resources>''', "utf-8")
(res / "values-en" / "strings.xml").write_text('''<resources>
    <string name="app_name">Super App</string>
    <string name="welcome">Welcome back, %1$s!</string>
</resources>''', "utf-8")
(res / "values-night" / "strings.xml").write_text(
    '<resources><string name="app_name">Super App</string></resources>',
    "utf-8")
(res / "values-night" / "colors.xml").write_text(
    '<resources><color name="bg">#000000</color></resources>', "utf-8")

log = []
rep = translator.apply(str(BASE), "vi", log)
print(json.dumps(rep, ensure_ascii=False))

ok = True
def check(name, cond):
    global ok
    print(("  ✅" if cond else "  ❌"), name)
    ok = ok and cond

s = (res / "values" / "strings.xml").read_text("utf-8")
check("app_name đã dịch", "Siêu ứng dụng" in s)
check("welcome giữ %1$s", "Chào mừng trở lại, %1$s!" in s)
check("msg_count giữ <b>%d</b> và \\n",
      "Bạn có <b>%d</b> tin nhắn mới\\nHãy kiểm tra hộp thư." in s)
check("translatable=false giữ nguyên", 'home_url" translatable="false"' in s)
check("URL bỏ qua", "Visit https://example.com" in s)
check("@ref bỏ qua", ">@string/app_name<" in s)
check("locked dịch + escape &amp;",
      "Đừng hoảng sợ — mọi việc ổn &amp; an toàn" in s)
a = (res / "values" / "arrays.xml").read_text("utf-8")
check("string-array dịch", "Thủy ngân" in a)
check("plurals dịch giữ %d", "%d bài hát" in a)
check("integer-array giữ nguyên", "<integer-array" in a and "1" in a)
en = (res / "values-en" / "strings.xml").read_text("utf-8")
check("values-en bị dọn string (tránh override)",
      "Super App" not in en and "Welcome back" not in en)
night = (res / "values-night" / "strings.xml").read_text("utf-8")
check("values-night string cũng bị dọn", "Super App" not in night)
colors = (res / "values-night" / "colors.xml").read_text("utf-8")
check("color giữ nguyên", "#000000" in colors)
check("không gọi mạng (mock)", len(calls) >= 1)

print("\n" + ("🎉 TẤT CẢ PASS" if ok else "💥 CÓ TEST FAIL"))
sys.exit(0 if ok else 1)
