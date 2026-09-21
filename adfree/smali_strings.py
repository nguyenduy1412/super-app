#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Dịch chuỗi HARDCODE trong code Java/Kotlin (lệnh `const-string` của smali).

Nhiều app — nhất là app Trung Quốc — nhét text giao diện thẳng vào code chứ
không qua `res/values`. Sau khi apktool decode, những chuỗi đó nằm trong file
`.smali` dưới dạng:

    const-string v0, "\\u786e\\u5b9a"
    const-string/jumbo v1, "Watch ad to unlock"

Module này sửa ngay trong smali rồi để apktool build lại dex — an toàn hơn hẳn
việc mổ trực tiếp bảng chuỗi của `classes.dex` (đổi độ dài chuỗi trong dex là
phải dựng lại toàn bộ `string_ids` + map offset).

**Bỏ qua code thư viện** (androidx, kotlin, com/google, okhttp, Unity SDK…):
chuỗi trong thư viện hầu hết là khoá, tên action, tham số API — dịch là sai
logic mà không thêm text UI nào. Không lọc theo package khai báo trong
manifest vì code thật hay nằm ở package khác (gặp thật: app package
`com.zfks.c.ibdvwharad` nhưng code nằm hết ở `lasm/`, `luaj/`). Quét tất cả
bằng `ADFREE_SMALI_ALL=1`.

Chuỗi được lọc qua `translator.natural_text` như bundle React Native (bỏ
camelCase, class CSS, id ngẫu nhiên, nhãn enum toàn chữ thường…), và bỏ luôn
chuỗi nằm cạnh các lệnh nghi là khoá dữ liệu (`put`, `getString`,
`SharedPreferences`…) — xem `_KEYISH_RE`.

CLI (chạy trên thư mục apktool đã decode):
    python3 smali_strings.py <thư_mục_decode> vi
'''

import os
import re
import sys
from pathlib import Path

import translator

# const-string v0, "..."  |  const-string/jumbo v0, "..."
_CONST_RE = re.compile(r'^(\s*const-string(?:/jumbo)?\s+[vp]\d+,\s*)"(.*)"\s*$',
                       re.M)

# Lệnh ngay sau const-string mà cho thấy chuỗi là KHOÁ chứ không phải text
# hiển thị: đưa vào Map/Bundle/SharedPreferences/JSON, hoặc so sánh chuỗi.
_KEYISH_RE = re.compile(
    r"(?:->(?:put|get|opt|has|remove|optString|getString|getInt|getBoolean|"
    r"equals|equalsIgnoreCase|startsWith|endsWith|contains|indexOf|split|"
    r"matches|compareTo|hashCode)\b)"
    r"|Landroid/content/SharedPreferences"
    r"|Lorg/json/JSON(?:Object|Array)"
    r"|Landroid/os/Bundle"
    r"|Ljava/util/(?:Map|HashMap|Properties)")

ALL_PACKAGES = os.environ.get("ADFREE_SMALI_ALL", "") == "1"

# Thư viện của bên thứ ba: chuỗi trong đây gần như luôn là khoá/tham số/tên
# action, dịch là sai logic mà chẳng thêm text UI nào. Bỏ qua theo tiền tố
# đường dẫn (tương ứng package). Code của app thì giữ, kể cả khi nằm ở
# package khác package khai báo trong manifest — gặp thật: app có package
# com.zfks.c.ibdvwharad nhưng toàn bộ code nằm ở lasm/ và luaj/.
_LIB_PREFIXES = (
    "android/", "androidx/", "kotlin/", "kotlinx/", "java/", "javax/",
    "dalvik/", "junit/", "org/junit/", "org/apache/", "org/json/",
    "org/w3c/", "org/xml/", "org/xmlpull/", "org/intellij/",
    "org/jetbrains/", "org/slf4j/", "org/reactivestreams/", "org/checkerframework/",
    "com/google/", "com/android/", "com/facebook/", "com/squareup/",
    "com/bumptech/", "com/airbnb/lottie/", "com/unity3d/", "com/applovin/",
    "com/vungle/", "com/ironsource/", "com/mbridge/", "com/bytedance/sdk/",
    "okhttp3/", "okio/", "retrofit2/", "io/reactivex/", "rx/", "dagger/",
    "hilt_aggregated_deps/", "io/flutter/", "io/sentry/", "expo/modules/",
    "com/swmansion/", "com/th3rdwave/", "com/horcrux/",
)


def _is_lib(rel):
    r = rel.replace("\\", "/")
    return any(r.startswith(pre) for pre in _LIB_PREFIXES)

# Escape của smali: \n \t \" \\ \uXXXX
_ESC_MAP = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "'": "'"}


def unescape(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c != "\\" or i + 1 >= len(s):
            out.append(c)
            i += 1
            continue
        nxt = s[i + 1]
        if nxt == "u" and i + 5 < len(s) + 1:
            try:
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 6
                continue
            except ValueError:
                pass
        out.append(_ESC_MAP.get(nxt, nxt))
        i += 2
    return "".join(out)


def escape(s):
    out = []
    for c in s:
        if c == "\\":
            out.append("\\\\")
        elif c == '"':
            out.append('\\"')
        elif c == "\n":
            out.append("\\n")
        elif c == "\t":
            out.append("\\t")
        elif c == "\r":
            out.append("\\r")
        elif ord(c) < 0x20 or ord(c) > 0x7E:
            out.append("\\u%04x" % ord(c))
        else:
            out.append(c)
    return "".join(out)


def app_package(decoded):
    """Package của app từ AndroidManifest (để chỉ dịch code của app)."""
    mf = Path(decoded) / "AndroidManifest.xml"
    try:
        m = re.search(r'package="([^"]+)"', mf.read_text("utf-8", "replace"))
    except OSError:
        return None
    return m.group(1) if m else None


def _smali_files(decoded):
    """File .smali cần quét: tất cả, trừ code thư viện đã biết."""
    for root in sorted(p for p in Path(decoded).glob("smali*") if p.is_dir()):
        for f in root.rglob("*.smali"):
            if ALL_PACKAGES or not _is_lib(str(f.relative_to(root))):
                yield f


def apply(decoded, lang, log=None, progress=None):
    """Dịch chuỗi const-string trong smali. Trả về report dict."""
    if log is None:
        log = []
    decoded = Path(decoded)
    pkg = app_package(decoded)
    if not any(Path(decoded).glob("smali*")):
        return {"enabled": False, "error": "không tìm thấy thư mục smali"}

    # 1) thu thập
    files = []
    raw_texts = []
    for f in _smali_files(decoded):
        try:
            text = f.read_text("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        hits = list(_CONST_RE.finditer(text))
        if not hits:
            continue
        keep = []
        for m in hits:
            # dòng ngay sau const-string cho biết chuỗi dùng làm gì
            after = text[m.end():m.end() + 400]
            if _KEYISH_RE.search(after.split("\n\n")[0]):
                continue
            keep.append(m)
        if keep:
            files.append((f, text, keep))
            raw_texts += [unescape(m.group(2)) for m in keep]

    n_candidates = len(raw_texts)
    if not n_candidates:
        log.append("[smali] không có chuỗi hardcode nào để dịch")
        return {"enabled": True, "candidates": 0, "translated": 0, "files": 0,
                "package": pkg,
                "scope": "all" if ALL_PACKAGES else "no-libs"}

    # 2) dịch (lọc như bundle JS: chỉ câu chữ, bỏ khoá/enum/định danh)
    tr = translator.translate_texts(
        list(dict.fromkeys(raw_texts)), lang, log, progress,
        label="chuỗi hardcode trong code")

    # 3) ghi lại
    n_tr = n_files = 0
    for f, text, hits in files:
        edits = []
        for m in hits:
            src = unescape(m.group(2))
            dst = tr.get(src)
            if dst is None or dst == src:
                continue
            edits.append((m.start(), m.end(),
                          m.group(1) + '"' + escape(dst) + '"'))
        if not edits:
            continue
        for start, end, new in sorted(edits, reverse=True):
            text = text[:start] + new + text[end:]
        f.write_text(text, "utf-8")
        n_tr += len(edits)
        n_files += 1

    log.append(f"[smali] {n_tr}/{n_candidates} chuỗi hardcode đã dịch trong "
               f"{n_files} file"
               + (" (bỏ qua code thư viện)" if not ALL_PACKAGES
                  else " (toàn bộ smali)"))
    return {"enabled": True, "candidates": n_candidates, "translated": n_tr,
            "files": n_files, "package": pkg,
            "scope": "all" if ALL_PACKAGES else "no-libs"}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print(__doc__)
        return 2
    log = []
    rep = apply(argv[0], argv[1].lower(), log)
    for ln in log:
        print(ln)
    print(rep)
    return 0


if __name__ == "__main__":
    sys.exit(main())
