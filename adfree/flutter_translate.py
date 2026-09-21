#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Dịch ứng dụng Flutter bằng cơ chế Native Hook tại runtime.

Thay vì sửa file nhị phân Dart AOT (`libapp.so`) vốn dễ gây crash:
1. Trích xuất văn bản giao diện từ `libapp.so` và dịch sang ngôn ngữ mục tiêu
   bằng engine dịch (offline/google) của translator.py.
2. Đóng gói từ điển vào `assets/flutter_dict.json` trong APK.
3. Nhúng thư viện C++ `libflutter_hook.so` vào `lib/<abi>/`.
4. Chèn lệnh `System.loadLibrary("flutter_hook")` vào Activity/Application smali.

Khi ứng dụng chạy, hook sẽ chặn ở tầng C++ `ParagraphBuilder::addText` của
Flutter Engine (`libflutter.so`) và tự động thay thế chuỗi bằng tiếng Việt
ngay trước khi render ra màn hình.
'''

import json
import os
import re
import shutil
import sys
import zipfile
from pathlib import Path

import apptech
import translator

ROOT = Path(__file__).resolve().parent
PREBUILT_DIR = ROOT / "prebuilt"

DART_BUILTINS = {
    "bool", "int", "double", "num", "void", "dynamic", "Null", "Never", "Object",
    "String", "List", "Map", "Set", "Future", "Stream", "Type", "Function",
    "switch", "case", "default", "break", "continue", "return", "throw", "rethrow",
    "try", "catch", "finally", "class", "enum", "mixin", "extends", "implements",
    "with", "abstract", "interface", "final", "const", "static", "late", "required",
    "import", "export", "part", "library", "as", "show", "hide", "typedef",
    "operator", "get", "set", "this", "super", "new", "assert", "yield", "await",
    "sync", "async", "true", "false", "null", "identical", "Struct", "Union", "Pointer"
}

_PRINTABLE_RE = re.compile(b"[\x20-\x7e]{3,250}")
_VOWEL_RE = re.compile(r"[aeiouyAEIOUY]")


# Cụm hay gặp trong thông báo lỗi Flutter/Dart framework — không phải UI app
_FW_NOISE_RE = re.compile(
    r"(?:\b(?:Exception|Error|Assert|Stack|Overflow|Null|Type|Cast|Subtype|"
    r"RenderObject|BuildContext|Element|Widget|State|Inherited|Overlay|"
    r"Scheduler|Semantics|Pointer|Gesture|Focus|KeyEvent|Platform|"
    r"MissingPlugin|Unimplemented|Unsupported|LateInitialization|"
    r"ConcurrentModification|NoSuchMethod|FormatException|SocketException|"
    r"HttpException|Handshake|Certificate|Isolate|Microtask)\b)"
    r"|(?:is not a subtype|was called on null|Looking up a deactivated|"
    r"Another exception was thrown|The following .+ was thrown|"
    r"When the exception was thrown|setState\(\) called|"
    r"A RenderFlex overflowed|Incorrect use of ParentDataWidget|"
    r"No Material widget found|No Overlay widget found|"
    r"widgets require a|widget ancestor)",
    re.I,
)


def is_flutter_ui(s):
    """Kiểm tra xem chuỗi có phải là văn bản giao diện Flutter hay không."""
    if s in DART_BUILTINS or len(s) < 3:
        return False
    if any(s.startswith(p) for p in (
        "dart:", "package:", "org.", "com.", "io.", "android.", "flutter.",
        "http://", "https://", "assets/", "lib/", "file://", "schema.", "res/"
    )):
        return False
    if any(c in s for c in ("::", "->", "()", "{}", "[]", "$$", "__", "==", "!=", "<=", ">=")):
        return False
    if _FW_NOISE_RE.search(s):
        return False
    if not translator.natural_text(s, allow_single=True):
        return False

    # Nếu chuỗi một từ: cần có nguyên âm, độ dài >= 4, không phải camelCase
    if " " not in s:
        if len(s) < 4:
            return False
        if not _VOWEL_RE.search(s):
            return False
        if not s[0].isupper():
            return False
        if re.search(r"[a-z][A-Z]", s):
            return False
        # Từ kiểu "Iterable", "Namespace", "Expando" — kiểu Dart, không phải UI
        if s.endswith(("able", "tion", "sion", "ance", "ence", "ment")) and len(s) <= 12:
            if s.lower() in (
                "iterable", "namespace", "capability", "exception", "assertion",
                "function", "argument", "parameter", "extension", "collection",
            ):
                return False
    return True


def extract_strings_from_bytes(data):
    """Trích xuất chuỗi ứng viên từ bytes của libapp.so."""
    raw = [m.group(0).decode("utf-8", errors="ignore")
           for m in _PRINTABLE_RE.finditer(data)]
    uniq = list(dict.fromkeys(raw))
    return [s for s in uniq if is_flutter_ui(s)]


def extract_strings_from_apk(apk_path):
    """Tìm mọi libapp.so trong APK và thu thập danh sách chuỗi."""
    all_candidates = []
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if re.match(r"^lib/[^/]+/libapp\.so$", name):
                try:
                    data = z.read(name)
                    cands = extract_strings_from_bytes(data)
                    all_candidates.extend(cands)
                except Exception:
                    pass
    return list(dict.fromkeys(all_candidates))


def build_dictionary(apk_path, lang, log=None, progress=None):
    """Trích xuất và dịch chuỗi từ libapp.so -> trả về dict {src: dst}."""
    if log is None:
        log = []
    candidates = extract_strings_from_apk(apk_path)
    log.append(f"[flutter] trích xuất được {len(candidates)} chuỗi ứng viên từ libapp.so")

    if not candidates:
        return {}

    # Dịch qua translator
    label = f"chuỗi Flutter AOT ({len(candidates)} chuỗi)"
    tr = translator.translate_texts(candidates, lang, log, progress,
                                    label=label, allow_single=True)
    # Loại bỏ các cặp không đổi hoặc rỗng
    final_dict = {k: v for k, v in tr.items() if v and v != k}

    # Bổ sung các biến thể chữ hoa / chữ thường để bắt kịp các đoạn code Dart gọi .toUpperCase() / .toLowerCase()
    variants = {}
    for k, v in final_dict.items():
        k_upper = k.upper()
        if k_upper not in final_dict and k_upper not in variants:
            variants[k_upper] = v.upper()
        k_lower = k.lower()
        if k_lower not in final_dict and k_lower not in variants:
            variants[k_lower] = v.lower()
        k_title = k.title()
        if k_title not in final_dict and k_title not in variants:
            variants[k_title] = v.title()
    final_dict.update(variants)

    log.append(f"[flutter] hoàn tất dịch {len(final_dict)} chuỗi (bao gồm biến thể hoa/thường)")
    return final_dict


def embed_into_decoded(decoded_dir, apk_path, lang, log=None, progress=None):
    """Nhúng từ điển + libflutter_hook.so vào cây apktool TRƯỚC khi build.

    Cách này đáng tin hơn sửa zip sau build: apktool đóng gói luôn
    assets/flutter_dict.json và lib/<abi>/libflutter_hook.so vào APK, đồng
    thời smali loadLibrary khớp với .so có thật — tránh UnsatisfiedLinkError.
    Trả về report dict (translated, abis, …) hoặc None nếu không làm được.
    """
    if log is None:
        log = []
    decoded = Path(decoded_dir)
    apk_path = Path(apk_path)
    if not decoded.is_dir():
        return None

    dict_data = build_dictionary(apk_path, lang, log, progress)
    if not dict_data:
        log.append("[flutter] không có chuỗi UI nào dịch được từ libapp.so")
        return {"kind": "flutter_aot", "translated": 0, "embedded": False}

    assets_dir = decoded / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    dict_path = assets_dir / "flutter_dict.json"
    dict_path.write_text(
        json.dumps(dict_data, ensure_ascii=False, indent=2), encoding="utf-8")
    log.append(f"[flutter] ghi {dict_path.relative_to(decoded)} "
               f"({len(dict_data)} chuỗi)")

    lib_root = decoded / "lib"
    abis = sorted(p.name for p in lib_root.iterdir()
                  if p.is_dir() and p.name != "dexopt") if lib_root.is_dir() else []
    if not abis:
        abis = ["arm64-v8a"]
        (lib_root / "arm64-v8a").mkdir(parents=True, exist_ok=True)

    hooked = []
    for abi in abis:
        src = PREBUILT_DIR / abi / "libflutter_hook.so"
        if not src.is_file():
            log.append(f"[flutter] thiếu prebuilt hook cho {abi}")
            continue
        dst = lib_root / abi / "libflutter_hook.so"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        hooked.append(abi)
        log.append(f"[flutter] copy lib/{abi}/libflutter_hook.so "
                   f"({src.stat().st_size // 1024} KB)")

    if not hooked:
        log.append("[flutter] không copy được hook nào — bỏ inject smali")
        return {"kind": "flutter_aot", "translated": len(dict_data),
                "embedded": False, "abis": [], "error": "missing prebuilt hook"}

    ok = inject_smali_loadlibrary(decoded, "flutter_hook", log)
    return {
        "kind": "flutter_aot",
        "engine": "Dart AOT (Native Hook, embed pre-build)",
        "translated": len(dict_data),
        "embedded": True,
        "smali_injected": bool(ok),
        "abis": hooked,
        "samples": [{"from": k, "to": v}
                    for k, v in list(dict_data.items())[:15]],
    }


def inject_smali_loadlibrary(decoded_dir, lib_name="flutter_hook", log=None):
    """Chèn System.loadLibrary('flutter_hook') vào Activity hoặc Application smali."""
    if log is None:
        log = []
    decoded = Path(decoded_dir)
    manifest = decoded / "AndroidManifest.xml"
    if not manifest.is_file():
        return False

    text = manifest.read_text(encoding="utf-8", errors="ignore")
    # 1. Tìm Application class hoặc MainActivity
    candidate_classes = []
    pkg_m = re.search(r'package="([^"]+)"', text)
    pkg = pkg_m.group(1) if pkg_m else ""

    m_app = re.search(r'<application[^>]+android:name="([^"]+)"', text)
    if m_app and m_app.group(1) not in ("android.app.Application", "Application"):
        candidate_classes.append(m_app.group(1))

    # Tìm các activity trong manifest
    for m_act in re.finditer(r'<activity[^>]+android:name="([^"]+)"', text):
        act_name = m_act.group(1)
        if act_name not in candidate_classes:
            candidate_classes.append(act_name)

    target_smali = None
    for target_class in candidate_classes:
        if target_class.startswith("."):
            target_class = pkg + target_class
        smali_rel = target_class.replace(".", "/") + ".smali"
        for sdir in decoded.glob("smali*"):
            cand = sdir / smali_rel
            if cand.is_file():
                target_smali = cand
                break
        if target_smali:
            break

    # Nếu vẫn chưa thấy, quét tìm class kế thừa FlutterActivity trong các file smali
    if not target_smali:
        for sdir in decoded.glob("smali*"):
            for smali_file in sdir.rglob("*.smali"):
                try:
                    head = smali_file.read_text(encoding="utf-8", errors="ignore")[:500]
                    if ".super Lio/flutter/embedding/android/FlutterActivity;" in head or \
                       ".super Lio/flutter/app/FlutterActivity;" in head or \
                       ".super Lio/flutter/app/FlutterApplication;" in head:
                        target_smali = smali_file
                        break
                except Exception:
                    pass
            if target_smali:
                break

    if not target_smali:
        log.append(f"[flutter-smali] không tìm thấy file smali cho Activity hoặc Application Flutter")
        return False

    smali_content = target_smali.read_text(encoding="utf-8", errors="ignore")
    load_code = (f'    const-string v0, "{lib_name}"\n'
                 f'    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n')

    # Tránh chèn 2 lần
    if f'"{lib_name}"' in smali_content:
        log.append(f"[flutter-smali] {lib_name} đã được load trước đó trong {target_smali.name}")
        return True

    # Ưu tiên chèn vào .method static constructor <clinit>()V
    if ".method static constructor <clinit>()V" in smali_content:
        new_content = smali_content.replace(
            ".method static constructor <clinit>()V\n    .registers 1\n",
            ".method static constructor <clinit>()V\n    .registers 1\n" + load_code
        )
        if new_content == smali_content:
            new_content = re.sub(
                r'(\.method static constructor <clinit>\(\)V.*?\n)',
                r'\1' + load_code,
                smali_content,
                count=1
            )
    else:
        # Nếu chưa có <clinit>, tạo mới <clinit>
        clinit_block = (
            '\n.method static constructor <clinit>()V\n'
            '    .registers 1\n'
            '    .prologue\n'
            + load_code +
            '    return-void\n'
            '.end method\n'
        )
        # Chèn trước method đầu tiên
        m_pos = smali_content.find(".method")
        if m_pos != -1:
            new_content = smali_content[:m_pos] + clinit_block + smali_content[m_pos:]
        else:
            new_content = smali_content + clinit_block

    target_smali.write_text(new_content, encoding="utf-8")
    log.append(f"[flutter-smali] đã chèn System.loadLibrary(\"{lib_name}\") vào {target_smali.name}")
    return True


def apply(apk_path, out_apk, lang, dict_data=None, log=None, progress=None):
    """Vá trực tiếp APK Flutter: nhúng libflutter_hook.so và flutter_dict.json."""
    if log is None:
        log = []
    apk_path = Path(apk_path)
    out_apk = Path(out_apk)

    if dict_data is None:
        dict_data = build_dictionary(apk_path, lang, log, progress)

    edits = {}
    # 1. Thêm assets/flutter_dict.json
    dict_bytes = json.dumps(dict_data, ensure_ascii=False, indent=2).encode("utf-8")
    edits["assets/flutter_dict.json"] = dict_bytes

    # 2. Thêm libflutter_hook.so theo ABI có trong APK
    with zipfile.ZipFile(apk_path, "r") as z:
        names = z.namelist()
        abis = set()
        for n in names:
            m = re.match(r"^lib/([^/]+)/", n)
            if m:
                abis.add(m.group(1))

    if not abis:
        abis = {"arm64-v8a"}

    for abi in abis:
        hook_so = PREBUILT_DIR / abi / "libflutter_hook.so"
        if hook_so.is_file():
            edits[f"lib/{abi}/libflutter_hook.so"] = hook_so.read_bytes()
            log.append(f"[flutter-hook] đã thêm lib/{abi}/libflutter_hook.so ({hook_so.stat().st_size // 1024} KB)")
        else:
            log.append(f"[flutter-hook] chưa có prebuilt hook cho abi: {abi}")

    # Ghi zip mới
    import deep_translate
    deep_translate._rewrite_zip(apk_path, out_apk, edits)
    log.append(f"[flutter] đã đóng gói APK mới với từ điển ({len(dict_data)} chuỗi) và native hook")
    return {"translated": len(dict_data), "edits": list(edits.keys())}


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Sử dụng: python3 flutter_translate.py <input.apk> <lang> [out.apk]")
        sys.exit(1)

    inp = sys.argv[1]
    target_lang = sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else "flutter_patched.apk"

    log_lines = []
    res = apply(inp, out, target_lang, log=log_lines)
    for l in log_lines:
        print(l)
    print("Xong:", res)
