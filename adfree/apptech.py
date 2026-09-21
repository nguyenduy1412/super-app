#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Phân loại công nghệ APK và **kiểm kê mọi kho text có thể dịch**.

Vì sao cần: text giao diện của app nằm ở chỗ hoàn toàn khác nhau tuỳ công nghệ.
Dịch `res/values/` chỉ đúng với app native (Kotlin/Java + XML). App React
Native để text trong bảng chuỗi của Hermes bytecode, Flutter nhúng vào Dart
AOT (`libapp.so`), Unity gói trong asset bundle, còn app Cordova/engine tự
viết thì để trong file JSON/XML trong `assets/`. Một app **có thể dùng nhiều
thứ cùng lúc** (vỏ Kotlin + màn hình React Native + mini-game Unity) nên hàm
này trả về DANH SÁCH kho text, không phải một loại duy nhất.

Mỗi kho báo kèm trạng thái:
  ready       — dịch được ngay, pipeline sẽ xử lý
  partial     — dịch được một phần (vd chỉ file i18n, không phải toàn bộ)
  unsupported — biết là có text ở đó nhưng chưa dịch được, kèm lý do

CLI:
    python3 apptech.py app.apk            # phân loại + kiểm kê
    python3 apptech.py app.apk --json
'''

import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import hbc_strings

ROOT = Path(__file__).resolve().parent

HERMES_MAGIC = hbc_strings.HBC_MAGIC

# ------------------------------------------------------- mẫu đường dẫn kho text
_RN_BUNDLE_RE = re.compile(
    r"^assets/(?:.*/)?(?:index\.android\.bundle|main\.jsbundle"
    r"|.*\.bundle|.*\.hbc)$")
_FLUTTER_LIB_RE = re.compile(r"^lib/[^/]+/libapp\.so$")
_FLUTTER_ASSET_RE = re.compile(r"^assets/flutter_assets/")
_UNITY_DATA_RE = re.compile(r"^assets/bin/Data/")
_UNITY_BUNDLE_RE = re.compile(r"^assets/(?:aa|AssetBundles|bundles)/")
_IL2CPP_RE = re.compile(r"global-metadata\.dat$")
_WEB_RE = re.compile(r"^assets/(?:www|public|dist|build|web)/")
_XAMARIN_RE = re.compile(r"^(?:assemblies/|assets/assemblies/)")
_UNREAL_RE = re.compile(r"^assets/.*\.(?:pak|locres)$", re.I)

# File i18n text (dịch được ngay): tên/đường dẫn gợi ý localization
_I18N_EXT = (".json", ".arb", ".xml", ".csv", ".po", ".properties", ".yaml",
             ".yml", ".strings", ".txt", ".ini", ".resjson")
_I18N_HINT_RE = re.compile(
    r"(?:^|/)(?:i18n|l10n|locale|locales|lang|langs|languages|translation|"
    r"translations|strings|localization|localisation|messages|intl|resources)"
    r"(?:/|_|-|\.|$)"
    r"|(?:^|/)(?:en|en[-_](?:US|GB)|vi|ja|ko|zh|fr|de|es|ru|th|id|pt)"
    r"\.(?:json|arb|xml|yaml|yml|po|properties|csv|strings)$", re.I)

# Manifest/notice — không phải text giao diện
_MANIFESTY_RE = re.compile(
    r"(?:AssetManifest|FontManifest|NativeAssetsManifest|NOTICES|"
    r"package_config|asset_manifest)", re.I)
_SKIP_ASSET_RE = re.compile(
    r"\.(?:png|jpe?g|webp|gif|svg|ttf|otf|woff2?|mp[34]|wav|ogg|zip|so|dex|"
    r"bin|dat|pack|db|sqlite|pdf|lottie|riv|glb|ktx|astc|pvr)$", re.I)

MAX_I18N_BYTES = 8 * 1024 * 1024


def _tech(apk):
    """Nền tảng theo techinfo (đã có sẵn trong project)."""
    try:
        import techinfo
        return techinfo.cached(str(apk))
    except Exception as e:
        return {"platforms": [], "error": str(e)}


# --------------------------------------------------------------- res/values
def _aapt2():
    for env in (os.environ.get("ANDROID_BUILD_TOOLS"),):
        if env and (Path(env) / "aapt2").is_file():
            return str(Path(env) / "aapt2")
    sdk = Path.home() / "Library/Android/sdk/build-tools"
    if sdk.is_dir():
        for d in sorted(sdk.iterdir(), reverse=True):
            if (d / "aapt2").is_file():
                return str(d / "aapt2")
    return None


def app_label(apk):
    """Tên hiển thị của app (để giữ nguyên khi dịch). None nếu không đọc được."""
    tool = _aapt2()
    if not tool:
        return None
    try:
        p = subprocess.run([tool, "dump", "badging", str(apk)],
                           capture_output=True, text=True, timeout=120,
                           errors="replace")
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"application-label:'([^']+)'", p.stdout or "")
    return m.group(1) if m else None


def _count_res_strings(apk):
    """Số <string> ở locale mặc định. None nếu không có aapt2 để đếm."""
    tool = _aapt2()
    if not tool:
        return None
    try:
        p = subprocess.run([tool, "dump", "resources", str(apk)],
                           capture_output=True, text=True, timeout=300,
                           errors="replace")
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    n = 0
    in_string = False
    for line in p.stdout.splitlines():
        st = line.strip()
        if st.startswith("resource "):
            in_string = " string/" in st
        elif in_string and st.startswith("()"):
            n += 1                     # giá trị ở config mặc định
    return n


# ------------------------------------------------------------------- Hermes
def _ui_like(s):
    """Chuỗi trông giống text giao diện (dùng để ĐẾM, không phải để dịch)."""
    if not (2 <= len(s) <= 200) or not re.search(r"[^\W\d_]", s, re.U):
        return False
    if re.search(r"[<>{}\\|`\$\^~=]|://|\.\w{2,4}$", s):
        return False
    return bool(re.search(r"[A-Za-z]{2}", s))


def _hermes_store(name, data):
    try:
        hbc = hbc_strings.parse(data)
    except hbc_strings.HbcError as e:
        return {"kind": "hermes", "where": name, "status": "unsupported",
                "why": f"không đọc được bundle Hermes: {e}"}
    c = hbc.counts_by_kind()
    ui = len(hbc.translatable_indices(_ui_like))
    store = {
        "kind": "hermes", "where": name, "engine": f"Hermes HBC v{hbc.version}",
        "strings": ui,
        "detail": {"total": hbc.h["stringCount"],
                   "string_kind": c.get(hbc_strings.KIND_STRING, 0),
                   "identifier_kind": c.get(hbc_strings.KIND_IDENTIFIER, 0),
                   "functions": hbc.h["functionCount"]},
        "status": "ready",
    }
    if hbc.newer_than_known:
        store["why"] = (f"HBC v{hbc.version} mới hơn bản đã kiểm chứng "
                        f"(v{hbc_strings.KNOWN_MAX_VERSION}) — vẫn dịch được "
                        f"nhưng nên test kỹ")
    return store


# --------------------------------------------------------------- asset i18n
def _count_i18n_strings(raw, name):
    """Đếm chuỗi dịch được trong một file i18n. None nếu không phải i18n."""
    low = name.lower()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if low.endswith((".json", ".arb", ".resjson")):
        try:
            obj = json.loads(text)
        except ValueError:
            return None

        def walk(o):
            if isinstance(o, str):
                return 1 if _ui_like(o) else 0
            if isinstance(o, dict):
                return sum(walk(v) for k, v in o.items()
                           if not str(k).startswith("@@"))
            if isinstance(o, list):
                return sum(walk(v) for v in o)
            return 0
        return walk(obj)
    if low.endswith((".xml",)):
        return len([m for m in re.findall(r"<string[^>]*>(.*?)</string>",
                                          text, re.S) if _ui_like(m)])
    if low.endswith((".properties", ".ini")):
        return len([1 for ln in text.splitlines()
                    if "=" in ln and not ln.strip().startswith(("#", ";"))
                    and _ui_like(ln.split("=", 1)[1])])
    if low.endswith(".po"):
        return len(re.findall(r'^msgid\s+"(.+)"', text, re.M))
    if low.endswith((".yaml", ".yml")):
        return len([1 for ln in text.splitlines()
                    if ":" in ln and _ui_like(ln.split(":", 1)[1])])
    if low.endswith(".csv"):
        return len([1 for ln in text.splitlines() if _ui_like(ln)])
    if low.endswith(".strings"):
        return len(re.findall(r'"\s*=\s*"(.+?)"\s*;', text))
    if low.endswith(".txt"):
        return None
    return None


def inventory(apk, log=None):
    """Phân loại app + liệt kê mọi kho text. Trả về dict báo cáo."""
    apk = Path(apk)
    tech = _tech(apk)
    platforms = [p["name"] for p in tech.get("platforms", [])]
    stores = []
    notes = []

    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        nameset = set(names)

        # 1) res/values (app native — Kotlin/Java)
        n_res = _count_res_strings(apk)
        if n_res is None:
            stores.append({"kind": "android_res", "where": "res/values",
                           "status": "ready", "strings": None,
                           "why": "chưa đếm được (thiếu aapt2) — vẫn dịch "
                                  "được sau khi apktool decode"})
        elif n_res:
            stores.append({"kind": "android_res", "where": "res/values",
                           "status": "ready", "strings": n_res,
                           "engine": "Android resources"})

        # 2) React Native — Hermes bytecode hoặc JS thuần
        for name in names:
            if not _RN_BUNDLE_RE.match(name):
                continue
            if _UNITY_BUNDLE_RE.match(name):
                continue              # .bundle của Unity Addressables
            try:
                head = z.open(name).read(8)
            except (KeyError, OSError, zipfile.BadZipFile):
                continue
            if head == HERMES_MAGIC:
                stores.append(_hermes_store(name, z.read(name)))
            elif name.endswith((".bundle", ".jsbundle")) and \
                    z.getinfo(name).file_size > 10000:
                data = z.read(name)
                try:
                    text = data.decode("utf-8", "strict")
                except UnicodeDecodeError:
                    continue
                lits = [m for m in re.findall(r'"((?:[^"\\]|\\.){2,120})"',
                                              text) if _ui_like(m)]
                stores.append({
                    "kind": "js_bundle", "where": name,
                    "engine": "JavaScript (JSC — không dùng Hermes)",
                    "strings": len(set(lits)), "status": "ready"})

        # 3) Flutter
        if any(_FLUTTER_LIB_RE.match(n) for n in names):
            lib = next(n for n in names if _FLUTTER_LIB_RE.match(n))
            n_ui = None
            try:
                import flutter_translate
                n_ui = len(flutter_translate.extract_strings_from_bytes(z.read(lib)))
            except Exception:
                pass
            stores.append({
                "kind": "flutter_aot", "where": lib,
                "engine": "Dart AOT (Native Hook)", "strings": n_ui,
                "status": "ready",
                "why": "Dịch động tại runtime qua Native Hook (chặn ở tầng C++ ParagraphBuilder::addText của Flutter Engine). Hỗ trợ tiếng Việt có dấu đầy đủ mà không sợ crash snapshot."})

        # 4) Unity
        unity_data = [n for n in names if _UNITY_DATA_RE.match(n)]
        unity_bundles = [n for n in names if _UNITY_BUNDLE_RE.match(n)
                         and n.endswith((".bundle", ".unity3d"))]
        meta_name = next((n for n in names if _IL2CPP_RE.search(n)), None)
        if meta_name:
            # Thử đọc luôn: metadata bị obfuscate (version lạ) thì không sửa
            import il2cpp_strings
            try:
                md = il2cpp_strings.parse(z.read(meta_name))
                ui = len(md.translatable_indices(_ui_like))
                stores.append({
                    "kind": "unity_il2cpp", "where": meta_name,
                    "engine": f"IL2CPP metadata v{md.version}",
                    "strings": ui, "status": "ready",
                    "detail": {"total": md.count,
                               "string_kind": ui,
                               "identifier_kind": md.count - ui,
                               "functions": len(md.pairs)}})
            except Exception as e:
                stores.append({
                    "kind": "unity_il2cpp", "where": meta_name,
                    "engine": "Unity IL2CPP metadata", "strings": None,
                    "status": "unsupported", "why": str(e)})
        if unity_data or unity_bundles:
            # Đếm TextAsset phải mở từng file bằng UnityPy — chậm với APK to,
            # nên để lúc dịch mới đếm.
            stores.append({
                "kind": "unity_assets",
                "where": ((unity_data or unity_bundles)[0].rsplit("/", 1)[0]
                          + "/"),
                "engine": "Unity asset bundle / .assets",
                "files": len(unity_data) + len(unity_bundles),
                "strings": None, "status": "ready",
                "why": "dịch TextAsset + bảng Unity Localization (đếm khi "
                       "dịch; nhiều game tải nội dung lúc chạy nên trong APK "
                       "có thể không có text nào)"})

        # 5) Xamarin/.NET
        if any(_XAMARIN_RE.match(n) for n in names):
            stores.append({
                "kind": "dotnet_resources", "where": "assemblies/",
                "engine": ".NET assembly", "strings": None,
                "status": "unsupported",
                "why": "chuỗi nằm trong .dll (.resources) — chưa làm"})

        # 6) Unreal
        if any(_UNREAL_RE.match(n) for n in names):
            stores.append({
                "kind": "unreal_locres", "where": "assets/*.pak|*.locres",
                "engine": "Unreal Engine", "strings": None,
                "status": "unsupported",
                "why": "text trong .pak/.locres của Unreal — chưa làm"})

        # 7) File text trong assets. Tách làm hai loại, RẤT khác nhau:
        #    · catalog dịch (i18n/locales/en.json…) → dịch được ngay
        #    · dữ liệu của app (data/level0.json…) → KHÔNG dịch mặc định:
        #      gặp thật ở app học tiếng Anh, dịch câu bài tập là phá luôn
        #      nội dung app. Chỉ dịch khi người dùng chọn.
        i18n, data_files = [], []
        total_i18n = total_data = 0
        for name in names:
            if not name.startswith("assets/") or _SKIP_ASSET_RE.search(name):
                continue
            if not name.lower().endswith(_I18N_EXT):
                continue
            if _MANIFESTY_RE.search(name):
                continue
            info = z.getinfo(name)
            if info.file_size > MAX_I18N_BYTES or info.file_size < 8:
                continue
            hinted = bool(_I18N_HINT_RE.search(name))
            if not hinted and not _WEB_RE.match(name) and \
                    not _FLUTTER_ASSET_RE.match(name):
                continue
            try:
                n_str = _count_i18n_strings(z.read(name), name)
            except (OSError, zipfile.BadZipFile):
                continue
            if not n_str:
                continue
            if hinted:
                i18n.append({"file": name, "strings": n_str})
                total_i18n += n_str
            else:
                data_files.append({"file": name, "strings": n_str})
                total_data += n_str
        if i18n:
            i18n.sort(key=lambda d: -d["strings"])
            stores.append({
                "kind": "asset_i18n",
                "where": f"{len(i18n)} file trong assets/",
                "engine": "catalog localization dạng text",
                "strings": total_i18n, "status": "ready",
                "files": i18n[:40]})
        if data_files:
            data_files.sort(key=lambda d: -d["strings"])
            stores.append({
                "kind": "asset_data",
                "where": f"{len(data_files)} file trong assets/",
                "engine": "dữ liệu app dạng JSON/CSV",
                "strings": total_data, "status": "partial",
                "files": data_files[:40],
                "why": "đây là dữ liệu nội dung của app (câu hỏi, bài học, "
                       "cấu hình), không phải catalog dịch — dịch có thể phá "
                       "nội dung. Chỉ dịch khi bạn chọn "
                       "(ADFREE_TRANSLATE_DATA=1)"})

        # 8) Web assets (Cordova/Capacitor) — HTML/JS có text cứng
        web = [n for n in names if _WEB_RE.match(n)
               and n.endswith((".html", ".htm", ".js"))]
        if web:
            stores.append({
                "kind": "web_assets", "where": web[0].rsplit("/", 1)[0] + "/",
                "engine": "WebView (Cordova/Capacitor)", "files": len(web),
                "strings": None, "status": "partial",
                "why": "chỉ dịch file i18n JSON; text cứng trong HTML/JS "
                       "chưa dịch (dễ phá logic)"})

    ready = [s for s in stores if s["status"] == "ready"]
    n_ready = sum(s["strings"] or 0 for s in ready)
    if not ready:
        notes.append("Không tìm thấy kho text nào dịch được bằng cách hiện có.")
    return {
        "apk": apk.name,
        "platforms": tech.get("platforms", []),
        "platform_names": platforms,
        "hybrid": len(platforms) > 1,
        "engine": tech.get("engine"),
        "stores": stores,
        "translatable": n_ready,
        "ready_kinds": [s["kind"] for s in ready],
        "notes": notes,
    }


# ------------------------------------------------------------------------ CLI
_LABEL = {
    "android_res": "res/values (Android resources)",
    "hermes": "Hermes bytecode (React Native)",
    "js_bundle": "JS bundle (React Native không Hermes)",
    "asset_i18n": "catalog i18n trong assets",
    "asset_data": "dữ liệu app trong assets (JSON/CSV)",
    "web_assets": "web assets (WebView)",
    "flutter_aot": "Dart AOT snapshot (Flutter)",
    "unity_assets": "Unity asset bundle",
    "unity_il2cpp": "Unity IL2CPP metadata",
    "dotnet_resources": ".NET assemblies",
    "unreal_locres": "Unreal locres/pak",
}
_MARK = {"ready": "✅", "partial": "🟡", "unsupported": "❌"}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        return 2
    rep = inventory(argv[0])
    if "--json" in argv:
        print(json.dumps(rep, ensure_ascii=False, indent=1))
        return 0
    print(f"APK        : {rep['apk']}")
    print("Công nghệ  : " + (", ".join(
        f"{p.get('icon', '')} {p['name']}" for p in rep["platforms"])
        or "không xác định")
        + ("   ← app lai (nhiều nền tảng)" if rep["hybrid"] else ""))
    print("\nKho text:")
    for s in rep["stores"]:
        n = s.get("strings")
        cnt = f"{n:,} chuỗi" if isinstance(n, int) else "chưa đếm"
        print(f"  {_MARK[s['status']]} {_LABEL.get(s['kind'], s['kind'])}"
              f" — {cnt}")
        print(f"      ở: {s['where']}"
              + (f" · {s['engine']}" if s.get("engine") else ""))
        if s.get("detail"):
            d = s["detail"]
            print(f"      bảng chuỗi: {d['total']:,} "
                  f"(String {d['string_kind']:,} · "
                  f"Identifier {d['identifier_kind']:,}), "
                  f"{d['functions']:,} function")
        if s.get("why"):
            print(f"      → {s['why']}")
        if s.get("files") and isinstance(s["files"], list):
            for f in s["files"][:6]:
                print(f"         · {f['file']} ({f['strings']:,})")
            if len(s["files"]) > 6:
                print(f"         · … {len(s['files']) - 6} file nữa")
    print(f"\nTổng dịch được: {rep['translatable']:,} chuỗi "
          f"({', '.join(rep['ready_kinds']) or 'không có'})")
    for n in rep["notes"]:
        print("⚠️  " + n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
