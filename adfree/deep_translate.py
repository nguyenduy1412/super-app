#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Dịch các kho text NGOÀI `res/values` — Hermes bundle, JS bundle, file i18n.

`translator.py` chỉ dịch string resources của Android, đúng cho app native.
Module này lo phần còn lại, dựa vào [apptech.py](apptech.py) để biết app dùng
công nghệ gì và text nằm ở đâu:

| Kho | Cách xử lý |
|---|---|
| Hermes bytecode (React Native ≥0.70) | dựng lại bảng chuỗi bằng [hbc_strings.py](hbc_strings.py), kiểm chứng bytecode từng function trước khi ghi |
| JS bundle thuần (React Native cũ/JSC) | thay literal chuỗi trong text JS |
| file i18n trong assets (JSON/ARB/XML/properties/PO/CSV) | dịch giá trị, giữ nguyên khoá |

Ghi trực tiếp vào file zip của APK (không qua apktool) nên nhanh và **không
có rủi ro aapt2 build lỗi**. APK ra chưa ký — người gọi ký sau.

Chỉ dịch chuỗi trông như câu chữ người đọc (xem `translator.natural_text`):
trong bundle JS lẫn rất nhiều tên icon, class CSS, id, tên hàm — dịch nhầm là
app hỏng. Mặc định bỏ qua chuỗi một từ (thường là giá trị enum), bật
`ADFREE_RN_SINGLE_WORD=1` nếu muốn dịch cả những chuỗi đó.

CLI (dịch + ký, KHÔNG cần apktool, KHÔNG vá ads):
    python3 deep_translate.py input.apk vi [out.apk]
    python3 deep_translate.py input.apk vi --preview     # chỉ xem sẽ dịch gì
'''

import json
import os
import re
import shutil
import sys
import zipfile
from pathlib import Path

import apptech
import hbc_strings
import hermes_render
import translator

# Manifest của Flutter/RN — không phải text giao diện
_ASSET_SKIP_RE = re.compile(
    r"(?:AssetManifest|FontManifest|NativeAssetsManifest|NOTICES|"
    r"package_config|AssetManifest\.bin)", re.I)


# --------------------------------------------------------------------- Hermes
def _hermes(data, lang, log, progress, preview=False):
    """Trả về (bytes mới | None, report)."""
    hbc = hbc_strings.parse(data)
    idx = hbc.translatable_indices()

    # (a) catalog i18n nhúng thành MỘT chuỗi JSON — nơi chứa text UI thật
    repl = {}
    n_cat = n_cat_units = 0
    cat_samples = []
    for i in idx:
        s = hbc.strings[i]
        if len(s) < 200:
            continue
        obj = looks_like_catalog(s)
        if obj is None:
            continue
        new_obj, n_units, samples = translate_catalog(
            obj, lang, log, progress,
            label=f"catalog i18n trong bundle ({len(s) // 1024} KB)")
        if not n_units:
            continue
        repl[i] = json.dumps(new_obj, ensure_ascii=False,
                             separators=(",", ":"))
        n_cat += 1
        n_cat_units += n_units
        cat_samples = cat_samples or samples

    # (b) các chuỗi rời còn lại. Trước khi đưa qua heuristic hình dạng
    # (natural_text hay bỏ sót câu 1 từ / chữ thường không dấu câu), thử
    # xác nhận bằng ngữ cảnh THẬT: chuỗi nào nằm ở đúng vị trí children/props
    # của lệnh gọi jsx()/createElement()/Alert.alert() thì chắc chắn là UI
    # (xem hermes_render.py) — không có hermes-decomp thì trả về rỗng, dịch
    # tiếp như cũ.
    texts = {i: hbc.strings[i] for i in idx if i not in repl}
    confirmed = hermes_render.confirmed_ui_strings(data, log)
    tr = translator.translate_texts(
        list(dict.fromkeys(texts.values())), lang, log, progress,
        label=f"chuỗi rời Hermes v{hbc.version}", confirmed=confirmed)
    repl.update({i: tr[t] for i, t in texts.items() if t in tr})
    rep = {"kind": "hermes", "engine": f"Hermes HBC v{hbc.version}",
           "candidates": len(idx), "translated": len(repl),
           "catalogs": n_cat, "catalog_entries": n_cat_units,
           "total_strings": hbc.h["stringCount"],
           "confirmed_render": len(confirmed)}
    if n_cat:
        log.append(f"[deep] Hermes: {n_cat} catalog i18n nhúng, "
                   f"{n_cat_units} entry đã dịch")
    # mẫu để xem: ưu tiên entry trong catalog (chuỗi JSON cả cụm thì vô nghĩa)
    loose = [{"from": hbc.strings[i][:120], "to": repl[i][:120]}
             for i in repl if len(hbc.strings[i]) < 200]
    rep["samples"] = (cat_samples + loose)[:40]
    if preview:
        return None, rep
    if not repl:
        rep["note"] = "không có chuỗi nào dịch được an toàn"
        return None, rep
    out = hbc_strings.rebuild(hbc, repl, log)
    ok, why = hbc_strings.verify(hbc, out, repl)
    if not ok:
        # thà giữ bundle gốc còn hơn xuất một app mở lên là crash
        log.append(f"[deep] BỎ dịch Hermes — kiểm chứng thất bại: {why}")
        rep["error"] = why
        return None, rep
    log.append(f"[deep] Hermes: {why}")
    rep["samples"] = rep["samples"][:20]
    return out, rep


# ----------------------------------------------------------------- JS bundle
_JS_LIT_RE = re.compile(r'"((?:[^"\\\n]|\\.){2,200})"')


def _js_bundle(data, lang, log, progress, preview=False):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, {"kind": "js_bundle", "error": "bundle không phải UTF-8"}
    lits = []
    for m in _JS_LIT_RE.finditer(text):
        raw = m.group(1)
        if "\\" in raw:
            continue                # bỏ literal có escape — ghép lại dễ sai
        lits.append(raw)
    uniq = list(dict.fromkeys(lits))
    tr = translator.translate_texts(uniq, lang, log, progress,
                                    label="chuỗi JS bundle")
    rep = {"kind": "js_bundle", "engine": "JavaScript (JSC)",
           "candidates": len(uniq), "translated": len(tr)}
    if preview:
        rep["samples"] = [{"from": k, "to": v} for k, v in
                          list(tr.items())[:40]]
        return None, rep
    if not tr:
        return None, rep

    def sub(m):
        raw = m.group(1)
        new = tr.get(raw)
        if new is None or "\\" in raw:
            return m.group(0)
        return '"' + new.replace("\\", "\\\\").replace('"', '\\"') + '"'

    out = _JS_LIT_RE.sub(sub, text)
    rep["samples"] = [{"from": k, "to": v} for k, v in list(tr.items())[:20]]
    return out.encode("utf-8"), rep


# ------------------------------------------------- catalog i18n nhúng (JSON)
# App React Native/Expo hiện đại thường gom TOÀN BỘ text giao diện vào một
# chuỗi JSON duy nhất trong bundle (Lingui/i18next compile ra), ví dụ:
#   {"-J_ajx":["Search neighborhoods..."],"0ztViJ":["Moving ",["dogName"],"?"]}
# Nên nếu chỉ dịch từng chuỗi rời thì text UI thật không hề được dịch. Hàm
# dưới nhận ra chuỗi JSON kiểu catalog, dịch giá trị bên trong rồi ghép lại.
#
# Phần tử mảng dạng ["tên"] là placeholder của Lingui — nối thành một câu với
# đánh dấu {{p0}} để engine không đụng tới, dịch xong tách lại thành mảng.
_PART_RE = re.compile(r"\{\{p(\d+)\}\}")
MIN_CATALOG_LEAVES = 5


def _is_parts_array(node):
    """Mảng kiểu Lingui: có ít nhất 1 chuỗi, phần còn lại là chuỗi/mảng."""
    if not isinstance(node, list) or not node:
        return False
    if not any(isinstance(x, str) for x in node):
        return False
    return all(isinstance(x, (str, list)) for x in node)


def _compose_parts(node):
    """(text có {{pN}}, [phần tử gốc]) từ mảng Lingui."""
    holes, out = [], []
    for el in node:
        if isinstance(el, str):
            out.append(el)
        else:
            out.append("{{p%d}}" % len(holes))
            holes.append(el)
    return "".join(out), holes


def _decompose_parts(text, holes):
    """Ngược của _compose_parts. None nếu bản dịch làm rơi placeholder."""
    seen = set()
    out, pos = [], 0
    for m in _PART_RE.finditer(text):
        i = int(m.group(1))
        if i >= len(holes) or i in seen:
            return None
        seen.add(i)
        seg = text[pos:m.start()]
        if seg:
            out.append(seg)
        out.append(holes[i])
        pos = m.end()
    if seen != set(range(len(holes))):
        return None
    tail = text[pos:]
    if tail:
        out.append(tail)
    return out or [""]


def _catalog_walk(node, fn):
    """Áp fn lên từng 'đơn vị dịch'. fn(kind, payload) → giá trị mới | None."""
    if isinstance(node, str):
        return fn("str", node)
    if _is_parts_array(node):
        return fn("parts", node)
    if isinstance(node, list):
        out = []
        for v in node:
            nv = _catalog_walk(v, fn)
            out.append(v if nv is None else nv)
        return out
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if isinstance(k, str) and k.startswith("@"):
                out[k] = v
                continue
            nv = _catalog_walk(v, fn)
            out[k] = v if nv is None else nv
        return out
    return None


def looks_like_catalog(text):
    """Chuỗi này là catalog i18n dạng JSON không? Trả về object đã parse."""
    st = text.lstrip()
    if not st or st[0] not in "{[" or len(text) < 80:
        return None
    try:
        obj = json.loads(text)
    except ValueError:
        return None
    if not isinstance(obj, (dict, list)):
        return None
    bag = []

    def count(kind, payload):
        bag.append(payload if kind == "str" else _compose_parts(payload)[0])
        return None
    _catalog_walk(obj, count)
    ui = [b for b in bag if isinstance(b, str) and len(b.split()) >= 1
          and re.search(r"[A-Za-z]{2}", b)]
    return obj if len(ui) >= MIN_CATALOG_LEAVES else None


def translate_catalog(obj, lang, log, progress, label="catalog"):
    """Dịch catalog đã parse. Trả về (obj mới, số đơn vị đã dịch, mẫu)."""
    texts = []

    def collect(kind, payload):
        texts.append(payload if kind == "str"
                     else _compose_parts(payload)[0])
        return None
    _catalog_walk(obj, collect)

    # Catalog JSON/ARB: mọi giá trị đều là nội dung hiển thị (câu hỏi, đáp án,
    # giải thích…). Tắt strict để không bỏ fill-in-the-blank ("Tom _____ now.")
    # hay câu có gạch dưới / ký hiệu bài tập — user chọn dịch data là muốn full.
    tr = translator.translate_texts(texts, lang, log, progress, label=label,
                                    allow_single=True, strict=False)
    n = 0
    samples = []

    def apply_one(kind, payload):
        nonlocal n
        if kind == "str":
            new = tr.get(payload)
            if new is None or new == payload:
                return None
            n += 1
            if len(samples) < 12:
                samples.append({"from": payload, "to": new})
            return new
        text, holes = _compose_parts(payload)
        new = tr.get(text)
        if new is None or new == text:
            return None
        parts = _decompose_parts(new, holes)
        if parts is None:
            return None
        n += 1
        if len(samples) < 12:
            samples.append({"from": text, "to": new})
        return parts
    new_obj = _catalog_walk(obj, apply_one)
    return new_obj, n, samples


# ---------------------------------------------------------------- asset i18n
def _walk_json(obj, fn):
    """Áp fn lên mọi chuỗi lá trong JSON, trả về (obj mới, số chuỗi đã đổi)."""
    if isinstance(obj, str):
        new = fn(obj)
        return (new, 1) if new is not None and new != obj else (obj, 0)
    if isinstance(obj, list):
        n = 0
        out = []
        for v in obj:
            nv, c = _walk_json(v, fn)
            out.append(nv)
            n += c
        return out, n
    if isinstance(obj, dict):
        n = 0
        out = {}
        for k, v in obj.items():
            # khoá "@..." của ARB là metadata, không dịch
            if isinstance(k, str) and k.startswith("@"):
                out[k] = v
                continue
            nv, c = _walk_json(v, fn)
            out[k] = nv
            n += c
        return out, n
    return obj, 0


def _collect_json(obj, bag):
    if isinstance(obj, str):
        bag.append(obj)
    elif isinstance(obj, list):
        for v in obj:
            _collect_json(v, bag)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k.startswith("@"):
                continue
            _collect_json(v, bag)


_XML_STR_RE = re.compile(r"(<string[^>]*>)(.*?)(</string>)", re.S)
_PROP_RE = re.compile(r"^([^#;=\n][^=\n]*)=(.*)$", re.M)
_PO_RE = re.compile(r'^(msgstr\s+)"(.*)"$', re.M)


def _asset_i18n(name, data, lang, log, progress, preview=False):
    low = name.lower()
    rep = {"kind": "asset_i18n", "where": name, "candidates": 0,
           "translated": 0}
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, None

    if low.endswith((".json", ".arb", ".resjson")):
        try:
            obj = json.loads(text)
        except ValueError:
            return None, None
        bag = []
        _collect_json(obj, bag)
        rep["candidates"] = len(set(bag))
        new_obj, n, samples = translate_catalog(
            obj, lang, log, progress, label=f"chuỗi {Path(name).name}")
        rep["translated"] = n
        rep["samples"] = samples[:8]
        if preview or not n:
            return None, rep
        return json.dumps(new_obj, ensure_ascii=False,
                          indent=1).encode("utf-8"), rep

    if low.endswith(".xml"):
        vals = [m.group(2) for m in _XML_STR_RE.finditer(text)]
        uniq = list(dict.fromkeys(vals))
        rep["candidates"] = len(uniq)
        tr = translator.translate_texts(uniq, lang, log, progress,
                                        label=f"chuỗi {Path(name).name}")
        rep["translated"] = len(tr)
        if preview or not tr:
            return None, rep
        out = _XML_STR_RE.sub(
            lambda m: m.group(1) + tr.get(m.group(2), m.group(2))
            + m.group(3), text)
        return out.encode("utf-8"), rep

    if low.endswith((".properties", ".ini")):
        vals = [m.group(2).strip() for m in _PROP_RE.finditer(text)]
        uniq = list(dict.fromkeys(v for v in vals if v))
        rep["candidates"] = len(uniq)
        tr = translator.translate_texts(uniq, lang, log, progress,
                                        label=f"chuỗi {Path(name).name}")
        rep["translated"] = len(tr)
        if preview or not tr:
            return None, rep
        out = _PROP_RE.sub(
            lambda m: m.group(1) + "=" + tr.get(m.group(2).strip(),
                                                m.group(2)), text)
        return out.encode("utf-8"), rep

    if low.endswith(".po"):
        vals = [m.group(2) for m in _PO_RE.finditer(text) if m.group(2)]
        uniq = list(dict.fromkeys(vals))
        rep["candidates"] = len(uniq)
        tr = translator.translate_texts(uniq, lang, log, progress,
                                        label=f"chuỗi {Path(name).name}")
        rep["translated"] = len(tr)
        if preview or not tr:
            return None, rep
        out = _PO_RE.sub(
            lambda m: m.group(1) + '"'
            + tr.get(m.group(2), m.group(2)).replace('"', '\\"') + '"', text)
        return out.encode("utf-8"), rep

    return None, None


# --------------------------------------------------------------------- áp dụng
def apply(apk_in, apk_out, lang, inv=None, log=None, progress=None,
          preview=False, include_kinds=None):
    """Dịch mọi kho text ngoài res/values rồi ghi APK mới (CHƯA ký).

    inv           — kết quả apptech.inventory() (tự chạy nếu None)
    include_kinds — chỉ xử lý những kind này (mặc định: mọi kind 'ready')
    preview       — chỉ báo cáo sẽ dịch gì, không ghi file

    Trả về report dict.
    """
    if log is None:
        log = []
    apk_in = Path(apk_in)
    inv = inv or apptech.inventory(apk_in, log)
    # Tên app là tên riêng — giữ nguyên, đừng để model dịch méo
    label = apptech.app_label(apk_in)
    if label:
        translator.keep_words([label] + label.split())
        log.append(f'[deep] giữ nguyên tên app: "{label}"')
    # Mặc định chỉ các kho "ready" (trừ res/values do translator.py lo).
    # Kho "partial" như asset_data (dữ liệu app) phải được chọn rõ ràng.
    # Dùng `is not None` vì include_kinds=[] nghĩa là "không dịch kho nào".
    want = set(include_kinds) if include_kinds is not None else None
    if want is None and os.environ.get("ADFREE_TRANSLATE_DATA") == "1":
        want = {s["kind"] for s in inv["stores"]
                if s["status"] in ("ready", "partial")} - {"android_res"}
    ready = [s for s in inv["stores"]
             if s["kind"] != "android_res"
             and (s["kind"] in want if want is not None
                  else s["status"] == "ready")]
    report = {"lang": lang, "platforms": inv["platform_names"],
              "stores": [], "files_changed": 0, "translated": 0}
    if not ready:
        report["note"] = ("không có kho text nào ngoài res/values dịch được "
                          "cho app này")
        log.append("[deep] " + report["note"])
        return report

    edits = {}          # tên entry trong APK -> bytes mới
    with zipfile.ZipFile(apk_in) as z:
        for store in ready:
            kind = store["kind"]
            if kind == "hermes":
                name = store["where"]
                new, rep = _hermes(z.read(name), lang, log, progress, preview)
            elif kind == "js_bundle":
                name = store["where"]
                new, rep = _js_bundle(z.read(name), lang, log, progress,
                                      preview)
            elif kind == "unity_il2cpp":
                import il2cpp_strings
                name = store["where"]
                new, rep = il2cpp_strings.translate(
                    z.read(name), lang, log, progress, preview)
            elif kind == "unity_assets":
                import unity_strings
                uedits, urep = unity_strings.apply(apk_in, lang, log,
                                                   progress, preview)
                report["stores"].append(urep)
                report["translated"] += urep.get("translated", 0)
                edits.update(uedits)
                continue
            elif kind == "flutter_aot":
                import flutter_translate
                dict_data = flutter_translate.build_dictionary(apk_in, lang, log, progress)
                rep = {"kind": "flutter_aot", "engine": "Dart AOT (Native Hook)",
                       "candidates": store.get("strings") or len(dict_data),
                       "translated": len(dict_data)}
                if dict_data:
                    dict_bytes = json.dumps(dict_data, ensure_ascii=False, indent=2).encode("utf-8")
                    edits["assets/flutter_dict.json"] = dict_bytes
                    abis = {m.group(1) for n in z.namelist() if (m := re.match(r"^lib/([^/]+)/", n))} or {"arm64-v8a"}
                    for abi in abis:
                        hook_so = flutter_translate.PREBUILT_DIR / abi / "libflutter_hook.so"
                        if hook_so.is_file():
                            edits[f"lib/{abi}/libflutter_hook.so"] = hook_so.read_bytes()
                            log.append(f"[flutter] đã thêm lib/{abi}/libflutter_hook.so")
                    rep["samples"] = [{"from": k, "to": v} for k, v in list(dict_data.items())[:15]]
                report["stores"].append(rep)
                report["translated"] += rep.get("translated", 0)
                continue
            elif kind in ("asset_i18n", "asset_data"):
                for f in store.get("files", []):
                    nm = f["file"]
                    if _ASSET_SKIP_RE.search(nm):
                        continue
                    new, rep = _asset_i18n(nm, z.read(nm), lang, log,
                                           progress, preview)
                    if rep:
                        report["stores"].append(rep)
                        report["translated"] += rep.get("translated", 0)
                    if new:
                        edits[nm] = new
                continue
            else:
                continue
            if rep:
                report["stores"].append(rep)
                report["translated"] += rep.get("translated", 0)
            if new:
                edits[name] = new

    if preview:
        report["preview"] = True
        return report
    if not edits:
        log.append("[deep] không có file nào thay đổi — giữ nguyên APK")
        if str(apk_in) != str(apk_out):
            shutil.copy2(apk_in, apk_out)
        return report

    _rewrite_zip(apk_in, apk_out, edits)
    report["files_changed"] = len(edits)
    log.append(f"[deep] ghi lại {len(edits)} file trong APK: "
               + ", ".join(sorted(edits)[:4])
               + (" …" if len(edits) > 4 else ""))
    return report


def _rewrite_zip(src, dst, edits):
    """Copy APK, thay nội dung một số entry, giữ nguyên kiểu nén từng entry.

    Giữ nguyên compress_type là bắt buộc: `resources.arsc` và `.so` trong APK
    hiện đại phải ở dạng STORED để Android map thẳng từ file.
    """
    src, dst = Path(src), Path(dst)
    with zipfile.ZipFile(src) as zin, \
            zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        seen = set()
        for item in zin.infolist():
            data = edits.get(item.filename)
            if data is None:
                data = zin.read(item.filename)
            seen.add(item.filename)
            info = zipfile.ZipInfo(item.filename, date_time=item.date_time)
            info.compress_type = item.compress_type
            info.external_attr = item.external_attr
            info.internal_attr = item.internal_attr
            info.create_system = item.create_system
            zout.writestr(info, data)
        # Ghi các file mới trong edits (ví dụ libflutter_hook.so, assets/flutter_dict.json)
        for name, data in edits.items():
            if name not in seen:
                info = zipfile.ZipInfo(name)
                if name.endswith(".so") or name == "resources.arsc":
                    info.compress_type = zipfile.ZIP_STORED
                else:
                    info.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(info, data)


# ------------------------------------------------------------------------ CLI
def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    preview = "--preview" in argv
    argv = [a for a in argv if not a.startswith("--")]
    if len(argv) < 2:
        print(__doc__)
        return 2
    src = Path(argv[0])
    lang = argv[1].lower()
    dst = Path(argv[2]) if len(argv) > 2 else \
        src.with_name(src.stem + "-" + lang + src.suffix)
    log = []
    os.environ.setdefault("ADFREE_MT_VERBOSE", "1")

    inv = apptech.inventory(src, log)
    print("Công nghệ: " + ", ".join(inv["platform_names"] or ["?"]))
    for s in inv["stores"]:
        n = s.get("strings")
        print(f"  {apptech._MARK[s['status']]} {s['kind']} — "
              f"{n if isinstance(n, int) else '?'} chuỗi · {s['where']}")

    work = src.parent / (".adfree-deep-" + dst.stem)
    work.mkdir(parents=True, exist_ok=True)
    unsigned = work / "deep-unsigned.apk"
    rep = apply(src, unsigned, lang, inv, log, preview=preview)
    for line in log:
        print(line)
    if preview:
        for st in rep["stores"]:
            print(f"\n--- {st['kind']} {st.get('where', '')}: "
                  f"{st.get('translated', 0)}/{st.get('candidates', 0)} "
                  f"chuỗi ---")
            for s in st.get("samples", [])[:15]:
                print(f"   {s['from']!r}\n   → {s['to']!r}")
        shutil.rmtree(work, ignore_errors=True)
        return 0
    if not rep.get("files_changed"):
        print("Không có gì để dịch.")
        shutil.rmtree(work, ignore_errors=True)
        return 1
    from patcher import sign_apk         # import muộn để CLI đứng độc lập
    sig = sign_apk(unsigned, dst, work, log)
    shutil.rmtree(work, ignore_errors=True)
    print(f"\nOK: {dst}")
    print(f"  Đã dịch {rep['translated']} chuỗi trong "
          f"{rep['files_changed']} file · chữ ký {sig}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
