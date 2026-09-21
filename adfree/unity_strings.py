#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Dịch text trong asset của Unity (`TextAsset`, bảng Unity Localization).

Game Unity không để text ở `res/values` mà trong các file asset của engine:

    assets/bin/Data/level0, sharedassets0.assets, globalgamemanagers.assets…
    assets/aa/Android/*.bundle          (Addressables)
    assets/**/*.unity3d, *.bundle       (asset bundle rời)

Trong đó text nằm ở:

  · **TextAsset** — file JSON/CSV/XML localization đóng thẳng vào asset.
    Đây là cách phổ biến nhất và cũng là cách sửa được chắc chắn nhất.
  · **MonoBehaviour** — bảng của package Unity Localization (`StringTable`)
    hoặc script tự viết. Chỉ đọc/ghi được khi file có TypeTree (build không
    strip). Không có TypeTree thì bỏ qua, báo rõ lý do.

Dùng UnityPy để đọc/ghi lại asset — tự cài vào cùng venv với engine dịch
(xem [offline_mt.py](offline_mt.py)).

Lưu ý về phạm vi: rất nhiều game **tải nội dung lúc chạy** (Addressables trên
CDN), lúc đó trong APK không có text nào để dịch — tool sẽ báo 0 chuỗi chứ
không phải lỗi.

CLI:
    python3 unity_strings.py app.apk            # liệt kê text tìm được
    python3 unity_strings.py app.apk vi out.apk # dịch (chưa ký)
'''

import json
import os
import re
import sys
import zipfile
from pathlib import Path

import offline_mt
import translator

# File asset của Unity trong APK
_UNITY_FILE_RE = re.compile(
    r"^assets/(?:bin/Data/(?!Managed/Metadata/)|aa/|AssetBundles/|bundles/)"
    r"|\.(?:bundle|unity3d|assets)$")
_SKIP_NAME_RE = re.compile(
    r"\.(?:json|xml|config|dat|txt|so|png|jpg|ogg|mp3|resS|resource)$", re.I)

# TextAsset nào là localization: nội dung JSON/CSV có text người đọc
MIN_UNITY_STRINGS = 2

# Khoá thường chứa text hiển thị trong MonoBehaviour của Unity Localization
_MONO_TEXT_KEYS = ("m_Localized", "m_Value", "Value", "text", "m_Text",
                   "m_TableData", "m_Entries")


def ensure(log=None, progress=None):
    """Bảo đảm UnityPy dùng được."""
    return offline_mt.ensure_extra(["UnityPy"], log, progress)


def _as_text(script):
    if isinstance(script, (bytes, bytearray)):
        try:
            return script.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return script if isinstance(script, str) else None


def _translate_text_blob(text, lang, log, progress, label):
    """Dịch nội dung một TextAsset. Trả về (text mới | None, số chuỗi)."""
    import deep_translate           # import muộn: tránh vòng import
    obj = deep_translate.looks_like_catalog(text)
    if obj is not None:
        new_obj, n, _ = deep_translate.translate_catalog(
            obj, lang, log, progress, label=label)
        if not n:
            return None, 0
        return json.dumps(new_obj, ensure_ascii=False,
                          separators=(",", ":")), n
    # CSV/TSV: dịch từng ô có chữ
    if "\n" in text and ("," in text or "\t" in text):
        sep = "\t" if text.count("\t") > text.count(",") else ","
        rows = [r.split(sep) for r in text.split("\n")]
        cells = [c.strip().strip('"') for r in rows for c in r]
        tr = translator.translate_texts(
            [c for c in cells if c], lang, log, progress, label=label,
            allow_single=True)
        if not tr:
            return None, 0
        n = 0
        out_rows = []
        for r in rows:
            out = []
            for c in r:
                key = c.strip().strip('"')
                new = tr.get(key)
                if new is None:
                    out.append(c)
                else:
                    n += 1
                    out.append(('"' + new + '"') if c.strip().startswith('"')
                               else new)
            out_rows.append(sep.join(out))
        return "\n".join(out_rows), n
    return None, 0


def _walk_typetree(node, fn):
    """Áp fn lên chuỗi trong typetree của MonoBehaviour (chỉ khoá text)."""
    n = 0
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if isinstance(v, str):
                if k in _MONO_TEXT_KEYS:
                    new = fn(v)
                    if new is not None and new != v:
                        node[k] = new
                        n += 1
            else:
                n += _walk_typetree(v, fn)
    elif isinstance(node, list):
        for v in node:
            n += _walk_typetree(v, fn)
    return n


def _collect_typetree(node, bag):
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str):
                if k in _MONO_TEXT_KEYS:
                    bag.append(v)
            else:
                _collect_typetree(v, bag)
    elif isinstance(node, list):
        for v in node:
            _collect_typetree(v, bag)


def process_file(name, data, lang, log=None, progress=None, preview=False):
    """Dịch một file asset Unity. Trả về (bytes mới | None, report)."""
    if log is None:
        log = []
    import UnityPy
    from UnityPy.enums import ClassIDType

    rep = {"kind": "unity_assets", "where": name, "text_assets": 0,
           "mono": 0, "candidates": 0, "translated": 0, "samples": []}
    try:
        env = UnityPy.load(data)
        objects = list(env.objects)
    except Exception as e:
        rep["error"] = f"không mở được asset: {e}"
        return None, rep

    changed = 0
    for obj in objects:
        if obj.type == ClassIDType.TextAsset:
            rep["text_assets"] += 1
            try:
                d = obj.read()
                text = _as_text(d.m_Script)
            except Exception:
                continue
            if not text or len(text) < 8:
                continue
            rep["candidates"] += 1
            new, n = _translate_text_blob(
                text, lang, log, progress,
                label=f"TextAsset {getattr(d, 'm_Name', '?')}")
            if not new or n < MIN_UNITY_STRINGS:
                continue
            rep["translated"] += n
            rep["samples"].append({"from": text[:90], "to": new[:90]})
            if not preview:
                d.m_Script = new
                d.save()
                changed += 1
        elif obj.type == ClassIDType.MonoBehaviour:
            try:
                tree = obj.read_typetree()
            except Exception:
                continue                # không có TypeTree → bỏ qua
            bag = []
            _collect_typetree(tree, bag)
            if not bag:
                continue
            rep["mono"] += 1
            rep["candidates"] += len(bag)
            tr = translator.translate_texts(
                list(dict.fromkeys(bag)), lang, log, progress,
                label=f"bảng Unity Localization ({name.rsplit('/', 1)[-1]})",
                allow_single=True)
            if not tr:
                continue
            n = _walk_typetree(tree, lambda s: tr.get(s))
            if not n:
                continue
            rep["translated"] += n
            for k, v in list(tr.items())[:3]:
                rep["samples"].append({"from": k, "to": v})
            if not preview:
                try:
                    obj.save_typetree(tree)
                    changed += 1
                except Exception as e:
                    log.append(f"[unity] không ghi lại được MonoBehaviour: {e}")

    if preview or not changed:
        return None, rep
    try:
        out = env.file.save(packer="original")
    except Exception:
        try:
            out = env.file.save()
        except Exception as e:
            rep["error"] = f"không ghi lại được asset: {e}"
            return None, rep
    log.append(f"[unity] {name.rsplit('/', 1)[-1]}: {rep['translated']} chuỗi "
               f"trong {changed} asset")
    return out, rep


def unity_files(apk):
    """Các entry trong APK là file asset của Unity."""
    with zipfile.ZipFile(apk) as z:
        for n in z.namelist():
            if n.endswith("/") or _SKIP_NAME_RE.search(n):
                continue
            if _UNITY_FILE_RE.search(n) and z.getinfo(n).file_size > 64:
                yield n


def apply(apk, lang, log=None, progress=None, preview=False):
    """Dịch mọi file asset Unity trong APK. Trả về ({entry: bytes}, report)."""
    if log is None:
        log = []
    ok, err = ensure(log, progress)
    if not ok:
        log.append(f"[unity] không dùng được UnityPy: {err}")
        return {}, {"kind": "unity_assets", "error": err}
    edits = {}
    stores = []
    names = list(unity_files(apk))
    with zipfile.ZipFile(apk) as z:
        for i, name in enumerate(names):
            new, rep = process_file(name, z.read(name), lang, log, progress,
                                    preview)
            if rep.get("candidates") or rep.get("error"):
                stores.append(rep)
            if new:
                edits[name] = new
    total = sum(s.get("translated", 0) for s in stores)
    return edits, {"kind": "unity_assets", "files": len(names),
                   "translated": total, "stores": stores}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        return 2
    os.environ.setdefault("ADFREE_MT_VERBOSE", "1")
    apk = Path(argv[0])
    log = []
    if len(argv) == 1:
        ok, err = ensure(log)
        if not ok:
            print("THẤT BẠI:", err)
            return 1
        import UnityPy
        from UnityPy.enums import ClassIDType
        n_files = n_ta = 0
        with zipfile.ZipFile(apk) as z:
            for name in unity_files(apk):
                n_files += 1
                try:
                    env = UnityPy.load(z.read(name))
                except Exception as e:
                    print(f"  {name}: không mở được ({e})")
                    continue
                tas = [o for o in env.objects
                       if o.type == ClassIDType.TextAsset]
                monos = [o for o in env.objects
                         if o.type == ClassIDType.MonoBehaviour]
                if tas or monos:
                    print(f"  {name}: {len(tas)} TextAsset, "
                          f"{len(monos)} MonoBehaviour")
                for o in tas[:5]:
                    try:
                        d = o.read()
                        t = _as_text(d.m_Script) or ""
                        print(f"      {d.m_Name!r} ({len(t)} ký tự): "
                              f"{t[:70]!r}")
                    except Exception:
                        pass
                n_ta += len(tas)
        print(f"\n{n_files} file asset Unity · {n_ta} TextAsset")
        return 0

    lang = argv[1].lower()
    edits, rep = apply(apk, lang, log, preview="--preview" in sys.argv)
    for ln in log:
        print(ln)
    print(f"\n{rep.get('translated', 0)} chuỗi dịch được trong "
          f"{len(edits)} file asset")
    for st in rep.get("stores", [])[:10]:
        print(f"  · {st['where']}: {st.get('translated', 0)}/"
              f"{st.get('candidates', 0)}"
              + (f" — {st['error']}" if st.get("error") else ""))
        for s in st.get("samples", [])[:3]:
            print(f"       {s['from']!r}\n     → {s['to']!r}")
    if len(argv) > 2 and edits:
        import deep_translate
        deep_translate._rewrite_zip(apk, argv[2], edits)
        print(f"\nĐã ghi {argv[2]} (chưa ký)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
