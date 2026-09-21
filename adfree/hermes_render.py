#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Xác nhận chuỗi Hermes nào CHẮC CHẮN render lên UI, bằng cách đọc lệnh gọi
thật trong bytecode (jsx/createElement/Alert.alert…) thay vì đoán qua hình
dạng chữ như `translator.natural_text`.

Vì sao cần: JSX (`<Text>alloo</Text>`) khi Metro compile xuống Hermes
bytecode chỉ còn là `jsx(Text, {children: "alloo"})` — không còn cây XML,
chuỗi "alloo" nằm lẫn trong hàng trăm chuỗi khác (tên icon, class CSS, key
JSON…) dưới dạng literal phẳng. `natural_text()` phải đoán qua hình dạng
(số từ, viết hoa, dấu câu…) nên bỏ sót thật: chuỗi 1 từ ("alloo", "Xong")
hoặc câu chữ thường không dấu câu ("nhập số điện thoại") bị coi là rác kỹ
thuật dù là text UI thật.

Ở đây dùng lại đúng "attribute" mà JSX luôn để lại dấu vết: tên property
truyền cho hàm dựng UI (`children`, `title`, `placeholder`…) — tương đương
`android:text` trong XML Android, chỉ khác là nó nằm trong object argument
của một lệnh gọi thay vì một tag XML. Đọc qua `hermes-decomp` (Rust, MIT,
https://github.com/SymbioticSec/hermes-decomp) để lấy IR dạng cây (giống
ESTree) rồi tìm đúng các lệnh gọi đó — không cần tự viết lại disassembler
hay lần dữ liệu qua từng thanh ghi (register) của bytecode.

An toàn: đây là lớp BỔ SUNG, không bắt buộc. Không có binary `hermes-decomp`
(không có trên PATH và không set ADFREE_HERMES_DECOMP) thì trả về tập rỗng,
pipeline dịch tiếp bằng heuristic `natural_text` như cũ — không lỗi, không
chặn build.

CLI:
    python3 hermes_render.py index.android.bundle
'''

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Tên property mang text hiển thị trong object props của jsx()/createElement().
# Tương đương các attribute Android biết chắc là chứa text (android:text,
# android:hint…) — nhưng ở đây phải liệt kê tay vì không có "danh sách
# attribute chuẩn" như Android SDK, các component RN tự đặt tên prop.
UI_PROPS = {"children", "title", "placeholder", "label", "hint", "message",
            "text", "subtitle", "description", "buttonText", "errorText",
            "helperText", "tooltip", "confirmText", "cancelText"}
# Hàm dựng UI: JSX (cả 2 runtime cũ/mới) và biến thể clone.
RENDER_CALLEES = {"jsx", "jsxs", "createElement", "cloneElement"}
# receiver.method mà tham số VỊ TRÍ (không qua props object) là text hiển thị.
POSITIONAL_TEXT_CALLS = {"alert"}          # Alert.alert(title, message)

_BIN_ENV = "ADFREE_HERMES_DECOMP"
_TIMEOUT = 180
# Fallback cho máy dev hiện tại — build sẵn tại đây, khỏi phải set env var mỗi
# lần. Máy khác không có path này thì tự động rơi về PATH/$ADFREE_HERMES_DECOMP.
_LOCAL_FALLBACK = ("/Volumes/Razer/code/hermes-dec/hermes-decomp/"
                   "target/release/hermes-decomp")
_bin_cache = None


def _binary():
    global _bin_cache
    if _bin_cache is None:
        cand = os.environ.get(_BIN_ENV) or shutil.which("hermes-decomp") or ""
        if not cand and os.path.isfile(_LOCAL_FALLBACK):
            cand = _LOCAL_FALLBACK
        _bin_cache = cand
    return _bin_cache or None


def available():
    """Có dùng được lớp phân tích render-call này không (có binary)?"""
    return _binary() is not None


def _ident(node):
    return node.get("Ident") if isinstance(node, dict) else None


def _callee_name(callee):
    """Tên property cuối của callee (vd `a.b.jsx` → "jsx")."""
    if isinstance(callee, dict) and "Member" in callee:
        return _ident(callee["Member"].get("property"))
    return None


def _string_const(node):
    if isinstance(node, dict) and "Value" in node:
        v = node["Value"]
        if isinstance(v, dict) and "Constant" in v:
            c = v["Constant"]
            if isinstance(c, dict) and "String" in c:
                return c["String"]
    return None


def _walk(node, out):
    if isinstance(node, dict):
        if "Call" in node:
            call = node["Call"]
            name = _callee_name(call.get("callee", {}))
            args = call.get("arguments", [])
            if name in RENDER_CALLEES:
                for a in args:
                    if isinstance(a, dict) and "Object" in a:
                        for p in a["Object"].get("properties", []):
                            if _ident(p.get("key")) in UI_PROPS:
                                s = _string_const(p.get("value"))
                                if s is not None:
                                    out.add(s)
                    elif isinstance(a, dict) and "Array" in a:
                        # <Text>phần 1{x}phần 2</Text> → children là mảng
                        for el in a["Array"].get("elements") or []:
                            s = _string_const(el)
                            if s is not None:
                                out.add(s)
            elif name in POSITIONAL_TEXT_CALLS:
                for a in args:
                    s = _string_const(a)
                    if s is not None:
                        out.add(s)
        for v in node.values():
            _walk(v, out)
    elif isinstance(node, list):
        for it in node:
            _walk(it, out)


def confirmed_ui_strings(data, log=None):
    """Chuỗi nào trong bundle Hermes chắc chắn render lên UI (không đoán qua
    hình dạng). Trả về set() nếu không có `hermes-decomp` hoặc phân tích lỗi
    — bỏ qua êm, không phải điều kiện bắt buộc để dịch tiếp."""
    binp = _binary()
    if not binp:
        return set()
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".hbc", delete=False) as f:
            f.write(data)
            tmp = f.name
        proc = subprocess.run(
            [binp, "decompile", tmp, "--json", "--no-cache"],
            capture_output=True, timeout=_TIMEOUT)
        if proc.returncode != 0:
            if log is not None:
                err = proc.stderr.decode("utf-8", "replace")[:300]
                log.append(f"[hermes_render] hermes-decomp lỗi: {err}")
            return set()
        ir = json.loads(proc.stdout)
    except Exception as e:
        if log is not None:
            log.append(f"[hermes_render] bỏ qua phân tích render-call: {e}")
        return set()
    finally:
        if tmp:
            for suffix in ("", ".hdcache"):
                try:
                    os.unlink(tmp + suffix)
                except OSError:
                    pass
    out = set()
    for fn in ir:
        _walk(fn.get("ir"), out)
    if log is not None and out:
        log.append(f"[hermes_render] {len(out)} chuỗi xác nhận qua "
                   "render-call (jsx/createElement/Alert.alert…)")
    return out


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        return 2
    if not available():
        print(f"Không tìm thấy binary hermes-decomp (PATH hoặc "
              f"${_BIN_ENV}).")
        return 1
    data = Path(argv[0]).read_bytes()
    log = []
    out = confirmed_ui_strings(data, log)
    for line in log:
        print(line, file=sys.stderr)
    for s in sorted(out):
        print(repr(s))
    print(f"\n{len(out)} chuỗi.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
