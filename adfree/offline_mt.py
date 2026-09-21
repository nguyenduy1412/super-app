#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Engine dịch OFFLINE cho AdFree: tự tải runtime + model dịch, rồi dịch local.

Không gọi API dịch nào của bên thứ ba. Lần đầu chạy cần Internet để tải:

  1. **Runtime** (~60 MB) — `ctranslate2` + `sentencepiece` được `pip install`
     vào một venv riêng ở `~/.adfree/mt/runtime-pyXY`, sau đó nạp thẳng vào
     process đang chạy (`site.addsitedir`). Không đụng tới Python hệ thống,
     không cần `argostranslate` (thư viện đó kéo theo torch/spacy ~1 GB —
     ở đây chỉ cần đúng 2 gói để chạy model).
  2. **Model** (~80 MB mỗi cặp ngôn ngữ) — file `.argosmodel` (là zip chứa
     model CTranslate2 + `sentencepiece.model`) tải từ index của Argos
     OpenTech, giải nén vào `~/.adfree/mt/models/`.

Sau lần đầu, mọi lần dịch sau chạy hoàn toàn offline.

Index chỉ có các cặp đi qua tiếng Anh (49 ngôn ngữ ↔ en), nên cặp không có
model trực tiếp (vd zh→vi) tự động dịch 2 chặng zh→en→vi.

Dùng như module:

    import offline_mt
    ok, err = offline_mt.ensure(src="en", tgt="vi", log=[])
    out = offline_mt.translate_batch(["Settings", "Watch ad"], "en", "vi")

CLI:

    python3 offline_mt.py status              # runtime/model đã có gì
    python3 offline_mt.py install vi          # tải sẵn runtime + model en→vi
    python3 offline_mt.py langs               # ngôn ngữ có model
    python3 offline_mt.py tr vi "Watch ad to unlock"
'''

import json
import os
import shutil
import site
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

# ------------------------------------------------------------------ cấu hình
HOME = Path(os.environ.get("ADFREE_MT_HOME",
                           Path.home() / ".adfree" / "mt")).expanduser()
MODELS_DIR = HOME / "models"
INDEX_URL = os.environ.get(
    "ADFREE_MT_INDEX",
    "https://raw.githubusercontent.com/argosopentech/argospm-index/main/index.json")
INDEX_TTL = 24 * 3600          # cache index.json 1 ngày
DEVICE = os.environ.get("ADFREE_MT_DEVICE", "cpu")
# Song song hoá CTranslate2:
#   inter_threads — số batch dịch song song (đa luồng thật)
#   intra_threads — số luồng trong 1 batch
# Mặc định: chia đều số nhân CPU, ưu tiên nhiều batch (inter) vì dịch
# hàng nghìn chuỗi JSON/Flutter — nhanh hơn hẳn so với inter=1 cũ.
_CPU = max(1, os.cpu_count() or 4)
INTER_THREADS = int(os.environ.get(
    "ADFREE_MT_INTER_THREADS",
    str(max(2, min(8, _CPU // 2)))))
INTRA_THREADS = int(os.environ.get(
    "ADFREE_MT_INTRA_THREADS",
    str(max(1, _CPU // INTER_THREADS))))
# beam_size=1 (greedy) nhanh ~3–4× so với 4; chất lượng vẫn ổn cho UI app.
# Đặt ADFREE_MT_BEAM=4 nếu muốn chất lượng cao hơn (chậm hơn).
BEAM_SIZE = int(os.environ.get("ADFREE_MT_BEAM", "1"))
# int8 trên CPU thường nhanh hơn float32 rõ rệt; "default" để CT2 tự chọn.
COMPUTE_TYPE = os.environ.get("ADFREE_MT_COMPUTE", "int8")
# 1 = không tự pip install (môi trường cấm mạng / đã cài sẵn tay)
NO_INSTALL = os.environ.get("ADFREE_MT_NO_INSTALL", "") == "1"
RUNTIME_PKGS = ["ctranslate2", "sentencepiece"]
# venv gắn theo phiên bản Python: wheel ctranslate2 build theo ABI từng bản
VENV = HOME / f"runtime-py{sys.version_info.major}{sys.version_info.minor}"

# Thư mục package của argostranslate — dùng lại model ai đó đã cài bằng
# `argospm install` thay vì tải lại 80 MB.
_ARGOS_DIRS = [
    Path.home() / ".local" / "share" / "argos-translate" / "packages",
    Path.home() / "Library" / "Application Support" / "argos-translate" / "packages",
]

# Mã ngôn ngữ của UI/Android → mã trong index Argos
CODE_ALIASES = {
    "zh-cn": "zh", "zh-hans": "zh", "zh": "zh",
    "zh-tw": "zt", "zh-hant": "zt", "zh-hk": "zt",
    "pt-br": "pb", "nb-no": "nb", "no": "nb",
    "in": "id", "iw": "he", "ji": "yi", "tl": "tl", "fil": "tl",
}

PIVOT = "en"                   # index Argos: mọi cặp đều nối qua tiếng Anh
# argos-net.com trả 403 cho User-Agent mặc định của urllib → phải giả browser
_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

_lock = threading.RLock()
_runtime = None                # None chưa thử | True | str = lý do lỗi
_index_cache = None
_translators = {}              # "en_vi" -> (ct2.Translator, sp, target_prefix)
_routes = {}                   # (src, tgt) -> [pkg_dir, …] hoặc None


# --------------------------------------------------------------------- utils
def norm_code(code):
    """Chuẩn hoá mã ngôn ngữ về mã dùng trong index Argos (zh-CN → zh…)."""
    c = (code or "").strip().replace("_", "-").lower()
    if c in CODE_ALIASES:
        return CODE_ALIASES[c]
    return c.split("-")[0]


def _urlopen(url, timeout=60):
    return urllib.request.urlopen(
        urllib.request.Request(url, headers={"User-Agent": _UA}),
        timeout=timeout)


def _say(log, msg):
    if log is not None:
        log.append(msg)
    if os.environ.get("ADFREE_MT_VERBOSE") == "1":
        print(msg, file=sys.stderr)


def _human(n):
    return f"{n / (1024 * 1024):.0f} MB" if n >= 1024 * 1024 \
        else f"{n / 1024:.0f} KB"


# ------------------------------------------------------------------- runtime
def _try_import():
    """Import ctranslate2 + sentencepiece, trả về True nếu dùng được."""
    try:
        import ctranslate2                          # noqa: F401
        import sentencepiece                        # noqa: F401
        return True
    except Exception:
        return False


def _venv_site():
    """site-packages của venv runtime (nếu đã tạo)."""
    for p in sorted(VENV.glob("lib/python*/site-packages")):
        return p
    return None


def ensure_runtime(log=None, progress=None):
    """Bảo đảm ctranslate2 + sentencepiece import được trong process này.

    Thứ tự: (1) đã cài sẵn ở Python hiện tại → dùng luôn; (2) venv riêng đã
    tạo → nạp vào sys.path; (3) tạo venv + pip install (cần mạng lần đầu).

    Trả về (ok, lý_do_lỗi).
    """
    global _runtime
    with _lock:
        if _runtime is True:
            return True, None
        if isinstance(_runtime, str):
            return False, _runtime

        if _try_import():
            _runtime = True
            return True, None

        # venv đã có từ lần trước → chỉ cần nạp đường dẫn
        sp_dir = _venv_site()
        if sp_dir and sp_dir.is_dir():
            site.addsitedir(str(sp_dir))
            if _try_import():
                _say(log, "[offline-mt] dùng runtime dịch offline đã cài "
                          f"({VENV.name})")
                _runtime = True
                return True, None

        if NO_INSTALL:
            _runtime = ("thiếu ctranslate2/sentencepiece và "
                        "ADFREE_MT_NO_INSTALL=1 đang chặn tự cài")
            return False, _runtime

        # tạo venv + cài 2 gói
        if progress:
            _ping(progress, "Đang cài runtime dịch offline (~60 MB)…", 0)
        _say(log, "[offline-mt] chưa có runtime dịch offline — "
                  "đang tải ctranslate2 + sentencepiece (~60 MB, lần đầu)…")
        HOME.mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        try:
            if not (VENV / "pyvenv.cfg").exists():
                shutil.rmtree(VENV, ignore_errors=True)
                subprocess.run([sys.executable, "-m", "venv", str(VENV)],
                               check=True, capture_output=True, timeout=300)
            pip = VENV / "bin" / "pip"
            if not pip.exists():                     # Windows
                pip = VENV / "Scripts" / "pip.exe"
            r = subprocess.run([str(pip), "install", "--disable-pip-version-check",
                                "--no-input", "-q", *RUNTIME_PKGS],
                               capture_output=True, text=True, timeout=1800)
            if r.returncode != 0:
                tail = (r.stderr or r.stdout or "").strip()[-400:]
                _runtime = f"pip install {' '.join(RUNTIME_PKGS)} thất bại: {tail}"
                _say(log, f"[offline-mt] {_runtime}")
                return False, _runtime
        except subprocess.TimeoutExpired:
            _runtime = "quá thời gian khi cài runtime dịch offline"
            _say(log, f"[offline-mt] {_runtime}")
            return False, _runtime
        except Exception as e:
            _runtime = f"không tạo được venv runtime: {e}"
            _say(log, f"[offline-mt] {_runtime}")
            return False, _runtime

        sp_dir = _venv_site()
        if sp_dir:
            site.addsitedir(str(sp_dir))
        if not _try_import():
            _runtime = ("cài xong nhưng vẫn không import được "
                        "ctranslate2/sentencepiece")
            _say(log, f"[offline-mt] {_runtime}")
            return False, _runtime
        _say(log, f"[offline-mt] runtime dịch offline sẵn sàng "
                  f"({time.time() - t0:.0f}s)")
        _runtime = True
        return True, None


def ensure_extra(packages, log=None, progress=None):
    """Cài thêm gói Python vào cùng venv runtime rồi import được ngay.

    Dùng cho các bộ đọc định dạng cần thư viện ngoài (UnityPy để mở asset
    bundle của Unity chẳng hạn) — giữ chung một venv với engine dịch để
    không rải cài đặt khắp máy.

    Trả về (ok, lý_do_lỗi).
    """
    missing = []
    for pkg in packages:
        mod = pkg.split("[")[0].replace("-", "_")
        try:
            __import__(mod)
        except Exception:
            missing.append(pkg)
    if not missing:
        return True, None
    # bảo đảm có venv trước (ensure_runtime tạo venv nếu chưa có)
    ok, err = ensure_runtime(log, progress)
    if not ok:
        return False, err
    with _lock:
        # thử lại: có thể vừa được nạp qua site.addsitedir
        still = []
        for pkg in missing:
            mod = pkg.split("[")[0].replace("-", "_")
            try:
                __import__(mod)
            except Exception:
                still.append(pkg)
        if not still:
            return True, None
        if NO_INSTALL:
            return False, (f"thiếu {', '.join(still)} và "
                           f"ADFREE_MT_NO_INSTALL=1 đang chặn tự cài")
        pip = VENV / "bin" / "pip"
        if not pip.exists():
            pip = VENV / "Scripts" / "pip.exe"
        _say(log, f"[offline-mt] cài thêm {', '.join(still)}…")
        if progress:
            _ping(progress, f"Đang cài {', '.join(still)}…", 0)
        try:
            r = subprocess.run([str(pip), "install", "-q", "--no-input",
                                "--disable-pip-version-check", *still],
                               capture_output=True, text=True, timeout=1800)
        except Exception as e:
            return False, f"pip install {' '.join(still)} lỗi: {e}"
        if r.returncode != 0:
            tail = (r.stderr or r.stdout or "").strip()[-400:]
            return False, f"pip install {' '.join(still)} thất bại: {tail}"
        sp = _venv_site()
        if sp:
            site.addsitedir(str(sp))
        for pkg in still:
            mod = pkg.split("[")[0].replace("-", "_")
            try:
                __import__(mod)
            except Exception as e:
                return False, f"cài xong nhưng không import được {mod}: {e}"
        _say(log, f"[offline-mt] {', '.join(still)} sẵn sàng")
        return True, None


def _ping(progress, label, pct):
    try:
        progress(label, pct)
    except Exception:
        pass


# --------------------------------------------------------------------- index
def load_index(force=False, log=None):
    """Danh sách model có sẵn (cache file 1 ngày). Mất mạng → dùng cache cũ."""
    global _index_cache
    with _lock:
        if _index_cache is not None and not force:
            return _index_cache
        cache = HOME / "index.json"
        fresh = (cache.exists() and not force
                 and time.time() - cache.stat().st_mtime < INDEX_TTL)
        if not fresh:
            try:
                HOME.mkdir(parents=True, exist_ok=True)
                with _urlopen(INDEX_URL, timeout=30) as r:
                    data = r.read()
                json.loads(data)                     # chặn ghi rác vào cache
                cache.write_bytes(data)
            except (urllib.error.URLError, OSError, ValueError) as e:
                _say(log, f"[offline-mt] không tải được danh sách model: {e}")
        try:
            _index_cache = json.loads(cache.read_text("utf-8"))
        except (OSError, ValueError):
            _index_cache = []
        return _index_cache


def supported_langs(log=None):
    """Các ngôn ngữ dịch được (từ en, trực tiếp hoặc qua en)."""
    idx = load_index(log=log)
    return sorted({p["to_code"] for p in idx if p.get("from_code") == PIVOT}
                  | {p["from_code"] for p in idx if p.get("to_code") == PIVOT})


# -------------------------------------------------------------------- models
def _pkg_dirs():
    """Mọi thư mục có thể chứa model đã giải nén."""
    return [MODELS_DIR] + [d for d in _ARGOS_DIRS if d.is_dir()]


def _find_local(src, tgt):
    """Model src→tgt đã giải nén sẵn ở máy? Trả về thư mục package."""
    for base in _pkg_dirs():
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir(), reverse=True):   # bản mới nhất trước
            meta = d / "metadata.json"
            if not meta.is_file() or not (d / "model").is_dir():
                continue
            try:
                m = json.loads(meta.read_text("utf-8"))
            except (OSError, ValueError):
                continue
            if m.get("from_code") == src and m.get("to_code") == tgt:
                return d
    return None


def _download(url, dest, label, log=None, progress=None):
    """Tải url → dest, báo tiến độ theo % (log mỗi 20%)."""
    tmp = dest.with_suffix(dest.suffix + ".part")
    last = -1
    with _urlopen(url, timeout=60) as r:
        total = int(r.headers.get("Content-Length") or 0)
        got = 0
        with tmp.open("wb") as f:
            while True:
                chunk = r.read(262144)
                if not chunk:
                    break
                f.write(chunk)
                got += len(chunk)
                pct = int(got * 100 / total) if total else 0
                if progress and pct != last:
                    _ping(progress, f"{label} {pct}%" if total
                          else f"{label} {_human(got)}", pct)
                if total and pct // 20 != last // 20:
                    _say(log, f"[offline-mt] {label}: {pct}% "
                              f"({_human(got)}/{_human(total)})")
                last = pct
    tmp.replace(dest)
    return dest


def install_model(src, tgt, log=None, progress=None):
    """Tải + giải nén model src→tgt. Trả về thư mục package hoặc None."""
    local = _find_local(src, tgt)
    if local:
        return local
    entry = None
    for p in load_index(log=log):
        if p.get("from_code") == src and p.get("to_code") == tgt \
                and p.get("links"):
            entry = p
            break
    if not entry:
        return None
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    name = entry.get("code") or f"translate-{src}_{tgt}"
    label = f"Đang tải model dịch {src}→{tgt} (~80 MB)"
    _say(log, f"[offline-mt] tải model dịch {src}→{tgt} (lần đầu, ~80 MB)…")
    errs = []
    links = [l for l in entry["links"] if l.startswith(("http://", "https://"))]
    if not links:
        _say(log, f"[offline-mt] gói {name} không có link http để tải")
        return None
    for url in links:
        archive = MODELS_DIR / f"{name}.argosmodel"
        try:
            _download(url, archive, label, log, progress)
            with tempfile.TemporaryDirectory(dir=str(MODELS_DIR)) as tmpd:
                with zipfile.ZipFile(archive) as z:
                    z.extractall(tmpd)
                root = Path(tmpd)
                # zip của Argos bọc sẵn 1 thư mục translate-xx_yy-N_N/
                if not (root / "metadata.json").is_file():
                    subs = [d for d in root.iterdir()
                            if (d / "metadata.json").is_file()]
                    if not subs:
                        raise ValueError("gói model không hợp lệ")
                    root = subs[0]
                dest = MODELS_DIR / root.name
                shutil.rmtree(dest, ignore_errors=True)
                shutil.move(str(root), str(dest))
            archive.unlink(missing_ok=True)
            _say(log, f"[offline-mt] đã cài model {src}→{tgt}: {dest.name}")
            return dest
        except Exception as e:
            errs.append(f"{url}: {e}")
            archive.unlink(missing_ok=True)
    _say(log, f"[offline-mt] tải model {src}→{tgt} thất bại — "
              + " | ".join(errs))
    return None


def route(src, tgt, log=None, progress=None, install=True):
    """Đường dịch src→tgt: [model trực tiếp] hoặc [src→en, en→tgt].

    Trả về list thư mục package theo thứ tự áp dụng, hoặc None nếu không có.
    """
    src, tgt = norm_code(src), norm_code(tgt)
    with _lock:
        key = (src, tgt)
        if key in _routes:
            return _routes[key]
        if src == tgt:
            _routes[key] = []
            return []
        get = install_model if install else \
            (lambda a, b, log=None, progress=None: _find_local(a, b))
        direct = get(src, tgt, log=log, progress=progress)
        if direct:
            _routes[key] = [direct]
            return _routes[key]
        hops = []
        if src != PIVOT and tgt != PIVOT:
            a = get(src, PIVOT, log=log, progress=progress)
            b = get(PIVOT, tgt, log=log, progress=progress) if a else None
            if a and b:
                hops = [a, b]
                _say(log, f"[offline-mt] không có model trực tiếp {src}→{tgt}"
                          f" — dịch 2 chặng {src}→{PIVOT}→{tgt}")
        if not hops:
            # KHÔNG cache thất bại: tải lỗi lần này (mất mạng, 403…) thì lần
            # sau trong cùng process vẫn phải được thử lại
            return None
        _routes[key] = hops
        return hops


def ensure(src, tgt, log=None, progress=None):
    """Bảo đảm runtime + model cho src→tgt. Trả về (ok, lý_do_lỗi)."""
    ok, err = ensure_runtime(log, progress)
    if not ok:
        return False, err
    src, tgt = norm_code(src), norm_code(tgt)
    if src == tgt:
        return True, None
    if route(src, tgt, log, progress):
        return True, None
    langs = supported_langs(log)
    if tgt not in langs:
        return False, (f"chưa có model dịch cho ngôn ngữ '{tgt}'. "
                       f"Ngôn ngữ hỗ trợ: {', '.join(langs)}")
    return False, f"không tải được model dịch {src}→{tgt}"


# ------------------------------------------------------------------ translate
def _load(pkg_dir):
    """Nạp (Translator, SentencePieceProcessor, target_prefix) cho 1 chặng."""
    with _lock:
        hit = _translators.get(str(pkg_dir))
        if hit:
            return hit
        import ctranslate2
        import sentencepiece as spm
        meta = {}
        try:
            meta = json.loads((pkg_dir / "metadata.json").read_text("utf-8"))
        except (OSError, ValueError):
            pass
        sp = spm.SentencePieceProcessor(
            model_file=str(pkg_dir / "sentencepiece.model"))
        tr = ctranslate2.Translator(
            str(pkg_dir / "model"), device=DEVICE,
            inter_threads=INTER_THREADS,
            intra_threads=INTRA_THREADS,
            compute_type=COMPUTE_TYPE)
        hit = (tr, sp, meta.get("target_prefix", ""))
        _translators[str(pkg_dir)] = hit
        _say(None,
             f"[offline-mt] nạp model {pkg_dir.name} "
             f"(inter={INTER_THREADS} intra={INTRA_THREADS} "
             f"beam={BEAM_SIZE} compute={COMPUTE_TYPE})")
        return hit


def _detokenize(sp, tokens, target_prefix):
    """Ghép token của sentencepiece thành text (theo đúng cách Argos làm)."""
    value = sp.decode_pieces(tokens).replace("▁", " ")
    if target_prefix and value.startswith(target_prefix):
        value = value[len(target_prefix):]
    return value.lstrip()


def _hop(texts, pkg_dir):
    """Dịch 1 chặng bằng model trong pkg_dir. Trả về list text (giữ thứ tự)."""
    tr, sp, prefix = _load(pkg_dir)
    tokens = [sp.encode(t, out_type=str) for t in texts]
    target_prefix = [[prefix]] * len(tokens) if prefix else None
    batches = tr.translate_batch(
        tokens, target_prefix=target_prefix, replace_unknowns=True,
        max_batch_size=2048, batch_type="tokens", beam_size=BEAM_SIZE,
        num_hypotheses=1, length_penalty=0.2, return_scores=False)
    return [_detokenize(sp, b.hypotheses[0], prefix) for b in batches]


def translate_batch(texts, src, tgt, log=None):
    """Dịch cả danh sách text. Phần tử lỗi trả None.

    Yêu cầu ensure(src, tgt) đã thành công trước đó.
    """
    texts = list(texts)
    if not texts:
        return []
    hops = route(src, tgt, log=log, install=False)
    if hops is None:
        return [None] * len(texts)
    if not hops:                      # src == tgt
        return texts
    cur = texts
    try:
        for pkg_dir in hops:
            cur = _hop(cur, pkg_dir)
        return [t if (t and t.strip()) else None for t in cur]
    except Exception as e:
        _say(log, f"[offline-mt] lỗi khi dịch: {e}")
        return [None] * len(texts)


def translate(text, src, tgt, log=None):
    """Dịch 1 chuỗi (tiện cho CLI/test)."""
    return translate_batch([text], src, tgt, log)[0]


# ---------------------------------------------------------------- trạng thái
def _dir_size(p):
    try:
        return sum(f.stat().st_size for f in Path(p).rglob("*") if f.is_file())
    except OSError:
        return 0


def status(check_index=False):
    """Báo cáo cho API/UI: runtime đã cài chưa, có model nào, tốn bao nhiêu đĩa."""
    models = []
    seen = set()
    for base in _pkg_dirs():
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            meta = d / "metadata.json"
            if not meta.is_file() or not (d / "model").is_dir():
                continue
            try:
                m = json.loads(meta.read_text("utf-8"))
            except (OSError, ValueError):
                continue
            pair = (m.get("from_code"), m.get("to_code"))
            if pair in seen:
                continue
            seen.add(pair)
            models.append({"from": pair[0], "to": pair[1],
                           "path": str(d), "bytes": _dir_size(d)})
    sp_dir = _venv_site()
    in_process = _try_import()
    disk = sum(m["bytes"] for m in models)
    if VENV.is_dir():
        disk += _dir_size(VENV)
    return {
        "runtime_ready": in_process or bool(sp_dir and sp_dir.is_dir()),
        "runtime_in_process": in_process,
        "runtime_path": str(sp_dir or ""),
        "home": str(HOME),
        "models": models,
        "pairs": sorted(f"{m['from']}→{m['to']}" for m in models),
        "disk_bytes": disk,
        "supported": supported_langs() if check_index else None,
        "no_install": NO_INSTALL,
    }


# ------------------------------------------------------------------------ CLI
def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = (argv[0] if argv else "status").lower()
    os.environ.setdefault("ADFREE_MT_VERBOSE", "1")
    log = []

    if cmd in ("status", "st"):
        s = status(check_index=True)
        print(f"Thư mục dữ liệu : {s['home']}")
        print(f"Runtime          : "
              f"{'sẵn sàng' if s['runtime_ready'] else 'CHƯA CÀI'}"
              f"{' (in-process)' if s['runtime_in_process'] else ''}")
        print(f"Model đã có      : {', '.join(s['pairs']) or '(chưa có)'}")
        print(f"Dung lượng       : {_human(s['disk_bytes'])}")
        print(f"Ngôn ngữ hỗ trợ  : {', '.join(s['supported'] or [])}")
        return 0

    if cmd in ("langs", "lang"):
        print(" ".join(supported_langs(log)))
        return 0

    if cmd in ("install", "i"):
        if len(argv) < 2:
            print("dùng: offline_mt.py install <lang đích> [lang nguồn=en]")
            return 2
        tgt, src = argv[1], (argv[2] if len(argv) > 2 else PIVOT)
        ok, err = ensure(src, tgt, log)
        for line in log:
            print(line)
        if not ok:
            print("THẤT BẠI:", err)
            return 1
        print(f"OK — dịch {norm_code(src)}→{norm_code(tgt)} đã chạy được offline")
        return 0

    if cmd in ("tr", "translate"):
        if len(argv) < 3:
            print('dùng: offline_mt.py tr <lang đích> "text" [lang nguồn=en]')
            return 2
        tgt, text = argv[1], argv[2]
        src = argv[3] if len(argv) > 3 else PIVOT
        ok, err = ensure(src, tgt, log)
        if not ok:
            print("THẤT BẠI:", err)
            return 1
        print(translate(text, src, tgt, log))
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
