#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''Dịch string resources của APK đã decode (apktool) sang một ngôn ngữ mục tiêu.

Toàn bộ text giao diện của app nằm trong res/values*/*.xml (apktool decode từ
resources.arsc). Module này:

1. Quét res/values/ (locale mặc định), thu thập <string>, <plurals> và
   <string-array> (bỏ translatable="false", tham chiếu @, URL, email…).
2. Dịch **chỉ bằng engine OFFLINE** ([offline_mt.py](offline_mt.py)): tự tải
   runtime CTranslate2 + model (~80 MB/cặp ngôn ngữ) lần đầu rồi dịch local —
   không gọi Google hay API dịch nào khác. Placeholder %1$s, tag <b>/<i>,
   escape \\n, \\'… được tách thành token [0], [1]… trước khi dịch và ghép lại
   sau — engine làm rơi token thì giữ nguyên chuỗi gốc.
3. Ghi ngược vào đúng file cũ (escape chuẩn Android: \\' \\" &amp; &lt; &gt;).

Dịch ghi đè vào res/values (locale MẶC ĐỊNH), đồng thời GỠ các entry string
khỏi res/values-* (values-en, values-vi…) để chúng không ghi đè bản dịch khi
ngôn ngữ máy trùng khớp — màu/chiều/kích thước trong các folder đó giữ
nguyên. Kết quả dịch được cache theo (ngôn ngữ, text) trong
translation_cache.json — chạy lại APK khác không phải dịch lại.

CLI (decode + dịch + build + ký, KHÔNG vá ads):
    python3 translator.py input.apk vi [out.apk]
'''

import html
import json
import os
import re
import sys
import threading
from pathlib import Path

import offline_mt

ROOT = Path(__file__).resolve().parent
CACHE_FILE = ROOT / "translation_cache.json"

LANG_NAMES = {
    "vi": "Tiếng Việt", "en": "Tiếng Anh", "ja": "Tiếng Nhật",
    "ko": "Tiếng Hàn", "zh-CN": "Tiếng Trung (giản thể)",
    "zh-TW": "Tiếng Trung (phồn thể)", "fr": "Tiếng Pháp",
    "de": "Tiếng Đức", "es": "Tiếng Tây Ban Nha",
    "pt": "Tiếng Bồ Đào Nha", "ru": "Tiếng Nga", "th": "Tiếng Thái",
    "id": "Tiếng Indonesia", "hi": "Tiếng Hindi", "ar": "Tiếng Ả Rập",
}

_MAX_LEN = 4000     # chuỗi dài hơn bỏ qua (tránh model nuốt hết context)
_OFF_BATCH = int(os.environ.get("ADFREE_MT_BATCH", "256"))  # chuỗi/lượt (ct2 tự chia batch con)

# Chỉ dùng offline. ADFREE_ENGINE=google/auto bị bỏ qua (cảnh báo 1 lần).
_ENGINE_ENV = os.environ.get("ADFREE_ENGINE", "offline").lower()
ENGINE = "offline"
if _ENGINE_ENV in ("google", "auto"):
    print(f"[translate] ADFREE_ENGINE={_ENGINE_ENV} đã bị tắt — "
          "AdFree chỉ dịch offline (local).", file=sys.stderr)

# Ngôn ngữ nguồn: "auto" = tự đoán (chữ Hán >25% → zh, ngược lại en).
OFFLINE_SOURCE = os.environ.get(
    "ADFREE_SOURCE_LANG",
    os.environ.get("ADFREE_ARGOS_SOURCE", "auto"))

# ----------------------------------------------------- danh sách giữ nguyên
# Tên riêng/thương hiệu bị model dịch méo rất lộ ("Dogspotting" →
# "Dogpoting"). Những từ trong danh sách này được token hoá như placeholder
# nên engine không đụng tới. Thêm bằng ADFREE_KEEP="Dogspotting,MyApp" hoặc
# gọi keep_words([...]) — pipeline tự thêm tên app đọc từ APK.
KEEP_WORDS = [w.strip() for w in
              os.environ.get("ADFREE_KEEP", "").split(",") if w.strip()]
_keep_re = None


def keep_words(words):
    """Thêm từ cần giữ nguyên (không dịch)."""
    global _keep_re
    for w in words:
        w = (w or "").strip()
        if w and w not in KEEP_WORDS:
            KEEP_WORDS.append(w)
    _keep_re = None


def _keep_pattern():
    global _keep_re
    if _keep_re is None and KEEP_WORDS:
        # từ dài trước để "Dogspotting Pro" thắng "Dogspotting"
        alts = "|".join(re.escape(w) for w in
                        sorted(KEEP_WORDS, key=len, reverse=True))
        _keep_re = re.compile(r"(?<![^\W_])(?:" + alts + r")(?![^\W_])")
    return _keep_re


# ------------------------------------------------------------------ parsing
# Thứ tự nhánh quan trọng: string-array phải đứng trước string, nếu không
# <string-array …> bị nhầm là <string …>. (?=[\s>]) chốt tên tag.
_BLOCK_RE = re.compile(
    r"<(string-array|plurals|string)(?=[\s>])([^>]*)>(.*?)</\1\s*>", re.S)
_ITEM_RE = re.compile(r"<item\b([^>]*)>(.*?)</item\s*>", re.S)

# Token bảo vệ khi dịch: tag markup (<b>, </i>, <xliff:g …>) | %% | printf
# (%1$s, %.2f…) | escape sequence (\n, \', \", \\, \uXXXX). Không được chứa
# nhóm bắt (capturing group) — re.split() dựa vào điều này.
_TOKEN_RE = re.compile(
    r"</?[A-Za-z][^<>]*>"
    r"|\{\{[^{}]{0,80}\}\}"                      # {{name}} — i18next/mustache
    r"|\{[A-Za-z_][\w.]{0,40}(?:,[^{}]{0,80})?\}"  # {count} · ICU {n, plural…}
    r"|%%"
    r"|%(?:\d+\$)?[-#+0,(]*\d*(?:\.\d+)?[bBhHsScCdoxXeEfgGaAn]"
    r"|\\u[0-9a-fA-F]{4}"
    r"|\\['\"\\ntr]"
    r"|[\n\r\t]+"          # newline/tab THẬT — engine dịch hay ăn mất
)

_REF_A_RE = re.compile(r"\{\s*(\d+)\s*\}")          # style {0}
_REF_B_RE = re.compile(r"⟦\s*(\d+)\s*⟧")            # style dự phòng khi text
_REF_C_RE = re.compile(r"\[\s*(\d+)\s*\]")          # style [0] — Argos giữ tốt
                                                     # gốc đã có sẵn {số}
# Tên resource kiểu cấu hình SDK/khoá API — dịch là app hỏng. Gặp thật:
# google_api_key "AIzaSy…" bị dịch thành "AlzaSy…", google_storage_bucket
# "english-grammar-test.appspot.com" thành "Name" → Firebase không init nổi.
_CFG_NAME_RE = re.compile(
    r"^(?:google|firebase|gcm|fcm|admob|applovin|unity|onesignal|sentry|"
    r"branch|adjust|appsflyer|facebook|twitter|amplitude|mixpanel|"
    r"crashlytics|mapbox|stripe|paypal|huawei|wechat|zalo)_"
    r"|(?:^|_)(?:api_key|app_id|client_id|secret|token|senderid|sender_id|"
    r"bucket|project_id|package_name|scheme|host|endpoint|applicationid)"
    r"(?:_|$)", re.I)
# Giá trị kiểu định danh: một "từ" liền không khoảng trắng mà có chữ số hoặc
# . _ - : / — mã khoá, package, tên bucket, tag ("androidx.startup"). Text
# giao diện thật gần như luôn có khoảng trắng hoặc không lẫn ký tự này.
_IDENT_RE = re.compile(r"^[^\s]*[\d._:/][^\s]*$")
_URL_RE = re.compile(r"(https?://|www\.)", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_LETTER_RE = re.compile(r"[^\W\d_]", re.U)
_XMLESC = {"&": "&amp;", "<": "&lt;", ">": "&gt;"}

# --------------------------------------------------------------------- cache
_cache = {}
_cache_lock = threading.Lock()
_cache_loaded = False


# ------------------------------------------------- engine offline (local MT)
def _notify(progress, done, total, label=None):
    """Gọi callback tiến độ. Callback cũ chỉ nhận (done, total) — thử kèm
    label trước, TypeError thì gọi lại kiểu cũ."""
    if not callable(progress):
        return
    try:
        progress(done, total, label)
    except TypeError:
        try:
            progress(done, total)
        except Exception:
            pass
    except Exception:
        pass


def _offline_ready(src, tgt, log, progress=None):
    """Bảo đảm engine offline (runtime + model src→tgt) dùng được.

    offline_mt tự tải runtime ctranslate2/sentencepiece (~60 MB) và model
    (~80 MB/cặp) lần đầu, sau đó chạy hoàn toàn không cần mạng."""
    def on_download(label, pct):
        _notify(progress, pct, 100, label)

    ok, err = offline_mt.ensure(src, tgt, log, on_download)
    if not ok:
        log.append(f"[translate] engine offline không dùng được: {err}")
    return ok


def _offline_chunk(texts, src, tgt, log):
    return offline_mt.translate_batch(texts, src, tgt, log)


_CJK_RE = re.compile(r"[\u4e00-\u9fff]")


def _detect_source(files_plan):
    """Đoán ngôn ngữ nguồn của string mặc định trong APK: >25% chuỗi chứa
    chữ Hán → 'zh' (app Trung Quốc kiểu XingTu), ngược lại 'en'.
    Google không cần (sl=auto) — chỉ Argos cần biết nguồn chính xác."""
    plains = [e[3] for plan in files_plan for e in plan[2]][:500]
    if not plains:
        return "en"
    cjk = sum(1 for t in plains if _CJK_RE.search(t))
    return "zh" if cjk > len(plains) * 0.25 else "en"


def _load_cache():
    global _cache, _cache_loaded
    with _cache_lock:
        if _cache_loaded:
            return
        try:
            _cache = json.loads(CACHE_FILE.read_text("utf-8"))
        except Exception:
            _cache = {}
        _cache_loaded = True


def _save_cache():
    with _cache_lock:
        try:
            CACHE_FILE.write_text(
                json.dumps(_cache, ensure_ascii=False), "utf-8")
        except OSError:
            pass


def _cache_get(lang, text):
    return _cache.get(lang + "\x00" + text)


def _cache_put(lang, text, translated):
    _cache[lang + "\x00" + text] = translated


# ---------------------------------------------------------- token & escape
def _tokenize(raw, engine="offline"):
    """Tách placeholder/tag/escape khỏi text, trả về (plain, tokens, ref_re).

    plain chỉ còn text thuần (đã token hoá) — an toàn để gửi đi dịch.
    tokens là list (text_gốc, có_khoảng_trắng_trước, có_khoảng_trắng_sau).

    Engine offline giữ [0] tốt hơn {0}; nếu raw đã có sẵn [số] thì dùng ⟦N⟧.
    Tham số `engine` giữ để tương thích cũ — luôn dùng style offline.
    """
    fmt, ref_re = "[{}]", _REF_C_RE
    if _REF_C_RE.search(raw):          # raw đã có sẵn [số] → đổi style
        fmt, ref_re = "⟦{}⟧", _REF_B_RE
    tokens = []

    def make_repl(text):
        def repl(m):
            tok = m.group(0)
            # \' và \" không cần token hoá — bỏ \ gửi dấu nháy trần, engine
            # dịch tự nhiên hơn ("Don't" chứ không phải "Don{0}t"); lúc ghi
            # file sẽ escape lại
            if tok in ("\\'", '\\"'):
                return tok[1]
            pre_ws = m.start() == 0 or text[m.start() - 1].isspace()
            post_ws = m.end() >= len(text) or text[m.end()].isspace()
            tokens.append((tok, pre_ws, post_ws))
            return fmt.format(len(tokens) - 1)
        return repl

    keep_re = _keep_pattern()
    plain = keep_re.sub(make_repl(raw), raw) if keep_re else raw
    plain = _TOKEN_RE.sub(make_repl(plain), plain)
    # {N} xuất hiện thật trong text gốc → bọc thành token để offline không nuốt
    plain = _REF_A_RE.sub(make_repl(plain), plain)
    return plain, tokens, ref_re


# --- lọc "ngôn ngữ tự nhiên" cho kho text ngoài XML (Hermes/JSON/JS) ---
# Trong bundle React Native, chuỗi kind=String lẫn lộn: text giao diện thật,
# tên icon (LucideMap), class tailwind (h-16.5 border-neutral-11), hash
# (50vk4p), tên hàm nội bộ (onSettledFulfill). Dịch nhầm mấy loại sau là
# app hỏng giao diện hoặc sai logic, nên chỉ nhận chuỗi trông như câu chữ.
_CAMEL_RE = re.compile(r"[a-z][A-Z]")
_CODEY_RE = re.compile(r"[_/\\|<>{}#$^~`=@*+]|::|\d[A-Za-z]|[A-Za-z]\d")
_WORD_RE = re.compile(r"^[^\W\d_]+(?:['’\-][^\W\d_]+)*[.,!?:;%)]*$", re.U)
# class CSS/tailwind: "size-9", "gap-1.5", "bg-neutral-11"
_CSSY_RE = re.compile(r"-\d|\w\.\d")
# id ngẫu nhiên kiểu "hckbmu", "uljnxc": 4 phụ âm liền nhau
_CONSONANTS_RE = re.compile(r"[bcdfghjklmnpqrstvwxz]{4}", re.I)
_REF_ANY_RE = re.compile(r"\[\d+\]|\{\d+\}|⟦\d+⟧")
# Mặc định CHỈ dịch chuỗi nhiều từ ở các kho ngoài XML. Chuỗi một từ trong
# bundle JS phần lớn là giá trị enum/CSS/tên component ("italic", "quote",
# "Body") — dịch là sai logic chứ không chỉ sai chữ. Bật ADFREE_RN_SINGLE_WORD=1
# nếu muốn dịch cả chuỗi một từ (được nhiều text UI hơn nhưng rủi ro hơn).
ALLOW_SINGLE_WORD = os.environ.get("ADFREE_RN_SINGLE_WORD", "") == "1"


def natural_text(plain, allow_single=None):
    """plain (đã token hoá) có phải câu chữ người đọc không?

    allow_single — cho dịch chuỗi một từ. Mặc định theo biến môi trường; với
    catalog i18n (mọi giá trị chắc chắn là text hiển thị) thì nên bật."""
    v = _REF_ANY_RE.sub(" ", plain).strip()
    if not (2 <= len(v) <= 200):
        return False
    if _CAMEL_RE.search(v) or _CODEY_RE.search(v):
        return False
    toks = v.split()
    if not toks:
        return False
    if len(toks) < 2 and not (ALLOW_SINGLE_WORD if allow_single is None
                              else allow_single):
        return False
    if _CSSY_RE.search(v):
        return False              # danh sách class CSS/tailwind
    hyphened = [t for t in toks if "-" in t]
    if len(hyphened) * 2 >= len(toks) and len(toks) > 1:
        return False              # phần lớn token nối gạch → class/enum
    wordy = [t for t in toks if _WORD_RE.match(t)]
    if len(wordy) < max(1, (len(toks) + 1) // 2):
        return False
    if not any(len(t) >= 3 for t in wordy):
        return False
    # Nhãn trạng thái/enum nội bộ: toàn chữ thường, nhiều từ, không dấu câu.
    # Gặp thật: whatwg-url lưu trạng thái parser là chuỗi ("path or
    # authority", "special authority slashes") rồi dispatch theo nội dung —
    # dịch mấy chuỗi đó làm new URL() vỡ, app React Native crash lúc mở.
    # Text hiển thị hầu như luôn viết hoa đầu câu hoặc có dấu câu.
    first = next((c for c in v if c.isalpha()), "")
    if first and first.islower() and len(toks) < 6 \
            and not any(c in v for c in ".,!?:;…%") \
            and not (allow_single if allow_single is not None
                     else ALLOW_SINGLE_WORD):
        return False
    if len(toks) == 1:
        t = toks[0]
        # một từ: bỏ ALLCAPS (hằng số) và từ nối gạch toàn chữ thường
        # ("no-store", "date-time" là giá trị kỹ thuật, không phải text UI)
        if t.isupper() and len(t) > 1:
            return False
        if "-" in t and t.islower():
            return False
        if _CONSONANTS_RE.search(t):
            return False          # id ngẫu nhiên, không phải từ
    return True


_LATIN_MAX = 0x2AF          # hết Latin Extended-B
_LATIN_EXTRA = ((0x1E00, 0x1EFF),)   # Latin Extended Additional (có tiếng Việt)


# Ký tự đặc trưng của từng ngôn ngữ đích — dùng để nhận ra chuỗi ĐÃ được
# dịch sẵn (app dịch dở dang, catalog trộn hai ngôn ngữ) và bỏ qua, tránh
# đưa tiếng Việt vào model en→vi lần nữa.
_TARGET_SIG = {
    "vi": "ăâđêôơưĂÂĐÊÔƠƯáàảãạắằẳẵặấầẩẫậéèẻẽẹếềểễệíìỉĩịóòỏõọốồổỗộớờởỡợ"
          "úùủũụứừửữựýỳỷỹỵ",
    "th": "\u0e00-\u0e7f", "ru": "а-яА-Я", "el": "α-ωΑ-Ω",
    "ar": "\u0600-\u06ff", "hi": "\u0900-\u097f",
    "ja": "\u3040-\u30ff", "ko": "\uac00-\ud7af",
    "zh": "\u4e00-\u9fff", "zt": "\u4e00-\u9fff",
}
_target_re_cache = {}


def already_target(text, lang):
    """Chuỗi đã ở ngôn ngữ đích rồi? (bỏ qua, đừng dịch lại)"""
    sig = _TARGET_SIG.get((lang or "").lower().split("-")[0])
    if not sig:
        return False
    rx = _target_re_cache.get(sig)
    if rx is None:
        rx = _target_re_cache[sig] = re.compile("[" + sig + "]")
    return bool(rx.search(text))


def _script_ok(text, src):
    """Text có cùng hệ chữ với ngôn ngữ nguồn không?

    Bundle React Native thường nhúng sẵn catalog i18n của thư viện cho mọi
    locale (Hy Lạp, Ba Tư, Séc…). Đưa chuỗi Hy Lạp vào model en→vi chỉ ra
    rác, nên bỏ qua chuỗi khác hệ chữ với nguồn."""
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return True
    cjk = sum(1 for c in letters if 0x3000 <= ord(c) <= 0x9FFF
              or 0xF900 <= ord(c) <= 0xFAFF)
    latin = sum(1 for c in letters
                if ord(c) <= _LATIN_MAX
                or any(a <= ord(c) <= b for a, b in _LATIN_EXTRA))
    if src in ("zh", "zt", "ja", "ko"):
        return cjk * 2 >= len(letters)
    return latin * 10 >= len(letters) * 9


def _skip(plain, name=""):
    """Chuỗi này có nên BỎ QUA (không dịch) không?"""
    v = plain.strip()
    if not v or not _LETTER_RE.search(v):
        return True           # rỗng / chỉ số & ký hiệu
    if v[0] in "@?":
        return True           # tham chiếu resource
    if _URL_RE.search(v) or _EMAIL_RE.search(v):
        return True
    if len(v) > _MAX_LEN:
        return True
    if name and _CFG_NAME_RE.search(name):
        return True           # khoá API / id cấu hình SDK
    if _IDENT_RE.match(v):
        return True           # định danh, không phải câu chữ giao diện
    return False


def _escape_text(s):
    s = s.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')
    return re.sub(r"[&<>]", lambda m: _XMLESC[m.group(0)], s)


def _join_tokens(translated, tokens, ref_re, escape=True):
    """Ghép text đã dịch + token gốc. Khoảng trắng do engine chèn quanh token
    bị bỏ nếu bản gốc không có (`<b>%d</b>` không thành `<b> %d </b>`).

    escape=True cho XML resource (Android), False cho JSON/JS/bytecode."""
    esc = _escape_text if escape else (lambda x: x)
    out, pos = [], 0
    prev_post_ws = True          # token trước có cho phép space đứng sau?
    for m in ref_re.finditer(translated):
        idx = int(m.group(1))
        if idx >= len(tokens):
            return None
        tok, pre_ws, post_ws = tokens[idx]
        seg = translated[pos:m.start()]
        if not prev_post_ws:
            seg = seg.lstrip()   # gốc: token trước dán liền text sau nó
        if not pre_ws:
            seg = seg.rstrip()   # gốc: text dán liền token này
        out.append(esc(seg))
        out.append(tok)
        prev_post_ws = post_ws
        pos = m.end()
    tail = translated[pos:]
    if not prev_post_ws:
        tail = tail.lstrip()
    out.append(esc(tail))
    return "".join(out)


def _build_value(translated, tokens, ref_re):
    """Giá trị ghi vào file XML resource. Bọc "…" nếu có khoảng trắng đầu/cuối
    (AAPT cắt mặc định)."""
    v = _join_tokens(translated, tokens, ref_re, escape=True)
    if v is None:
        return None
    return '"' + v + '"' if v != v.strip() else v


def _reject(translated, plain):
    """True = bản dịch nguy hiểm, phải giữ nguyên chuỗi gốc.

    · Bắt đầu bằng @ hoặc ? mà bản gốc không: aapt2 đọc đó là tham chiếu
      resource (`@string/…`) hoặc attr (`?attr/…`) → link lỗi, **build vỡ**
      cả APK. Gặp thật: mảng tên nước tiếng Ba Tư bị engine trả về
      "????????????????" → aapt2 tìm `attr/???…` không có.
    · Mất sạch chữ (chỉ còn ? và dấu câu) trong khi bản gốc có chữ: engine
      gặp ký tự nó không encode được, kết quả là rác.
    """
    t = translated.strip()
    if not t:
        return True
    if t[0] in "@?" and plain.strip()[:1] not in "@?":
        return True
    if _LETTER_RE.search(plain) and not _LETTER_RE.search(t):
        return True
    # Cụt câu / suy biến: model đôi khi nhả ra "Name", "Comment" hoặc bỏ hẳn
    # nửa sau của câu dài. So số từ để bắt.
    n_src = len(plain.split())
    n_dst = len(t.split())
    if n_src >= 6 and n_dst < n_src * 0.45:
        return True
    if n_src >= 5 and n_dst <= 1:
        return True
    return False


def _refs_ok(translated, expected):
    """translated phải chứa ĐỦ các token ref theo chỉ số 0..expected-1
    (chấp nhận cả hai style). Dùng để chặn cache kết quả hỏng."""
    refs = set(int(x) for x in _REF_A_RE.findall(translated))
    refs |= set(int(x) for x in _REF_B_RE.findall(translated))
    refs |= set(int(x) for x in _REF_C_RE.findall(translated))
    return refs == expected


# ------------------------------------------- dịch text tự do (mọi kho khác)
# Chuỗi dài quá thì model dịch cụt (mất hẳn câu sau), nên cắt theo câu rồi
# dịch từng câu, ghép lại bằng đúng dấu phân cách cũ.
_SENT_SPLIT_RE = re.compile(r"(?<=[.!?:;])\s+(?=[^\s])")
_LONG_TEXT = 60


def _split_sentences(plain):
    """[đoạn…] — ghép lại bằng ' ' đúng như chỗ đã cắt, hoặc None nếu không
    cần cắt. Ngưỡng thấp (60 ký tự) vì model dịch cụt sớm hơn tưởng: câu
    118 ký tự đã mất hẳn câu thứ hai."""
    if len(plain) <= _LONG_TEXT:
        return None
    parts = _SENT_SPLIT_RE.split(plain)
    if len(parts) < 2:
        return None
    return parts



def translate_texts(texts, lang, log=None, progress=None, src_lang=None,
                    label="chuỗi", strict=True, allow_single=None,
                    confirmed=None):
    """Dịch một danh sách text KHÔNG phải XML resource (Hermes bundle, JSON
    i18n, JS bundle…).

    Bảo vệ placeholder (`%1$s`, `{{name}}`, `{count}`, `<b>`), dùng cache
    chung với dịch res/values, và loại bản dịch không an toàn (rơi
    placeholder, biến thành `@`/`?`, mất hết chữ).

    confirmed — tập raw text đã được XÁC NHẬN là text UI thật qua ngữ cảnh
    (vd hermes_render.confirmed_ui_strings: chuỗi nằm ở đúng vị trí
    children/props của lệnh gọi jsx()/createElement()/Alert.alert()...).
    Chuỗi trong tập này bỏ qua bộ lọc hình dạng `natural_text` (vốn hay loại
    nhầm câu 1 từ hoặc câu chữ thường không dấu câu) vì bằng chứng ngữ cảnh
    đã chắc hơn đoán hình dạng — vẫn phải qua `_skip` (URL/khoá cấu hình…).

    Trả về {text_gốc: bản_dịch} — text nào dịch không an toàn thì KHÔNG có
    trong dict, người gọi giữ nguyên bản gốc.
    """
    if log is None:
        log = []
    confirmed = confirmed or ()
    _load_cache()
    uniq = {}                # đoạn cần dịch -> [đoạn]  (khoá = chính nó)
    meta = {}                # đoạn -> (tokens, ref_re) của CHUỖI chứa nó
    plan = []                # (raw, plain, tokens, ref_re, [đoạn…])
    for raw in dict.fromkeys(texts):
        plain, tokens, ref_re = _tokenize(raw, "offline")
        if _skip(plain):
            continue
        if strict and raw not in confirmed \
                and not natural_text(plain, allow_single):
            continue
        parts = _split_sentences(plain) or [plain]
        plan.append((raw, plain, tokens, ref_re, parts))
        for part in parts:
            uniq.setdefault(part, []).append(part)
            cur = meta.get(part)
            if cur is None or len(tokens) > len(cur[0]):
                meta[part] = (tokens, ref_re)

    src = src_lang or (OFFLINE_SOURCE if OFFLINE_SOURCE != "auto" else
                       ("zh" if sum(1 for t in list(uniq)[:500]
                                    if _CJK_RE.search(t)) > len(
                           list(uniq)[:500]) * 0.25 else "en"))
    if strict:
        for plain in [p for p in uniq
                      if not _script_ok(p, src) or already_target(p, lang)]:
            del uniq[plain]
            del meta[plain]

    todo, done_map = [], {}
    for plain in uniq:
        hit = _cache_get(lang, plain)
        if hit is None:
            todo.append(plain)
        else:
            done_map[plain] = hit
    n_cache = len(done_map)

    if todo:
        if _offline_ready(src, lang, log, progress):
            for i in range(0, len(todo), _OFF_BATCH):
                chunk = todo[i:i + _OFF_BATCH]
                for plain, dst in zip(chunk,
                                      _offline_chunk(chunk, src, lang, log)):
                    if dst is None:
                        continue
                    tokens = meta[plain][0]
                    if not _refs_ok(dst, set(range(len(tokens)))):
                        continue
                    done_map[plain] = dst
                    _cache_put(lang, plain, dst)
                _notify(progress, i + len(chunk), len(todo),
                        f"Đang dịch {label}: {i + len(chunk)}/{len(todo)}…")
                _save_cache()
        _save_cache()

    out = {}
    n_bad = 0
    for raw, plain, tokens, ref_re, parts in plan:
        pieces = []
        bad = False
        for part in parts:
            dst = done_map.get(part)
            if dst is None or _reject(dst, part):
                bad = True
                break
            pieces.append(dst)
        if bad:
            n_bad += 1
            continue
        merged = " ".join(pieces)
        # token phải còn ĐỦ sau khi ghép các câu lại
        if set(int(x) for x in ref_re.findall(merged)) != \
                set(range(len(tokens))):
            n_bad += 1
            continue
        value = _join_tokens(merged, tokens, ref_re, escape=False)
        if value is None or not value.strip():
            n_bad += 1
            continue
        out[raw] = value
    log.append(f"[translate] {label}: {len(out)}/{len(plan)} chuỗi dịch được "
               f"({n_cache} đoạn từ cache, {n_bad} bị loại vì không an toàn)")
    return out


# ------------------------------------------------------------------ áp dụng
def apply(decoded, lang, log=None, progress=None):
    """Dịch toàn bộ string resources trong thư mục decode của apktool.

    decoded  — thư mục output của `apktool d` (chứa res/)
    lang     — mã ngôn ngữ đích (vi, en, ja, zh-CN…)
    log      — list để append log (cùng list với patcher)
    progress — callback(done, total) báo tiến độ dịch

    Trả về dict báo cáo cho UI/API.
    """
    if log is None:
        log = []
    res = Path(decoded) / "res"
    if not res.is_dir():
        return {"enabled": False,
                "error": "không tìm thấy thư mục res/ sau khi decode"}
    _load_cache()

    # 1) Đọc + thu thập. Chỉ values/ (mặc định) mới được dịch; các folder
    # values-* khác chỉ ghi nhận vị trí block string để gỡ (tránh override).
    files_plan = []     # (path, text, [(start, end, tokens, plain, raw, name)])
    locale_plan = []    # (path, text, [(start, end, name)]) — block sẽ gỡ
    uniq = {}                # plain -> bản dịch (điền sau)
    need = {}                # plain -> số token tối đa
    n_candidates = n_skipped = 0

    for f in sorted(res.glob("values*/*.xml")):
        is_default = f.parent.name == "values"
        try:
            text = f.read_text("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        entries = []
        removals = []
        for m in _BLOCK_RE.finditer(text):
            kind, attrs, inner = m.group(1), m.group(2), m.group(3)
            name_m = re.search(r'name="([^"]+)"', attrs)
            name = name_m.group(1) if name_m else ""
            if kind == "string":
                if "translatable=\"false\"" in attrs:
                    continue
                if not is_default:
                    removals.append((m.start(), m.end(), name))
                    continue
                raw = m.group(3)
                plain, tokens, ref_re = _tokenize(raw, "offline")
                plain = html.unescape(plain)
                if _skip(plain, name):
                    n_skipped += 1
                    continue
                n_candidates += 1
                uniq.setdefault(plain, None)
                need[plain] = max(need.get(plain, 0), len(tokens))
                entries.append((m.start(3), m.end(3), tokens, plain, raw,
                                ref_re, name))
            else:  # plurals / string-array — dịch từng <item>
                if not is_default:
                    removals.append((m.start(), m.end(), name))
                    continue
                base = m.start(3)
                for im in _ITEM_RE.finditer(inner):
                    iattrs = im.group(1)
                    if "translatable=\"false\"" in (attrs + iattrs):
                        continue
                    raw = im.group(2)
                    plain, tokens, ref_re = _tokenize(raw, "offline")
                    plain = html.unescape(plain)
                    if _skip(plain, name):
                        n_skipped += 1
                        continue
                    n_candidates += 1
                    uniq.setdefault(plain, None)
                    need[plain] = max(need.get(plain, 0), len(tokens))
                    entries.append((base + im.start(2), base + im.end(2),
                                    tokens, plain, raw, ref_re, name))
        if entries:
            files_plan.append((f, text, entries))
        elif removals:
            locale_plan.append((f, text, removals))

    # 2) Tra cache trước, dịch phần còn lại bằng engine offline
    for plain in uniq:
        hit = _cache_get(lang, plain)
        if hit is not None:
            uniq[plain] = hit
    todo = [p for p, tr in uniq.items() if tr is None]
    n_cache = len(uniq) - len(todo)
    n_offline = 0
    src_lang = (_detect_source(files_plan)
                if OFFLINE_SOURCE == "auto" else OFFLINE_SOURCE)
    if todo:
        if src_lang != "en":
            log.append(f"[translate] phát hiện nguồn {src_lang.upper()} — "
                       f"engine offline sẽ dịch {src_lang}→{lang}")
        if _offline_ready(src_lang, lang, log, progress):
            o_fail = 0
            for i in range(0, len(todo), _OFF_BATCH):
                chunk = todo[i:i + _OFF_BATCH]
                results = _offline_chunk(chunk, src_lang, lang, log)
                ok = len([r for r in results if r is not None])
                n_offline += ok
                for src, dst in zip(chunk, results):
                    if dst is not None and _refs_ok(
                            dst, set(range(need.get(src, 0)))) \
                            and not _reject(dst, src):
                        uniq[src] = dst
                        _cache_put(lang, src, dst)
                _notify(progress, i + len(chunk), len(todo),
                        f"Đang dịch offline: {i + len(chunk)}/{len(todo)}"
                        " chuỗi…")
                _save_cache()
                if ok:
                    o_fail = 0
                else:
                    o_fail += 1
                    if o_fail >= 3:
                        log.append("[translate] engine offline lỗi liên tục "
                                   "— giữ text gốc cho phần còn lại")
                        break

    # 3) Ghép giá trị mới + ghi lại đúng vị trí cũ trong từng file
    n_translated = n_failed = n_files = 0
    success_names = set()
    for f, text, entries in files_plan:
        edits = []
        for start, end, tokens, plain, raw, ref_re, name in entries:
            translated = uniq.get(plain)
            if translated is None:
                n_failed += 1
                continue
            refs = set(int(x) for x in ref_re.findall(translated))
            if refs != set(range(len(tokens))):
                n_failed += 1          # engine làm rơi/thêm token → giữ gốc
                continue
            if _reject(translated, plain):
                n_failed += 1          # bản dịch có thể làm vỡ build → giữ gốc
                continue
            newval = _build_value(translated, tokens, ref_re)
            if newval is None or newval == raw:
                continue               # dịch xong y hệt / escape trùng gốc
            edits.append((start, end, newval))
            n_translated += 1
            success_names.add(name)
        if not edits:
            continue
        for start, end, newval in sorted(edits, reverse=True):
            text = text[:start] + newval + text[end:]
        f.write_text(text, "utf-8")
        n_files += 1
    # 3.5) Gỡ string khỏi các folder locale đã dịch được ở default — nếu để
    # lại, máy có ngôn ngữ trùng folder sẽ hiện text cũ thay vì bản dịch
    n_locale_files = 0
    for f, text, removals in locale_plan:
        drops = [(s, e) for s, e, n in removals if n in success_names]
        if not drops:
            continue
        for s, e in sorted(drops, reverse=True):
            text = text[:s] + text[e:]
        f.write_text(text, "utf-8")
        n_locale_files += 1
    _save_cache()

    log.append(f"[translate] ngôn ngữ {lang}: {n_translated} chuỗi đã dịch "
               f"({n_cache} từ cache, {n_skipped} bỏ qua, {n_failed} lỗi) "
               f"trong {n_files} file"
               + (f", dọn {n_locale_files} file locale." if n_locale_files
                  else "."))
    if n_offline:
        log.append(f"[translate] engine: offline {n_offline} chuỗi.")
    return {"enabled": True, "lang": lang,
            "lang_name": LANG_NAMES.get(lang, lang),
            "strings": n_candidates, "translated": n_translated,
            "cache_hit": n_cache, "skipped": n_skipped,
            "failed": n_failed, "files": n_files,
            "locales_cleaned": n_locale_files,
            "via_google": 0, "via_offline": n_offline}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2 or argv[0].startswith("-"):
        print(__doc__)
        return 2
    src = Path(argv[0])
    lang = argv[1].lower()
    dst = Path(argv[2]) if len(argv) > 2 else \
        src.with_name(src.stem + "-" + lang + src.suffix)
    from patcher import Patcher      # import muộn để CLI đứng độc lập
    p = Patcher(workdir=src.parent / (".adfree-" + dst.stem),
                block_ads=False, translate_lang=lang)
    report = p.patch(src, dst)
    if report.get("ok"):
        tr = report.get("translate", {})
        print(f"OK: {dst}")
        print(f"  Ngôn ngữ: {tr.get('lang_name', lang)}")
        print(f"  Đã dịch: {tr.get('translated', 0)}/{tr.get('strings', 0)}"
              f" chuỗi ({tr.get('cache_hit', 0)} cache, "
              f"{tr.get('failed', 0)} lỗi)")
        return 0
    print("THẤT BẠI:", report.get("error"))
    print(report.get("detail", ""))
    return 1


if __name__ == "__main__":
    sys.exit(main())
