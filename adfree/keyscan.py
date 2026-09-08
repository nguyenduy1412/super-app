#!/usr/bin/env python3
"""
Keyscan — tìm & gán nhãn các API key / secret của SDK bên thứ ba nhúng trong
APK (Google Maps, thời tiết, quảng cáo, phân tích hành vi, thanh toán…), kèm
trích đoạn lời gọi API (URL) xung quanh nếu có — phục vụ thư mục ảo "env/"
trong tính năng "Phân tích tài nguyên".

Cách hoạt động: quét trực tiếp bytes của các entry không phải media (dex,
resources.arsc, AndroidManifest.xml, assets/res dạng text…) bằng các mẫu
regex định dạng key đã biết (Google, AWS, Firebase, Mapbox, Stripe…) và các
tên miền API đã biết (Maps, thời tiết, quảng cáo, phân tích…) — không cần
decompile / apktool. Đây là quét theo mẫu (signature-based), không đảm bảo
tìm ra 100% key, nhất là key được ghép chuỗi lúc runtime.

Riêng file bundle Hermes bytecode (assets/index.android.bundle của React
Native/Expo) được xử lý chính xác hơn: Hermes đóng gói mọi chuỗi trong app
liền nhau không có ký tự phân cách, nên quét byte thô dễ dính rác từ chuỗi
kế bên vào cuối key. Module này dùng luôn bộ đọc bytecode Hermes có sẵn
trong repo (src/hermes_dec) để tách đúng bảng string gốc trước khi quét.

Cách dùng CLI:
    python3 keyscan.py input.apk
"""
import re
import sys
import json
import os
import subprocess
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path

import assetinfo

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
try:
    from hermes_dec.parsers.hbc_file_parser import HBCReader, HEADER_MAGIC
except ImportError:
    HBCReader = HEADER_MAGIC = None

MAX_SCAN_SIZE = 60 * 1024 * 1024   # bỏ qua entry lớn hơn (hiếm, tránh treo)
CONTEXT_WINDOW = 300                # số byte quanh key để tìm lời gọi API / ngữ cảnh
MAX_SNIPPET = 220
DECOMPILE_TIMEOUT = 120             # giây — giới hạn thời gian decompile Hermes
CODE_CONTEXT_LINES = 12             # số dòng code quanh key khi trace được

URL_RE = re.compile(rb"https?://[A-Za-z0-9_\-./%?&=+,:@~]{6,400}")

# (regex nhận diện host trong URL, nhãn thư viện, mô tả SDK, [regex tham số chứa key trong query])
HOST_SDKS = [
    (re.compile(rb"maps\.googleapis\.com|maps\.google\.com"), "Google Maps",
     "Google Maps Platform (Maps/Directions/Places/Geocoding API)",
     [re.compile(rb"[?&]key=([A-Za-z0-9_\-]{20,60})")]),
    (re.compile(rb"api\.openweathermap\.org"), "OpenWeatherMap",
     "Weather data API (thời tiết)",
     [re.compile(rb"[?&]appid=([A-Za-z0-9]{20,40})")]),
    (re.compile(rb"api\.weatherapi\.com"), "WeatherAPI.com",
     "Weather data API (thời tiết)",
     [re.compile(rb"[?&]key=([A-Za-z0-9]{20,40})")]),
    (re.compile(rb"api\.mapbox\.com"), "Mapbox",
     "Bản đồ / định vị (Mapbox Maps SDK)",
     [re.compile(rb"[?&]access_token=([A-Za-z0-9_.\-]{20,120})")]),
    (re.compile(rb"firebaseio\.com|firebaseinstallations\.googleapis\.com|"
                rb"fcm\.googleapis\.com|firebaseremoteconfig\.googleapis\.com"),
     "Firebase", "Google Firebase (Realtime DB / Cloud Messaging / Remote Config)", []),
    (re.compile(rb"graph\.facebook\.com"), "Facebook Graph API", "Facebook SDK", []),
    (re.compile(rb"googleads\.g\.doubleclick\.net|googlesyndication\.com|admob"),
     "Google AdMob", "Quảng cáo (AdMob)", []),
    (re.compile(rb"applovin\.com"), "AppLovin", "Quảng cáo (AppLovin MAX)", []),
    (re.compile(rb"unity3d\.com|unityads"), "Unity Ads", "Quảng cáo (Unity Ads)", []),
    (re.compile(rb"api\.mixpanel\.com"), "Mixpanel", "Phân tích hành vi người dùng (analytics)",
     [re.compile(rb"[?&]token=([A-Za-z0-9]{20,40})")]),
    (re.compile(rb"api2?\.amplitude\.com"), "Amplitude", "Phân tích hành vi người dùng (analytics)", []),
    (re.compile(rb"sentry\.io"), "Sentry", "Báo lỗi / crash reporting", []),
    (re.compile(rb"api\.stripe\.com"), "Stripe", "Thanh toán (Stripe)", []),
    (re.compile(rb"api\.twilio\.com"), "Twilio", "SMS / gọi thoại (Twilio)", []),
    (re.compile(rb"onesignal\.com"), "OneSignal", "Push notification", []),
    (re.compile(rb"api\.cloudinary\.com"), "Cloudinary", "Lưu trữ / xử lý ảnh", []),
]

# (nhãn key, mô tả SDK mặc định khi không xác định được host, regex khoá tự nhận diện)
# Lưu ý: quét trên byte thô không biết ranh giới chuỗi thật (dex/arsc đóng gói
# string liền nhau không có ký tự phân cách) -> mọi regex ở đây đều CHẶN TRẦN độ
# dài (thay vì {n,} vô hạn) để giảm nguy cơ "tràn" sang chuỗi kế bên và dính rác
# vào cuối key.
FORMAT_KEYS = [
    ("Google API Key", "Maps/Places/Firebase/Cloud… (định dạng chung của Google — "
     "xem cột 'Gọi API' để rõ dịch vụ)", re.compile(rb"AIza[0-9A-Za-z_\-]{35}")),
    ("AWS Access Key ID", "Amazon Web Services", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("Firebase Cloud Messaging Server Key", "Firebase Cloud Messaging (legacy HTTP)",
     re.compile(rb"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{130,160}")),
    ("Mapbox Access Token", "Bản đồ / định vị (Mapbox)",
     re.compile(rb"pk\.[A-Za-z0-9_\-]{15,220}\.[A-Za-z0-9_\-]{15,220}")),
    ("Stripe Live Secret Key", "Thanh toán (Stripe)", re.compile(rb"sk_live_[0-9a-zA-Z]{20,120}")),
    ("Stripe Live Publishable Key", "Thanh toán (Stripe)", re.compile(rb"pk_live_[0-9a-zA-Z]{20,120}")),
    ("Slack Token", "Slack", re.compile(rb"xox[baprs]-[0-9A-Za-z\-]{10,100}")),
    ("Twilio API Key SID", "SMS / gọi thoại (Twilio)", re.compile(rb"SK[0-9a-fA-F]{32}")),
    ("Supabase Publishable Key", "Backend-as-a-service (DB/Auth) — Supabase",
     re.compile(rb"sb_publishable_[A-Za-z0-9_\-]{15,60}")),
    ("Supabase Secret Key", "Backend-as-a-service (DB/Auth) — Supabase",
     re.compile(rb"sb_secret_[A-Za-z0-9_\-]{15,60}")),
    ("JWT credential", "Signed JWT token — Supabase/Auth0/Firebase/custom auth",
     re.compile(rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("OneSignal REST API Key", "Push notification (OneSignal)",
     re.compile(rb"os_v2_app_[A-Za-z0-9]{40,160}")),
]

SENTRY_DSN_RE = re.compile(rb"https://([a-f0-9]{32})@[a-z0-9.\-]+\.ingest\.sentry\.io/\d+")

# quét dòng kiểu file .env: TEN_BIEN=gia_tri (không ngoặc kép) — Expo/RN hay nhúng
# nguyên file .env hoặc app.config dạng này vào assets lúc build
ENV_LINE_RE = re.compile(rb'(?m)^[ \t]{0,4}([A-Z][A-Z0-9_]{3,60})[ \t]*=[ \t]*([^\s"\'<>]{6,200})[ \t]*$')

# đoán nhãn SDK dựa theo TÊN biến (dùng khi tên biến còn giữ được, ví dụ trong
# app.config / .env dạng thô — không áp dụng được nếu bundle đã inline giá trị
# và xoá mất tên biến)
NAME_HINTS = [
    (re.compile(rb"SUPABASE", re.I), "Supabase", "Backend-as-a-service (DB/Auth) — Supabase"),
    (re.compile(rb"MAPBOX", re.I), "Mapbox", "Bản đồ / định vị (Mapbox)"),
    (re.compile(rb"GOOGLE[_-]?MAPS", re.I), "Google Maps", "Google Maps Platform"),
    (re.compile(rb"WEATHER", re.I), "Weather API", "Weather data API (thời tiết) — chưa rõ nhà cung cấp cụ thể"),
    (re.compile(rb"FIREBASE", re.I), "Firebase", "Google Firebase"),
    (re.compile(rb"ONESIGNAL", re.I), "OneSignal", "Push notification"),
    (re.compile(rb"SENTRY", re.I), "Sentry", "Báo lỗi / crash reporting"),
    (re.compile(rb"STRIPE", re.I), "Stripe", "Thanh toán"),
    (re.compile(rb"TWILIO", re.I), "Twilio", "SMS / gọi thoại"),
    (re.compile(rb"MIXPANEL", re.I), "Mixpanel", "Phân tích hành vi người dùng"),
    (re.compile(rb"AMPLITUDE", re.I), "Amplitude", "Phân tích hành vi người dùng"),
    (re.compile(rb"ADMOB", re.I), "Google AdMob", "Quảng cáo"),
    (re.compile(rb"ALGOLIA", re.I), "Algolia", "Tìm kiếm (search)"),
    (re.compile(rb"SENDGRID", re.I), "SendGrid", "Gửi email"),
    (re.compile(rb"CLOUDINARY", re.I), "Cloudinary", "Lưu trữ / xử lý ảnh"),
    (re.compile(rb"AUTH0", re.I), "Auth0", "Xác thực người dùng (authentication)"),
    (re.compile(rb"CLERK", re.I), "Clerk", "Xác thực người dùng (authentication)"),
    (re.compile(rb"REVENUECAT", re.I), "RevenueCat", "Quản lý mua trong app (IAP)"),
    (re.compile(rb"POSTHOG", re.I), "PostHog", "Phân tích hành vi người dùng"),
]

# TLD hợp lệ thường gặp — dùng lọc domain rác (chuỗi vô nghĩa lẫn trong .so/.dex
# tình cờ có dạng "http://tên.tên" nhưng không phải domain thật)
COMMON_TLDS = {
    "com", "net", "org", "io", "co", "dev", "app", "xyz", "info", "gov", "edu",
    "me", "ai", "so", "gg", "tv", "cc", "vn", "us", "uk", "de", "fr", "jp", "kr",
    "cn", "in", "au", "ca", "biz", "link", "click", "site", "online", "tech",
    "cloud", "store", "shop", "live", "top", "pro", "name", "mobi", "asia", "id",
    "sg", "my", "th", "ph", "es", "it", "nl", "ru", "br", "mx", "tw", "hk", "eu", "int",
}

# domain "rác" hay gặp trong namespace XML/schema — không phải endpoint API thật
NOISE_HOSTS = {
    "schemas.android.com", "www.w3.org", "xmlpull.org", "schemas.xmlsoap.org",
    "www.apache.org", "developer.android.com", "developer.mozilla.org",
    "creativecommons.org", "purl.org", "ns.adobe.com", "www.springframework.org",
    "www.example.com", "example.com", "localhost",
}
NOISE_HOST_SUFFIXES = (".w3.org", ".apache.org", ".xmlsoap.org", ".purl.org")

# Domain tài liệu / mã nguồn / tiêu chuẩn / học thuật — hay bị nhúng làm link
# tham chiếu, KHÔNG phải backend app gọi. Lọc để phần "domain" chỉ còn endpoint
# thật. (khớp chính xác hoặc theo hậu tố tên miền)
DOC_HOSTS = {
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "reactnative.dev", "reactnavigation.org", "opentelemetry.io", "slf4j.org",
    "unicode.org", "tensorflow.org", "dashif.org", "mozilla.org",
    "json-schema.org", "schema.org", "ietf.org", "rfc-editor.org",
    "ecma-international.org", "khronos.org", "kotlinlang.org", "swift.org",
    "llvm.org", "cmake.org", "gradle.org", "npmjs.com", "medium.com",
    "android.googlesource.com", "googlesource.com", "go.dev", "golang.org",
    "sf.net", "sourceforge.net", "doi.org", "dx.doi.org",
}
DOC_HOST_SUFFIXES = (
    ".wikipedia.org", ".wikisource.org", ".wikimedia.org", ".github.io",
    ".gitlab.io", ".googlesource.com", ".jetbrains.com", ".readthedocs.io",
    ".readthedocs.org", ".blogspot.com", ".medium.com", ".sf.net",
    ".sourceforge.net", ".edu", ".ac.uk", ".or.jp",
)
# subdomain đầu chỉ rõ là trang tài liệu/hỗ trợ, không phải API
DOC_HOST_PREFIXES = ("docs.", "doc.", "developer.", "developers.", "help.",
                     "support.", "blog.", "wiki.", "learn.", "kb.")
# đường dẫn cho thấy URL là tài liệu chứ không phải lời gọi API
DOC_PATH_MARKERS = (
    "/docs", "/doc/", "/wiki", "/blog", "/guide", "/reference", "/issue",
    "/issues", "/pull/", "/tree/", "/blob/", "/-/", "/schema", "/license",
    "/charts/", "/spec", "/troubleshooting", "/debugging", "/faq",
)
HOST_EXTRACT_RE = re.compile(rb"https?://([A-Za-z0-9.\-]+)")
# lấy cả path để phân biệt URL tài liệu với lời gọi API. Path dừng ở khoảng
# trắng, byte điều khiển/null, dấu nháy và ngoặc — tránh chạy lố sang chuỗi kế
# bên trong dex/arsc (đóng gói chuỗi liền nhau, phân cách bằng \x00).
URL_PARTS_RE = re.compile(rb'https?://([A-Za-z0-9.\-]+)(/[^\s\x00-\x20"\'<>\\{}|^\[\]]*)?')
# file không phải "code" thật sự — URL trong đó là tham chiếu/tài liệu/giấy phép
NON_API_SOURCE_NAMES = {"NOTICE", "LICENSE", "README", "CHANGES", "COPYING",
                        "NOTICE.md", "README.md", "LICENSE.md", "CHANGELOG.md"}
MAX_HOST_SOURCES = 4

# nhóm tài nguyên (theo assetinfo.classify) gần như chắc chắn không chứa key -> bỏ qua
SKIP_GROUPS = {"image", "svg", "video", "audio", "font", "rive", "spine"}
# đuôi file văn bản có cấu trúc -> áp thêm mẫu "tên biến key = giá trị"
CONTEXT_EXTS = {".json", ".xml", ".txt", ".properties", ".cfg", ".ini", ".yml", ".yaml"}
GENERIC_KV_RE = re.compile(
    rb'(?i)(api[_-]?key|apikey|app[_-]?id|client[_-]?secret|access[_-]?token|secret[_-]?key)'
    rb'["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-.]{12,80})["\']'
)

# UUID hằng số quen thuộc (nil, RFC 4122 namespace, all-F) — loại khỏi nghi ngờ
WELLKNOWN_UUIDS = {
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
    "6ba7b812-9dad-11d1-80b4-00c04fd430c8",
    "6ba7b814-9dad-11d1-80b4-00c04fd430c8",
}

def _clean_snippet(raw):
    text = raw.decode("utf-8", errors="replace")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_SNIPPET]


def _find_context(window, key_bytes=None):
    """Tìm URL thật sự liên quan tới key trong window: ưu tiên URL khớp host
    SDK đã biết, nếu không thì URL có chứa chính giá trị key (bằng chứng lời
    gọi API cụ thể) — bỏ qua URL chỉ tình cờ đứng gần trong buffer."""
    for m in URL_RE.finditer(window):
        url = m.group(0)
        for host_re, label, desc, _ in HOST_SDKS:
            if host_re.search(url):
                return label, desc, url
        if key_bytes and key_bytes in url:
            return None, None, url
    return None, None, None


def _scan_urls(data, source, seen_keys, findings):
    for m in URL_RE.finditer(data):
        url = m.group(0)
        for host_re, label, desc, param_res in HOST_SDKS:
            if not host_re.search(url):
                continue
            for param_re in param_res:
                pm = param_re.search(url)
                if not pm:
                    continue
                key = pm.group(1).decode("ascii", errors="ignore")
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append({
                    "key": key, "label": label, "desc": desc,
                    "source": source, "api_call": _clean_snippet(url),
                })


def _scan_format_keys(data, source, seen_keys, findings):
    for label, desc, key_re in FORMAT_KEYS:
        for m in key_re.finditer(data):
            key = m.group(0).decode("ascii", errors="ignore")
            if key in seen_keys:
                continue
            seen_keys.add(key)
            # Nhãn theo ĐỊNH DẠNG của chính key (AIza=Google, pk.eyJ=Mapbox,
            # sb_=Supabase…) là đáng tin nhất — KHÔNG để URL đứng gần trong
            # buffer đè lên nó (các key hay nằm cụm cạnh một URL bất kỳ, rất dễ
            # gán nhầm). Chỉ đính kèm URL làm bằng chứng khi URL CHỨA chính key.
            api_call = None
            start = max(0, m.start() - CONTEXT_WINDOW)
            end = min(len(data), m.end() + CONTEXT_WINDOW)
            for um in URL_RE.finditer(data[start:end]):
                if m.group(0) in um.group(0):
                    api_call = _clean_snippet(um.group(0))
                    break
            findings.append({
                "key": key,
                "label": label,
                "desc": desc,
                "source": source,
                "api_call": api_call,
            })


def _scan_generic_kv(data, source, seen_keys, findings):
    for m in GENERIC_KV_RE.finditer(data):
        key = m.group(2).decode("ascii", errors="ignore")
        if key in seen_keys or len(set(key.lower())) < 4:  # bỏ chuỗi giả kiểu "000000", "xxxxxx"
            continue
        seen_keys.add(key)
        name = m.group(1).decode("ascii", errors="ignore")
        # tên biến (name) đáng tin hơn host đứng gần trong buffer -> ưu tiên name
        name_label, name_desc = _guess_from_name(m.group(1))
        start = max(0, m.start() - CONTEXT_WINDOW)
        end = min(len(data), m.end() + CONTEXT_WINDOW)
        window = data[start:end]
        host_label, host_desc, api_call = _find_context(window, m.group(2))
        findings.append({
            "key": key,
            "label": name_label or host_label or f"Chưa rõ SDK (phát hiện qua tên biến '{name}')",
            "desc": name_desc or host_desc or "Không khớp SDK nào đã biết — kiểm tra thủ công theo file nguồn",
            "source": source,
            "api_call": _clean_snippet(api_call) if api_call else None,
        })


def _guess_from_name(name):
    for name_re, label, desc in NAME_HINTS:
        if name_re.search(name):
            return label, desc
    return None, None


def _scan_sentry_dsn(data, source, seen_keys, findings):
    for m in SENTRY_DSN_RE.finditer(data):
        key = m.group(1).decode("ascii", errors="ignore")
        if key in seen_keys:
            continue
        seen_keys.add(key)
        findings.append({
            "key": key, "label": "Sentry DSN (public key)",
            "desc": "Báo lỗi / crash reporting (Sentry)",
            "source": source, "api_call": _clean_snippet(m.group(0)),
        })


def _scan_env_lines(data, source, seen_keys, findings):
    """Bắt dạng dòng file .env thô 'TEN_BIEN=gia_tri' (không ngoặc kép) —
    khác với _scan_generic_kv (yêu cầu value có ngoặc kép kiểu JSON/XML)."""
    for m in ENV_LINE_RE.finditer(data):
        name_b, val_b = m.group(1), m.group(2)
        key = val_b.decode("ascii", errors="ignore")
        if (key in seen_keys or len(set(key.lower())) < 4
                or key.lower() in ("true", "false", "null")
                or re.fullmatch(r"[\d.]+", key)):
            continue
        seen_keys.add(key)
        name = name_b.decode("ascii", errors="ignore")
        label, desc = _guess_from_name(name_b)
        findings.append({
            "key": key,
            "label": label or f"Biến môi trường '{name}'",
            "desc": desc or "Không khớp SDK nào đã biết qua tên biến — kiểm tra thủ công",
            "source": source, "api_call": None,
        })


def _is_noise_host(host):
    if host in NOISE_HOSTS or host.endswith(NOISE_HOST_SUFFIXES) or "." not in host:
        return True
    return host.rsplit(".", 1)[-1] not in COMMON_TLDS


def _host_sdk(host):
    """Nếu host khớp 1 SDK đã biết trong HOST_SDKS, trả về (nhãn, mô tả)."""
    hb = host.encode("ascii", errors="ignore")
    for host_re, label, desc, _ in HOST_SDKS:
        if host_re.search(hb):
            return label, desc
    return None, None


def _is_doc_host(host):
    bare = host[4:] if host.startswith("www.") else host
    if bare in DOC_HOSTS or bare.endswith(DOC_HOST_SUFFIXES):
        return True
    return host.startswith(DOC_HOST_PREFIXES)


def _is_non_api_source(source):
    """File tham chiếu/tài liệu (thư viện native .so, hoặc NOTICE/README/LICENSE…)
    — URL trong đó gần như luôn là link tham chiếu, không phải API app gọi."""
    if source.endswith(".so"):
        return True
    return source.rsplit("/", 1)[-1] in NON_API_SOURCE_NAMES


def _is_doc_url(path):
    return any(marker in path for marker in DOC_PATH_MARKERS)


def _scan_hosts(data, source, host_stats):
    """Gom mọi domain/base URL xuất hiện trong file để lộ ra backend/API app
    gọi tới. Bỏ URL tài liệu (docs/wiki/github…) vì không phải endpoint thật;
    ghi nhận nguồn có phải chỉ từ thư viện native .so hay không (URL trong .so
    gần như luôn là link tham chiếu của lib C/C++, không phải API của app)."""
    is_native = _is_non_api_source(source)
    for m in URL_PARTS_RE.finditer(data):
        host = m.group(1).decode("ascii", errors="ignore").lower().split(":")[0]
        path = (m.group(2) or b"").decode("ascii", errors="ignore").lower()
        if not host or _is_noise_host(host) or _is_doc_host(host) or _is_doc_url(path):
            continue
        entry = host_stats.setdefault(
            host, {"count": 0, "example": None, "sources": set(), "code_src": False})
        entry["count"] += 1
        entry["code_src"] = entry["code_src"] or not is_native
        if entry["example"] is None:
            entry["example"] = _clean_snippet(m.group(0))
        if len(entry["sources"]) < MAX_HOST_SOURCES:
            entry["sources"].add(source)


def _scan_suspects(data, source, seen_keys, suspect_stats):
    """Gom mọi chuỗi khớp các định dạng key "trần" (UUID, 32/40/64 hex). Chưa
    quyết định báo hay bỏ ở đây — để scan() gộp toàn app rồi lọc theo ngưỡng."""
    for label, fmt_re, _ in SUSPECT_FORMATS:
        for m in fmt_re.finditer(data):
            val = m.group(0).decode("ascii", errors="ignore")
            low = val.lower()
            if val in seen_keys or low in WELLKNOWN_UUIDS:
                continue
            bucket = suspect_stats.setdefault(label, {})
            if low not in bucket:
                bucket[low] = source


def _scan_context_services(data, present):
    """Đánh dấu dịch vụ (dùng key không tiền tố) có dấu vết trong app — để nhắc
    người xem là có thể có key dạng tương ứng nằm trong danh sách nghi ngờ."""
    for svc_re, name, hint in CONTEXT_SERVICES:
        if name in present:
            continue
        if svc_re.search(data):
            present[name] = hint


# Bytecode version tối thiểu để tin dùng bảng string của Hermes: từ 72 trở đi
# Hermes lưu chuỗi trực tiếp (trước đó dùng predefined string id, không đọc
# được). Việc TÁCH BẢNG STRING chỉ phụ thuộc offset trong header — ổn định qua
# các version, độc lập với thay đổi opcode (thứ mà cảnh báo ">96 chưa hỗ trợ
# chính thức" nói tới). Đã kiểm chứng trên bytecode v98 thực tế: chuỗi tách ra
# khớp CHÍNH XÁC giá trị gốc (token Mapbox đầy đủ), trong khi quét byte thô lại
# dính thêm rác của chuỗi kế bên vào cuối key. Nên ưu tiên dùng bảng string này.
MIN_HERMES_STRING_VERSION = 72


def _hermes_parse(data):
    """Parse Hermes bytecode, trả về (joined_buffer, string_list).
    Cả hai là None nếu không phải Hermes / version quá cũ / parser lỗi."""
    if HBCReader is None or len(data) < 8:
        return None, None
    if int.from_bytes(data[:8], "little") != HEADER_MAGIC:
        return None, None
    try:
        reader = HBCReader()
        reader.read_whole_file(BytesIO(data))
    except Exception:
        return None, None
    version = getattr(reader.header, "version", None)
    if version is None or version < MIN_HERMES_STRING_VERSION or not reader.strings:
        return None, None
    cleaned = [s.strip() for s in reader.strings if s.strip()]
    joined = "\n".join(cleaned).encode("utf-8", errors="ignore")
    return joined, cleaned


def _load_packager_hashes(z):
    """Đọc assets/app.manifest (nếu có) để lấy danh sách packagerHash —
    đây là hash build artifact của từng asset, KHÔNG phải API key. Khi quét
    chuỗi 32-hex standalone trong Hermes, cần loại chúng ra để chỉ còn key thật."""
    hashes = set()
    try:
        raw = z.read("assets/app.manifest")
        manifest = json.loads(raw)
        for asset in manifest.get("assets", []):
            h = asset.get("packagerHash", "")
            if h:
                hashes.add(h)
    except (KeyError, json.JSONDecodeError, OSError, zipfile.BadZipFile):
        pass
    return hashes


def _scan_hermes_standalone_keys(strings, source, seen_keys, candidates,
                                 packager_hashes):
    """Thu thập chuỗi định dạng key trần trong Hermes dưới dạng candidate.
    Candidate KHÔNG được báo cho người dùng trừ khi decompile tìm thấy ngữ
    cảnh sử dụng trực tiếp (biến/property/tham số API)."""
    for s in strings:
        # 32-hex: loại packagerHash và all-zeros
        if re.fullmatch(r"[0-9a-f]{32}", s):
            if s in packager_hashes or s == "0" * 32 or s in seen_keys:
                continue
            seen_keys.add(s)
            candidates.append({
                "key": s, "label": "API key (chuỗi 32 hex)",
                "desc": "Key/token không có tiền tố đặc trưng — kiểm tra thêm "
                        "theo dịch vụ được phát hiện trong app",
                "source": source, "api_call": None, "origin": "standalone",
            })
            continue
        # 64-hex: secret/token dài
        if re.fullmatch(r"[0-9a-f]{64}", s):
            if s in seen_keys:
                continue
            seen_keys.add(s)
            candidates.append({
                "key": s, "label": "API secret (chuỗi 64 hex)",
                "desc": "Secret/token dài — có thể là API secret hoặc signing key",
                "source": source, "api_call": None, "origin": "standalone",
            })
            continue
        # UUID: loại hằng số nổi tiếng
        if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", s):
            if s.lower() in WELLKNOWN_UUIDS or s in seen_keys:
                continue
            seen_keys.add(s)
            candidates.append({
                "key": s, "label": "UUID (app ID / project ID)",
                "desc": "UUID có thể là app ID (OneSignal, Firebase…) hoặc "
                        "project ID — đối chiếu thêm với dịch vụ trong app",
                "source": source, "api_call": None, "origin": "standalone",
            })


SERVICE_KEY_HINTS = [
    # (regex khớp domain/service, nhãn service, biến env gợi ý,
    #  định dạng key service dùng: set gồm '32hex','64hex','uuid')
    (re.compile(r"openweathermap|weatherapi", re.I),
     "OpenWeatherMap / WeatherAPI", "EXPO_PUBLIC_WEATHER_API_KEY",
     {"32hex"}),
    (re.compile(r"onesignal", re.I),
     "OneSignal", "EXPO_PUBLIC_ONESIGNAL_APP_ID",
     {"uuid"}),
    (re.compile(r"godetour|detour", re.I),
     "Detour (deep link)", "EXPO_PUBLIC_DETOUR_API_KEY / EXPO_PUBLIC_DETOUR_APP_ID",
     {"64hex", "uuid"}),
    (re.compile(r"supabase", re.I),
     "Supabase", "EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY",
     set()),
    (re.compile(r"mapbox", re.I),
     "Mapbox", "EXPO_PUBLIC_MAPBOX_TOKEN",
     set()),
    (re.compile(r"mixpanel", re.I),
     "Mixpanel", "MIXPANEL_TOKEN",
     {"32hex"}),
    (re.compile(r"amplitude", re.I),
     "Amplitude", "AMPLITUDE_API_KEY",
     {"32hex"}),
    (re.compile(r"algolia", re.I),
     "Algolia", "ALGOLIA_API_KEY",
     {"32hex"}),
]


def _key_format_of(key):
    """Trả về định dạng của key: '32hex', '64hex', 'uuid', hoặc None."""
    if re.fullmatch(r"[0-9a-f]{32}", key):
        return "32hex"
    if re.fullmatch(r"[0-9a-f]{64}", key):
        return "64hex"
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", key):
        return "uuid"
    return None


def _infer_service_labels(host_stats, context, findings):
    """Dựa trên các domain/service đã phát hiện trong APK, gán nhãn service
    và tên biến env gợi ý cho các key định dạng chung (32-hex, 64-hex, UUID)
    chưa có nhãn rõ ràng. Mỗi key hiển thị TẤT CẢ service phù hợp để người
    dùng tự đối chiếu — vì scanner không trace được bytecode nên không biết
    chắc key nào thuộc service nào."""
    # Gom tất cả domain text thành 1 chuỗi để match
    all_hosts = " ".join(host_stats.keys()) if host_stats else ""
    all_context = " ".join(context.keys()) if context else ""
    service_text = all_hosts + " " + all_context

    # Xác định các service có trong app
    active_services = []
    for svc_re, label, env_hint, formats in SERVICE_KEY_HINTS:
        if svc_re.search(service_text):
            active_services.append((label, env_hint, formats))

    if not active_services:
        return

    # Gom key theo định dạng để biết mỗi format có bao nhiêu key
    format_counts = {}
    for f in findings:
        fmt = _key_format_of(f["key"])
        if fmt:
            format_counts[fmt] = format_counts.get(fmt, 0) + 1

    # Với mỗi key generic, liệt kê tất cả service có định dạng tương ứng
    for f in findings:
        fmt = _key_format_of(f["key"])
        if fmt is None:
            continue
        matching = [(label, hint) for label, hint, formats in active_services
                    if fmt in formats]
        n = format_counts[fmt]
        if matching:
            svc_names = ", ".join(label for label, _ in matching)
            env_names = " / ".join(hint for _, hint in matching)
            f["label"] = f"{fmt} → có thể thuộc: {svc_names}"
            f["desc"] = (f"Tìm thấy {n} key {fmt} trong app. "
                         f"Biến env gợi ý: {env_names}. "
                         f"Đối chiếu với .env của bạn để xác định key thật.")
        else:
            f["label"] = f"Không xác định ({fmt})"
            f["desc"] = ("Key định dạng chung, không khớp service nào đã phát "
                         "hiện trong app — có thể là hằng số nội bộ của thư viện")


def _decompile_hermes(data):
    """Decompile Hermes bytecode thành pseudo-JS bằng hermes_dec decompiler.
    Trả về text đã decompile, hoặc None nếu lỗi / timeout."""
    rust_decompiler = (Path(__file__).resolve().parent.parent
                       / "hermes-decomp" / "target" / "release"
                       / "hermes-decomp")
    if rust_decompiler.exists():
        try:
            with tempfile.NamedTemporaryFile(suffix=".hbc", delete=False) as fin:
                fin.write(data)
                in_path = fin.name
            fd_out, out_path = tempfile.mkstemp(suffix=".js")
            os.close(fd_out)
            try:
                subprocess.run(
                    [str(rust_decompiler), "decompile", in_path, "-o", out_path],
                    capture_output=True, timeout=DECOMPILE_TIMEOUT, check=True)
                out = Path(out_path)
                if out.exists() and out.stat().st_size > 0:
                    return out.read_text(encoding="utf-8", errors="replace")
            finally:
                for p in (in_path, out_path):
                    try:
                        os.unlink(p)
                    except OSError:
                        pass
        except (subprocess.TimeoutExpired, OSError, subprocess.CalledProcessError):
            pass
    return None


def _clean_code_lines(lines):
    """Trim whitespace dư thừa và bỏ dòng trống liên tiếp trong code context."""
    result = []
    for line in lines:
        stripped = " ".join(line.split())
        if stripped:
            result.append(stripped[:200])
    return result


def _find_key_code_context(decompiled, key_value):
    """Tìm key trong code đã decompile, trả về context (các dòng code gần đó)."""
    if not decompiled or not key_value:
        return None
    lines = decompiled.split("\n")
    n = len(lines)
    for i, line in enumerate(lines):
        if key_value in line:
            start = max(0, i - CODE_CONTEXT_LINES // 2)
            end = min(n, i + CODE_CONTEXT_LINES // 2 + 1)
            context_lines = _clean_code_lines(lines[start:end])
            if context_lines:
                return "\n".join(f"    {ln}" for ln in context_lines)
    return None


def _extract_literal_env_vars(decompiled):
    """Lấy biến public env còn giữ giá trị literal trong bundle đã decompile."""
    pattern = re.compile(
        r"\b((?:EXPO_PUBLIC_|REACT_APP_|VITE_|NEXT_PUBLIC_)[A-Z0-9_]{2,80})"
        r"\s*[:=]\s*[\"']([^\"'\n]{4,500})[\"']")
    found = {}
    for match in pattern.finditer(decompiled):
        name, value = match.group(1), match.group(2)
        if name not in found:
            found[name] = value
    return found


def _trace_key_contexts(hermes_data, findings, env_literals=None):
    """Decompile Hermes bundle và tìm ngữ cảnh code cho từng key đã phát hiện.
    Cập nhật trường code_context của finding nếu tìm thấy."""
    if not hermes_data:
        return
    decompiled = _decompile_hermes(hermes_data)
    if not decompiled:
        return
    if env_literals is not None:
        env_literals.update(_extract_literal_env_vars(decompiled))
    if not findings:
        return
    for f in findings:
        ctx = _find_key_code_context(decompiled, f["key"])
        if ctx:
            f["code_context"] = ctx
            # Auto-classify: nếu context chứa '__packager_asset' hoặc
            # 'registerAsset' thì đây là hash build artifact, KHÔNG phải key
            if "__packager_asset" in ctx or "registerAsset" in ctx:
                f["label"] = "Packager asset hash (KHÔNG phải API key)"
                f["desc"] = ("Hash định danh asset trong React Native/Expo — "
                             "xuất hiện trong registerAsset(), không phải key")
                continue
            _infer_context_label(f, ctx)
        elif f.get("origin") == "standalone":
            f["label"] = "Không có ngữ cảnh sử dụng (bỏ)"


def _infer_context_label(finding, context):
    """Gán nhãn service chính xác khi key xuất hiện trực tiếp trong ngữ cảnh."""
    if re.search(r"[?&]appid=", context, re.I) or \
            re.search(r"openweathermap\.org", context, re.I):
        finding["label"] = "OpenWeatherMap API key"
        finding["desc"] = ("Biến: EXPO_PUBLIC_WEATHER_API_KEY / OPENWEATHER_API_KEY. "
                           "Key được truyền vào tham số appid khi gọi OpenWeatherMap.")
    elif re.search(r"OneSignal\.initialize", context):
        finding["label"] = "OneSignal App ID"
        finding["desc"] = ("Biến: EXPO_PUBLIC_ONESIGNAL_APP_ID. "
                           "Key là App ID khởi tạo OneSignal SDK.")
    elif re.search(r"detour-storage", context):
        finding["label"] = "Detour SDK credentials"
        finding["desc"] = ("apiKey/appID của Detour SDK, lưu trong MMKV "
                           "'detour-storage' và thường cấu hình qua .env.")
    elif re.search(r"maps\.googleapis\.com|places/autocomplete|places/details|"
                   r"geocode/json", context, re.I):
        finding["label"] = "Google Maps Platform API key"
        finding["desc"] = ("Biến: EXPO_PUBLIC_GOOGLE_MAPS_API_KEY / "
                           "GOOGLE_MAPS_API_KEY. Key dùng cho Geocoding, Places "
                           "hoặc Maps Web Service.")


def _has_direct_key_evidence(finding):
    """Chỉ chấp nhận candidate khi có biến/property/tham số API rõ ràng."""
    context = finding.get("code_context", "")
    if not context:
        return False
    if "__packager_asset" in context or "registerAsset" in context:
        return False
    evidence = re.compile(
        r"(?i)(?:^|[^a-z])(?:api[_-]?key|apikey|app(?:[_-]?id)?|client[_-]?secret|"
        r"access[_-]?token|secret[_-]?key|token|appid|key)\s*[:=]\s*['\"]"
        r"|[?&](?:appid|key|access_token)="
        r"|OneSignal\.initialize|createClient\(")
    return bool(evidence.search(context))


def _manifest_variants(data):
    """AndroidManifest.xml là binary AXML: string có thể là UTF-8 hoặc UTF-16LE
    tùy công cụ build — thử thêm bản giải UTF-16LE để bắt được cả hai trường hợp."""
    variants = [data]
    try:
        decoded = data.decode("utf-16-le", errors="ignore")
        variants.append(decoded.encode("utf-8", errors="ignore"))
    except (UnicodeDecodeError, UnicodeEncodeError):
        pass
    return variants


def scan(apk_path):
    """Quét toàn bộ APK, trả về dict {keys, hosts, suspects, context}."""
    findings = []
    seen_keys = set()
    host_stats = {}
    hermes_candidates = []
    context = {}         # tên dịch vụ (dùng key không tiền tố) -> gợi ý format
    hermes_strings = None  # danh sách string riêng lẻ từ Hermes (nếu có)
    hermes_raw = None      # raw bytes của Hermes bundle (để decompile sau)
    with zipfile.ZipFile(apk_path) as z:
        packager_hashes = _load_packager_hashes(z)
        for info in z.infolist():
            if info.is_dir() or info.file_size == 0 or info.file_size > MAX_SCAN_SIZE:
                continue
            if assetinfo.classify(z, info) in SKIP_GROUPS:
                continue
            try:
                data = z.read(info)
            except (zipfile.BadZipFile, OSError, RuntimeError):
                continue
            source = info.filename
            is_hermes = False
            if source == "AndroidManifest.xml":
                buffers = _manifest_variants(data)
            else:
                hermes_buf, hermes_strs = _hermes_parse(data)
                if hermes_buf is not None:
                    buffers, is_hermes = [hermes_buf], True
                    if hermes_strings is None:
                        hermes_strings = hermes_strs
                    if hermes_raw is None:
                        hermes_raw = data
                else:
                    buffers = [data]
            ext = Path(source).suffix.lower()
            # chỉ dò "nghi ngờ theo định dạng" trên buffer dạng text (bảng string
            # Hermes / file text / JSON) — tránh byte ngẫu nhiên trong .dex/.so
            # tình cờ tạo chuỗi hex làm nhiễu số đếm
            textish = is_hermes or ext in CONTEXT_EXTS
            for buf in buffers:
                if not textish and buf.lstrip()[:1] in (b"{", b"["):
                    textish = True
                # ưu tiên quét theo tên biến trước (env-line, key=value có ngoặc)
                # vì nhãn suy ra từ tên biến cụ thể hơn nhãn định dạng chung
                # chung (vd "Google Maps" thay vì "Google API Key") — key đã
                # gán nhãn rồi sẽ bị các bước sau bỏ qua nhờ seen_keys
                _scan_env_lines(buf, source, seen_keys, findings)
                if ext in CONTEXT_EXTS or buf.lstrip()[:1] in (b"{", b"["):
                    _scan_generic_kv(buf, source, seen_keys, findings)
                _scan_urls(buf, source, seen_keys, findings)
                _scan_format_keys(buf, source, seen_keys, findings)
                _scan_sentry_dsn(buf, source, seen_keys, findings)
                _scan_hosts(buf, source, host_stats)
    # Quét standalone keys trong bảng string Hermes (nếu có): lọc packagerHash,
    # chỉ giữ lại làm candidate, chưa phải key xác nhận
    if hermes_strings is not None:
        hermes_src = "assets/index.android.bundle"
        _scan_hermes_standalone_keys(
            hermes_strings, hermes_src, seen_keys, hermes_candidates,
            packager_hashes)
    findings.extend(hermes_candidates)
    # Decompile Hermes bundle để trace ngữ cảnh code quanh từng key
    _trace_key_contexts(hermes_raw, findings)
    findings = [f for f in findings
                if f.get("origin") != "standalone"
                or _has_direct_key_evidence(f)]
    return {"keys": findings, "hosts": host_stats,
            "context": context}


def _format_hosts(host_stats):
    # Bỏ host chỉ xuất hiện trong thư viện native .so — gần như luôn là URL
    # tham chiếu/tài liệu nhúng trong lib C/C++ (wiki, docs, standards…), không
    # phải backend app gọi. Host có nguồn từ dex/bundle (code_src) mới giữ lại.
    hosts = {h: i for h, i in host_stats.items() if i.get("code_src")}
    dropped_native = len(host_stats) - len(hosts)
    if not hosts:
        note = ""
        if dropped_native:
            note = (f" (đã bỏ {dropped_native} domain chỉ xuất hiện trong thư "
                    "viện .so — link tài liệu, không phải API)")
        return ("\n=== Domain / base URL gọi trong APK ===\n"
                f"Không tìm thấy endpoint API đáng chú ý{note}.\n")
    known, unknown = [], []
    for host, info in hosts.items():
        label, desc = _host_sdk(host)
        (known if label else unknown).append((host, info, label, desc))
    known.sort(key=lambda x: -x[1]["count"])
    unknown.sort(key=lambda x: -x[1]["count"])

    lines = ["", "=== Domain / base URL gọi trong APK ===",
              f"Tổng: {len(hosts)} domain (đã lọc bỏ link tài liệu/mã nguồn/tiêu "
              f"chuẩn và {dropped_native} domain chỉ nằm trong thư viện .so).",
              "Domain 'chưa khớp SDK' bên dưới có thể là backend/API riêng của app, "
              "hoặc SDK khác chưa nằm trong danh sách đã biết của tool — tự đối chiếu thêm.\n"]

    if known:
        lines.append(f"[Khớp SDK đã biết] ({len(known)} domain)")
        for host, info, label, desc in known[:30]:
            lines.append(f"  - {host}  ({info['count']} lần) — {label}: {desc}")
            lines.append(f"      vd: {info['example']}")
        lines.append("")

    if unknown:
        lines.append(f"[Chưa khớp SDK đã biết — có thể là backend riêng của app] ({len(unknown)} domain)")
        for host, info, label, desc in unknown[:40]:
            srcs = ", ".join(sorted(info["sources"]))
            lines.append(f"  - {host}  ({info['count']} lần, nguồn: {srcs})")
            lines.append(f"      vd: {info['example']}")
        lines.append("")

    return "\n".join(lines)




    lines = ["", "=== Nghi ngờ là key (suy đoán theo ngữ cảnh / định dạng) ===",
              "Đây KHÔNG phải key đã xác nhận — chỉ là chuỗi có dạng giống key mà "
              "không có tiền tố đặc trưng để chắc chắn. Tự đối chiếu thêm.\n"]

    if context:
        lines.append("Dịch vụ phát hiện trong app thường dùng key KHÔNG có tiền tố riêng:")
        for name, hint in context.items():
            lines.append(f"  - {name} → {hint}")
        lines.append("")

    lines.append("Chuỗi khả nghi (đã bỏ hash/hằng số phổ biến và key đã xác nhận):")
    printed = False
    for label in order:
        bucket = suspect_stats.get(label) or {}
        if not bucket:
            continue
        thr = thresholds[label]
        n = len(bucket)
        if n > thr:
            lines.append(f"  [{label}]: {n} chuỗi — quá nhiều, gần như đều là "
                         f"hash/id ngẫu nhiên → đã bỏ qua.")
            printed = True
            continue
        lines.append(f"  [{label}] ({n} chuỗi):")
        for val, src in sorted(bucket.items()):
            lines.append(f"      - {val}   (nguồn: {src})")
        printed = True
    if not printed:
        lines.append("  (không có chuỗi nào dưới ngưỡng đáng ngờ)")
    lines.append("")
    return "\n".join(lines)


def _env_var_name(finding):
    """Trả về tên biến env tương ứng với key đã suy luận được."""
    key = finding["key"]
    label = finding.get("label", "")
    if key.startswith("sb_publishable_"):
        return "EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY"
    if key.startswith("pk.eyJ"):
        return "EXPO_PUBLIC_MAPBOX_TOKEN"
    if key.startswith("os_v2_app_"):
        return "ONESIGNAL_REST_API_KEY"
    if key.startswith("AIza"):
        if finding.get("source") not in {"assets/index.android.bundle", "assets/app.config"}:
            return "GOOGLE_API_KEY"
        return "EXPO_PUBLIC_GOOGLE_MAPS_API_KEY"
    if "OpenWeatherMap" in label:
        return "EXPO_PUBLIC_WEATHER_API_KEY"
    if "OneSignal" in label:
        return "EXPO_PUBLIC_ONESIGNAL_APP_ID"
    if "Detour" in label:
        return ("EXPO_PUBLIC_DETOUR_API_KEY" if _key_format_of(key) == "64hex"
                else "EXPO_PUBLIC_DETOUR_APP_ID")
    if "AWS Access Key" in label:
        return "AWS_ACCESS_KEY_ID"
    if "Stripe" in label:
        return "STRIPE_SECRET_KEY"
    if re.fullmatch(r"[0-9a-f]{32}", key):
        return "API_KEY"
    if re.fullmatch(r"[0-9a-f]{64}", key):
        return "API_SECRET"
    if re.fullmatch(r"[0-9a-fA-F-]{36}", key):
        return "APP_ID"
    return "API_KEY"


def format_report(result):
    findings = result["keys"]
    real_keys = [f for f in findings if "KHÔNG phải API key" not in f.get("label", "")]
    if not real_keys:
        return ""
    else:
        lines = [f"{_env_var_name(f)}={f['key']}" for f in real_keys]
        return "\n".join(lines)


def write_report(apk_path, output_dir):
    """Ghi báo cáo vào output_dir/api_keys.txt, trả về số key tìm thấy."""
    result = scan(apk_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "api_keys.txt").write_text(format_report(result), encoding="utf-8")
    return len(result["keys"])


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    print(format_report(scan(sys.argv[1])))
