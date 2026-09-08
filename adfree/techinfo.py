#!/usr/bin/env python3
"""
Techinfo — nhận diện APK được viết bằng gì và dùng những công nghệ nào.

Đọc trực tiếp file zip: tên entry, vài file cấu hình, byte của dex và của
Hermes bundle. Không giải nén ra đĩa, không cần apktool.

Mọi thứ báo cáo đều kèm nguồn bằng chứng (tên file, dấu vết trong dex, chuỗi
trong JS bundle) — phần suy ra được đánh dấu rõ là suy ra, không trộn lẫn với
file cấu hình lấy nguyên văn từ APK.

Cách dùng CLI:
    python3 techinfo.py app.apk
"""
import ast
import ast
import json
import re
import sys
import zipfile
from io import BytesIO
from pathlib import Path

DEX_SCAN_LIMIT = 200 * 1024 * 1024   # tổng byte dex tối đa đem quét
BUNDLE_SCAN_LIMIT = 120 * 1024 * 1024
CONFIG_MAX = 24 * 1024               # cắt bớt file cấu hình quá dài khi hiển thị
HERMES_MAGIC = b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"
_CACHE = {}
_CACHE_LIMIT = 4

# ---------------------------------------------------------------- nền tảng
# (tên, icon, mẫu đường dẫn trong APK, dấu vết trong dex, ghi chú)
PLATFORMS = [
    ("React Native", "⚛️",
     [r"^assets/index\.android\.bundle$", r"^lib/[^/]+/libreactnative\.so$",
      r"^lib/[^/]+/libhermes\.so$", r"^lib/[^/]+/libjsc\.so$"],
     [b"com/facebook/react/ReactActivity", b"com/facebook/react/bridge"],
     "JavaScript chạy trên máy ảo JS, giao diện dựng bằng view native"),
    ("Flutter", "🐦",
     [r"^lib/[^/]+/libflutter\.so$", r"^assets/flutter_assets/"],
     [b"io/flutter/embedding", b"io/flutter/plugin"],
     "Dart biên dịch AOT, giao diện tự vẽ bằng Skia/Impeller"),
    ("Unity", "🎮",
     [r"^lib/[^/]+/libunity\.so$", r"^assets/bin/Data/"],
     [b"com/unity3d/player"],
     "C# qua IL2CPP hoặc Mono, tài nguyên đóng trong asset bundle"),
    ("Unreal Engine", "🕹️",
     [r"^lib/[^/]+/libUnreal\.so$", r"^lib/[^/]+/libUE4\.so$"],
     [b"com/epicgames/unreal", b"com/epicgames/ue4"],
     "C++ biên dịch native"),
    ("Godot", "🤖",
     [r"^lib/[^/]+/libgodot_android\.so$", r"\.pck$"],
     [b"org/godotengine/godot"], "GDScript/C# trên engine Godot"),
    (".NET MAUI / Xamarin", "🟣",
     [r"^assemblies/", r"^lib/[^/]+/libmonodroid\.so$",
      r"^lib/[^/]+/libmonosgen", r"^lib/[^/]+/libxamarin"],
     [b"mono/android", b"crc64"], "C# chạy trên Mono"),
    ("Capacitor", "⚡",
     [r"^assets/public/index\.html$", r"^assets/capacitor\.config\.json$"],
     [b"com/getcapacitor"], "Web app đóng gói trong WebView"),
    ("Cordova / Ionic", "📱",
     [r"^assets/www/cordova\.js$", r"^res/xml/config\.xml$"],
     [b"org/apache/cordova"], "Web app đóng gói trong WebView"),
    ("Kotlin Multiplatform", "🧩", [],
     [b"kotlin/native/internal"], "Kotlin dùng chung nhiều nền tảng"),
]

# ------------------------------------------------------- thư viện & công nghệ
# tên -> (nhóm, dấu vết dex, mẫu đường dẫn, dấu vết trong JS bundle)
LIBRARIES = {
    # --- lớp nền / ngôn ngữ
    "Kotlin": ("Ngôn ngữ & nền tảng", [b"kotlin/jvm/internal"], [r"^kotlin/"], []),
    "Jetpack Compose": ("Giao diện native", [b"androidx/compose/runtime"], [], []),
    "AndroidX": ("Giao diện native", [b"androidx/appcompat"], [], []),
    "Material Components": ("Giao diện native", [b"com/google/android/material"], [], []),
    # --- engine JS
    "Hermes": ("Máy ảo JavaScript", [b"com/facebook/hermes"],
               [r"^lib/[^/]+/libhermes"], []),
    "JavaScriptCore": ("Máy ảo JavaScript", [b"org/webkit/javascriptcore"],
                       [r"^lib/[^/]+/libjsc\.so$"], []),
    # --- hệ sinh thái React Native
    "Expo": ("Khung React Native", [b"expo/modules/core"],
             [r"^assets/app\.config$", r"^assets/app\.manifest$"], [b"expo-modules-core"]),
    "expo-router": ("Khung React Native", [], [], [b"expo-router"]),
    "react-native-reanimated": ("Thư viện React Native",
                                [b"com/swmansion/reanimated"], [], [b"react-native-reanimated"]),
    "react-native-gesture-handler": ("Thư viện React Native",
                                     [b"com/swmansion/gesturehandler"], [], [b"gesture-handler"]),
    "react-native-screens": ("Thư viện React Native", [b"com/swmansion/rnscreens"], [], []),
    "react-native-safe-area-context": ("Thư viện React Native",
                                       [b"com/th3rdwave/safeareacontext"], [], []),
    "react-native-svg": ("Thư viện React Native", [b"com/horcrux/svg"], [], []),
    "react-native-mmkv": ("Thư viện React Native", [b"com/tencent/mmkv"], [], [b"react-native-mmkv"]),
    "@shopify/react-native-skia": ("Thư viện React Native",
                                   [b"com/shopify/reactnative/skia"], [], [b"RNSkia"]),
    "@shopify/flash-list": ("Thư viện React Native", [b"com/shopify/reactnative/flash_list"],
                            [], [b"FlashList"]),
    "@gorhom/bottom-sheet": ("Thư viện React Native", [], [], [b"BottomSheetModalProvider"]),
    "react-native-keyboard-controller": ("Thư viện React Native",
                                         [b"com/reactnativekeyboardcontroller"], [], []),
    "react-native-web": ("Thư viện React Native", [], [], [b"react-native-web"]),
    # --- animation
    "lottie-android": ("Animation", [b"com/airbnb/lottie"], [], []),
    "lottie-react-native": ("Animation", [b"com/airbnb/android/react/lottie"], [],
                            [b"lottie-react-native"]),
    "dotLottie (@lottiefiles)": ("Animation", [], [],
                                 [b"@lottiefiles/dotlottie-web", b"DotLottieReact"]),
    "Rive": ("Animation", [b"app/rive/runtime", b"com/rive"],
             [r"^lib/[^/]+/librive", r"\.riv$"], [b"rive-react-native"]),
    "GSAP": ("Animation", [], [], [b"useGSAP", b"gsap.registerPlugin"]),
    "Moti": ("Animation", [], [], [b"moti/author", b"MotiView"]),
    # --- dữ liệu & state
    "@tanstack/react-query": ("Dữ liệu & state", [], [], [b"QueryClientProvider"]),
    "Zustand": ("Dữ liệu & state", [], [], [b"zustand"]),
    "Redux": ("Dữ liệu & state", [], [], [b"@reduxjs/toolkit", b"react-redux"]),
    "Supabase": ("Dịch vụ", [], [], [b"@supabase/supabase-js", b"supabase"]),
    "Zod": ("Dữ liệu & state", [], [], [b"zodResolver", b"ZodError"]),
    "react-hook-form": ("Dữ liệu & state", [], [], [b"handleSubmit", b"formState"]),
    # --- mạng
    "OkHttp": ("Mạng", [b"okhttp3/OkHttpClient"], [], []),
    "Retrofit": ("Mạng", [b"retrofit2/Retrofit"], [], []),
    "Ktor": ("Mạng", [b"io/ktor/client"], [], []),
    "Axios": ("Mạng", [], [], [b"axios"]),
    # --- dịch vụ
    "Firebase": ("Dịch vụ", [b"com/google/firebase"], [], [b"@react-native-firebase"]),
    "Google Play Services": ("Dịch vụ", [b"com/google/android/gms/common"], [], []),
    "RevenueCat": ("Dịch vụ", [b"com/revenuecat/purchases"], [], [b"react-native-purchases"]),
    "Sentry": ("Dịch vụ", [b"io/sentry"], [], [b"@sentry"]),
    "Amplitude": ("Phân tích", [b"com/amplitude"], [], [b"@amplitude/analytics"]),
    "Mixpanel": ("Phân tích", [b"com/mixpanel"], [], [b"mixpanel-react-native"]),
    "OneSignal": ("Dịch vụ", [b"com/onesignal"], [], [b"react-native-onesignal"]),
    "Branch": ("Phân tích", [b"io/branch/referral"], [], []),
    # --- i18n & giao diện
    "Lingui": ("Đa ngôn ngữ", [], [], [b"@lingui/core", b"lingui"]),
    "i18next": ("Đa ngôn ngữ", [], [], [b"i18next"]),
    "Tailwind CSS": ("Giao diện JS", [], [], [b"tailwindcss", b"uniwind"]),
    "Lucide icons": ("Giao diện JS", [], [], [b"lucide-react-native", b"LucideIcon"]),
    # --- quảng cáo
    "Google AdMob": ("Quảng cáo", [b"com/google/android/gms/ads/MobileAds",
                              b"com/google/android/gms/ads/AdRequest"], [], []),
    "AppLovin": ("Quảng cáo", [b"com/applovin"], [], []),
    "Unity Ads": ("Quảng cáo", [b"com/unity3d/ads"], [], []),
    "IronSource": ("Quảng cáo", [b"com/ironsource"], [], []),
    "Facebook Audience Network": ("Quảng cáo", [b"com/facebook/ads"], [], []),
}

# file cấu hình lấy nguyên văn ra hiển thị
CONFIG_FILES = [
    ("assets/app.config", "Cấu hình Expo (app.config)", "json"),
    ("assets/app.manifest", "Manifest cập nhật Expo", "json"),
    ("assets/capacitor.config.json", "Cấu hình Capacitor", "json"),
    ("kotlin-tooling-metadata.json", "Thông tin build Kotlin", "json"),
    ("assets/flutter_assets/AssetManifest.json", "Danh mục asset Flutter", "json"),
    ("assets/www/manifest.json", "Manifest web app", "json"),
]

# gói JS suy ra từ chuỗi trong bundle: tên hiển thị -> các dấu hiệu
JS_PACKAGES = {
    "expo": [b"expo-modules-core"], "expo-router": [b"expo-router"],
    "expo-image": [b"expo-image"], "expo-font": [b"expo-font"],
    "expo-updates": [b"expo-updates"], "expo-haptics": [b"expo-haptics"],
    "expo-linear-gradient": [b"expo-linear-gradient"], "expo-blur": [b"expo-blur"],
    "expo-localization": [b"expo-localization"], "expo-symbols": [b"SymbolView"],
    "expo-glass-effect": [b"GlassView"], "expo-audio": [b"expo-audio"],
    "expo-clipboard": [b"expo-clipboard"], "expo-web-browser": [b"expo-web-browser"],
    "expo-image-picker": [b"expo-image-picker"], "expo-splash-screen": [b"expo-splash-screen"],
    "react-native-reanimated": [b"react-native-reanimated"],
    "react-native-gesture-handler": [b"gesture-handler"],
    "react-native-svg": [b"react-native-svg"], "react-native-mmkv": [b"react-native-mmkv"],
    "react-native-screens": [b"react-native-screens"],
    "react-native-purchases": [b"react-native-purchases"],
    "react-native-qrcode-svg": [b"QRCode"], "react-native-otp-entry": [b"OtpInput"],
    "react-native-web": [b"react-native-web"], "react-native-worklets": [b"react-native-worklets"],
    "@shopify/react-native-skia": [b"RNSkia"], "@shopify/flash-list": [b"FlashList"],
    "@gorhom/bottom-sheet": [b"BottomSheetModalProvider"],
    "@tanstack/react-query": [b"QueryClientProvider"],
    "@supabase/supabase-js": [b"@supabase/supabase-js"],
    "@lottiefiles/dotlottie-react": [b"DotLottieReact"],
    "@lingui/core": [b"@lingui/core", b"lingui"],
    "@lingui/react": [b"@lingui/react", b"lingui"],
    "@hookform/resolvers": [b"zodResolver"], "react-hook-form": [b"handleSubmit", b"formState"],
    "zustand": [b"zustand"], "zod": [b"ZodError"], "dayjs": [b"dayjs"],
    "react-native-keyboard-controller": [b"KeyboardController"],
    "@legendapp/state": [b"@legendapp/state"],
    "@lodev09/react-native-true-sheet": [b"TrueSheet"],
    "expo-apple-authentication": [b"expo-apple-authentication"],
    "expo-constants": [b"expo-constants"], "expo-linking": [b"expo-linking"],
    "expo-asset": [b"expo-asset"], "expo-system-ui": [b"expo-system-ui"],
    "expo-status-bar": [b"expo-status-bar"], "expo-dev-client": [b"expo-dev-client"],
    "react-native-scroll-track": [b"react-native-scroll-track"],
    "@expo-google-fonts/inter": [b"@expo-google-fonts/inter"],
    "@expo-google-fonts/poppins": [b"@expo-google-fonts/poppins"],
    "moti": [b"moti/author", b"MotiView"], "gsap": [b"useGSAP"],
    "lucide-react-native": [b"lucide-react-native", b"LucideIcon"],
    "tailwindcss": [b"tailwindcss"], "uniwind": [b"uniwind"],
    "axios": [b"axios/lib"], "lodash": [b"lodash/"],
    "@react-native-community/netinfo": [b"netinfo", b"NetInfo"],
    "@react-native-masked-view/masked-view": [b"masked-view", b"RNCMaskedView"],
    "@expo/vector-icons": [b"@expo/vector-icons"],
    "@react-native-async-storage/async-storage": [b"RNCAsyncStorage", b"async-storage"],
    "@legendapp/state": [b"@legendapp/state", b"legendapp"],
    "@legendapp/list": [b"LegendList"],
    "@swmansion/react-native-detour": [b"react-native-detour"],
    "@quidone/react-native-wheel-picker": [b"WheelPicker"],
    "react-native-toast-message": [b"toast-message"],
    "react-native-onesignal": [b"react-native-onesignal", b"OneSignal"],
    "react-native-device-info": [b"react-native-device-info", b"RNDeviceInfo"],
    "react-native-url-polyfill": [b"react-native-url-polyfill"],
    "expo-auth-session": [b"expo-auth-session"],
    "clsx": [b"clsx"], "tailwind-merge": [b"twMerge", b"tailwind-merge"],
    "libphonenumber-js": [b"libphonenumber"],
    "@rnmapbox/maps": [b"@rnmapbox/maps", b"RNMBX"],
}


# Module Expo tự dò trong dex qua "expo/modules/<tên>/".
# Một số là hạ tầng nội bộ của Expo, không phải package người dùng cài.
EXPO_INTERNAL = {
    "adapters", "apploader", "core", "devlauncher", "devmenu", "easclient",
    "interfaces", "jsonutils", "kotlin", "logbox", "manifests",
    "structuredheaders", "updatesinterface", "imageloader", "fetch",
}
# tên gói Expo có dấu gạch nối mà tên package Java lại viết liền
EXPO_COMPOUND = {
    "lineargradient": "linear-gradient", "imagepicker": "image-picker",
    "splashscreen": "splash-screen", "statusbar": "status-bar",
    "systemui": "system-ui", "webbrowser": "web-browser",
    "devclient": "dev-client", "keepawake": "keep-awake",
    "filesystem": "file-system", "applesignin": "apple-authentication",
    "backgroundfetch": "background-fetch", "securestore": "secure-store",
    "notifications": "notifications", "trackingtransparency":
    "tracking-transparency", "screenorientation": "screen-orientation",
    "navigationbar": "navigation-bar", "buildproperties": "build-properties",
    "mediallibrary": "media-library", "medialibrary": "media-library",
}


# Tiền tố module Gradle tương ứng với scope npm (@scope/tên)
GRADLE_SCOPES = {
    "lodev09", "swmansion", "quidone", "shopify", "gorhom", "legendapp",
    "rnmapbox", "th3rdwave", "candlefinance", "dr-pogodin", "sentry",
}
# module Gradle không phải gói npm — bỏ qua để khỏi bịa tên
GRADLE_SKIP = {"expo-modules-core", "expo-dev-launcher", "expo-dev-menu",
               "expo-json-utils", "expo-eas-client", "expo-manifests",
               "expo-log-box", "expo-image-loader", "expo-updates-interface"}


def _gradle_to_npm(raw):
    """Đổi tên module Gradle (BuildConfig) sang tên gói npm, hoặc None."""
    name = raw.replace("_", "-")
    if name in GRADLE_SKIP:
        return None
    if name == "expo-ui":
        return "@expo/ui"
    if name.startswith(("react-native-", "expo-")) or name == "lottie-react-native":
        return name
    match = re.match(r"^([a-z0-9]+)-(react-native-.+)$", name)
    if match and match.group(1) in GRADLE_SCOPES:
        return f"@{match.group(1)}/{match.group(2)}"
    match = re.match(r"^(rnmapbox)-(maps)$", name)
    if match:
        return "@rnmapbox/maps"
    return None


def _gradle_modules(dex_blobs):
    """Gói native suy ra từ tên module Gradle nhúng trong dex ("<tên>_release").

    RN autolinking đặt tên module Gradle trùng tên gói npm, nên đây là nguồn
    nhận diện rộng hơn nhiều so với dò từng lớp Java một.
    """
    names = set()
    for blob in dex_blobs:
        for match in re.finditer(rb"([a-z0-9][\w.-]{2,60})_(?:release|debug)\b", blob):
            npm = _gradle_to_npm(match.group(1).decode())
            if npm:
                names.add(npm)
    return names


def _expo_modules(dex_blobs):
    """Tên package expo-* suy ra từ các lớp Java trong dex."""
    names = set()
    for blob in dex_blobs:
        for match in re.finditer(rb"expo/modules/([a-z][a-z0-9]{2,24})/", blob):
            raw = match.group(1).decode()
            if raw in EXPO_INTERNAL:
                continue
            names.add("expo-" + EXPO_COMPOUND.get(raw, raw))
    return names


try:
    _SRC = Path(__file__).resolve().parent.parent / "src"
    if str(_SRC) not in sys.path:
        sys.path.insert(0, str(_SRC))
    from hermes_dec.parsers.hbc_file_parser import HBCReader
    from hermes_dec.parsers.hbc_bytecode_parser import parse_hbc_bytecode
    from hermes_dec.parsers.serialized_literal_parser import (
        TagType, unpack_slp_array,
    )
    from hermes_dec.parsers.serialized_literal_parser import (
        TagType, unpack_slp_array,
    )
    HERMES_OK = True
except ImportError:
    HERMES_OK = False

SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][\w.]+)?$")
_DEFINE_OPS = {"DefineOwnById", "DefineOwnByIdLong",
               "PutNewOwnById", "PutNewOwnByIdLong"}
_NEW_OBJ_OPS = {"NewObjectWithBuffer", "NewObjectWithBufferLong"}


def _shape_keys(reader, index):
    # bundle cũ (< 97) không có bảng shape -> getattr tránh AttributeError
    return [ast.literal_eval(k)
            for k in getattr(reader, "object_shape_keys", [])[index]]


def _shape_values(reader, offset, count):
    values = []
    for item in unpack_slp_array(reader.literal_values[offset:], count).items:
        if item.tag_type in (TagType.LongStringTag, TagType.ShortStringTag,
                             TagType.ByteStringTag):
            values.append(reader.strings[item.value])
        elif item.tag_type == TagType.NumberTag:
            values.append(int(item.value) if item.value.is_integer()
                          else item.value)
        else:
            values.append(item.value)
    return values


def _bundle_versions(bundle):
    """Phiên bản các gói, đọc thẳng từ Hermes bytecode.

    Hai nguồn, cả hai đều là dữ liệu có sẵn chứ không phải suy đoán:

    1. package.json của chính thư viện bị Metro nhúng vào bundle — object mang
       đủ cặp {name, version}, nên version thuộc gói nào là chắc chắn.
    2. Object {major, minor, patch} của module ReactNativeVersion.
    """
    if not (HERMES_OK and bundle[:8] == HERMES_MAGIC):
        return {}
    try:
        reader = HBCReader()
        reader.read_whole_file(BytesIO(bundle))
    except Exception:
        return {}

    named, rn_shapes, renderer_shapes = {}, set(), {}
    shape_keys = getattr(reader, "object_shape_keys", None)
    if not shape_keys:
        return {}
    for index in range(len(shape_keys)):
        try:
            keys = _shape_keys(reader, index)
        except (ValueError, SyntaxError):
            continue
        if "name" in keys and "version" in keys:
            named[index] = keys
        # React tự khai phiên bản qua object đăng ký với DevTools hook
        if "rendererPackageName" in keys and "version" in keys:
            renderer_shapes[index] = keys
        if {"major", "minor", "patch"} <= set(keys):
            rn_shapes.add(index)

    versions = {}
    want_rn = bool(rn_shapes)
    if not named and not want_rn and not renderer_shapes:
        return versions
    for header in reader.function_headers:
        if header.bytecodeSizeInBytes < 16:
            continue
        registers, fields = {}, {}
        try:
            for ins in parse_hbc_bytecode(header, reader):
                name = ins.inst.name
                if name in _NEW_OBJ_OPS and ins.arg2 in renderer_shapes:
                    keys = renderer_shapes[ins.arg2]
                    entry = dict(zip(keys, _shape_values(
                        reader, ins.arg3, len(keys))))
                    ver = entry.get("version")
                    if isinstance(ver, str) and SEMVER.match(ver):
                        versions.setdefault("react", ver)
                elif name in _NEW_OBJ_OPS and ins.arg2 in named:
                    keys = named[ins.arg2]
                    entry = dict(zip(keys, _shape_values(
                        reader, ins.arg3, len(keys))))
                    pkg, ver = entry.get("name"), entry.get("version")
                    if (isinstance(pkg, str) and isinstance(ver, str)
                            and SEMVER.match(ver)):
                        versions.setdefault(pkg, ver)
                elif not want_rn:
                    continue
                elif name == "LoadConstZero":
                    registers[ins.arg1] = 0
                elif name in ("LoadConstUInt8", "LoadConstInt"):
                    registers[ins.arg1] = ins.arg2
                elif name in _DEFINE_OPS:
                    key = reader.strings[ins.arg4]
                    if key in ("major", "minor", "patch"):
                        fields[key] = registers.get(ins.arg2)
            if want_rn and all(isinstance(fields.get(k), int)
                               for k in ("major", "minor", "patch")):
                versions.setdefault(
                    "react-native",
                    f"{fields['major']}.{fields['minor']}.{fields['patch']}")
                want_rn = False
        except Exception:
            continue
    return versions


def _read(z, name, limit=None):
    try:
        with z.open(name) as f:
            return f.read(limit) if limit else f.read()
    except (KeyError, OSError, zipfile.BadZipFile):
        return b""


def _dex_bytes(z, names):
    out, total = [], 0
    for name in names:
        if total >= DEX_SCAN_LIMIT:
            break
        data = _read(z, name)
        total += len(data)
        out.append(data)
    return out


def _bundle_bytes(z, names):
    for name in names:
        data = _read(z, name)
        if data[:8] == HERMES_MAGIC or b"__BUNDLE_START_TIME__" in data[:4096]:
            return data
    return b""


def _found(marker_sets, blobs):
    return any(any(m in blob for blob in blobs) for m in marker_sets)


def _detect_platform(entries, dex_blobs, entry_text):
    hits = []
    for name, icon, patterns, dex_markers, note in PLATFORMS:
        why = [p for p in patterns if re.search(p, entry_text, re.M)]
        if dex_markers and _found(dex_markers, dex_blobs):
            why.append("dấu vết trong dex")
        if why:
            hits.append({"name": name, "icon": icon, "note": note, "evidence": why[:3]})
    return hits


def _js_engine(bundle, entries):
    if not bundle:
        return None
    if bundle[:8] == HERMES_MAGIC:
        # header Hermes: magic 8 byte rồi tới uint32 phiên bản bytecode
        version = int.from_bytes(bundle[8:12], "little") if len(bundle) >= 12 else 0
        return f"Hermes bytecode (HBC v{version})" if version else "Hermes bytecode"
    return "JavaScript thuần (không dùng Hermes)"


def _configs(z, entries):
    out = []
    for path, label, kind in CONFIG_FILES:
        if path not in entries:
            continue
        raw = _read(z, path, CONFIG_MAX + 1)
        if not raw:
            continue
        truncated = len(raw) > CONFIG_MAX
        text = raw[:CONFIG_MAX].decode("utf-8", errors="replace")
        if kind == "json" and not truncated:
            try:
                text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
            except ValueError:
                pass
        out.append({"path": path, "label": label, "content": text,
                    "truncated": truncated})
    return out


def _libraries(dex_blobs, bundle, entry_text):
    groups = {}
    for name, (group, dex_markers, patterns, js_markers) in LIBRARIES.items():
        sources = []
        if dex_markers and _found(dex_markers, dex_blobs):
            sources.append("dex")
        if patterns and any(re.search(p, entry_text, re.M) for p in patterns):
            sources.append("file trong APK")
        if js_markers and bundle and any(m in bundle for m in js_markers):
            sources.append("JS bundle")
        if sources:
            groups.setdefault(group, []).append(
                {"name": name, "sources": sources})
    return [{"group": g, "items": sorted(v, key=lambda x: x["name"])}
            for g, v in sorted(groups.items())]


NPM_NAME = re.compile(r"^(?:@[\w.-]+/)?[a-z][\w.-]*$")
# gói chỉ dùng lúc build, không thuộc dependencies lúc chạy
DEV_ONLY = {"typescript", "eslint", "prettier", "jest", "metro", "babel",
            "@babel/core", "metro-config", "metro-runtime", "ts-node"}


def _js_dependencies(bundle, dex_blobs, stack, versions):
    """Danh sách gói SUY RA từ dấu vết trong APK — không phải package.json thật.

    Gộp nhiều nguồn theo thứ tự tin cậy giảm dần. Các nguồn đặt tên khác nhau
    cho cùng một gói (expo.modules.documentpicker vs module Gradle
    expo-document-picker), nên gộp trùng theo tên đã bỏ dấu gạch nối và giữ
    tên của nguồn đáng tin hơn.
    """
    found, seen = [], {}

    def add(name, marker):
        key = name.replace("-", "").replace("_", "").lower()
        if key in seen:
            return
        seen[key] = name
        found.append({"name": name, "marker": marker})

    add("react-native", "nền tảng của app")
    add("react", "nền tảng của app")
    # 1. package.json của thư viện nhúng trong bundle — tên chuẩn xác nhất
    for name in sorted(versions):
        add(name, "package.json nhúng trong bundle")
    # 2. tên module Gradle — RN autolinking đặt trùng tên gói npm
    for name in sorted(_gradle_modules(dex_blobs)):
        add(name, "module Gradle trong dex")
    # 3. bảng thư viện đã nhận ở phần stack (bỏ nhóm thuần native)
    native_only = {"Giao diện native", "Ngôn ngữ & nền tảng",
                   "Máy ảo JavaScript", "Mạng"}
    for group in stack:
        if group["group"] in native_only:
            continue
        for item in group["items"]:
            if NPM_NAME.match(item["name"]) and "android" not in item["name"]:
                add(item["name"], ", ".join(item["sources"]))
    # 4. dấu hiệu trong JS bundle
    if bundle:
        for name, markers in JS_PACKAGES.items():
            hit = next((m for m in markers if m in bundle), None)
            if hit:
                add(name, hit.decode("utf-8", errors="replace"))
    # 5. lớp expo.modules — tên viết liền nên kém chính xác hơn module Gradle
    for name in sorted(_expo_modules(dex_blobs)):
        add(name, "lớp expo.modules trong dex")
    # 6. đường dẫn node_modules còn sót lại (bỏ gói chỉ dùng lúc build)
    if bundle:
        for match in re.finditer(rb"node_modules/((?:@[\w.-]+/)?[\w.-]+)", bundle):
            name = match.group(1).decode("utf-8", errors="replace")
            if name.startswith(("*", "@types/")) or name in DEV_ONLY:
                continue
            add(name, "đường dẫn node_modules")
    return sorted(found, key=lambda x: x["name"].lstrip("@"))


# Thư viện native đã biết — không tính là engine riêng của app
KNOWN_LIBS = re.compile(
    r"^lib(c\+\+_shared|c\+\+abi|unity|il2cpp|main|flutter|app|monodroid|"
    r"monosgen|xamarin|godot_android|UE4|Unreal|hermes|jsc|jsi|reactnative|"
    r"react.*|fbjni|folly|glog|yoga|jsinspector|hermes-executor.*|"
    r"turbomodulejsijni|rrc_.*|imagepipeline|native-imagetranscoder|"
    r"png|jpeg|webp|avif|sqlite.*|crypto|ssl|avcodec|avformat|avutil|swscale|"
    r"skia|skottie|rive.*|lottie.*|mmkv|realm.*|sentry.*|tensorflowlite.*|"
    r"opencv.*|marisa|conscrypt.*|datastore_shared_counter|"
    r"expo.*|reanimated|worklets|gesturehandler|rnscreens|.*jni.*)\.so$")
# Middleware nhận ra bằng chuỗi trong thư viện native
NATIVE_MIDDLEWARE = {
    "Spine (animation 2D)": (b"spSkeleton", b"spine/"),
    "Box2D": (b"b2Body", b"b2World"),
    "Bullet Physics": (b"btCollisionObject",),
    "FMOD": (b"FMOD_", b"fmod_"),
    "Wwise": (b"AkSoundEngine", b"AK::"),
    "Cocos2d-x": (b"cocos2d::",),
    "SDL": (b"SDL_CreateWindow",),
    "bgfx": (b"bgfx::",),
    "Lua": (b"lua_pcall", b"luaL_newstate"),
    "Duktape (JavaScript)": (b"duk_push_", b"duk_create_heap"),
    "V8 (JavaScript)": (b"v8::Isolate",),
    "OpenGL ES": (b"glDrawElements", b"glCreateShader"),
    "Vulkan": (b"vkCreateDevice", b"vkQueueSubmit"),
}
NATIVE_MIN_SIZE = 2 * 1024 * 1024      # .so nhỏ hơn thường chỉ là helper
NATIVE_SCAN_LIMIT = 96 * 1024 * 1024   # giới hạn byte đem quét chuỗi


def _own_native_libs(archive, entries):
    """Các .so lớn không thuộc engine/thư viện đã biết — nhiều khả năng là
    engine do chính app viết."""
    found = []
    for name in entries:
        if not name.endswith(".so"):
            continue
        base = name.rsplit("/", 1)[-1]
        if KNOWN_LIBS.match(base):
            continue
        try:
            size = archive.getinfo(name).file_size
        except KeyError:
            continue
        if size >= NATIVE_MIN_SIZE:
            found.append((size, name, base))
    return sorted(found, reverse=True)


def _native_middleware(archive, name):
    """Quét chuỗi trong một .so để biết nó dùng middleware gì."""
    try:
        with archive.open(name) as handle:
            blob = handle.read(NATIVE_SCAN_LIMIT)
    except (OSError, KeyError):
        return []
    return [label for label, markers in NATIVE_MIDDLEWARE.items()
            if any(m in blob for m in markers)]


def _android_layer(dex_blobs):
    """Lớp Android gốc: Kotlin/Java + bộ dựng giao diện native."""
    if not _found([b"kotlin/jvm/internal"], dex_blobs):
        if not _found([b"androidx/appcompat"], dex_blobs):
            return None
        language = "Java"
    else:
        language = "Kotlin"
    toolkit = ("Jetpack Compose"
               if _found([b"androidx/compose/runtime"], dex_blobs)
               else "View/XML")
    return f"{language} + {toolkit}"


def _payload_sizes(archive, entries):
    """Dung lượng mã Android so với dữ liệu của engine — để biết phần nào lớn."""
    dex = engine = 0
    for name in entries:
        try:
            size = archive.getinfo(name).file_size
        except KeyError:
            continue
        if name.endswith(".dex"):
            dex += size
        elif ("bin/Data" in name or name.startswith("assets/aa/")
              or "flutter_assets" in name or name.endswith(".unity3d")
              or name.endswith(".bundle")):
            engine += size
    return dex, engine


def _expo_meta(z, entries):
    """Vài trường trong app.config của Expo — file có thật trong APK."""
    if "assets/app.config" not in entries:
        return {}
    try:
        cfg = json.loads(_read(z, "assets/app.config", CONFIG_MAX))
    except (ValueError, TypeError):
        return {}
    return {k: cfg[k] for k in ("name", "slug", "version", "sdkVersion")
            if k in cfg}


def package_json(report):
    """Dựng nội dung package.json từ báo cáo — chỉ ghi version thật sự đọc được."""
    deps = (report.get("dependencies") or {}).get("items", [])
    meta = report.get("expo") or {}
    known = report.get("versions") or {}
    out = {
        "name": (meta.get("slug") or "app-tu-apk"),
        "version": meta.get("version") or "0.0.0",
        "private": True,
        "_generatedBy": "adfree techinfo — dựng lại từ APK, KHÔNG phải "
                        "package.json gốc; version '*' là không đọc được",
        "_versionSources": report.get("version_sources") or {},
        "dependencies": {},
    }
    for dep in deps:
        name = dep["name"]
        version = known.get(name)
        if not version and name.startswith("expo") and meta.get("sdkVersion"):
            version = "~" + meta["sdkVersion"].rsplit(".", 1)[0] + ".0"
        out["dependencies"][name] = version or "*"
    out["dependencies"] = dict(sorted(out["dependencies"].items()))
    return out


def detect(apk_path):
    """Báo cáo công nghệ của một APK."""
    empty = {"platforms": [], "engine": None, "stack": [], "configs": [],
             "dependencies": None, "expo": {}, "versions": {},
             "version_sources": {}, "native_note": ""}
    try:
        with zipfile.ZipFile(apk_path) as z:
            entries = [i.filename for i in z.infolist() if not i.is_dir()]
            entry_text = "\n".join(entries)
            dex_blobs = _dex_bytes(z, [n for n in entries if n.endswith(".dex")])
            bundle = _bundle_bytes(
                z, [n for n in entries
                    if n.endswith(".bundle") or n.endswith(".jsbundle")])
            if len(bundle) > BUNDLE_SCAN_LIMIT:
                bundle = bundle[:BUNDLE_SCAN_LIMIT]
            platforms = _detect_platform(entries, dex_blobs, entry_text)
            native_note = ""
            report_extra = []
            if not platforms:
                own = _own_native_libs(z, entries)
                if own:
                    size, path, base = own[0]
                    middleware = _native_middleware(z, path)
                    platforms.append({
                        "name": "C++ native (engine tự viết)", "icon": "🛠️",
                        "note": "Toàn bộ game/app nằm trong thư viện native "
                                f"riêng ({base}, {size // 1024 // 1024} MB) — "
                                "không dùng engine có sẵn nào",
                        "evidence": [path],
                    })
                    for item in middleware:
                        report_extra.append(item)
                elif any(n.endswith(".dex") for n in entries) and not any(
                        n.endswith(".so") for n in entries):
                    native_note = ("APK này không chứa thư viện native nào — "
                                   "nếu là base split thì phần native nằm ở "
                                   "split khác (split_config.<abi>.apk)")
            report = {
                "platforms": platforms,
                "engine": _js_engine(bundle, entries),
                "stack": _libraries(dex_blobs, bundle, entry_text),
                "native_note": native_note,
                "configs": _configs(z, entries),
                "dependencies": None,
            }
            if report_extra:
                report["stack"].append({
                    "group": "Middleware native",
                    "items": [{"name": item, "sources": ["chuỗi trong .so"]}
                              for item in sorted(report_extra)],
                })
            layer = _android_layer(dex_blobs)
            if layer:
                dex_size, engine_size = _payload_sizes(z, entries)
                detail = ""
                if platforms and engine_size:
                    detail = (f" — mã Android {dex_size // 1024 // 1024} MB, "
                              f"dữ liệu engine {engine_size // 1024 // 1024} MB")
                platforms.append({
                    "name": layer, "icon": "🤖",
                    "note": "Lớp vỏ Android gốc" + (
                        detail if detail else
                        " — toàn bộ giao diện dựng bằng thành phần native"),
                    "evidence": ["dex"],
                })
            report["expo"] = _expo_meta(z, set(entries))
            versions = _bundle_versions(bundle)
            # đọc trực tiếp từ bytecode -> chính xác; suy từ SDK Expo -> xấp xỉ
            sources = {name: "đọc từ bytecode" for name in versions}
            if report["expo"].get("sdkVersion"):
                sdk = report["expo"]["sdkVersion"]
                if versions.setdefault("expo", "^" + sdk) == "^" + sdk:
                    sources["expo"] = "suy từ sdkVersion trong app.config"
            report["versions"] = versions
            report["version_sources"] = sources
            if any(p["name"] == "React Native" for p in platforms):
                deps = _js_dependencies(bundle, dex_blobs, report["stack"], versions)
                report["dependencies"] = {
                    "items": deps,
                    "note": "Suy ra từ dấu vết trong JS bundle — APK không chứa "
                            "package.json, nên đây là danh sách nhận diện được, "
                            "không phải bản gốc.",
                }
            if report["dependencies"]:
                report["package_json"] = package_json(report)
            return report
    except (OSError, zipfile.BadZipFile):
        return empty


def cached(apk_path):
    path = Path(apk_path)
    try:
        stat = path.stat()
    except OSError:
        return detect(apk_path)
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    if key not in _CACHE:
        if len(_CACHE) >= _CACHE_LIMIT:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = detect(apk_path)
    return _CACHE[key]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    print(json.dumps(detect(sys.argv[1]), indent=2, ensure_ascii=False))
