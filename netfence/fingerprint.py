"""Nhận diện tên & loại/OS thiết bị trên LAN — không cần root.

Kết hợp nhiều tín hiệu:
  - mDNS/Bonjour reverse PTR  -> tên .local thân thiện (Apple, Android có mDNS, IoT, máy in)
  - NetBIOS node status (UDP 137) -> tên máy Windows/Samba
  - reverse DNS (unicast)     -> tên fallback
  - OUI vendor (từ MAC)       -> hãng
  - TTL (ping 1 gói)          -> phỏng đoán họ OS (64 unix/mac/mobile, 128 Windows, 255 router)
"""
from __future__ import annotations

import re
import socket
import struct
import subprocess
import time

import oui

MDNS_ADDR = ("224.0.0.251", 5353)


# --------------------------------------------------------------------------
# mDNS reverse PTR
# --------------------------------------------------------------------------

def _dns_name(data: bytes, off: int) -> tuple[str, int]:
    """Đọc 1 tên DNS (hỗ trợ nén con trỏ 0xC0). Trả (tên, offset_kế)."""
    labels = []
    jumped = False
    next_off = off
    guard = 0
    while guard < 128:
        guard += 1
        if off >= len(data):
            break
        length = data[off]
        if length == 0:
            off += 1
            if not jumped:
                next_off = off
            break
        if length & 0xC0 == 0xC0:  # con trỏ nén
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                next_off = off + 2
            off = ptr
            jumped = True
            continue
        labels.append(data[off + 1:off + 1 + length].decode("ascii", "ignore"))
        off += 1 + length
    return ".".join(labels), next_off


def mdns_reverse(ip: str, timeout: float = 1.4) -> str:
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    rev_l = rev.lower()
    pkt = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    for part in rev.split("."):
        pkt += bytes([len(part)]) + part.encode()
    pkt += b"\x00" + struct.pack(">HH", 12, 1)  # PTR / IN
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, MDNS_ADDR)
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, _ = s.recvfrom(4096)
            except socket.timeout:
                break
            name = _parse_ptr_answer(data, rev_l)
            if name:
                return name
    except OSError:
        pass
    finally:
        s.close()
    return ""


def _parse_ptr_answer(data: bytes, rev_l: str) -> str:
    """Chỉ trả hostname nếu gói thực sự trả lời đúng địa chỉ reverse đã hỏi."""
    try:
        _, _, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
        off = 12
        for _ in range(qd):  # bỏ qua phần câu hỏi
            _, off = _dns_name(data, off)
            off += 4
        for _ in range(an):
            aname, off = _dns_name(data, off)
            atype, _aclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata_off = off
            off += rdlen
            if atype == 12 and aname.lower() == rev_l:  # PTR đúng địa chỉ
                target, _ = _dns_name(data, rdata_off)
                target = target.rstrip(".")
                if target:
                    return target
    except (struct.error, IndexError):
        pass
    return ""


# --------------------------------------------------------------------------
# NetBIOS node status (Windows / Samba)
# --------------------------------------------------------------------------

def netbios_name(ip: str, timeout: float = 1.0) -> str:
    # Query name '*' (mã hoá kiểu NetBIOS) -> node status
    pkt = struct.pack(">H", 0x4142) + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    pkt += b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00"
    pkt += struct.pack(">HH", 0x0021, 0x0001)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(2048)
    except OSError:
        return ""
    finally:
        s.close()
    try:
        count = data[56]
        off = 57
        names = []
        for _ in range(count):
            nm = data[off:off + 15].decode("ascii", "ignore").rstrip()
            suffix = data[off + 15]
            flags = struct.unpack(">H", data[off + 16:off + 18])[0]
            names.append((nm, suffix, flags))
            off += 18
        # tên máy = suffix 0x00, không phải group (bit 0x8000)
        for nm, suffix, flags in names:
            if suffix == 0x00 and not (flags & 0x8000) and nm:
                return nm
        return names[0][0] if names else ""
    except (IndexError, struct.error):
        return ""


SSDP_ADDR = ("239.255.255.250", 1900)


def ssdp_discover_all(timeout: float = 1.2) -> dict[str, str]:
    """Quét UPnP/SSDP 1 lần cho cả mạng (bắn 1 gói multicast, nghe hết phản hồi -
    đỡ phải mỗi thiết bị tự bắn 1 lần). Trả {ip: friendlyName} - chỉ có với các
    thiết bị đang bật chia sẻ DLNA/media/UPnP (không phải máy nào cũng có)."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()
    out: dict[str, str] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(timeout)
    try:
        s.sendto(msg, SSDP_ADDR)
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            ip = addr[0]
            if ip in out:
                continue
            loc = None
            for line in data.decode("utf-8", "ignore").split("\r\n"):
                if line.lower().startswith("location:"):
                    loc = line.split(":", 1)[1].strip()
                    break
            if loc:
                name = _ssdp_fetch_friendly_name(loc, ip)
                if name:
                    out[ip] = name
    except OSError:
        pass
    finally:
        s.close()
    return out


def _ssdp_fetch_friendly_name(location: str, expect_host: str, timeout: float = 1.0) -> str:
    """Tải XML mô tả thiết bị UPnP, lấy <friendlyName>. Chỉ chấp nhận URL http://
    trỏ đúng về IP đã hỏi (chặn thiết bị trỏ URL sang chỗ khác - SSRF)."""
    try:
        from urllib.parse import urlparse
        import urllib.request

        parsed = urlparse(location)
        if parsed.scheme != "http" or parsed.hostname != expect_host:
            return ""
        with urllib.request.urlopen(location, timeout=timeout) as r:  # noqa: S310
            body = r.read(8192).decode("utf-8", "ignore")
        m = re.search(r"<friendlyName>(.*?)</friendlyName>", body, re.I | re.S)
        return m.group(1).strip() if m else ""
    except Exception:
        return ""


def reverse_dns(ip: str, timeout: float = 0.5) -> str:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0].rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(old)


def ttl_probe(ip: str, timeout_ms: int = 500) -> int | None:
    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_ms), ip],
            capture_output=True, text=True, timeout=(timeout_ms / 1000.0) + 1.0,
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return None
    m = re.search(r"ttl=(\d+)", out)
    return int(m.group(1)) if m else None


# --------------------------------------------------------------------------
# Phân loại
# --------------------------------------------------------------------------

# (từ khoá trong tên) -> (loại, OS, icon). Thứ tự = độ ưu tiên (khớp trước thắng).
_NAME_RULES = [
    # Apple – di động / phụ kiện
    (("iphone",), "iPhone", "iOS", "📱"),
    (("ipad",), "iPad", "iPadOS", "📱"),
    (("ipod",), "iPod", "iOS", "🎵"),
    (("apple-tv", "appletv", "apple tv"), "Apple TV", "tvOS", "📺"),
    (("homepod",), "HomePod", "Apple", "🔊"),
    (("apple-watch", "applewatch"), "Apple Watch", "watchOS", "⌚"),
    # Apple – máy tính
    (("macbook",), "MacBook", "macOS", "💻"),
    (("imac",), "iMac", "macOS", "🖥️"),
    (("mac-mini", "macmini", "mac-studio", "macstudio", "macpro", "mac-pro"),
     "Mac", "macOS", "🖥️"),
    # Phần cứng Windows (đặt trước để không bị nhãn hãng/di động chiếm)
    (("thinkpad", "ideapad", "elitebook", "probook", "latitude", "optiplex",
      "inspiron", "-xps", "xps-", "surface", "mini-pc", "minipc", "-pc",
      "pc-", "desktop-", "laptop-", "win-", "windows", "dell", "lenovo",
      "asus-", "-asus", "msi-", "acer"),
     "Windows PC", "Windows", "🪟"),
    # Android – theo hãng
    (("galaxy", "samsung", "sm-", "sm_"), "Samsung", "Android", "📱"),
    (("pixel",), "Google Pixel", "Android", "📱"),
    (("redmi", "xiaomi", "poco", "mi-"), "Xiaomi", "Android", "📱"),
    (("oneplus", "oppo", "realme", "vivo", "huawei", "honor"),
     "Android phone", "Android", "📱"),
    (("android",), "Android", "Android", "📱"),
    # Linux / SBC
    (("raspberrypi", "raspberry", "rpi"), "Raspberry Pi", "Linux", "🍓"),
    (("ubuntu", "debian", "fedora", "archlinux", "-linux", "linux"),
     "Linux", "Linux", "🐧"),
    # Thiết bị khác
    (("printer", "epson", "canon", "brother", "hpprint", "hp-print", "officejet"),
     "Máy in", "—", "🖨️"),
    (("chromecast", "googlehome", "google-home", "nest-", "nest"),
     "Google / Nest", "—", "📺"),
    (("echo", "alexa", "firetv", "fire-tv", "kindle"), "Amazon", "FireOS", "🔊"),
    (("smarttv", "bravia", "aquos", "webos", "-tv-"), "Smart TV", "—", "📺"),
    # Mac lỏng (đặt cuối: bắt các tên kiểu "Johns-Mac")
    (("-mac", "s-mac", " mac", "-mac-", "macos"), "Mac", "macOS", "💻"),
]

_VENDOR_RULES = [
    ("apple", "Thiết bị Apple", "Apple", "🍎"),
    ("samsung", "Samsung", "Android", "📱"),
    ("google", "Google", "—", "📺"),
    ("amazon", "Amazon", "FireOS", "🔊"),
    ("raspberry", "Raspberry Pi", "Linux", "🍓"),
    ("espressif", "Thiết bị IoT", "—", "🔌"),
    ("iot", "Thiết bị IoT", "—", "🔌"),
    ("xiaomi", "Xiaomi", "Android", "📱"),
    ("sonos", "Sonos", "—", "🔊"),
    ("sony", "Sony", "—", "📺"),
    ("lg", "LG", "—", "📺"),
    ("ubiquiti", "Thiết bị mạng", "—", "🛜"),
    ("netgear", "Thiết bị mạng", "—", "🛜"),
    ("tp-link", "Thiết bị mạng", "—", "🛜"),
    ("d-link", "Thiết bị mạng", "—", "🛜"),
    ("intel", "Máy tính (Intel NIC)", "—", "🖥️"),
    ("vmware", "Máy ảo", "—", "🖥️"),
    ("virtualbox", "Máy ảo", "—", "🖥️"),
    ("qemu", "Máy ảo", "—", "🖥️"),
]


# Domain HẠ TẦNG (push/update/connectivity) -> hãng/OS. Chỉ dùng domain hạ tầng,
# KHÔNG dùng website thông thường (tránh người dùng Mac vô tình vào samsung.com
# bị đoán nhầm thành điện thoại Samsung). Thứ tự = độ ưu tiên (cụ thể trước).
_DOMAIN_RULES = [
    (("pushmessage.samsung.com", "regi.samsung.com", "samsungotn.net", "samsungcloud.com"),
     "Samsung", "Android", "📱", "cao"),
    (("push.connect.xiaomi.com", "track.xiaomi.com", "sdk.xiaomi.com"),
     "Xiaomi / POCO / Redmi", "Android", "📱", "cao"),
    (("push.oppomobile.com", "push.heytapmobi.com", "coloros.com"),
     "OPPO / Realme", "Android", "📱", "cao"),
    (("push.vivo.com", "inf.vivoglobal.com"),
     "vivo", "Android", "📱", "cao"),
    (("push.hicloud.com", "push.dbankcloud.com"),
     "Huawei / Honor", "HarmonyOS/Android", "📱", "cao"),
    (("mesu.apple.com",), "iPhone / iPad", "iOS", "📱", "cao"),
    (("swscan.apple.com", "swcdn.apple.com"), "Mac", "macOS", "💻", "cao"),
    (("msftconnecttest.com", "windowsupdate.com", "download.windowsupdate.com"),
     "Windows PC", "Windows", "🪟", "cao"),
    (("tuyaus.com", "tuyaeu.com", "a1.tuya", "smartlif"), "IoT Tuya / Smart Life", "—", "🔌", "cao"),
    (("tplinkcloud.com",), "TP-Link (IoT/Router)", "—", "🛜", "cao"),
    (("ewelink",), "IoT eWeLink / Sonoff", "—", "🔌", "cao"),
    (("smartthings.com",), "Samsung SmartThings (IoT)", "—", "🏠", "cao"),
    (("hik-connect.com", "hikvision"), "Camera Hikvision", "—", "📷", "cao"),
    (("push.apple.com", "gateway.icloud.com", "captive.apple.com", "icloud.com", "mzstatic.com"),
     "Thiết bị Apple (iPhone/iPad/Mac)", "iOS/macOS", "🍎", "vừa"),
    (("mtalk.google.com", "android.googleapis.com", "connectivitycheck.gstatic.com",
      "play.googleapis.com", "device-provisioning.googleapis.com"),
     "Android / Chrome", "Android?", "🤖", "vừa"),
    (("login.live.com", "login.microsoftonline.com"),
     "Thiết bị dùng Microsoft Account", "—", "🪟", "thấp"),
]


def guess_from_domains(domains: list[str]) -> dict | None:
    """Đoán loại/hãng thiết bị từ các tên miền nó truy cập (traffic DNS/SNI đã bắt).

    Chỉ khớp domain hạ tầng (push/update/connectivity) — không khớp website thường.
    Trả {"type","os","icon","confidence","evidence"} hoặc None nếu không có tín hiệu."""
    if not domains:
        return None
    uniq = list(dict.fromkeys(
        d.lower().rstrip(".") for d in domains if d
    ))
    for patterns, typ, os_, icon, conf in _DOMAIN_RULES:
        hits = [d for d in uniq if any(p in d for p in patterns)]
        if hits:
            return {"type": typ, "os": os_, "icon": icon,
                    "confidence": conf, "evidence": hits[:3]}
    return None

def _first_name_hit(hay: str):
    for keys, typ, os_, icon in _NAME_RULES:
        if any(k in hay for k in keys):
            return typ, os_, icon
    return None


def classify(name: str, netbios: str, vendor: str, ttl, role: str) -> dict:
    if role == "gateway":
        return {"type": "Router / Gateway", "os": "—", "icon": "🛜", "confidence": "cao"}
    if role == "self":
        return {"type": "Máy này (Mac)", "os": "macOS", "icon": "🍎", "confidence": "cao"}

    hay = f"{(name or '').lower()} {(netbios or '').lower()}"
    hit = _first_name_hit(hay)
    if hit:
        return {"type": hit[0], "os": hit[1], "icon": hit[2], "confidence": "cao"}

    # Có NetBIOS nhưng tên không rõ -> nhiều khả năng Windows (Samba/Linux nếu ttl~64)
    if netbios:
        if ttl and 55 <= ttl <= 70:
            return {"type": "Máy chia sẻ SMB (Linux/NAS?)", "os": "Linux?",
                    "icon": "🖥️", "confidence": "vừa"}
        return {"type": "Windows PC", "os": "Windows", "icon": "🪟", "confidence": "vừa"}

    v = (vendor or "").lower()
    for key, typ, os_, icon in _VENDOR_RULES:
        if key in v:
            return {"type": typ, "os": os_, "icon": icon, "confidence": "vừa"}

    # Chỉ còn TTL
    if ttl:
        if ttl >= 200:
            return {"type": "Thiết bị mạng", "os": "—", "icon": "🛜", "confidence": "thấp"}
        if 120 <= ttl <= 132:
            return {"type": "Windows PC", "os": "Windows", "icon": "🪟", "confidence": "thấp"}
        if 55 <= ttl <= 70:
            return {"type": "Unix-like (Linux/Mac/di động)", "os": "Linux/Apple/Android?",
                    "icon": "🖥️", "confidence": "thấp"}
    return {"type": "Không rõ", "os": "—", "icon": "❓", "confidence": "—"}


def from_dhcp(hostname: str, vendor_class: str) -> dict | None:
    """Phân loại từ dữ liệu DHCP (option 12 hostname + option 60 vendor-class)."""
    vc = (vendor_class or "").lower()
    m = re.search(r"android-dhcp-(\d+)", vc)
    if m:
        return {"type": "Android", "os": f"Android {m.group(1)}",
                "icon": "📱", "confidence": "cao"}
    if "android" in vc:
        return {"type": "Android", "os": "Android", "icon": "📱", "confidence": "cao"}
    if "msft" in vc:
        return {"type": "Windows PC", "os": "Windows", "icon": "🪟", "confidence": "cao"}
    if vc.startswith("dhcpcd") or "udhcp" in vc:
        return {"type": "Linux", "os": "Linux", "icon": "🐧", "confidence": "vừa"}
    # không có vendor-class rõ -> thử từ hostname
    if hostname:
        hit = _first_name_hit(hostname.lower() + " ")
        if hit:
            return {"type": hit[0], "os": hit[1], "icon": hit[2], "confidence": "cao"}
    return None


def is_generic_name(s: str) -> bool:
    """True nếu tên chỉ là placeholder do hệ điều hành tự sinh (vd: "Android-3",
    "iOS-Device") chứ không phải tên/model thật của thiết bị. Từ Android 10 và
    iOS gần đây, các OS này CHỦ ĐỘNG phát tên giả kiểu này qua mDNS/DHCP để
    chống bị theo dõi qua tên máy - không phản ánh model thật."""
    if not s:
        return True
    s = s.lower().strip()
    if re.match(r"^(android|ios)(-[\w]+)?$", s):
        return True
    return s in ["localhost", "unknown", "broadcom", "device", "pc"]


def best_name(mdns: str, netbios: str, rdns: str, ssdp: str = "") -> str:
    """So sánh tất cả nguồn tên bắt được (SSDP/UPnP, mDNS, rDNS, NetBIOS) và
    chọn nguồn đầu tiên KHÔNG phải tên chung chung do OS tự sinh (vd: bỏ qua
    "Android-3"/"iOS-Device" nếu có nguồn khác cho tên thật hơn). Nếu không
    nguồn nào "sạch", đành trả tên chung chung còn hơn để trống."""
    m = mdns[:-6] if mdns.endswith(".local") else mdns
    r = rdns if (rdns and not rdns.replace(".", "").isdigit()) else ""
    # Thứ tự ưu tiên khi có từ 2 nguồn "sạch" trở lên: SSDP (tên khai báo tay,
    # đáng tin nhất) > mDNS > rDNS > NetBIOS.
    candidates = [ssdp, m, r, netbios]
    for c in candidates:
        if c and not is_generic_name(c):
            return c
    for c in candidates:
        if c:
            return c
    return ""


def fingerprint(ip: str, mac: str, role: str, want_ttl: bool = True, ssdp: str = "") -> dict:
    """Trả về dict enrich cho 1 thiết bị."""
    vendor = oui.lookup(mac)
    mdns = mdns_reverse(ip)
    nb = netbios_name(ip)
    rdns = reverse_dns(ip)
    ttl = ttl_probe(ip) if want_ttl else None
    chosen_name = best_name(mdns, nb, rdns, ssdp)
    name_hay = f"{chosen_name} {mdns} {rdns} {ssdp}"
    cls = classify(name_hay, nb, vendor, ttl, role)
    return {
        "vendor": vendor,
        "name": chosen_name,
        "mdns": mdns,
        "netbios": nb,
        "rdns": rdns,
        "ssdp": ssdp,
        "ttl": ttl,
        "type": cls["type"],
        "os": cls["os"],
        "icon": cls["icon"],
        "confidence": cls["confidence"],
    }
