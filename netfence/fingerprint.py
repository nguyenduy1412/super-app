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
    if not s:
        return True
    s = s.lower().strip()
    return bool(re.match(r"^android(-\d+)?$", s) or s in ["localhost", "unknown", "broadcom", "device", "pc"])


def best_name(mdns: str, netbios: str, rdns: str) -> str:
    m = mdns[:-6] if mdns.endswith(".local") else mdns
    r = rdns if (rdns and not rdns.replace(".", "").isdigit()) else ""
    # Nếu mDNS chỉ là tên chung chung (Android, Android-2) mà rDNS có tên model thật (vd: poco-x6-pro-5g.lan) -> ưu tiên rDNS
    if is_generic_name(m) and r and not is_generic_name(r):
        return r
    if m and not is_generic_name(m):
        return m
    if netbios and not is_generic_name(netbios):
        return netbios
    return r or m or netbios or ""


def fingerprint(ip: str, mac: str, role: str, want_ttl: bool = True) -> dict:
    """Trả về dict enrich cho 1 thiết bị."""
    vendor = oui.lookup(mac)
    mdns = mdns_reverse(ip)
    nb = netbios_name(ip)
    rdns = reverse_dns(ip)
    ttl = ttl_probe(ip) if want_ttl else None
    chosen_name = best_name(mdns, nb, rdns)
    name_hay = f"{chosen_name} {mdns} {rdns}"
    cls = classify(name_hay, nb, vendor, ttl, role)
    return {
        "vendor": vendor,
        "name": chosen_name,
        "mdns": mdns,
        "netbios": nb,
        "rdns": rdns,
        "ttl": ttl,
        "type": cls["type"],
        "os": cls["os"],
        "icon": cls["icon"],
        "confidence": cls["confidence"],
    }
