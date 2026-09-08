"""Tra cứu nhà sản xuất từ MAC (OUI) — best-effort, offline.

Ưu tiên đọc file oui.csv (dạng "AABBCC,Vendor") nếu có trong cùng thư mục;
nếu không có thì dùng bảng rút gọn các prefix phổ biến bên dưới.
"""
from __future__ import annotations

import os

_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.csv")

# Prefix (3 byte đầu, chữ hoa, không dấu ':') -> tên hãng.
_BUILTIN = {
    # Apple (một phần nhỏ, Apple có rất nhiều dải)
    "F0189E": "Apple", "3C0754": "Apple", "A85C2C": "Apple", "DC2B2A": "Apple",
    "F86214": "Apple", "AC87A3": "Apple", "8866A5": "Apple", "F0DBF8": "Apple",
    "D0817A": "Apple", "A4B197": "Apple", "88665A": "Apple", "BCD074": "Apple",
    # Samsung
    "F0257B": "Samsung", "5CF6DC": "Samsung", "E8508B": "Samsung",
    "347593": "Samsung", "8425DB": "Samsung",
    # Google / Nest
    "F4F5D8": "Google", "3C5AB4": "Google", "F88FCA": "Google", "1CF29A": "Google",
    "D831CF": "Google",
    # Amazon (Echo/FireTV)
    "FC65DE": "Amazon", "44650D": "Amazon", "84D6D0": "Amazon", "F0272D": "Amazon",
    "68DBF5": "Amazon", "0C47C9": "Amazon",
    # Espressif (ESP8266/ESP32 — IoT)
    "240AC4": "Espressif (IoT)", "3C6105": "Espressif (IoT)",
    "A020A6": "Espressif (IoT)", "84F3EB": "Espressif (IoT)",
    "7C9EBD": "Espressif (IoT)", "D8A01D": "Espressif (IoT)",
    # Raspberry Pi
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "28CDC1": "Raspberry Pi",
    # TP-Link
    "50C7BF": "TP-Link", "1C61B4": "TP-Link", "AC84C6": "TP-Link", "60A4B7": "TP-Link",
    # Xiaomi
    "286C07": "Xiaomi", "64B473": "Xiaomi", "F8A45F": "Xiaomi", "78110F": "Xiaomi",
    # Intel
    "00A0C9": "Intel", "3448ED": "Intel", "94E979": "Intel", "8C1645": "Intel",
    # Realtek / các hãng NIC phổ biến
    "525400": "QEMU/KVM (ảo)", "000C29": "VMware", "005056": "VMware",
    "0800271": "VirtualBox",
    # Sonos / LG / Sony
    "5CAAFD": "Sonos", "B8E937": "Sonos",
    "001E75": "LG", "CCFA00": "LG",
    "FCF152": "Sony", "D8D43C": "Sony",
    # Ubiquiti / Netgear / D-Link (thiết bị mạng)
    "788A20": "Ubiquiti", "F09FC2": "Ubiquiti", "245A4C": "Ubiquiti",
    "A040A0": "Netgear", "20E52A": "Netgear",
    "1CBDB9": "D-Link", "C8BE19": "D-Link",
}

_csv_cache: dict[str, str] | None = None


def _load_csv() -> dict[str, str]:
    global _csv_cache
    if _csv_cache is not None:
        return _csv_cache
    table: dict[str, str] = {}
    try:
        with open(_CSV, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "," not in line:
                    continue
                prefix, name = line.split(",", 1)
                prefix = prefix.replace(":", "").replace("-", "").upper()[:6]
                if len(prefix) == 6:
                    table[prefix] = name.strip()
    except FileNotFoundError:
        pass
    _csv_cache = table
    return table


def _is_locally_administered(first_octet: int) -> bool:
    # bit thứ 2 của octet đầu = 1 => địa chỉ do thiết bị tự sinh (random/private)
    return bool(first_octet & 0x02)


def lookup(mac: str) -> str:
    if not mac or ":" not in mac:
        return "Không rõ"
    octets = mac.split(":")
    try:
        first = int(octets[0], 16)
    except ValueError:
        return "Không rõ"
    key = "".join(f"{int(o, 16):02X}" for o in octets[:3])
    csv = _load_csv()
    name = csv.get(key) or _BUILTIN.get(key)
    if name:
        return name
    if _is_locally_administered(first):
        return "MAC ngẫu nhiên (riêng tư)"
    return "Không rõ"
