#!/usr/bin/python3
"""NetFence — LAN inventory & reversible access control (bản macOS, kiểu LocalFence).

Chạy dưới quyền user thường:
  - /api/scan   : quét thiết bị trong LAN (UDP probe + bảng ARP + vendor + tên).
  - /api/status : thông tin interface/gateway + trạng thái engine + danh sách đang chặn.
  - /api/block, /api/unblock, /api/stop : điều khiển chặn/bỏ chặn (ARP), đảo ngược được.

Việc CHẶN cần một engine chạy root (arp_engine.py). Lần đầu bấm "Chặn", macOS sẽ
hiện hộp thoại nhập mật khẩu admin để khởi động engine. Chỉ dùng cho LAN của bạn.

Lưu ý macOS 15+ / 27 (Local Network Privacy): Homebrew Python (/opt/homebrew/...)
thường bị chặn đọc bảng ARP (`arp -an` trả về rỗng) → quét thiết bị thất bại.
NetFence ưu tiên /usr/bin/python3 (Apple-signed) và tự chuyển sang interpreter đó.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# macOS Local Network Privacy: binary không do Apple ký (Homebrew Python) có thể
# nhận `arp -an` rỗng dù Terminal chạy lệnh đó bình thường. Dùng Python hệ thống.
_SYSTEM_PYTHON = "/usr/bin/python3"


def _arp_cli_readable() -> bool:
    try:
        r = subprocess.run(
            ["/usr/sbin/arp", "-an"],
            capture_output=True, text=True, timeout=5,
        )
        return bool(r.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return False


def _ensure_local_network_python() -> None:
    """Ưu tiên /usr/bin/python3 trên macOS để tránh Local Network Privacy.

    Launcher (Run Super App.command) phải start thẳng /usr/bin/python3.
    Hàm này phòng vệ khi chạy thủ công bằng Homebrew `python3`.
    """
    if sys.platform != "darwin" or os.environ.get("NETFENCE_NO_REEXEC"):
        return
    try:
        if os.path.isfile(_SYSTEM_PYTHON) and os.path.samefile(sys.executable, _SYSTEM_PYTHON):
            return
    except OSError:
        pass
    # Chỉ ép chuyển khi đang dùng Python không do Apple (Homebrew/MacPorts/pyenv…)
    # hoặc khi ARP thực sự bị chặn.
    non_system = any(
        p in sys.executable
        for p in ("/opt/homebrew/", "/usr/local/Cellar/", "/usr/local/opt/",
                  "pyenv", "miniconda", "anaconda", "/opt/local/")
    )
    if not non_system and not _local_network_blocked():
        return
    if not os.path.isfile(_SYSTEM_PYTHON):
        print(
            "Cảnh báo NetFence: không tìm thấy /usr/bin/python3 "
            "(cần để đọc ARP trên macOS 15+/27).",
            file=sys.stderr, flush=True,
        )
        return
    print(
        f"NetFence: chuyển từ {sys.executable} sang {_SYSTEM_PYTHON} "
        "(tránh Local Network Privacy chặn ARP)...",
        flush=True,
    )
    os.environ["NETFENCE_NO_REEXEC"] = "1"
    os.execv(
        _SYSTEM_PYTHON,
        [_SYSTEM_PYTHON, os.path.abspath(__file__), *sys.argv[1:]],
    )


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oui  # noqa: E402
import fingerprint  # noqa: E402

HOST = "127.0.0.1"
PORT = int(os.environ.get("NETFENCE_PORT", 8748))
BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
ENGINE = BASE / "arp_engine.py"
SNIFFER = BASE / "dhcp_sniffer.py"
STATE_DIR = Path(os.environ.get("NETFENCE_STATE", "/tmp/netfence"))
REQ_FILE = STATE_DIR / "request.json"
STATUS_FILE = STATE_DIR / "status.json"
DHCP_NAMES = STATE_DIR / "dhcp_names.json"
SNIFFER_STATUS = STATE_DIR / "sniffer_status.json"
THREATS_FILE = STATE_DIR / "threats.json"
DOMAINS_FILE = STATE_DIR / "domains.json"
_last_threat_counts: dict[str, int] = {}

DEFAULT_INTERVAL_MS = 1000
MAX_ENTRIES = 255
AUTO_SCAN_INTERVAL = 90.0   # giây giữa các lần tự quét nền để dò tên thiết bị lạ

_lock = threading.RLock()
_blocks: dict[str, dict] = {}      # ip -> {"mac":.., "name":.., "interval_ms":.., "status":.., "fail_count":.., "last_seen":..}
_monitors: dict[str, dict] = {}    # ip -> {...} chế độ giám sát (MITM trong suốt, xem tên miền)
_generation = int(time.time())
_events: list[dict] = []
_event_seq = 0
_last_subnet = ""
_auto_monitor_enabled = False  # tự bắt traffic thiết bị chưa xác định để dò tên (mặc định tắt)
_last_auto_scan = 0.0


def _add_event(event_type: str, message: str, data: dict | None = None) -> None:
    global _event_seq
    with _lock:
        _event_seq += 1
        evt = {
            "id": _event_seq,
            "type": event_type,
            "message": message,
            "time": time.time(),
            "time_str": time.strftime("%H:%M:%S"),
            "data": data or {},
        }
        _events.append(evt)
        if len(_events) > 50:
            del _events[:-50]

# --------------------------------------------------------------------------
# Thông tin mạng
# --------------------------------------------------------------------------

def _run(cmd: list[str], timeout: float = 5.0) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _ipv6_gw() -> str:
    out = _run(["route", "-n", "get", "-inet6", "default"])
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            gw6 = line.split(":", 1)[1].strip()
            if "%" in gw6:
                gw6 = gw6.split("%")[0]
            return gw6
    return ""


def net_info() -> dict:
    out = _run(["route", "-n", "get", "default"])
    iface = gw = ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            iface = line.split(":", 1)[1].strip()
        elif line.startswith("gateway:"):
            gw = line.split(":", 1)[1].strip()

    ip = netmask_hex = mac = ""
    if iface:
        ic = _run(["ifconfig", iface])
        m_ip = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", ic)
        if m_ip:
            ip, netmask_hex = m_ip.group(1), m_ip.group(2)
        m_mac = re.search(r"ether ((?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})", ic)
        if m_mac:
            mac = _norm_mac(m_mac.group(1))

    cidr = subnet = ""
    prefixlen = None
    if ip and netmask_hex:
        mask_int = int(netmask_hex, 16)
        prefixlen = bin(mask_int).count("1")
        try:
            net = ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False)
            cidr = str(net)
            subnet = str(net.network_address)
        except ValueError:
            pass

    gw_mac = _arp_lookup(gw) if gw else ""
    private = False
    try:
        private = ipaddress.ip_address(ip).is_private if ip else False
    except ValueError:
        pass

    gw_ip6 = _ipv6_gw()
    return {
        "interface": iface, "ip": ip, "mac": mac, "netmask_hex": netmask_hex,
        "prefixlen": prefixlen, "cidr": cidr, "subnet": subnet,
        "gateway_ip": gw, "gateway_mac": gw_mac, "gateway_ip6": gw_ip6, "private": private,
    }


def _norm_mac(mac: str) -> str:
    try:
        return ":".join(f"{int(p, 16):02x}" for p in mac.split(":"))
    except ValueError:
        return mac.lower()


def _is_placeholder_mac(mac: str) -> bool:
    """MAC giả / bị Local Network Privacy che (thường gặp: 02:00:00:00:00:00)."""
    return _norm_mac(mac) in (
        "00:00:00:00:00:00",
        "02:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
    )


def _arp_table() -> dict[str, str]:
    """ip -> mac (đã chuẩn hoá), bỏ incomplete / MAC giả / multicast.

    Dùng đường dẫn tuyệt đối /usr/sbin/arp để tránh nhầm binary khác trong PATH.
    """
    out = _run(["/usr/sbin/arp", "-an"])
    table: dict[str, str] = {}
    for line in out.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)", line)
        if not m:
            continue
        ip, mac = m.group(1), m.group(2)
        if "incomplete" in line or mac.count(":") != 5:
            continue
        mac_n = _norm_mac(mac)
        if _is_placeholder_mac(mac_n):
            continue
        # Bỏ multicast/broadcast (224.x, 239.x, *.255 broadcast đã lọc qua placeholder ff:..)
        try:
            a = ipaddress.ip_address(ip)
            if a.is_multicast:
                continue
        except ValueError:
            continue
        table[ip] = mac_n
    return table


def _arp_lookup(ip: str) -> str:
    return _arp_table().get(ip, "")


def _local_network_blocked() -> bool:
    """True khi process hiện tại bị macOS chặn đọc ARP LAN."""
    raw = _run(["/usr/sbin/arp", "-an"]).strip()
    if not raw:
        return True
    # Có output nhưng toàn incomplete / placeholder → coi như bị chặn/che
    return not bool(_arp_table()) and "incomplete" not in raw.lower()


# --------------------------------------------------------------------------
# Quét LAN: gửi UDP probe cho từng host để kernel giải ARP, rồi đọc bảng ARP
# --------------------------------------------------------------------------

def _probe_sweep(net: ipaddress.IPv4Network, self_ip: str) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    for host in net.hosts():
        h = str(host)
        if h == self_ip:
            continue
        try:
            s.sendto(b"\x00", (h, 9))  # discard port; chỉ cần kích hoạt ARP
        except OSError:
            pass
    s.close()


def _reverse_name(ip: str) -> str:
    try:
        socket.setdefaulttimeout(0.4)
        name = socket.gethostbyaddr(ip)[0]
        return name.rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(None)


def scan(auto_monitor: bool | None = None) -> dict:
    if auto_monitor is None:
        auto_monitor = _auto_monitor_enabled
    info = net_info()
    result = {"ok": True, "info": info, "devices": [], "error": None}
    if not info["cidr"]:
        result.update(ok=False, error="Không xác định được subnet.")
        return result
    net = ipaddress.ip_network(info["cidr"], strict=False)
    if not (net.is_private):
        result.update(ok=False, error="Interface không nằm trong subnet private.")
        return result
    if net.prefixlen < 22 or net.prefixlen > 30:
        result.update(ok=False,
                      error=f"Subnet /{net.prefixlen} nằm ngoài phạm vi cho phép (/22–/30).")
        return result

    _probe_sweep(net, info["ip"])
    time.sleep(1.6)
    table = _arp_table()

    if not table and _local_network_blocked():
        result.update(
            ok=False,
            error=(
                "Không đọc được bảng ARP — macOS Local Network Privacy đang chặn "
                f"Python hiện tại ({sys.executable}). Hãy tắt NetFence, chạy lại bằng "
                "/usr/bin/python3 (hoặc Super App đã cập nhật), và nếu cần bật "
                "Quyền riêng tư > Mạng cục bộ cho Terminal."
            ),
        )
        return result

    ips = [ip for ip in table if ipaddress.ip_address(ip) in net]

    def _role(ip: str) -> str:
        if ip == info["gateway_ip"]:
            return "gateway"
        if ip == info["ip"]:
            return "self"
        return "device"

    # SSDP/UPnP: 1 lượt quét chung cho cả mạng (khỏi mỗi thiết bị tự bắn multicast riêng)
    ssdp_map = fingerprint.ssdp_discover_all()

    # Nhận diện song song: mDNS + NetBIOS + reverse DNS + SSDP + OUI + TTL
    enrich: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=32) as ex:
        futs = {ex.submit(fingerprint.fingerprint, ip, table[ip], _role(ip),
                          ssdp=ssdp_map.get(ip, "")): ip
                for ip in ips}
        for fut in futs:
            ip = futs[fut]
            try:
                enrich[ip] = fut.result(timeout=6)
            except Exception:  # noqa: BLE001
                enrich[ip] = {"vendor": oui.lookup(table[ip]), "name": "",
                              "type": "Không rõ", "os": "—", "icon": "❓",
                              "netbios": "", "mdns": "", "rdns": "", "ssdp": "",
                              "ttl": None, "confidence": "—"}

    with _lock:
        blocked = dict(_blocks)

    dhcp = _read_dhcp_names()  # MAC -> {hostname, vendor_class}

    devices = []
    for ip in sorted(ips, key=lambda x: tuple(int(o) for o in x.split("."))):
        e = dict(enrich[ip])
        dn = dhcp.get(table[ip].lower())
        if dn and _role(ip) == "device":
            # Bổ sung từ DHCP: tên và loại/OS (ưu tiên khi thiết bị im lặng
            # hoặc khi tên tìm được chỉ là tên chung chung kiểu "android-3")
            if fingerprint.is_generic_name(e.get("name", "")) and dn.get("hostname"):
                e["name"] = dn["hostname"]
            cls = fingerprint.from_dhcp(dn.get("hostname", ""), dn.get("vendor_class", ""))
            if cls and (e.get("type") in (None, "Không rõ")
                        or e.get("confidence") in ("thấp", "—")):
                e.update(type=cls["type"], os=cls["os"], icon=cls["icon"],
                         confidence=cls["confidence"])
            e["dhcp"] = True
        is_blk = ip in blocked
        blk_status = blocked[ip].get("status", "online") if is_blk else None
        devices.append({
            "ip": ip, "mac": table[ip], "role": _role(ip),
            "blocked": is_blk, "block_status": blk_status, **e,
        })

    with _lock:
        for d in devices:
            if d["ip"] in _blocks and not _blocks[d["ip"]].get("name") and d.get("name"):
                _blocks[d["ip"]]["name"] = d["name"]

    # Tự động dò tên: bắt traffic các thiết bị CHƯA XÁC ĐỊNH, ngừng khi có tên
    if auto_monitor and _auto_monitor_enabled:
        to_add: list[dict] = []
        resolved: list[tuple[str, str]] = []
        net_addr = net.network_address
        bc_addr = net.broadcast_address
        with _lock:
            mon_ips_snapshot = list(_monitors.keys())
        doms_map = _read_domains(mon_ips_snapshot)
        with _lock:
            for d in devices:
                ip = d["ip"]
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if addr in (net_addr, bc_addr):   # bỏ địa chỉ mạng/broadcast (.0/.255)
                    continue
                if d["role"] != "device":
                    continue
                mon_entry = _monitors.get(ip)
                # Đã xác định được thiết bị chưa? (có tên / nhận diện cao / đoán cao từ traffic)
                guess = None
                if mon_entry and mon_entry.get("auto"):
                    guess = fingerprint.guess_from_domains(
                        [e["d"] for e in doms_map.get(ip, [])])
                identified = (bool(d.get("name"))
                              or d.get("confidence") == "cao"
                              or bool(guess and guess.get("confidence") == "cao"))
                if identified and mon_entry and mon_entry.get("auto"):
                    del _monitors[ip]
                    label = (d.get("name")
                             or (f"{guess['icon']} {guess['type']} (theo traffic)" if guess else None)
                             or d.get("type") or ip)
                    resolved.append((ip, label))
                    continue
                if (not identified
                        and ip not in _blocks and ip not in _monitors
                        and len(_monitors) < MAX_ENTRIES):
                    _monitors[ip] = {
                        "mac": d["mac"], "name": "", "interval_ms": DEFAULT_INTERVAL_MS,
                        "status": "online", "last_seen": time.time(), "auto": True,
                    }
                    to_add.append({"ip": ip, "mac": d["mac"]})
        if to_add:
            ok, _msg = ensure_engine()
            if not ok:
                with _lock:
                    for e in to_add:
                        _monitors.pop(e["ip"], None)
            else:
                ensure_sniffer()
                _bump_and_push()
                _add_event(
                    "auto_monitor",
                    f"🧠 Tự động bắt traffic {len(to_add)} thiết bị chưa xác định để dò tên qua DNS/SNI",
                    {"ips": [e["ip"] for e in to_add]}
                )
        for ip, name in resolved:
            _bump_and_push()
            _add_event(
                "auto_monitor",
                f"✅ Đã xác định thiết bị {ip}: {name} — ngừng giám sát tự động",
                {"ip": ip, "name": name}
            )

    result["devices"] = devices
    result["count"] = len(devices)
    return result


def _read_dhcp_names() -> dict:
    try:
        with open(DHCP_NAMES) as f:
            data = json.load(f)
        return {k.lower(): v for k, v in data.items()}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _read_threats() -> list:
    try:
        with open(THREATS_FILE) as f:
            d = json.load(f)
            return d.get("threats", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []


_last_domains_cache: dict[str, list] = {}


def _read_domains(monitored_ips: list[str]) -> dict:
    """Đọc domains.json: chỉ lấy các IP đang giám sát, mới nhất đứng đầu."""
    global _last_domains_cache
    try:
        with open(DOMAINS_FILE) as f:
            d = json.load(f)
        all_doms = d.get("domains", {})
    except (FileNotFoundError, json.JSONDecodeError):
        all_doms = {}
    out: dict[str, list] = {}
    for ip in monitored_ips:
        lst = all_doms.get(ip)
        if lst is None and ip in _last_domains_cache:
            out[ip] = _last_domains_cache[ip]
        else:
            out[ip] = list(reversed((lst or [])[-150:]))
    _last_domains_cache = out
    return out


def _read_sniffer_status() -> dict:
    try:
        with open(SNIFFER_STATUS) as f:
            st = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"running": False, "count": 0}
    alive = (time.time() - st.get("ts", 0) < 8) and _pid_alive(st.get("pid", -1))
    st["running"] = bool(st.get("running")) and alive
    return st


def ensure_sniffer(force_restart: bool = False) -> tuple[bool, str]:
    """Khởi động DHCP sniffer & ARP IDS (root) nếu chưa chạy. Có thể hiện hộp thoại admin."""
    sniff_run = STATE_DIR / "dhcp_sniffer.py"
    if _read_sniffer_status().get("running") and not force_restart:
        try:
            if sniff_run.is_file() and SNIFFER.is_file():
                if sniff_run.stat().st_mtime >= SNIFFER.stat().st_mtime:
                    return True, "sniffer đang chạy"
        except OSError:
            return True, "sniffer đang chạy"
    info = net_info()
    iface = info.get("interface") or ""
    py = sys.executable or "/usr/bin/python3"
    sniff_run = STATE_DIR / "dhcp_sniffer.py"
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SNIFFER, sniff_run)
        os.chmod(sniff_run, 0o755)
    except OSError as e:
        return False, f"Không copy được sniffer: {e}"
    shell = (
        f"mkdir -p {STATE_DIR} && chmod 777 {STATE_DIR}; "
        f"{_q(py)} {_q(str(sniff_run))} {_q(str(STATE_DIR))} {_q(iface)} "
        f"--daemon && echo started"
    )
    script = f'do shell script "{_osx_escape(shell)}" with administrator privileges'
    try:
        p = subprocess.run(["osascript", "-e", script],
                           capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return False, "Hết thời gian chờ nhập mật khẩu admin."
    if p.returncode != 0:
        err = (p.stderr or "").strip()
        if "-128" in err or "User canceled" in err:
            return False, "Bạn đã huỷ hộp thoại quyền admin."
        return False, f"Không khởi động được sniffer: {err or 'lỗi không rõ'}"
    for _ in range(20):
        if _read_sniffer_status().get("running"):
            return True, "sniffer đã khởi động"
        time.sleep(0.25)
    return False, "Sniffer không phản hồi (xem sniffer.log)."


# --------------------------------------------------------------------------
# Engine (root) — điều phối
# --------------------------------------------------------------------------

def _read_engine_status() -> dict:
    try:
        with open(STATUS_FILE) as f:
            st = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"running": False}
    # coi là "sống" nếu cập nhật trong vòng 6 giây và pid còn tồn tại
    alive = (time.time() - st.get("ts", 0) < 6) and _pid_alive(st.get("pid", -1))
    st["running"] = bool(st.get("running")) and alive
    return st


def _pid_alive(pid: int) -> bool:
    if not pid or pid < 1:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return pid > 0 and isinstance(pid, int) and _proc_exists(pid)
    except OSError:
        return False


def _proc_exists(pid: int) -> bool:
    return b"" != _run(["ps", "-p", str(pid), "-o", "pid="]).strip().encode()


def _write_request(shutdown: bool = False) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(STATE_DIR, 0o777)
    except OSError:
        pass
    info = net_info()
    with _lock:
        entries = ([{"ip": ip, "mac": b["mac"], "interval_ms": b["interval_ms"],
                     "mode": "block"} for ip, b in _blocks.items()]
                   + [{"ip": ip, "mac": m["mac"], "interval_ms": m["interval_ms"],
                       "mode": "monitor"} for ip, m in _monitors.items()])
        gen = _generation
    payload = {
        "generation": gen,
        "shutdown": shutdown,
        "interface": info["interface"],
        "our_mac": info["mac"],
        "gateway_ip": info["gateway_ip"],
        "gateway_mac": info["gateway_mac"],
        "gateway_ip6": info.get("gateway_ip6", ""),
        "entries": entries,
    }
    tmp = REQ_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload))
    os.replace(tmp, REQ_FILE)
    try:
        os.chmod(REQ_FILE, 0o666)
    except OSError:
        pass


def ensure_engine(force_restart: bool = False) -> tuple[bool, str]:
    """Đảm bảo engine root đang chạy. Trả (ok, message). Có thể hiện hộp thoại admin.

    Nếu engine đang chạy nhưng arp_engine.py nguồn đã được sửa (mtime mới hơn bản
    copy trong STATE_DIR), hoặc force_restart=True, sẽ yêu cầu engine cũ thoát
    sạch (khôi phục ARP/forwarding) rồi khởi động lại bản mới - để các thay đổi
    code (vd: tính năng force-renew) có hiệu lực ngay mà không cần thao tác tay.
    """
    engine_run = STATE_DIR / "arp_engine.py"
    st = _read_engine_status()
    if st.get("running") and not force_restart:
        try:
            if engine_run.is_file() and ENGINE.is_file():
                if engine_run.stat().st_mtime >= ENGINE.stat().st_mtime:
                    return True, "engine đang chạy"
        except OSError:
            return True, "engine đang chạy"
    if st.get("running"):
        _write_request(shutdown=True)
        for _ in range(20):
            if not _read_engine_status().get("running"):
                break
            time.sleep(0.25)
    _write_request()  # tạo request.json trước để engine đọc ngay
    py = sys.executable or "/usr/bin/python3"
    # Tiến trình root (qua osascript) KHÔNG mở được file trên ổ ngoài /Volumes
    # do TCC chặn -> copy engine (file độc lập, chỉ dùng stdlib) sang STATE_DIR
    # trên ổ hệ thống rồi chạy bản copy.
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ENGINE, engine_run)
        os.chmod(engine_run, 0o755)
    except OSError as e:
        return False, f"Không copy được engine sang {STATE_DIR}: {e}"
    # Engine tự daemon hoá (double-fork + setsid) nên KHÔNG dùng nohup/&:
    # tránh lỗi "nohup: can't detach from console" khi chạy qua osascript.
    shell = (
        f"mkdir -p {STATE_DIR} && chmod 777 {STATE_DIR}; "
        f"{_q(py)} {_q(str(engine_run))} {_q(str(STATE_DIR))} --daemon && echo started"
    )
    script = f'do shell script "{_osx_escape(shell)}" with administrator privileges'
    try:
        p = subprocess.run(["osascript", "-e", script],
                           capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return False, "Hết thời gian chờ nhập mật khẩu admin."
    if p.returncode != 0:
        err = (p.stderr or "").strip()
        if "-128" in err or "User canceled" in err:
            return False, "Bạn đã huỷ hộp thoại quyền admin."
        return False, f"Không khởi động được engine: {err or 'lỗi không rõ'}"
    # chờ engine báo sống
    for _ in range(20):
        if _read_engine_status().get("running"):
            return True, "engine đã khởi động"
        time.sleep(0.25)
    return False, "Engine không phản hồi sau khi khởi động (xem engine.log)."


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _osx_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _bump_and_push() -> None:
    global _generation
    with _lock:
        _generation = int(time.time() * 1000)
    _write_request()


# --------------------------------------------------------------------------
# Giám sát hiện diện & thay đổi mạng thời gian thực
# --------------------------------------------------------------------------

def _check_device_alive(ip: str, mac: str) -> bool:
    try:
        p = subprocess.run(
            ["ping", "-c", "1", "-t", "1", "-W", "400", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.0
        )
        if p.returncode == 0:
            return True
    except (subprocess.TimeoutExpired, OSError):
        pass

    for port in (5353, 62078, 80, 443):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.15)
                s.connect((ip, port))
                return True
        except (ConnectionRefusedError, ConnectionResetError):
            return True
        except (OSError, socket.timeout):
            pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"\x00", (ip, 9))
    except OSError:
        pass

    return False


def _check_network_and_blocks() -> None:
    global _last_subnet, _last_threat_counts
    # Kiểm tra các mối đe dọa tấn công ARP mới phát hiện từ sniffer
    threats = _read_threats()
    for t in threats:
        mac = t.get("attacker_mac", "").lower()
        cnt = t.get("count", 0)
        last_cnt = _last_threat_counts.get(mac, 0)
        if cnt > last_cnt:
            _last_threat_counts[mac] = cnt
            name = t.get("attacker_name") or t.get("attacker_ip") or mac
            _add_event(
                "threat_detected",
                f"🚨 PHÁT HIỆN TẤN CÔNG: Thiết bị {name} ({mac}) đang giả mạo Gateway {t.get('spoofed_ip')}!",
                t
            )
    info = net_info()
    cur_subnet = info.get("subnet") or ""
    prefixlen = info.get("prefixlen")

    if cur_subnet and _last_subnet and cur_subnet != _last_subnet:
        with _lock:
            try:
                cur_net = ipaddress.ip_network(f"{info['ip']}/{prefixlen}", strict=False)
                removed = [ip for ip in list(_blocks.keys()) if ipaddress.ip_address(ip) not in cur_net]
                for ip in removed:
                    del _blocks[ip]
                removed_m = [ip for ip in list(_monitors.keys()) if ipaddress.ip_address(ip) not in cur_net]
                for ip in removed_m:
                    del _monitors[ip]
                if removed or removed_m:
                    _bump_and_push()
                    _add_event(
                        "network_changed",
                        f"Mạng Wi-Fi đã đổi sang {cur_subnet}/{prefixlen}. Đã tự động dọn {len(removed) + len(removed_m)} thiết bị mạng cũ.",
                        {"old_subnet": _last_subnet, "new_subnet": cur_subnet, "removed": removed + removed_m}
                    )
            except Exception:
                pass
        _last_subnet = cur_subnet
    elif cur_subnet and not _last_subnet:
        _last_subnet = cur_subnet
        with _lock:
            try:
                cur_net = ipaddress.ip_network(f"{info['ip']}/{prefixlen}", strict=False)
                removed = [ip for ip in list(_blocks.keys()) if ipaddress.ip_address(ip) not in cur_net]
                for ip in removed:
                    del _blocks[ip]
                if removed:
                    _bump_and_push()
            except Exception:
                pass

    with _lock:
        if not _blocks:
            return
        blocks_copy = {ip: dict(b) for ip, b in _blocks.items()}

    arp_table = _arp_table()
    ips_to_check = []

    for ip, b in blocks_copy.items():
        mac = b.get("mac", "").lower()
        name = b.get("name", "")

        migrated_ip = None
        for cur_ip, cur_mac in arp_table.items():
            if cur_mac.lower() == mac and cur_ip != ip:
                migrated_ip = cur_ip
                break

        if migrated_ip:
            with _lock:
                if ip in _blocks:
                    migrated_entry = dict(_blocks.pop(ip))
                    migrated_entry["status"] = "online"
                    migrated_entry["fail_count"] = 0
                    migrated_entry["last_seen"] = time.time()
                    _blocks[migrated_ip] = migrated_entry
                    _bump_and_push()
            _add_event(
                "ip_changed",
                f"Thiết bị {name or migrated_ip} đã đổi sang IP mới {migrated_ip} (trước đó: {ip}). Đã tự động cập nhật chặn IP mới!",
                {"old_ip": ip, "new_ip": migrated_ip, "mac": mac, "name": name}
            )
        else:
            ips_to_check.append((ip, mac, name))

    if not ips_to_check:
        return

    with ThreadPoolExecutor(max_workers=min(len(ips_to_check), 10)) as ex:
        futs = {ex.submit(_check_device_alive, ip, mac): (ip, mac, name)
                for ip, mac, name in ips_to_check}
        for fut in futs:
            ip, mac, name = futs[fut]
            try:
                alive = fut.result(timeout=2.0)
            except Exception:
                alive = False

            with _lock:
                if ip not in _blocks:
                    continue
                cur = _blocks[ip]
                if alive:
                    cur["fail_count"] = 0
                    cur["last_seen"] = time.time()
                    if cur.get("status") == "offline":
                        cur["status"] = "online"
                        _add_event(
                            "device_online",
                            f"Thiết bị {name or ip} ({ip}) đã kết nối lại mạng!",
                            {"ip": ip, "mac": mac, "name": name}
                        )
                else:
                    cur["fail_count"] = cur.get("fail_count", 0) + 1
                    if cur["fail_count"] >= 3 and cur.get("status") != "offline":
                        cur["status"] = "offline"
                        _add_event(
                            "device_offline",
                            f"Thiết bị {name or ip} ({ip}) đã ngắt kết nối hoặc đổi mạng!",
                            {"ip": ip, "mac": mac, "name": name}
                        )


def _monitor_loop() -> None:
    global _last_auto_scan
    time.sleep(1.5)
    while True:
        try:
            _check_network_and_blocks()
        except Exception:
            pass
        if _auto_monitor_enabled and time.time() - _last_auto_scan >= AUTO_SCAN_INTERVAL:
            _last_auto_scan = time.time()
            try:
                scan()   # quét nền: tự monitor thiết bị lạ + tự ngừng khi dò được tên
            except Exception:
                pass
        time.sleep(2.0)


# --------------------------------------------------------------------------
# Hành động block/unblock/stop/cleanup
# --------------------------------------------------------------------------

def do_block(ip: str, mac: str, interval_ms: int, name: str = "") -> dict:
    info = net_info()
    if not ip or not mac:
        return {"ok": False, "error": "Thiếu ip hoặc mac."}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "IP không hợp lệ."}
    if not addr.is_private:
        return {"ok": False, "error": "Chỉ chặn thiết bị trong subnet private."}
    if ip == info["gateway_ip"]:
        return {"ok": False, "error": "Không thể chặn gateway."}
    if ip == info["ip"]:
        return {"ok": False, "error": "Không thể tự chặn chính máy này."}
    cur = _arp_table().get(ip)
    if cur and _norm_mac(mac) != cur:
        return {"ok": False,
                "error": f"MAC không khớp bảng ARP hiện tại ({cur}). Hãy quét lại."}
    interval_ms = max(5, min(5000, int(interval_ms or DEFAULT_INTERVAL_MS)))

    with _lock:
        if ip not in _blocks and len(_blocks) >= MAX_ENTRIES:
            return {"ok": False, "error": f"Đã đạt tối đa {MAX_ENTRIES} thiết bị."}
        _blocks[ip] = {
            "mac": _norm_mac(mac),
            "name": name,
            "interval_ms": interval_ms,
            "status": "online",
            "fail_count": 0,
            "last_seen": time.time(),
        }
        had_monitor = _monitors.pop(ip, None) is not None   # chặn thắng: gỡ giám sát nếu có

    ok, msg = ensure_engine()
    if not ok:
        with _lock:
            _blocks.pop(ip, None)
        return {"ok": False, "error": msg}
    _bump_and_push()
    _add_event("block", f"Đã bắt đầu chặn {name or ip} ({ip})" +
               (" — đã tự gỡ chế độ giám sát" if had_monitor else ""),
               {"ip": ip, "mac": mac, "name": name})
    return {"ok": True, "message": f"Đã chặn {name or ip}", "blocked": _blocked_list()}


def do_monitor(ip: str, mac: str, name: str = "") -> dict:
    """Bật chế độ giám sát (MITM trong suốt): máy đích vẫn dùng mạng bình thường,
    NetFence ghi lại tên miền (DNS + TLS SNI) mà thiết bị truy cập."""
    info = net_info()
    if not ip or not mac:
        return {"ok": False, "error": "Thiếu ip hoặc mac."}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "IP không hợp lệ."}
    if not addr.is_private:
        return {"ok": False, "error": "Chỉ giám sát thiết bị trong subnet private."}
    if ip == info["gateway_ip"]:
        return {"ok": False, "error": "Không thể giám sát gateway."}
    if ip == info["ip"]:
        return {"ok": False, "error": "Không thể giám sát chính máy này."}
    with _lock:
        if ip in _blocks:
            return {"ok": False, "error": "Thiết bị đang bị chặn — bỏ chặn trước khi giám sát."}
    cur = _arp_table().get(ip)
    if cur and _norm_mac(mac) != cur:
        return {"ok": False,
                "error": f"MAC không khớp bảng ARP hiện tại ({cur}). Hãy quét lại."}

    with _lock:
        if ip not in _monitors and len(_monitors) >= MAX_ENTRIES:
            return {"ok": False, "error": f"Đã đạt tối đa {MAX_ENTRIES} thiết bị giám sát."}
        _monitors[ip] = {
            "mac": _norm_mac(mac),
            "name": name,
            "interval_ms": DEFAULT_INTERVAL_MS,
            "status": "online",
            "last_seen": time.time(),
        }

    ok, msg = ensure_engine()
    if not ok:
        with _lock:
            _monitors.pop(ip, None)
        return {"ok": False, "error": msg}
    ok_s, msg_s = ensure_sniffer()
    if not ok_s:
        with _lock:
            _monitors.pop(ip, None)
        _bump_and_push()
        return {"ok": False, "error": msg_s}
    _bump_and_push()
    _add_event("monitor", f"Đã bật giám sát {name or ip} ({ip})", {"ip": ip, "mac": mac, "name": name})
    return {"ok": True, "message": f"Đang giám sát {name or ip}", "monitors": _monitored_list()}


def do_monitor_stop(ip: str) -> dict:
    with _lock:
        existed = _monitors.pop(ip, None)
    if existed is None:
        return {"ok": True, "message": f"{ip} vốn không bị giám sát", "monitors": _monitored_list()}
    _bump_and_push()
    name = existed.get("name") or ip
    _add_event("monitor_stop", f"Đã dừng giám sát {name} ({ip})", {"ip": ip, "name": name})
    return {"ok": True, "message": f"Đã dừng giám sát {name}", "monitors": _monitored_list()}


def do_unblock(ip: str) -> dict:
    with _lock:
        existed = _blocks.pop(ip, None)
    if existed is None:
        return {"ok": True, "message": f"{ip} vốn không bị chặn", "blocked": _blocked_list()}
    _bump_and_push()
    name = existed.get("name") or ip
    _add_event("unblock", f"Đã bỏ chặn {name} ({ip})", {"ip": ip, "name": name})
    return {"ok": True, "message": f"Đã bỏ chặn {name}", "blocked": _blocked_list()}


def do_stop() -> dict:
    with _lock:
        _blocks.clear()
        _monitors.clear()
    global _generation
    _generation = int(time.time() * 1000)
    _write_request(shutdown=True)
    _add_event("stop", "Đã bỏ chặn/bỏ giám sát tất cả thiết bị & dừng engine.", {})
    return {"ok": True, "message": "Đã bỏ chặn/bỏ giám sát tất cả & dừng engine.", "blocked": []}


def do_cleanup_offline() -> dict:
    with _lock:
        to_remove = [ip for ip, b in _blocks.items() if b.get("status") == "offline"]
        for ip in to_remove:
            del _blocks[ip]
        if to_remove:
            _bump_and_push()
            _add_event(
                "cleanup",
                f"Đã dọn dẹp {len(to_remove)} thiết bị ngoại tuyến / đã đổi mạng.",
                {"removed": to_remove}
            )
    return {"ok": True, "message": f"Đã dọn dẹp {len(to_remove)} thiết bị ngoại tuyến.", "blocked": _blocked_list()}


def do_auto_monitor(enabled: bool) -> dict:
    global _auto_monitor_enabled, _last_auto_scan
    _auto_monitor_enabled = bool(enabled)
    if _auto_monitor_enabled:
        _last_auto_scan = 0.0   # cho phép quét nền chạy ngay ở chu kỳ kế tiếp
    else:
        with _lock:
            to_remove = [ip for ip, m in _monitors.items() if m.get("auto")]
            for ip in to_remove:
                del _monitors[ip]
        if to_remove:
            _bump_and_push()
    return {"ok": True, "enabled": _auto_monitor_enabled}


def _blocked_list() -> list:
    with _lock:
        return [{"ip": ip, **b} for ip, b in _blocks.items()]


def _monitored_list() -> list:
    with _lock:
        return [{"ip": ip, **m} for ip, m in _monitors.items()]


def do_sniff_start() -> dict:
    ok, msg = ensure_sniffer()
    return {"ok": ok, "message": msg if ok else None,
            "error": None if ok else msg, "sniffer": _read_sniffer_status()}


def status() -> dict:
    with _lock:
        blk = _blocked_list()
        mon = _monitored_list()
        evts = list(_events)
        online_cnt = sum(1 for b in blk if b.get("status") != "offline")
        offline_cnt = sum(1 for b in blk if b.get("status") == "offline")
    eng_st = _read_engine_status()
    info = net_info()
    doms_map = _read_domains([m["ip"] for m in mon])
    for m in mon:
        g = fingerprint.guess_from_domains([e["d"] for e in doms_map.get(m["ip"], [])])
        if g:
            m["guess"] = g
    return {
        "ok": True,
        "info": info,
        "engine": eng_st,
        "sniffer": _read_sniffer_status(),
        "blocked": blk,
        "monitors": mon,
        "domains": doms_map,
        "auto_monitor": _auto_monitor_enabled,
        "blocked_summary": {
            "total": len(blk),
            "online": online_cnt,
            "offline": offline_cnt,
        },
        "defense": {
            "active": eng_st.get("gateway_locked", False),
            "gateway_ip": info.get("gateway_ip", ""),
            "gateway_mac": info.get("gateway_mac", ""),
        },
        "threats": _read_threats(),
        "events": evts,
    }


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "NetFence/1.0"

    def log_message(self, *a):  # yên lặng
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json; charset=utf-8")

    def _file(self, path: Path) -> None:
        if not path.is_file():
            self._send(404, b"Not found", "text/plain")
            return
        ctype = {
            ".html": "text/html; charset=utf-8", ".css": "text/css",
            ".js": "application/javascript", ".svg": "image/svg+xml",
        }.get(path.suffix, "application/octet-stream")
        self._send(200, path.read_bytes(), ctype)

    def do_GET(self):  # noqa: N802
        p = urlparse(self.path).path
        if p in ("/", "/index.html"):
            self._file(STATIC / "index.html")
        elif p == "/api/status":
            self._json(status())
        elif p == "/api/scan":
            try:
                qs = parse_qs(urlparse(self.path).query)
                am_param = qs.get("auto_monitor")
                am = (am_param[0] != "0") if am_param is not None else _auto_monitor_enabled
                self._json(scan(auto_monitor=am))
            except Exception as e:  # noqa: BLE001
                self._json({"ok": False, "error": str(e)}, 500)
        elif p.startswith("/static/"):
            self._file(STATIC / p[len("/static/"):])
        else:
            self._send(404, b"Not found", "text/plain")

    def do_POST(self):  # noqa: N802
        p = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._json({"ok": False, "error": "JSON không hợp lệ."}, 400)
            return
        try:
            if p == "/api/block":
                self._json(do_block(data.get("ip", ""), data.get("mac", ""),
                                    data.get("interval_ms", DEFAULT_INTERVAL_MS),
                                    data.get("name", "")))
            elif p == "/api/unblock":
                self._json(do_unblock(data.get("ip", "")))
            elif p == "/api/monitor":
                self._json(do_monitor(data.get("ip", ""), data.get("mac", ""),
                                      data.get("name", "")))
            elif p == "/api/monitor_stop":
                self._json(do_monitor_stop(data.get("ip", "")))
            elif p == "/api/auto_monitor":
                self._json(do_auto_monitor(bool(data.get("enabled", True))))
            elif p == "/api/stop":
                self._json(do_stop())
            elif p == "/api/cleanup_offline":
                self._json(do_cleanup_offline())
            elif p == "/api/events/clear":
                with _lock:
                    _events.clear()
                self._json({"ok": True})
            elif p == "/api/threats/clear":
                try:
                    with open(THREATS_FILE, "w") as f:
                        json.dump({"threats": []}, f)
                except Exception:
                    pass
                self._json({"ok": True})
            elif p == "/api/sniff":
                self._json(do_sniff_start())
            elif p == "/api/restart":
                ok, msg = ensure_engine(force_restart=True)
                self._json({"ok": ok, "message": msg})
            else:
                self._send(404, b"Not found", "text/plain")
        except Exception as e:  # noqa: BLE001
            self._json({"ok": False, "error": str(e)}, 500)


class Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        exc_type = sys.exc_info()[0]
        if exc_type in (ConnectionResetError, BrokenPipeError, TimeoutError):
            return
        super().handle_error(request, client_address)


def main() -> int:
    if sys.platform != "darwin":
        print("NetFence chỉ hỗ trợ macOS.", file=sys.stderr)
        return 1
    _ensure_local_network_python()
    if not (STATIC / "index.html").is_file():
        print(f"Thiếu giao diện: {STATIC/'index.html'}", file=sys.stderr)
        return 1
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=_monitor_loop, daemon=True, name="netfence-monitor").start()
    # Tự động kích hoạt phòng vệ (Static Gateway Lock) và IDS Sniffer ngay khi bật server
    threading.Thread(target=ensure_engine, daemon=True).start()
    threading.Thread(target=ensure_sniffer, daemon=True).start()
    srv = Server((HOST, PORT), Handler)
    print(f"NetFence chạy tại: http://{HOST}:{PORT}/")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
