#!/usr/bin/env python3
"""NetFence DHCP & ARP Intrusion Detection Sniffer (privileged).

Chạy bằng ROOT. Dùng libpcap bắt:
  1. Gói DHCP (UDP 67/68): Trích xuất hostname và vendor_class ghi vào dhcp_names.json.
  2. Gói ARP: Phát hiện các đòn tấn công ARP Spoofing (kẻ mạo danh Gateway) ghi vào threats.json.
  3. Gói DNS (UDP 53) & TLS ClientHello/SNI (TCP 443) của thiết bị đang GIÁM SÁT
     (mode=monitor trong request.json): trích xuất tên miền truy cập ghi vào
     domains.json (chế độ Monitor/Audit: MITM trong suốt, máy đích vẫn online).
"""
from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import re
import socket
import struct
import sys
import time

PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF
SNAPLEN = 1600
SAVE_EVERY = 2.0
MAX_DOMAINS_PER_IP = 200
DOMAIN_DEDUPE_SEC = 15.0   # cùng 1 (ip, domain, src) không ghi lại trong khoảng này


class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_int32)]


class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("ts", timeval), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]


class bpf_program(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


def _load_pcap():
    path = ctypes.util.find_library("pcap") or "/usr/lib/libpcap.dylib"
    lib = ctypes.CDLL(path)
    lib.pcap_open_live.restype = ctypes.c_void_p
    lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_char_p]
    lib.pcap_next_ex.restype = ctypes.c_int
    lib.pcap_next_ex.argtypes = [ctypes.c_void_p,
                                 ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)),
                                 ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
    lib.pcap_compile.restype = ctypes.c_int
    lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(bpf_program),
                                 ctypes.c_char_p, ctypes.c_int, ctypes.c_uint]
    lib.pcap_setfilter.restype = ctypes.c_int
    lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(bpf_program)]
    lib.pcap_geterr.restype = ctypes.c_char_p
    lib.pcap_geterr.argtypes = [ctypes.c_void_p]
    return lib


def _default_iface() -> str:
    try:
        import subprocess
        out = subprocess.run(["route", "-n", "get", "default"],
                             capture_output=True, text=True).stdout
        m = re.search(r"interface:\s*(\S+)", out)
        return m.group(1) if m else "en0"
    except OSError:
        return "en0"


def _parse_dhcp(pkt: bytes):
    """Trả (mac, hostname, vendor_class) nếu là gói DHCP từ client, ngược lại None."""
    if len(pkt) < 14 + 20 + 8 + 240:
        return None
    if pkt[12:14] != b"\x08\x00":
        return None
    eth_src = ":".join(f"{b:02x}" for b in pkt[6:12])
    ihl = (pkt[14] & 0x0F) * 4
    if pkt[14 + 9] != 17:
        return None
    udp = 14 + ihl
    sport = struct.unpack("!H", pkt[udp:udp + 2])[0]
    dport = struct.unpack("!H", pkt[udp + 2:udp + 4])[0]
    if 67 not in (sport, dport) and 68 not in (sport, dport):
        return None
    dhcp = udp + 8
    boot = pkt[dhcp:]
    if len(boot) < 240 or boot[236:240] != b"\x63\x82\x53\x63":
        return None
    chaddr = ":".join(f"{b:02x}" for b in boot[28:34])
    mac = chaddr if chaddr != "00:00:00:00:00:00" else eth_src

    hostname = ""
    vendor = ""
    is_client_msg = False
    i = 240
    while i < len(boot):
        opt = boot[i]
        if opt == 255:
            break
        if opt == 0:
            i += 1
            continue
        if i + 1 >= len(boot):
            break
        ln = boot[i + 1]
        val = boot[i + 2:i + 2 + ln]
        if opt == 12:
            hostname = val.decode("utf-8", "ignore").strip()
        elif opt == 60:
            vendor = val.decode("utf-8", "ignore").strip()
        elif opt == 53 and ln >= 1:
            is_client_msg = val[0] in (1, 3, 8)
        i += 2 + ln

    if not is_client_msg or (not hostname and not vendor):
        return None
    return mac.lower(), hostname, vendor


def _parse_arp(pkt: bytes):
    """Phân tích khung Ethernet chứa ARP (opcode, sender_mac, sender_ip, target_mac, target_ip)."""
    if len(pkt) < 42:
        return None
    if pkt[12:14] != b"\x08\x06":
        return None
    try:
        hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack("!HHBBH", pkt[14:22])
        if hw_type != 1 or proto_type != 0x0800 or hw_len != 6 or proto_len != 4:
            return None
        smac = ":".join(f"{b:02x}" for b in pkt[22:28]).lower()
        sip = socket.inet_ntoa(pkt[28:32])
        tmac = ":".join(f"{b:02x}" for b in pkt[32:38]).lower()
        tip = socket.inet_ntoa(pkt[38:42])
        return {
            "opcode": opcode,
            "sender_mac": smac,
            "sender_ip": sip,
            "target_mac": tmac,
            "target_ip": tip,
        }
    except Exception:
        return None


def _parse_dns_queries(pkt: bytes):
    """Trả (src_ip, [qname, ...]) nếu là truy vấn DNS (UDP dst 53), ngược lại None."""
    if len(pkt) < 14 + 20 + 8 + 12:
        return None
    if pkt[12:14] != b"\x08\x00":
        return None
    ip_start = 14
    ihl = (pkt[ip_start] & 0x0F) * 4
    if pkt[ip_start + 9] != 17:  # không phải UDP
        return None
    src_ip = socket.inet_ntoa(pkt[ip_start + 12: ip_start + 16])
    udp = ip_start + ihl
    if len(pkt) < udp + 8:
        return None
    dport = struct.unpack("!H", pkt[udp + 2:udp + 4])[0]
    if dport != 53:
        return None
    dns = pkt[udp + 8:]
    if len(dns) < 12:
        return None
    qdcount = struct.unpack("!H", dns[4:6])[0]
    if qdcount == 0 or qdcount > 8:
        return None
    names: list[str] = []
    off = 12
    for _ in range(qdcount):
        labels: list[str] = []
        guard = 0
        while off < len(dns) and guard < 64:
            guard += 1
            ln = dns[off]
            if ln == 0:
                off += 1
                break
            if ln & 0xC0:  # tên nén trong câu hỏi: hiếm/bất thường -> dừng query này
                return src_ip, names
            if off + 1 + ln > len(dns):
                return src_ip, names
            labels.append(dns[off + 1: off + 1 + ln].decode("ascii", "ignore"))
            off += 1 + ln
        if off + 4 > len(dns):
            break
        off += 4  # QTYPE + QCLASS
        if labels:
            name = ".".join(labels).lower()
            # Bỏ qua truy vấn ngược (reverse DNS)
            if len(labels) >= 3 and ".".join(labels[-2:]) in ("in-addr.arpa", "ip6.arpa"):
                continue
            names.append(name)
    return src_ip, names


def _parse_tls_sni(pkt: bytes):
    """Trả (src_ip, server_name) từ TLS ClientHello (TCP 443), ngược lại None.

    Chỉ xử lý ClientHello nằm trọn trong 1 segment TCP (trường hợp phổ biến);
    gói bị phân mảnh sẽ bỏ qua (best-effort).
    """
    if len(pkt) < 14 + 20:
        return None
    if pkt[12:14] != b"\x08\x00":
        return None
    ip_start = 14
    ihl = (pkt[ip_start] & 0x0F) * 4
    if pkt[ip_start + 9] != 6:  # không phải TCP
        return None
    src_ip = socket.inet_ntoa(pkt[ip_start + 12: ip_start + 16])
    tcp = ip_start + ihl
    if len(pkt) < tcp + 20:
        return None
    dport = struct.unpack("!H", pkt[tcp + 2:tcp + 4])[0]
    if dport != 443:
        return None
    data_off = (pkt[tcp + 12] >> 4) * 4
    payload = pkt[tcp + data_off:]
    if len(payload) < 6 or payload[0] != 0x16:  # TLS record: handshake
        return None
    hs = payload[5:]
    if len(hs) < 43 or hs[0] != 0x01:  # ClientHello
        return None
    p = 1 + 3 + 2 + 32  # type(1) + len(3) + version(2) + random(32)
    sid_len = hs[p]
    p += 1 + sid_len
    if len(hs) < p + 2:
        return None
    cs_len = struct.unpack("!H", hs[p:p + 2])[0]
    p += 2 + cs_len
    if len(hs) < p + 1:
        return None
    comp_len = hs[p]
    p += 1 + comp_len
    if len(hs) < p + 2:
        return None
    ext_len = struct.unpack("!H", hs[p:p + 2])[0]
    p += 2
    end = min(p + ext_len, len(hs))
    while p + 4 <= end:
        etype, elen = struct.unpack("!HH", hs[p:p + 4])
        p += 4
        if etype == 0:  # server_name extension
            data = hs[p:p + elen]
            # server_name_list: list_len(2) + name_type(1)=0 + name_len(2) + hostname
            if len(data) >= 5 and data[2] == 0:
                name_len = struct.unpack("!H", data[3:5])[0]
                try:
                    sni = data[5:5 + name_len].decode("ascii", "ignore").lower().rstrip(".")
                except Exception:
                    return None
                return (src_ip, sni) if sni else None
            return None
        p += elen
    return None


class Sniffer:
    def __init__(self, state_dir: str, iface: str):
        self.state_dir = state_dir
        self.iface = iface
        self.out = os.path.join(state_dir, "dhcp_names.json")
        self.status = os.path.join(state_dir, "sniffer_status.json")
        self.threats_path = os.path.join(state_dir, "threats.json")
        self.domains_path = os.path.join(state_dir, "domains.json")
        self.req_path = os.path.join(state_dir, "request.json")
        self.pid_path = os.path.join(state_dir, "sniffer.pid")
        self._ensure_single_instance()
        self.names = self._load()
        self.threats = self._load_threats()
        self.domains: dict[str, list] = self._load_domains()
        self.domain_seen: dict[tuple, float] = {}
        self.mac_to_ip: dict[str, str] = {}
        self.monitored_ips: set[str] = set()

    def _ensure_single_instance(self) -> None:
        try:
            if os.path.isfile(self.pid_path):
                with open(self.pid_path) as f:
                    old_pid = int(f.read().strip())
                if old_pid > 0 and old_pid != os.getpid():
                    try:
                        os.kill(old_pid, 9)
                    except OSError:
                        pass
            with open(self.pid_path, "w") as f:
                f.write(str(os.getpid()))
        except Exception:
            pass

    def _cleanup_pid(self) -> None:
        try:
            if os.path.isfile(self.pid_path):
                os.remove(self.pid_path)
        except OSError:
            pass

    def _load(self) -> dict:
        try:
            with open(self.out) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _load_threats(self) -> dict:
        try:
            with open(self.threats_path) as f:
                d = json.load(f)
                return {t["attacker_mac"]: t for t in d.get("threats", [])}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save(self) -> None:
        tmp = self.out + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.names, f, ensure_ascii=False)
            os.replace(tmp, self.out)
            os.chmod(self.out, 0o666)
        except OSError:
            pass

    def _save_threats(self) -> None:
        tmp = self.threats_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"threats": list(self.threats.values())}, f, ensure_ascii=False)
            os.replace(tmp, self.threats_path)
            os.chmod(self.threats_path, 0o666)
        except OSError:
            pass

    def _load_domains(self) -> dict:
        try:
            with open(self.domains_path) as f:
                d = json.load(f)
            return d.get("domains", {})
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_domains(self) -> None:
        tmp = self.domains_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"domains": self.domains}, f, ensure_ascii=False)
            os.replace(tmp, self.domains_path)
            os.chmod(self.domains_path, 0o666)
        except OSError:
            pass

    def _record_domain(self, ip: str, domain: str, src: str, now: float) -> None:
        domain = (domain or "").strip().lower().rstrip(".")
        if not domain or "." not in domain or domain.endswith(".arpa"):
            return
        key = (ip, domain, src)
        if now - self.domain_seen.get(key, 0.0) < DOMAIN_DEDUPE_SEC:
            return
        self.domain_seen[key] = now
        if len(self.domain_seen) > 5000:  # dọn bảng dedupe định kỳ
            cutoff = now - DOMAIN_DEDUPE_SEC * 4
            self.domain_seen = {k: v for k, v in self.domain_seen.items() if v > cutoff}
        lst = self.domains.setdefault(ip, [])
        lst.append({"d": domain, "ts": now, "src": src})
        if len(lst) > MAX_DOMAINS_PER_IP:
            del lst[:-MAX_DOMAINS_PER_IP]

    def _write_status(self, running: bool, note: str = "") -> None:
        try:
            with open(self.status, "w") as f:
                json.dump({"running": running, "pid": os.getpid(), "ts": time.time(),
                           "iface": self.iface, "count": len(self.names),
                           "threats_count": len(self.threats),
                           "domains_count": sum(len(v) for v in self.domains.values()),
                           "note": note}, f)
            os.chmod(self.status, 0o666)
        except OSError:
            pass

    def run(self) -> int:
        if os.geteuid() != 0:
            self._write_status(False, "cần chạy bằng root")
            print("Sniffer cần quyền root.", file=sys.stderr)
            return 1
        lib = _load_pcap()
        errbuf = ctypes.create_string_buffer(256)
        handle = lib.pcap_open_live(self.iface.encode(), SNAPLEN, 0, 500, errbuf)
        if not handle:
            self._write_status(False, "pcap_open_live lỗi: " + errbuf.value.decode())
            return 1
        fp = bpf_program()
        # Bắt DHCP, ARP, DNS (udp/53) và TLS ClientHello (tcp/443)
        bpf_expr = b"arp or (udp and (port 67 or port 68)) or udp port 53 or tcp port 443"
        if lib.pcap_compile(handle, ctypes.byref(fp), bpf_expr, 1, PCAP_NETMASK_UNKNOWN) == 0:
            lib.pcap_setfilter(handle, ctypes.byref(fp))

        self._write_status(True, "started")
        hdr = ctypes.POINTER(pcap_pkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        last_save = time.time()
        last_req_read = 0.0
        gw_ip = ""
        gw_mac = ""
        our_mac = ""

        while True:
            rc = lib.pcap_next_ex(handle, ctypes.byref(hdr), ctypes.byref(data))
            now = time.time()

            # Đọc lại thông tin gateway từ request.json mỗi 2s
            if now - last_req_read >= 2.0:
                last_req_read = now
                try:
                    if os.path.isfile(self.req_path):
                        with open(self.req_path) as rf:
                            rdata = json.load(rf)
                            if rdata.get("shutdown"):
                                self._write_status(False, "shutdown")
                                self._cleanup_pid()
                                return 0
                            gw_ip = rdata.get("gateway_ip", "").strip()
                            gw_mac = rdata.get("gateway_mac", "").strip().lower()
                            our_mac = rdata.get("our_mac", "").strip().lower()
                            mon = set()
                            for ent in rdata.get("entries", []):
                                if ent.get("mode") == "monitor" and ent.get("ip"):
                                    mon.add(str(ent["ip"]))
                            self.monitored_ips = mon
                except Exception:
                    pass

            if rc == 1:
                caplen = hdr.contents.caplen
                pkt = ctypes.string_at(data, caplen)

                # 1. Kiểm tra DHCP
                parsed_dhcp = _parse_dhcp(pkt)
                if parsed_dhcp:
                    mac, hostname, vendor = parsed_dhcp
                    entry = self.names.get(mac, {})
                    if hostname:
                        entry["hostname"] = hostname
                    if vendor:
                        entry["vendor_class"] = vendor
                    entry["ts"] = now
                    self.names[mac] = entry

                # 2. Kiểm tra ARP
                parsed_arp = _parse_arp(pkt)
                if parsed_arp:
                    smac = parsed_arp["sender_mac"]
                    sip = parsed_arp["sender_ip"]

                    # Ghi nhận IP thực tế của MAC này
                    if sip and sip != gw_ip and smac:
                        self.mac_to_ip[smac] = sip

                    # PHÁT HIỆN TẤN CÔNG ARP SPOOFING:
                    # Gói tin tuyên bố sender_ip == gw_ip nhưng sender_mac khác MAC router thật
                    if gw_ip and gw_mac and sip == gw_ip:
                        if smac != gw_mac and smac != our_mac and smac != "00:00:00:00:00:00":
                            real_ip = self.mac_to_ip.get(smac, "")
                            name_info = self.names.get(smac, {})
                            name = name_info.get("hostname", "")
                            vendor_cls = name_info.get("vendor_class", "")

                            th = self.threats.get(smac, {
                                "attacker_mac": smac,
                                "attacker_ip": real_ip,
                                "attacker_name": name,
                                "vendor_class": vendor_cls,
                                "spoofed_ip": gw_ip,
                                "target_ip": parsed_arp["target_ip"],
                                "first_seen": now,
                                "first_seen_str": time.strftime("%H:%M:%S", time.localtime(now)),
                                "count": 0,
                            })
                            th["last_seen"] = now
                            th["last_seen_str"] = time.strftime("%H:%M:%S", time.localtime(now))
                            th["count"] += 1
                            if not th.get("attacker_ip") and real_ip:
                                th["attacker_ip"] = real_ip
                            if not th.get("attacker_name") and name:
                                th["attacker_name"] = name
                            self.threats[smac] = th
                            self._save_threats()

                # 3. DNS & TLS SNI — chỉ ghi cho thiết bị đang được giám sát
                if self.monitored_ips:
                    pdns = _parse_dns_queries(pkt)
                    if pdns:
                        src_ip, qnames = pdns
                        if src_ip in self.monitored_ips:
                            for qn in qnames:
                                self._record_domain(src_ip, qn, "dns", now)
                    psni = _parse_tls_sni(pkt)
                    if psni:
                        src_ip, sni_name = psni
                        if src_ip in self.monitored_ips:
                            self._record_domain(src_ip, sni_name, "sni", now)

            if now - last_save >= SAVE_EVERY:
                self._save()
                self._save_threats()
                self._save_domains()
                self._write_status(True)
                last_save = now


def _daemonize(log_path: str) -> None:
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    logfd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(logfd, 1)
    os.dup2(logfd, 2)


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    daemon = "--daemon" in sys.argv[1:]
    state_dir = args[0] if args else "/tmp/netfence"
    iface = args[1] if len(args) > 1 else _default_iface()
    os.makedirs(state_dir, exist_ok=True)
    if daemon:
        _daemonize(os.path.join(state_dir, "sniffer.log"))
    return Sniffer(state_dir, iface).run()


if __name__ == "__main__":
    raise SystemExit(main())
