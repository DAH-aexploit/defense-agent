"""테스트용 raw IPv4/TCP 패킷 builder, checksum 생략과 엔진 검증 제외"""

from __future__ import annotations

import struct


def build_packet(dport: int, payload: bytes, sport: int = 40001,
                 flags: int = 0x18, proto: int = 6,
                 src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02",
                 seq: int = 1, frag: int = 0) -> bytes:
    """최소 유효 IPv4(20B)+TCP(20B) header 기반 payload 구성, 기본 flag PSH+ACK"""
    total_len = min(20 + 20 + len(payload), 0xFFFF)  # IP total_len은 16비트
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234, frag, 64, proto, 0, src, dst)
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, (5 << 4), flags, 65535, 0, 0)
    return ip + tcp + payload


def build_udp_packet(dport: int, payload: bytes, sport: int = 40001,
                     src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02") -> bytes:
    """최소 유효 IPv4(20B)+UDP(8B) header 기반 payload 구성, binary protocol test용"""
    total_len = min(20 + 8 + len(payload), 0xFFFF)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234, 0, 64, 17, 0, src, dst)
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    return ip + udp + payload


def build_ipv6_packet(dport: int, payload: bytes, sport: int = 40001,
                      src: bytes = b"\x20\x01" + b"\x00" * 14,
                      dst: bytes = b"\x20\x02" + b"\x00" * 14,
                      seq: int = 1) -> bytes:
    """최소 IPv6+TCP packet, extension header 없는 기본 경로 test용"""
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, (5 << 4), 0x18, 65535, 0, 0)
    ip6 = struct.pack(">IHBB16s16s", 6 << 28, len(tcp) + len(payload), 6, 64, src, dst)
    return ip6 + tcp + payload


def http_get(path: str, host: str = "target", cookie: str | None = None,
             extra: dict | None = None) -> bytes:
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}"]
    if cookie:
        lines.append(f"Cookie: {cookie}")
    for k, v in (extra or {}).items():
        lines.append(f"{k}: {v}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "ignore")


def packet_for(dport: int, path: str, **kw) -> bytes:
    """지정 port 대상 HTTP GET raw packet 생성"""
    return build_packet(dport, http_get(path, **kw))


def write_pcap(path: str, records, linktype: int = 101) -> None:
    """테스트용 classic pcap 작성, records=[(ts_float, raw_ip_bytes)]와 linktype 101=raw IP"""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for ts, ip in records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            f.write(struct.pack("<IIII", sec, usec, len(ip), len(ip)))
            f.write(ip)
