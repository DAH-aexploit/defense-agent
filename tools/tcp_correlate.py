#!/usr/bin/env python3
"""결정론적 TCP 연결 상관분석 (오프라인 분석 전용 · verdict 경로 무관).

완전한 연결 식별과 seq 기반 재조립으로 flag 응답을 올바른 요청에 귀속한다. 기존 `(src, sport)`
키는 source-port 재사용 시 서로 다른 연결을 병합해 flag를 잘못 귀속하고 재조립 산출물을 오염시켰다.

연결 식별: (ip_version, proto, client_ip, client_port, server_ip, server_port, generation)
  - generation: client SYN(ACK 없는 SYN) 수신 시 같은 5-tuple의 이전 상태를 폐기하고 +1
  - retransmission/중복(같은 seq·len)과 cross-pcap 중복 캡처는 삽입하지 않음
  - FIN/RST를 기록하고 다음 SYN 전까지 teardown 재전송을 흡수
  - payload는 capture 순서가 아니라 sequence 번호로 재조립(out-of-order·overlap first-seen)
  - TCP 32-bit sequence wraparound 안전(ISN 기준 offset 마스킹)

HTTP keep-alive는 Content-Length/chunked framing으로 transaction 단위 분리한다.
실제 flag/token/cookie는 다루지 않으며, 식별에는 짧은 SHA-256 fingerprint만 쓴다.
"""
from __future__ import annotations

import hashlib
import struct

_SYN = 0x02
_ACK = 0x10
_FIN = 0x01
_RST = 0x04


def parse_tcp(ip: bytes):
    """IPv4/TCP 패킷을 (ver, proto, src, sport, dst, dport, seq, flags, payload)로 파싱. 실패 시 None."""
    if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 0xF) * 4
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None
    sport, dport, seq = struct.unpack_from(">HHI", tcp, 0)
    doff = (tcp[12] >> 4) * 4
    if doff < 20 or len(tcp) < doff:
        return None
    return (4, 6, bytes(ip[12:16]), sport, bytes(ip[16:20]), dport, seq, tcp[13], tcp[doff:])


def _reassemble(seqmap: dict, base, cap: int = 1 << 20) -> bytes:
    """seq→payload 맵을 ISN 기준 offset으로 정렬 재조립. out-of-order·overlap(first-seen)·retransmit
    처리. 빈 구간(누락 segment)을 만나면 그 지점까지만 반환(불완전 — 성급한 판정 금지). wraparound 안전."""
    if not seqmap:
        return b""
    if base is None:
        base = min(seqmap)
    segs = sorted(((seq - base) & 0xFFFFFFFF, pl) for seq, pl in seqmap.items())
    out = bytearray()
    for off, pl in segs:
        if off > len(out):
            break                                   # 앞 구간 누락 → 불완전, 여기까지만
        end = off + len(pl)
        if end > len(out):
            out += pl[len(out) - off:]              # overlap은 first-seen 유지, 새 구간만 추가
        if len(out) >= cap:
            break
    return bytes(out)


class Connection:
    __slots__ = ("ip_version", "proto", "client", "server", "generation",
                 "_c2s", "_s2c", "_c2s_base", "_s2c_base", "fin", "rst", "first_ts", "last_ts")

    def __init__(self, ip_version, proto, client, server, generation, ts):
        self.ip_version = ip_version
        self.proto = proto
        self.client = client                        # (ip_bytes, port)
        self.server = server
        self.generation = generation
        self._c2s: dict = {}
        self._s2c: dict = {}
        self._c2s_base = None
        self._s2c_base = None
        self.fin = False
        self.rst = False
        self.first_ts = ts
        self.last_ts = ts

    @property
    def key(self):
        return (self.ip_version, self.proto, self.client[0], self.client[1],
                self.server[0], self.server[1], self.generation)

    @property
    def c2s(self) -> bytes:
        return _reassemble(self._c2s, self._c2s_base)

    @property
    def s2c(self) -> bytes:
        return _reassemble(self._s2c, self._s2c_base)


def correlate(packets, service_port: int) -> list:
    """(ts, ip_bytes) 시퀀스를 지정 service_port 기준으로 연결·세대별 상관분석한다.
    packets는 ts 오름차순이어야 한다(호출측 정렬). 결정론적."""
    gens: dict = {}                                 # 5-tuple(base5) → 현재 generation
    conns: dict = {}                                # (base5, gen) → Connection
    seen: set = set()                               # cross-pcap 중복 캡처 억제
    order: list = []
    for ts, ip in packets:
        p = parse_tcp(ip)
        if p is None:
            continue
        ver, proto, src, sport, dst, dport, seq, flags, payload = p
        if dport == service_port:
            direction, cip, cport, sip, sp = "c2s", src, sport, dst, dport
        elif sport == service_port:
            direction, cip, cport, sip, sp = "s2c", dst, dport, src, sport
        else:
            continue
        base5 = (cip, cport, sip, sp)
        dedup = (direction, base5, seq, len(payload), flags & (_SYN | _FIN | _RST),
                 hashlib.sha1(payload).digest() if payload else b"")
        if dedup in seen:                           # retransmission/cross-pcap 중복 → 무시
            continue
        seen.add(dedup)
        is_client_syn = direction == "c2s" and (flags & _SYN) and not (flags & _ACK)
        if is_client_syn:
            gen = gens[base5] = gens.get(base5, 0) + 1
            conn = Connection(ver, proto, (cip, cport), (sip, sp), gen, ts)
            conn._c2s_base = (seq + 1) & 0xFFFFFFFF  # 데이터는 ISN+1부터
            conns[(base5, gen)] = conn
            order.append((base5, gen))
            continue                                # SYN 세그먼트는 보통 payload 없음
        gen = gens.get(base5)
        if gen is None:                             # SYN 미관측(캡처 중간 시작) → generation 0
            gen = gens[base5] = 0
            conn = Connection(ver, proto, (cip, cport), (sip, sp), gen, ts)
            conns[(base5, gen)] = conn
            order.append((base5, gen))
        conn = conns[(base5, gen)]
        conn.last_ts = ts
        if flags & _FIN:
            conn.fin = True
        if flags & _RST:
            conn.rst = True
        if payload:
            side = conn._c2s if direction == "c2s" else conn._s2c
            if direction == "s2c" and conn._s2c_base is None:
                conn._s2c_base = seq                # 첫 응답 seq를 기준으로
            side.setdefault(seq, payload)           # overlap first-seen, 중복 무시
    return [conns[k] for k in order]


# ── HTTP transaction 분리 (keep-alive/pipelining) ────────────────────────────
def split_http_transactions(data: bytes, max_txn: int = 32, max_scan: int = 1 << 20) -> list:
    """재조립된 c2s 바이트를 HTTP/1 요청 transaction 단위로 분리한다(bounded). 각 transaction:
    {method, target, headers, body, complete}. Content-Length/chunked로 body 경계를 계산해 다음
    요청과 섞이지 않게 한다. 불완전한 마지막 transaction은 complete=False로 표시한다."""
    import re
    data = data[:max_scan]
    out = []
    i, n = 0, len(data)
    reqline = re.compile(rb"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[ \t]+(\S+)[ \t]+HTTP/1\.[01]\r\n")
    while i < n and len(out) < max_txn:
        m = reqline.match(data, i) or reqline.search(data, i)
        if not m:
            break
        hdr_end = data.find(b"\r\n\r\n", m.start())
        if hdr_end == -1:
            out.append({"method": m.group(1).decode(), "target": m.group(2).decode("latin-1"),
                        "headers": data[m.end():], "body": b"", "complete": False})
            break
        headers = data[m.start():hdr_end]
        body_start = hdr_end + 4
        te = re.search(rb"(?im)^transfer-encoding:[ \t]*([^\r\n]{1,256})$", headers)
        cl = re.search(rb"(?im)^content-length:[ \t]*(\d{1,9})", headers)
        complete = True
        if te and te.group(1).strip().lower().split(b",")[-1].strip() == b"chunked":
            end = data.find(b"\r\n0\r\n\r\n", body_start)
            if end == -1:
                body = data[body_start:]; nxt = n; complete = False
            else:
                body = data[body_start:end]; nxt = end + 7
        elif cl:
            length = int(cl.group(1))
            if body_start + length > n:
                body = data[body_start:]; nxt = n; complete = False
            else:
                body = data[body_start:body_start + length]; nxt = body_start + length
        else:
            body = b""; nxt = body_start
        out.append({"method": m.group(1).decode(), "target": m.group(2).decode("latin-1"),
                    "headers": headers, "body": body, "complete": complete})
        if nxt <= i:
            break
        i = nxt
    return out


def fingerprint(data: bytes, length: int = 12) -> str:
    """짧은 SHA-256 fingerprint(실제 값·secret 미노출). 식별/중복 판정용."""
    return hashlib.sha256(data).hexdigest()[:length]
