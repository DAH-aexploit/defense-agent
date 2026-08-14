"""pcap 분석 — 리허설·Break의 실제 protocol·port·이상 traffic 파악과 룰 초안 추출

표준 library 전용(scapy 불필요), classic pcap 직접 parsing과 방어 engine parse_l4 재사용
`-i any` capture의 LINUX_SLL/SLL2, Ethernet, raw IP linktype 지원

  python3 tools/pcap_analyze.py <파일.pcap> [파일2.pcap ...]

산출: 포트별 프로토콜/유형(텍스트·바이너리)/샘플/반복/rate 요약, 현재 룰의 verdict 분포,
이상 후보와 룰 힌트
사람의 검토를 통한 detectors.py 검사기 추가
"""

from __future__ import annotations

import collections
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defender import VERDICT_DROP, VerdictEngine, load_engine

# linktype → IP 앞 L2 header 길이(byte), tcpdump -i any는 주로 SLL(113)/SLL2(276)
_L2_OFFSET = {1: 14, 101: 0, 12: 0, 14: 0, 113: 16, 276: 20}
_TOKEN_RE = re.compile(rb"[a-zA-Z_][a-zA-Z0-9_]{2,}")
_PROTO_NAME = {6: "TCP", 17: "UDP"}


def read_pcap(path: str):
    """(ts_float, raw_ip_bytes) generator, 손상 record 제외"""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        return
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian, nano = ">", magic[3] == 0x4D
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian, nano = "<", magic[0] == 0x4D
    else:
        raise ValueError(f"{path}: pcap 매직 아님 (pcapng?)")
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    l2 = _L2_OFFSET.get(linktype, 0)
    off, n = 24, len(data)
    while off + 16 <= n:
        ts_sec, ts_frac, incl, _orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        if off + incl > n:
            break
        pkt = data[off:off + incl]
        off += incl
        ip = pkt[l2:]
        if ip and (ip[0] >> 4) in (4, 6):
            ts = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
            yield ts, ip


def _payload_kind(sample: bytes) -> str:
    if not sample:
        return "-"
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    return "텍스트" if printable / len(sample) > 0.85 else "바이너리"


def analyze(paths: list[str], engine: VerdictEngine | None = None) -> None:
    engine = engine or load_engine()
    ports: dict = collections.defaultdict(lambda: {
        "count": 0, "bytes": 0, "protos": set(), "times": [],
        "sample": b"", "repeat": collections.Counter(), "tokens": collections.Counter()})
    ip_total = drop_total = 0

    for path in paths:
        try:
            stream = read_pcap(path)
        except (OSError, ValueError) as e:
            print(f"[skip] {e}", file=sys.stderr)
            continue
        for ts, ip in stream:
            parsed = VerdictEngine.parse_l4(ip)
            if not parsed:
                continue
            proto, dport, payload, _ = parsed
            ip_total += 1
            p = ports[dport]
            p["count"] += 1
            p["bytes"] += len(payload)
            p["protos"].add(proto)
            p["times"].append(ts)
            if payload:
                if not p["sample"]:
                    p["sample"] = payload[:96]
                p["repeat"][payload[:64]] += 1
                for tok in _TOKEN_RE.findall(payload[:512].lower()):
                    p["tokens"][tok.decode("latin-1")] += 1
            if engine.verdict(ip)[0] == VERDICT_DROP:
                drop_total += 1

    if not ip_total:
        print("IPv4/IPv6 패킷을 찾지 못함 (linktype/포맷 확인 — pcapng이면 classic으로 재캡처).")
        return

    print(f"\n=== pcap 분석: {', '.join(paths)} ===")
    print(f"IP {ip_total} 패킷 · 포트 {len(ports)}개 · 현재 룰 DROP {drop_total}\n")
    hdr = f"{'포트':>6} {'proto':<7} {'패킷':>6} {'바이트':>8} {'유형':<8} {'peak/s':>6}  샘플"
    print(hdr)
    print("-" * len(hdr))
    anomalies, hints = [], []
    for dport in sorted(ports):
        p = ports[dport]
        protos = "/".join(_PROTO_NAME.get(x, str(x)) for x in sorted(p["protos"]))
        kind = _payload_kind(p["sample"])
        peak = _peak_rate(p["times"])
        sample = p["sample"].decode("latin-1", "ignore").replace("\r", " ").replace("\n", " ")[:44]
        print(f"{dport:>6} {protos:<7} {p['count']:>6} {p['bytes']:>8} {kind:<8} {peak:>6}  {sample!r}")

        top_payload, top_n = (p["repeat"].most_common(1) or [(b"", 0)])[0]
        if top_n >= max(10, p["count"] * 0.5):
            anomalies.append(f":{dport} 동일 페이로드 {top_n}회 반복 → 정형 트래픽(SLA 체크) 또는 반복 공격")
        if peak >= 30:
            anomalies.append(f":{dport} peak {peak}/s → 대량 요청(rate 이상 후보)")
        if kind == "바이너리":
            magic = p["sample"][:4].hex()
            anomalies.append(f":{dport} 바이너리(magic {magic}) → 프로토콜 미상, 전용 Detector 필요")
        elif p["tokens"]:
            common = ", ".join(f"{t}({c})" for t, c in p["tokens"].most_common(5))
            hints.append(f":{dport} 텍스트 빈출 토큰: {common}")

    if anomalies:
        print("\n[이상 후보]")
        for a in anomalies:
            print(f" - {a}")
    if hints:
        print("\n[룰 힌트] (텍스트 포트 — 자주 나오는 토큰에서 시그니처 후보를 고른다)")
        for h in hints:
            print(f" - {h}")
    print("\n→ 판단 후 detectors.py에 Detector를 추가하고 replay/테스트로 오탐 확인 후 배포.")


def _peak_rate(times: list[float]) -> int:
    """1초 sliding window 최대 요청 수(정수)"""
    if not times:
        return 0
    ts = sorted(times)
    best = i = 0
    for j in range(len(ts)):
        while ts[j] - ts[i] > 1.0:
            i += 1
        best = max(best, j - i + 1)
    return best


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    analyze(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
