"""합성 QA pcap 3종(정상/정상 상태변화/공격) 생성과 기대 verdict 검증

실제 본선 pcap 대체용이 아닌 parser·정책 회귀용 synthetic fixture
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defender import VERDICT_ACCEPT, VERDICT_DROP, VerdictEngine
from detectors import crc16_ccitt
from tests.packet_util import build_udp_packet, packet_for, write_pcap
from tests.rule_fixtures import TEST_SIGNATURES, TEST_WHITELIST
from tools.pcap_analyze import read_pcap

OUT = ROOT / "qa-results" / "fixtures"


def mav2(seq, timestamp):
    """상태 변화·replay 회귀 시험용 최소 MAVLink 2 후보 frame 생성"""
    header = bytes([0xFD, 0, 1, 0, seq, 1, 1]) + (76).to_bytes(3, "little")
    return header + b"\x00\x00" + bytes([7]) + timestamp.to_bytes(6, "little") + b"\x00" * 6


def ccsds(seq=1, corrupt=False):
    """유효 또는 의도적 FECF 손상 상태의 최소 CCSDS Space Packet 생성"""
    payload = b"abc"
    packet = struct.pack(">HHH", 42, (3 << 14) | seq, len(payload) - 1) + payload
    crc = crc16_ccitt(packet) ^ (1 if corrupt else 0)
    return packet + crc.to_bytes(2, "big")


def rtps_malformed():
    """submessage 길이가 실제 payload보다 큰 비정상 RTPS message 생성"""
    return b"RTPS\x02\x03\x01\x0f" + b"G" * 12 + b"\x15\x01\x63\x00x"


def fixtures():
    """정상·정상 상태 변화·공격·손상 입력의 결정적 packet 묶음 반환"""
    return {
        "normal": [packet_for(8082, "/health"), packet_for(8084, "/product?id=5"),
                   build_udp_packet(10000, ccsds(seq=1))],
        # 정상 재기동 가능성이 있는 sequence reset의 observe mode 차단 제외
        "normal_state_change": [build_udp_packet(14550, mav2(100, 1000)),
                                build_udp_packet(14550, mav2(0, 2000))],
        "attack_and_malformed": [packet_for(8084, "/product?id=1 union select sql"),
                                 build_udp_packet(10000, ccsds(seq=2, corrupt=True)),
                                 build_udp_packet(7400, rtps_malformed())],
    }


def replay(path):
    """PCAP의 신규 engine 순차 적용과 verdict·점수·근거 반환"""
    engine = VerdictEngine.from_config(TEST_SIGNATURES, TEST_WHITELIST)
    return [{"verdict": verdict, "score": round(info.get("score", 0.0), 6),
             "reasons": info["reasons"]}
            for verdict, info in (engine.verdict(packet) for _, packet in read_pcap(str(path)))]


def main():
    """합성 PCAP 생성과 2회 재생 기반 결정성·기대 verdict 검증"""
    OUT.mkdir(parents=True, exist_ok=True)
    now = 1_700_000_000.0
    paths = {}
    for name, packets in fixtures().items():
        path = OUT / f"{name}.pcap"
        write_pcap(str(path), [(now + i * 0.1, packet) for i, packet in enumerate(packets)])
        paths[name] = path
    first = {name: replay(path) for name, path in paths.items()}
    second = {name: replay(path) for name, path in paths.items()}
    assert first == second, "same pcap produced non-deterministic results"
    assert all(x["verdict"] == VERDICT_ACCEPT for x in first["normal"])
    assert all(x["verdict"] == VERDICT_ACCEPT for x in first["normal_state_change"])
    assert [x["verdict"] for x in first["attack_and_malformed"]] == [
        VERDICT_DROP, VERDICT_ACCEPT, VERDICT_ACCEPT]
    evidence = {"fixture_type": "synthetic regression data; not real competition traffic",
                "deterministic": True, "results": first}
    (OUT / "results.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(evidence, ensure_ascii=False))


if __name__ == "__main__":
    main()
