"""방산 챌린지 시뮬레이터 — 실제 엔진으로 방산 프로토콜 flag 유출 방어를 실측한다.

arena 챌린지는 리허설 웹(본선 무관)이라 방산 enforce를 시험하지 못한다. 이 도구는 대회
계약(인바운드 전용·300ms 예산)을 재현해 예상 방산 챌린지에서 우리 방어가 flag 탈취 스캔을
차단하는지, 정상 트래픽을 오탐하지 않는지(SLA)를 프로토콜별로 측정한다.

시나리오(각 챌린지):
  - flag는 특정 대상(레지스터/DID/OID/APID/topic)에 있다.
  - 정상 클라이언트는 고정된 소수 대상을 반복 폴링한다(정상 baseline).
  - 공격자는 attack-agent의 실제 framing으로 대상 공간을 순차로 훑어 flag를 찾는다.
  - 인바운드 요청만 엔진(enforce+포트)에 흘려 verdict를 받는다(응답은 방어가 못 봄).

지표(arena와 동일한 관점):
  - stolen : flag 대상을 읽는 요청이 DROP 전에 ACCEPT됐는가(레이어 이진값)
  - drop   : 공격 요청 중 DROP 수
  - SLA    : 정상 요청 중 ACCEPT 비율(오탐 = SLA 손실)

주의: 인바운드 전용 + 단일 read 한계상, flag가 임계 도달 전 초반 주소에 있으면 유출될 수
있다(honest). 도구는 flag 위치를 바꿔가며 이 경계도 함께 보여준다.
"""
from __future__ import annotations

import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defender import VERDICT_DROP, VerdictEngine   # noqa: E402
from detectors import (CcsdsDetector, Iec104Detector, MavlinkDetector,   # noqa: E402
                       ModbusDetector, RtpsDetector, SnmpDetector, UdsCanDetector)


# ── 인바운드 패킷 합성 (대회 계약: 방어는 요청 방향만 본다) ──────────────────────
def tcp(dport, payload, sport=40001, seq=1):
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(payload), 0x1234, 0, 64, 6, 0,
                     b"\n\x00\x00\x01", b"\n\x00\x00\x02")
    t = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, (5 << 4), 0x18, 65535, 0, 0)
    return ip + t + payload


def udp(dport, payload, sport=40001):
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(payload), 0x1234, 0, 64, 17, 0,
                     b"\n\x00\x00\x01", b"\n\x00\x00\x02")
    u = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    return ip + u + payload


# ── 프로토콜별 "대상 N을 읽는 요청" framing (attack-agent 스펙과 동일) ──────────
def modbus_read(addr):
    pdu = b"\x03" + (addr & 0xFFFF).to_bytes(2, "big") + b"\x00\x01"
    return struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu


def uds_read(did):
    pdu = b"\x22" + (did & 0xFFFF).to_bytes(2, "big")
    return struct.pack(">IB", 0x7DF, len(pdu)) + pdu


def iec104_read(ioa):
    asdu = bytes([102, 0x01]) + struct.pack("<H", 5) + struct.pack("<H", 1) \
        + (ioa & 0xFFFFFF).to_bytes(3, "little")
    return bytes([0x68, 4 + len(asdu)]) + b"\x00\x00\x00\x00" + asdu


def ccsds_read(apid, seq_count=0):
    first = apid & 0x7FF
    payload = b"tm"
    seq = (3 << 14) | (seq_count & 0x3FFF)     # 정상 telemetry는 sequence_count가 증가한다
    return struct.pack(">HHH", first, seq, len(payload) - 1) + payload


def rtps_read(topic):
    header = b"RTPS" + bytes((2, 3)) + b"\x01\x0f" + b"G" * 12
    body = b"\x00\x00\x00\x00RRRR" + (topic & 0xFFFFFFFF).to_bytes(4, "big") + b"\x00" * 8
    return header + bytes([0x15, 0x01]) + len(body).to_bytes(2, "little") + body


def _ber(tag, val):
    return bytes([tag, len(val)]) + val


def snmp_read(oid_last):
    oid = _ber(0x06, bytes([0x2B, 6, 1, 2, 1, 1, oid_last & 0x7F]))
    vb = _ber(0x30, oid + _ber(0x05, b""))
    pdu = _ber(0xA0, _ber(0x02, b"\x01") + _ber(0x02, b"\x00") + _ber(0x02, b"\x00") + _ber(0x30, vb))
    return _ber(0x30, _ber(0x02, b"\x01") + _ber(0x04, b"public") + pdu)


# ── 예상 방산 챌린지 정의 ─────────────────────────────────────────────────────
#   layer/protocol, 포트, 엔진 detector, 요청 framer, 전송(tcp/udp),
#   정상 폴링 대상(소수 고정), 공격 sweep 범위, flag 위치.
CHALLENGES = [
    {"layer": "L1_SAT", "proto": "CCSDS", "port": 10000, "transport": udp,
     "detector": lambda p: CcsdsDetector(mode="enforce", ports=[p], apid_scan_targets=8),
     "read": ccsds_read, "normal": [0x10, 0x11], "sweep": range(0x100, 0x100 + 60),
     "flag": 0x100 + 40},
    {"layer": "L2_MCS", "proto": "Modbus", "port": 502, "transport": tcp,
     "detector": lambda p: ModbusDetector(mode="enforce", ports=[p], read_scan_targets=16),
     "read": modbus_read, "normal": [0, 1, 2], "sweep": range(0x1000, 0x1000 + 60),
     "flag": 0x1000 + 40},
    {"layer": "L3_UAV", "proto": "MAVLink", "port": 14550, "transport": udp,
     "detector": lambda p: MavlinkDetector(mode="enforce", ports=[p], param_read_scan=12),
     "read": None, "normal": [0, 1], "sweep": range(20, 20 + 40), "flag": 20 + 30,
     "mav_param": True},
    {"layer": "L4_UGV", "proto": "UDS/CAN", "port": 6801, "transport": tcp,
     "detector": lambda p: UdsCanDetector(mode="enforce", ports=[p], read_scan_targets=16),
     "read": uds_read, "normal": [0xF190, 0xF191], "sweep": range(0xF000, 0xF000 + 60),
     "flag": 0xF000 + 40},
    {"layer": "L4_UGV", "proto": "RTPS", "port": 7400, "transport": udp,
     "detector": lambda p: RtpsDetector(mode="enforce", ports=[p], topic_scan=16),
     "read": rtps_read, "normal": [0x0103, 0x0203], "sweep": range(0x1000, 0x1000 + 60),
     "flag": 0x1000 + 40},
    {"layer": "L2_MCS", "proto": "IEC-104", "port": 2404, "transport": tcp,
     "detector": lambda p: Iec104Detector(mode="enforce", ports=[p], read_scan_targets=16),
     "read": iec104_read, "normal": [1, 2], "sweep": range(1000, 1000 + 60), "flag": 1000 + 40},
    {"layer": "L1_SAT", "proto": "SNMP", "port": 161, "transport": udp,
     "detector": lambda p: SnmpDetector(mode="enforce", ports=[p], read_scan_targets=16),
     "read": snmp_read, "normal": [1, 2], "sweep": range(1, 1 + 60), "flag": 1 + 40},
]


def _mav_param_frame(param_index, seq=1):
    payload = struct.pack("<hBB16s", param_index, 1, 1, b"\x00" * 16)
    header = bytes([0xFD, len(payload), 0, 0, seq & 0xFF, 1, 1]) + (20).to_bytes(3, "little")
    return header + payload + b"\x00\x00"


def _packet(ch, target, sport, seq, count=0):
    if ch.get("mav_param"):
        frame = _mav_param_frame(target, seq=seq)
    elif ch["proto"] == "CCSDS":
        frame = ccsds_read(target, seq_count=count)     # 정상 seq 증가로 replay 오탐 방지
    else:
        frame = ch["read"](target)
    tr = ch["transport"]
    return tr(ch["port"], frame, sport=sport, seq=seq) if tr is tcp else tr(ch["port"], frame, sport=sport)


def _seq_start():
    return 1000


def measure_sla(ch, rounds=20):
    """정상 클라이언트만 흘려 오탐(SLA 손실)을 측정."""
    engine = VerdictEngine([ch["detector"](ch["port"])])
    seq, ok, total, count = _seq_start(), 0, 0, 1
    for _ in range(rounds):
        for tgt in ch["normal"]:
            pkt = _packet(ch, tgt, sport=40001, seq=seq, count=count)
            verdict, _ = engine.verdict(pkt)
            seq += len(pkt)
            count += 1
            total += 1
            ok += (verdict != VERDICT_DROP)
    return ok / total if total else 1.0


def measure_sla_under_scan(ch):
    """공격 스캔이 진행되는 동안 정상 클라이언트의 재조회가 통과하는지(부수 차단) 측정.

    surgical 차단 검증의 핵심: '프로토콜 통째 차단'이면 스캔 중 정상 재조회도 막혀 0%가 되고,
    '스캔 확장 요청만 차단'이면 정상 재조회는 통과해 100%가 나온다."""
    engine = VerdictEngine([ch["detector"](ch["port"])])
    aseq = bseq = _seq_start()
    # 정상 클라가 자기 대상을 먼저 학습(스캔 시작 전 baseline)
    for c, tgt in enumerate(ch["normal"], 1):
        p = _packet(ch, tgt, sport=40001, seq=bseq, count=c)
        engine.verdict(p)
        bseq += len(p)
    ok = total = 0
    normal = list(ch["normal"])
    for i, atk in enumerate(ch["sweep"], 1):
        # 공격 스캔 read (새 대상)
        pa = _packet(ch, atk, sport=41001, seq=aseq, count=1000 + i)
        engine.verdict(pa)
        aseq += len(pa)
        # 정상 클라 재조회 (아는 대상)
        pn = _packet(ch, normal[i % len(normal)], sport=40001, seq=bseq, count=2000 + i)
        verdict, _ = engine.verdict(pn)
        bseq += len(pn)
        total += 1
        ok += (verdict != VERDICT_DROP)
    return ok / total if total else 1.0


def run_attack(ch):
    """공격 sweep을 흘려 flag 유출 여부·차단 수·verdict 지연을 측정."""
    engine = VerdictEngine([ch["detector"](ch["port"])])
    seq, drops, stolen, latencies = _seq_start(), 0, False, []
    for count, target in enumerate(ch["sweep"], 1):
        pkt = _packet(ch, target, sport=41001, seq=seq, count=count)
        t0 = time.perf_counter()
        verdict, _ = engine.verdict(pkt)
        latencies.append((time.perf_counter() - t0) * 1000.0)
        seq += len(pkt)
        if verdict == VERDICT_DROP:
            drops += 1
            continue
        if target == ch["flag"]:      # flag 대상 요청이 통과 → 응답으로 유출
            stolen = True
            break                     # 공격자는 flag 확보 후 중단
    p99 = sorted(latencies)[max(0, int(len(latencies) * 0.99) - 1)] if latencies else 0.0
    return stolen, drops, p99


def _flag_offset(ch):
    """flag가 sweep 시작에서 몇 번째인지(임계 대비 위치 파악용)."""
    sweep = list(ch["sweep"])
    return sweep.index(ch["flag"]) if ch["flag"] in sweep else -1


def main():
    print("═══ 방산 챌린지 시뮬레이터 — 실제 엔진·인바운드 전용·enforce ═══\n")
    print(f"{'레이어':8} {'프로토콜':9} {'포트':>5}  {'stolen':7} {'drop':>5} "
          f"{'SLA':>5} {'스캔중SLA':>8}  {'p99(ms)':>8}  판정")
    print("─" * 84)
    worst_p99 = 0.0
    for ch in CHALLENGES:
        sla = measure_sla(ch)
        sla_scan = measure_sla_under_scan(ch)
        stolen, drops, p99 = run_attack(ch)
        worst_p99 = max(worst_p99, p99)
        verdict = "방어 ✓" if (not stolen and sla >= 0.99 and sla_scan >= 0.99) else (
            "유출!" if stolen else "SLA↓")
        print(f"{ch['layer']:8} {ch['proto']:9} {ch['port']:>5}  "
              f"{'있음' if stolen else '없음':7} {drops:>5} {sla*100:>4.0f}% "
              f"{sla_scan*100:>7.0f}%  {p99:>8.3f}  {verdict}")
    print("─" * 84)
    print("  SLA=정상만 흘렸을 때, 스캔중SLA=공격 스캔 진행 중 정상 재조회 통과율(부수차단 검증)")
    print(f"\n최악 verdict p99: {worst_p99:.3f} ms (대회 300ms 예산 대비)")

    # 유출 경계: flag가 sweep 시작에서 몇 번째 주소일 때 새는지(임계 타이밍 정직 공개)
    print("\n── 유출 경계 (Modbus 예, read_scan_targets=16) ──")
    print("  flag 위치(sweep 오프셋)별 stolen: 임계 도달 전 주소면 유출, 이후면 차단")
    modbus = next(c for c in CHALLENGES if c["proto"] == "Modbus")
    base = list(modbus["sweep"])[0]
    row = []
    for off in (0, 5, 10, 15, 16, 17, 20, 30):
        ch = dict(modbus, flag=base + off)
        stolen, _, _ = run_attack(ch)
        row.append(f"off={off}:{'유출' if stolen else '차단'}")
    print("  " + "  ".join(row))
    print("  → 초반 ~임계개(16) 이내 주소의 flag는 스캔이 차단되기 전 읽혀 유출될 수 있다.")
    print("    인바운드 전용·단일 read 구조 한계. 임계를 낮추면 유출 창이 줄지만 오탐(SLA) 위험↑.")
    print("\n해석:")
    print("  · flag가 sweep 임계 이후 주소면 스캔이 먼저 차단돼 유출 없음(방어 ✓).")
    print("  · flag가 임계 이전 초반 주소면 유출될 수 있음(인바운드 전용·단일 read 한계).")
    print("  · SLA 100% = 정상 폴링을 오탐하지 않음. 임계는 실제 baseline에 맞춰 조정.")


if __name__ == "__main__":
    main()
