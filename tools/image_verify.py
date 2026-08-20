"""배포 이미지 내부 판정 검증 — 컨테이너 안에서 실행

Push된 이미지가 실제로 무엇을 차단하고 무엇을 통과시키는지 컨테이너 안에서 직접 확인한다.
로컬 QA 통과와 이미지 동작은 별개이며, Push 성공은 대회 반영 성공이 아니다.

`make verify-image`가 이 파일을 이미지에 mount해 실행한다. 저장소 밖의 코드에 의존하지
않도록 패킷 builder를 자체 포함한다.

실패 시 종료 코드 1을 반환해 배포 파이프라인을 중단시킨다.
"""
import struct
import sys

sys.path.insert(0, "/app")
from defender import VERDICT_ACCEPT, VERDICT_DROP, VerdictEngine, load_engine
from detectors import (CcsdsDetector, DnsDetector, Iec104Detector, MavlinkDetector,
                       ModbusDetector, MqttDetector,
                       RtpsDetector, SnmpDetector, TlsObserveDetector, UdsCanDetector)


def pkt(dport, payload, sport=40001, seq=1):
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(payload), 0x1234, 0, 64, 6, 0,
                     b"\n\x00\x00\x01", b"\n\x00\x00\x02")
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, (5 << 4), 0x18, 65535, 0, 0)
    return ip + tcp + payload


def upkt(dport, payload, sport=40001):
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(payload), 0x1234, 0, 64, 17, 0,
                     b"\n\x00\x00\x01", b"\n\x00\x00\x02")
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    return ip + udp + payload


def ccsds(apid, seq=0, payload=b"tm"):
    first = apid & 0x7FF
    return struct.pack(">HHH", first, (3 << 14) | (seq & 0x3FFF), len(payload) - 1) + payload


def rtps_data(writer_id):
    header = b"RTPS" + bytes((2, 3)) + b"\x01\x0f" + b"G" * 12
    body = b"\x00\x00\x00\x00RRRR" + writer_id + b"\x00" * 8
    return header + bytes([0x15, 0x01]) + len(body).to_bytes(2, "little") + body


def ccsds_apid_scan_reasons(count=10):
    engine = VerdictEngine([CcsdsDetector(mode="observe", ports=[10000], apid_scan_targets=4)])
    reasons = []
    for apid in range(count):
        _, info = engine.verdict(upkt(10000, ccsds(100 + apid, seq=apid)))
        reasons.extend(info.get("reasons", []))
    return reasons


def rtps_topic_scan_reasons(count=10):
    engine = VerdictEngine([RtpsDetector(mode="observe", ports=[7400], topic_scan=4)])
    reasons = []
    for t in range(count):
        _, info = engine.verdict(upkt(7400, rtps_data(bytes([0, 0, t, 0x03]))))
        reasons.extend(info.get("reasons", []))
    return reasons


def uds_can(pdu, arb=0x7DF):
    return struct.pack(">IB", arb & 0x1FFFFFFF, len(pdu) & 0xFF) + pdu


def uds_did_scan_reasons(count=10):
    engine = VerdictEngine([UdsCanDetector(mode="observe", ports=[6801], read_scan_targets=4)])
    reasons, seq = [], 1
    for did in range(count):
        frame = uds_can(b"\x22" + struct.pack(">H", 0xF000 + did))
        _, info = engine.verdict(pkt(6801, frame, seq=seq))
        seq += len(frame)
        reasons.extend(info.get("reasons", []))
    return reasons


def iec104(ioa, type_id=102, cot=5, ca=1):
    asdu = bytes([type_id, 0x01]) + struct.pack("<H", cot) + struct.pack("<H", ca) \
        + (ioa & 0xFFFFFF).to_bytes(3, "little")
    return bytes([0x68, 4 + len(asdu)]) + b"\x00\x00\x00\x00" + asdu


def iec104_ioa_scan_reasons(count=10):
    engine = VerdictEngine([Iec104Detector(mode="observe", ports=[2404], read_scan_targets=4)])
    reasons, seq = [], 1
    for ioa in range(count):
        frame = iec104(ioa)
        _, info = engine.verdict(pkt(2404, frame, seq=seq))
        seq += len(frame)
        reasons.extend(info.get("reasons", []))
    return reasons


def _ber(tag, val):
    return bytes([tag, len(val)]) + val


def snmp_get(oid_last):
    oid = _ber(0x06, bytes([0x2B, 6, 1, 2, 1, 1, oid_last & 0x7F]))   # 1.3.6.1.2.1.1.<n>
    vb = _ber(0x30, oid + _ber(0x05, b""))
    pdu = _ber(0xA0, _ber(0x02, b"\x01") + _ber(0x02, b"\x00") + _ber(0x02, b"\x00")
               + _ber(0x30, vb))
    return _ber(0x30, _ber(0x02, b"\x01") + _ber(0x04, b"public") + pdu)


def snmp_oid_scan_reasons(count=10):
    engine = VerdictEngine([SnmpDetector(mode="observe", ports=[161], read_scan_targets=4)])
    reasons = []
    for i in range(count):
        _, info = engine.verdict(upkt(161, snmp_get(i + 1)))
        reasons.extend(info.get("reasons", []))
    return reasons


def mav2(seq, msgid, payload):
    header = bytes([0xFD, len(payload), 0, 0, seq & 0xFF, 1, 1]) + msgid.to_bytes(3, "little")
    return header + payload + b"\x00\x00"


def mav_msgid_novel_reasons():
    """정상 msgid 집합 학습 후 인젝션(신규 msgid 76) 관찰 이유를 반환."""
    engine = VerdictEngine([MavlinkDetector(mode="observe", ports=[14550],
                                            msgid_warmup=6, msgid_rate_limit=1000)])
    for i in range(12):
        engine.verdict(upkt(14550, mav2(i % 256, [0, 30, 33][i % 3], b"\x00" * 4)))
    _, info = engine.verdict(upkt(14550, mav2(200, 76, b"\x00" * 33)))
    return info.get("reasons", [])


def mqtt_sub(topic):
    body = b"\x00\x01" + len(topic).to_bytes(2, "big") + topic + b"\x00"
    return bytes([0x82, len(body)]) + body


def dns_query(name):
    q = b"".join(bytes([len(l)]) + l for l in name.split(b"."))
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + q + b"\x00\x00\x01\x00\x01"


def tls_client_hello(sni="finals.svc"):
    name = sni.encode()
    server_name = b"\x00" + len(name).to_bytes(2, "big") + name
    snl = len(server_name).to_bytes(2, "big") + server_name
    ext = b"\x00\x00" + len(snl).to_bytes(2, "big") + snl
    exts = len(ext).to_bytes(2, "big") + ext
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00" + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def feed(req, dport, order, sport):
    e = load_engine()
    segs = [(1 + i, req[i:i + 8]) for i in range(0, len(req), 8)]
    segs = [segs[i] for i in order(len(segs))]
    return [e.verdict(pkt(dport, p, sport=sport, seq=s))[0] for s, p in segs]


ssrf = (b"GET /fetch?url=http%3A%2F%2Fhelper-box%3A8080%2Fsecret HTTP/1.1\r\n"
        b"Host: t:8082\r\n\r\n")
admin = (b"GET /admin HTTP/1.1\r\n"
         b"Cookie: session=eyJ1c2VyIjogImd1ZXN0IiwgInJvbGUiOiAiYWRtaW4ifQ==\r\n"
         b"Host: t:8083\r\n\r\n")
good = b"GET /fetch?url=https%3A%2F%2Fexample.com%2Fx HTTP/1.1\r\nHost: t:8082\r\n\r\n"
enc_path = (b"GET /%66%65%74%63%68?url=http%3A%2F%2Fhelper-box%3A8080%2Fsecret HTTP/1.1\r\n"
            b"Host: t\r\n\r\n")
enc_all = (b"GET /%66%65%74%63%68?%75%72%6C=%68%74%74%70%3A%2F%2F%68%65%6C%70%65%72"
           b"%2D%62%6F%78%3A%38%30%38%30%2F%73%65%63%72%65%74 HTTP/1.1\r\nHost: t\r\n\r\n")
sqli = b"GET /product?id=-1+UNION+ALL+SELECT+1,v,3+FROM+app_meta HTTP/1.1\r\nHost: t\r\n\r\n"


def shuffle(n):
    return list(range(3, n)) + list(range(3))


def inorder(n):
    return list(range(n))


def mbap(pdu, unit=1, tid=1, proto_id=0, length=None):
    declared = length if length is not None else len(pdu) + 1
    return struct.pack(">HHHB", tid, proto_id, declared, unit) + pdu


# Modbus는 기본 배포에 DEF_MODBUS_PORTS가 비어 있어 load_engine()으로는 검증되지 않는다
# (MAVLink/CCSDS/RTPS와 동일하게 포트 미확정 상태에서는 의도적으로 비활성).
# 여기서는 이미지에 클래스가 정상 반영·동작하는지만 별도 엔진으로 확인한다.
modbus_engine = VerdictEngine([ModbusDetector(mode="enforce", ports=[502], read_scan_targets=4)])


def modbus_read(addr):
    return b"\x03" + addr.to_bytes(2, "big") + b"\x00\x01"   # FC03 read 1 reg @addr


def modbus_sweep_reasons(count=10):
    """한 연결에서 연속 read로 주소 공간을 훑는 스캔을 재생하고 관찰 이유를 반환."""
    engine = VerdictEngine([ModbusDetector(mode="enforce", ports=[502], read_scan_targets=4)])
    verdicts, reasons, seq = [], [], 1
    for addr in range(count):
        frame = mbap(modbus_read(addr))
        verdict, info = engine.verdict(pkt(502, frame, seq=seq))
        seq += len(frame)
        verdicts.append(verdict)
        reasons.extend(info.get("reasons", []))
    return verdicts, reasons


_sweep_verdicts, _sweep_reasons = modbus_sweep_reasons()


# ── 단일 read 구분자 knob 검증 (당일 baseline 후 활성; 이미지 안에서 실제 발동하는지 확인) ──
def modbus_qty(addr, qty):
    return b"\x03" + addr.to_bytes(2, "big") + qty.to_bytes(2, "big")   # FC03 read qty regs @addr


def snmp_get_multi(n):
    """한 GetRequest에 OID n개를 배치한 프레임(다중 OID 배치 스윕)."""
    vbs = b"".join(_ber(0x30, _ber(0x06, bytes([0x2B, 6, 1, 2, 1, 1, i + 1])) + _ber(0x05, b""))
                   for i in range(n))
    pdu = _ber(0xA0, _ber(0x02, b"\x01") + _ber(0x02, b"\x00") + _ber(0x02, b"\x00")
               + _ber(0x30, vbs))
    return _ber(0x30, _ber(0x02, b"\x01") + _ber(0x04, b"public") + pdu)


_mb_qty = VerdictEngine([ModbusDetector(mode="enforce", ports=[502], max_read_qty=1)])
_snmp_oids = VerdictEngine([SnmpDetector(mode="enforce", ports=[161], max_oids=1)])
_uds_allow = VerdictEngine([UdsCanDetector(mode="enforce", ports=[6801], did_allowlist=[0xF190])])
_iec_allow = VerdictEngine([Iec104Detector(mode="enforce", ports=[2404], ioa_allowlist=[100])])

e = load_engine()
checks = [
    ("L1 순서 뒤섞인 분할 SSRF", VERDICT_DROP in feed(ssrf, 8082, shuffle, 41001)),
    ("L2 순서 뒤섞인 분할 admin 세션", VERDICT_DROP in feed(admin, 8083, shuffle, 41002)),
    ("L1 순서대로 분할 SSRF", VERDICT_DROP in feed(ssrf, 8082, inorder, 41003)),
    ("정상 분할 요청 ACCEPT", VERDICT_DROP not in feed(good, 8082, shuffle, 41004)),
    ("인코딩 경로 SSRF DROP", e.verdict(pkt(8082, enc_path, sport=41005))[0] == VERDICT_DROP),
    ("경로·파라미터 전체 인코딩 DROP", e.verdict(pkt(8082, enc_all, sport=41006))[0] == VERDICT_DROP),
    ("L3 UNION SQLi DROP", e.verdict(pkt(8084, sqli, sport=41007))[0] == VERDICT_DROP),
    ("L3 정상 상품 ID ACCEPT",
     e.verdict(pkt(8084, b"GET /product?id=5 HTTP/1.1\r\nHost: t\r\n\r\n", sport=41008))[0]
     == VERDICT_ACCEPT),
    ("L1 정상 /health ACCEPT",
     e.verdict(pkt(8082, b"GET /health HTTP/1.1\r\nHost: t\r\n\r\n", sport=41009))[0]
     == VERDICT_ACCEPT),
    ("Modbus 읽기(FC03) ACCEPT",
     modbus_engine.verdict(pkt(502, mbap(b"\x03\x00\x00\x00\x0a"), sport=41010))[0]
     == VERDICT_ACCEPT),
    ("Modbus 쓰기(FC06) 관찰만, DROP 안 함",
     modbus_engine.verdict(pkt(502, mbap(b"\x06\x00\x01\x00\x2a"), sport=41011))[0]
     == VERDICT_ACCEPT),
    ("Modbus 단일 read 무신호",
     VerdictEngine([ModbusDetector(mode="observe", ports=[502], read_scan_targets=4)])
     .verdict(pkt(502, mbap(modbus_read(0)), sport=41012))[1]["reasons"] == []),
    ("Modbus read 스캔 enforce+포트 차단(flag 유출 방지)",
     VERDICT_DROP in _sweep_verdicts
     and any("modbus_read_enumeration" in r for r in _sweep_reasons)),
    ("Modbus read 스캔 observe는 관찰만(차단 안 함)",
     (lambda vs: all(v == VERDICT_ACCEPT for v in vs))(
         [VerdictEngine([ModbusDetector(mode="observe", ports=[502], read_scan_targets=4)])
          .verdict(pkt(502, mbap(modbus_read(a)), seq=1 + a * 12))[0] for a in range(10)])),
    ("CCSDS APID 스캔 관찰됨(차단 안 함)",
     any("ccsds_apid_enumeration" in r for r in ccsds_apid_scan_reasons())),
    ("RTPS topic 스캔 관찰됨(차단 안 함)",
     any("rtps_topic_enumeration" in r for r in rtps_topic_scan_reasons())),
    ("UDS/CAN DID 스캔 관찰됨(차단 안 함)",
     any("uds_did_enumeration" in r for r in uds_did_scan_reasons())),
    ("IEC-104 IOA 스캔 관찰됨(차단 안 함)",
     any("iec104_ioa_enumeration" in r for r in iec104_ioa_scan_reasons())),
    ("SNMP OID 스캔 관찰됨(차단 안 함)",
     any("snmp_oid_enumeration" in r for r in snmp_oid_scan_reasons())),
    ("TLS 채널 관찰됨(SNI 추출, 차단 안 함)",
     (lambda r: r[0] == VERDICT_ACCEPT and any("tls_channel" in x for x in r[1]["reasons"]))(
         VerdictEngine([TlsObserveDetector(mode="observe")]).verdict(
             pkt(8443, tls_client_hello("finals.svc"))))),
    ("MAVLink msgid 프로파일 밖 인젝션 관찰(차단 안 함)",
     any("mavlink_msgid_novel" in r for r in mav_msgid_novel_reasons())),
    ("MQTT topic 스캔 enforce+포트 차단",
     (lambda: (lambda eng, seqs: any(
         eng.verdict(pkt(1883, mqtt_sub(f"t/{i}".encode()), seq=s))[0] == VERDICT_DROP
         for i, s in enumerate(seqs)))(
         VerdictEngine([MqttDetector(mode="enforce", ports=[1883], read_scan_targets=4)]),
         [1 + i * 12 for i in range(10)]))()),
    ("DNS qname 스캔 enforce+포트 차단",
     (lambda: (lambda eng: any(
         eng.verdict(upkt(53, dns_query(f"h{i}.x.local".encode())))[0] == VERDICT_DROP
         for i in range(10)))(
         VerdictEngine([DnsDetector(mode="enforce", ports=[53], read_scan_targets=4)])))()),
    # ── 구분자 knob: 공격 read(정상과 다른) 차단 + 정상 단일 read 통과 (쌍으로 확인) ──
    ("Modbus qty knob: 정상 qty=1 ACCEPT",
     _mb_qty.verdict(pkt(502, mbap(modbus_qty(0, 1)), sport=41013))[0] == VERDICT_ACCEPT),
    ("Modbus qty knob: 블록 qty=16 DROP",
     _mb_qty.verdict(pkt(502, mbap(modbus_qty(0, 16)), sport=41014))[0] == VERDICT_DROP),
    ("SNMP max_oids knob: 단일 OID ACCEPT",
     _snmp_oids.verdict(upkt(161, snmp_get(1), sport=41015))[0] == VERDICT_ACCEPT),
    ("SNMP max_oids knob: 다중 OID 배치 DROP",
     _snmp_oids.verdict(upkt(161, snmp_get_multi(3), sport=41016))[0] == VERDICT_DROP),
    ("UDS DID allowlist knob: 허용 DID ACCEPT",
     _uds_allow.verdict(pkt(6801, uds_can(b"\x22\xf1\x90"), sport=41017))[0] == VERDICT_ACCEPT),
    ("UDS DID allowlist knob: 목록 밖 DID DROP",
     _uds_allow.verdict(pkt(6801, uds_can(b"\x22\xde\xad"), sport=41018))[0] == VERDICT_DROP),
    ("IEC-104 IOA allowlist knob: 허용 IOA C_RD ACCEPT",
     _iec_allow.verdict(pkt(2404, iec104(100, type_id=102), sport=41019))[0] == VERDICT_ACCEPT),
    ("IEC-104 IOA allowlist knob: 목록 밖 IOA C_RD DROP",
     _iec_allow.verdict(pkt(2404, iec104(0xDEAD, type_id=102), sport=41020))[0] == VERDICT_DROP),
]

ok = True
for name, passed in checks:
    ok &= passed
    print(f"  {'PASS' if passed else 'FAIL'}  {name}")
print()
print("이미지 내부 검증:", "전체 통과" if ok else "실패 있음")
sys.exit(0 if ok else 1)
