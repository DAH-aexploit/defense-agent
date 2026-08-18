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
from detectors import ModbusDetector


def pkt(dport, payload, sport=40001, seq=1):
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 20 + len(payload), 0x1234, 0, 64, 6, 0,
                     b"\n\x00\x00\x01", b"\n\x00\x00\x02")
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, (5 << 4), 0x18, 65535, 0, 0)
    return ip + tcp + payload


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
modbus_engine = VerdictEngine([ModbusDetector(mode="enforce", ports=[502])])

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
]

ok = True
for name, passed in checks:
    ok &= passed
    print(f"  {'PASS' if passed else 'FAIL'}  {name}")
print()
print("이미지 내부 검증:", "전체 통과" if ok else "실패 있음")
sys.exit(0 if ok else 1)
