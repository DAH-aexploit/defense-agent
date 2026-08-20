"""VerdictEngine 단위 테스트, socket 불필요·macOS 실행 가능

  python3 -m unittest tests.test_engine -v
"""

from __future__ import annotations

import base64
import socket
import struct
import hmac
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defender import (MSG_HEARTBEAT, MSG_PACKET, MSG_VERDICT, VERDICT_ACCEPT,
                      VERDICT_DROP, BackgroundAnalyst, ParseStatus, TcpStreamWindow,
                      UnknownSampler,
                      VerdictEngine, _validate_llm_result, classify_rule_coverage, heartbeat_loop,
                      load_engine, main_loop)
from detectors import (BoundedState, CcsdsDetector, Detector, Evidence,
                       EvidenceClass, Hit, Iec104Detector, IdentificationBasis,
                       MavlinkDetector,
                       ModbusDetector, PacketContext, ParamRangeDetector, RateDetector,
                       RequestBurstDetector,
                       RtpsDetector, SignatureDetector, SnmpDetector, TlsObserveDetector,
                       UdsCanDetector,
                       crc16_ccitt, mavlink_frame_crc, normalize,
                       parse_ccsds_packet, parse_mavlink_frames,
                       parse_rtps_message)
# 리허설 스켈레톤 전용 검사기 — 본선 무관, rehearsal_web_detectors.py 참조
from rehearsal_web_detectors import (AuthSessionDetector, L3ProductIdDetector,
                                     McsScriptTraversalDetector, UrlSsrGuardDetector)
from tests.packet_util import (build_ipv6_packet, build_packet, build_udp_packet,
                               http_get, packet_for)
from tests.rule_fixtures import TEST_SIGNATURES, TEST_WHITELIST


def engine() -> VerdictEngine:
    return VerdictEngine.from_config(TEST_SIGNATURES, TEST_WHITELIST)


class TestAttackDetection(unittest.TestCase):
    def setUp(self):
        self.e = engine()

    def _v(self, pkt):
        return self.e.verdict(pkt)[0]

    def test_sqli_union_dropped(self):
        pkt = packet_for(8084, "/product?id=1 UNION SELECT sql FROM sqlite_master")
        self.assertEqual(self._v(pkt), VERDICT_DROP)

    def test_sqli_case_and_comment_evasion_dropped(self):
        # 대소문자·inline comment 우회의 정규화 무력화 후 DROP
        pkt = packet_for(8084, "/product?id=1 UnIoN/**/SeLeCt 1,2,3")
        self.assertEqual(self._v(pkt), VERDICT_DROP)

    def test_ssrf_loopback_dropped(self):
        pkt = packet_for(8082, "/fetch?url=http://127.0.0.1:8082/registry")
        self.assertEqual(self._v(pkt), VERDICT_DROP)

    def test_ssrf_url_encoded_evasion_dropped(self):
        # URL encoding으로 은닉한 /registry의 정규화 복원 후 DROP
        pkt = packet_for(8082, "/fetch?url=http://127.0.0.1:8082/%72%65%67%69%73%74%72%79")
        self.assertEqual(self._v(pkt), VERDICT_DROP)

    def test_double_encoded_traversal_reaches_threshold_with_quorum(self):
        # 이중 인코딩된 ../ + /etc/passwd (약한 신호 0.5 + 0.5 = 1.0) → DROP
        pkt = packet_for(8082, "/fetch?url=%252e%252e%252f%65%74%63%2f%70%61%73%73%77%64")
        self.assertEqual(self._v(pkt), VERDICT_DROP)

    def test_cookie_role_tamper_base64_dropped(self):
        # Layer 2: base64 은닉 {"role":"admin"} cookie의 평문화 후 DROP
        import base64
        tok = base64.b64encode(b'{"role":"admin"}').decode()
        pkt = packet_for(8083, "/admin", cookie=f"session={tok}")
        self.assertEqual(self._v(pkt), VERDICT_DROP)

    def test_normal_base64_cookie_accepted(self):
        # 정상 세션(base64 {"role":"user"})은 디코드돼도 룰에 안 걸려 통과 (오탐 없음)
        import base64
        tok = base64.b64encode(b'{"role":"user"}').decode()
        pkt = packet_for(8083, "/admin", cookie=f"session={tok}")
        self.assertEqual(self._v(pkt), VERDICT_ACCEPT)


class TestFalsePositiveGuard(unittest.TestCase):
    """오탐에 따른 SLA 곱셈 손실 방지를 위한 정상 traffic 통과 검증"""

    def setUp(self):
        self.e = engine()

    def _v(self, pkt):
        return self.e.verdict(pkt)[0]

    def test_health_whitelisted(self):
        self.assertEqual(self._v(packet_for(8082, "/health")), VERDICT_ACCEPT)

    def test_normal_product_query_accepted(self):
        self.assertEqual(self._v(packet_for(8084, "/product?id=5")), VERDICT_ACCEPT)

    def test_root_accepted(self):
        self.assertEqual(self._v(packet_for(8082, "/")), VERDICT_ACCEPT)

    def test_weak_signal_alone_not_dropped(self):
        # ../ 단독(weight 0.5) — 임계 미달이면 ACCEPT(관찰만), 과잉차단 방지
        v, info = self.e.verdict(packet_for(8082, "/static/../css/app.css"))
        self.assertEqual(v, VERDICT_ACCEPT)
        self.assertGreater(info.get("score", 0), 0)  # 관찰 대상으로 점수는 잡힘


class TestUrlSsrfGuard(unittest.TestCase):
    def setUp(self):
        self.e = VerdictEngine([UrlSsrGuardDetector()])

    def _verdict(self, path, **kwargs):
        return self.e.verdict(packet_for(8082, path, **kwargs))[0]

    def test_internal_hostname_encoded_dropped(self):
        path = "/fetch?url=http%3A%2F%2Fhelper-box%3A8080%2Fsecret"
        self.assertEqual(self._verdict(path), VERDICT_DROP)

    def test_file_scheme_dropped(self):
        self.assertEqual(self._verdict("/fetch?url=file:///flag"), VERDICT_DROP)

    def test_other_dangerous_schemes_dropped(self):
        for scheme in ("gopher", "ftp", "dict", "data"):
            with self.subTest(scheme=scheme):
                self.assertEqual(self._verdict(f"/fetch?url={scheme}://example.test/x"),
                                 VERDICT_DROP)

    def test_non_global_ip_variants_dropped(self):
        targets = ("127.0.0.1", "127.1", "0177.0.0.1", "[::1]", "0x7f000001",
                   "10.0.0.1", "169.254.169.254")
        for target in targets:
            with self.subTest(target=target):
                self.assertEqual(self._verdict(f"/fetch?url=http://{target}/registry"),
                                 VERDICT_DROP)

    def test_normal_external_urls_accepted(self):
        self.assertEqual(self._verdict("/fetch?url=https://example.com/data"), VERDICT_ACCEPT)
        self.assertEqual(self._verdict("/fetch?url=http://example.com/data"), VERDICT_ACCEPT)

    def test_health_and_root_accepted(self):
        self.assertEqual(self._verdict("/health"), VERDICT_ACCEPT)
        self.assertEqual(self._verdict("/"), VERDICT_ACCEPT)

    def test_user_agent_does_not_bypass_guard(self):
        path = "/fetch?url=http%3A%2F%2Fhelper-box%3A8080%2Fsecret"
        self.assertEqual(self._verdict(path, extra={"User-Agent": "lig-sla/1.0"}),
                         VERDICT_DROP)

    def test_attack_text_outside_url_parameter_accepted(self):
        self.assertEqual(self._verdict("/fetch?note=file:///flag"), VERDICT_ACCEPT)

    def test_percent_encoded_request_path_dropped(self):
        # 리허설 Round 14 관측 우회, `/%66%65%74%63%68` = `/fetch`
        path = "/%66%65%74%63%68?url=http%3A%2F%2Fhelper-box%3A8080%2Fsecret"
        self.assertEqual(self._verdict(path), VERDICT_DROP)

    def test_fully_encoded_path_and_parameter_dropped(self):
        path = ("/%66%65%74%63%68?%75%72%6C=%68%74%74%70%3A%2F%2F"
                "%68%65%6C%70%65%72%2D%62%6F%78%3A%38%30%38%30%2F%73%65%63%72%65%74")
        self.assertEqual(self._verdict(path), VERDICT_DROP)

    def test_double_encoded_parameter_name_dropped(self):
        path = "/fetch?%2575%2572%256C=http%3A%2F%2Fhelper-box%3A8080%2Fsecret"
        self.assertEqual(self._verdict(path), VERDICT_DROP)

    def test_unrelated_encoded_path_still_accepted(self):
        # `/fetch` 계열이 아닌 경로는 디코딩 후에도 검사 대상이 아니다
        self.assertEqual(self._verdict("/%68%65%61%6C%74%68"), VERDICT_ACCEPT)


def _split(payload: bytes, size: int, base_seq: int = 1) -> list[tuple[int, bytes]]:
    """payload를 size 단위 TCP 세그먼트 (seq, bytes) 목록으로 분할"""
    return [(base_seq + i, payload[i:i + size])
            for i in range(0, len(payload), size)]


class TestSegmentReassembly(unittest.TestCase):
    """TCP 분할·순서 뒤섞기 회피 대응

    리허설 Round 13·14에서 공격자가 요청 하나를 7~29개 세그먼트로 쪼개고 순서를
    뒤섞어 전송해 모든 룰을 회피한 사례에 대한 회귀 검증이다.
    """

    SSRF = http_get("/fetch?url=http%3A%2F%2Fhelper-box%3A8080%2Fsecret",
                    host="team9.lig.internal:8082")
    BENIGN = http_get("/fetch?url=https%3A%2F%2Fexample.com%2Fdata",
                      host="team9.lig.internal:8082")

    def _feed(self, segments, dport=8082, sport=40001, engine=None):
        """세그먼트를 주어진 순서로 판정하고 verdict 목록 반환"""
        e = engine or VerdictEngine([UrlSsrGuardDetector()])
        return [e.verdict(build_packet(dport, payload, sport=sport, seq=seq))[0]
                for seq, payload in segments]

    def test_reordered_segments_are_reassembled_and_dropped(self):
        segments = _split(self.SSRF, 8)
        shuffled = segments[3:] + segments[:3]       # 앞부분을 뒤로 미룬 순서 뒤섞기
        verdicts = self._feed(shuffled)
        self.assertIn(VERDICT_DROP, verdicts)

    def test_completing_segment_is_the_one_dropped(self):
        """빈 구간을 메우는 마지막 세그먼트에서 요청 전체가 드러나 DROP된다"""
        segments = _split(self.SSRF, 8)
        head, rest = segments[0], segments[1:]
        verdicts = self._feed(rest + [head])
        self.assertEqual(verdicts[-1], VERDICT_DROP)
        self.assertNotIn(VERDICT_DROP, verdicts[:-1])

    def test_in_order_segments_dropped(self):
        self.assertIn(VERDICT_DROP, self._feed(_split(self.SSRF, 8)))

    def test_many_small_segments_dropped(self):
        # 실제 관측된 13~29 세그먼트 규모
        self.assertIn(VERDICT_DROP, self._feed(_split(self.SSRF, 4)))

    def test_retransmitted_segment_keeps_same_verdict(self):
        """DROP된 세그먼트가 재전송돼도 동일하게 DROP된다"""
        segments = _split(self.SSRF, 8)
        e = VerdictEngine([UrlSsrGuardDetector()])
        first = self._feed(segments[1:] + [segments[0]], engine=e)
        self.assertEqual(first[-1], VERDICT_DROP)
        replay = self._feed([segments[0]], engine=e)
        self.assertEqual(replay[0], VERDICT_DROP)

    def test_split_benign_request_accepted(self):
        """정상 요청은 분할·순서 뒤섞임과 무관하게 통과한다 (SLA 오탐 방지)"""
        segments = _split(self.BENIGN, 8)
        verdicts = self._feed(segments[4:] + segments[:4])
        self.assertNotIn(VERDICT_DROP, verdicts)

    def test_split_admin_session_reassembled_and_dropped(self):
        token = base64.b64encode(b'{"user":"guest","role":"admin"}').decode()
        request = http_get("/admin", host="team9.lig.internal:8083",
                           cookie=f"session={token}")
        segments = _split(request, 6)
        e = VerdictEngine([AuthSessionDetector(mode="enforce")])
        verdicts = self._feed(segments[2:] + segments[:2], dport=8083, engine=e)
        self.assertIn(VERDICT_DROP, verdicts)

    def test_separate_flows_do_not_merge(self):
        """서로 다른 flow의 조각이 합쳐져 오탐을 만들지 않는다"""
        segments = _split(self.SSRF, 8)
        e = VerdictEngine([UrlSsrGuardDetector()])
        verdicts = [
            e.verdict(build_packet(8082, payload, sport=40001 + index, seq=seq))[0]
            for index, (seq, payload) in enumerate(segments)
        ]
        self.assertNotIn(VERDICT_DROP, verdicts)


class TestTcpStreamWindow(unittest.TestCase):
    FLOW = (4, 6, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", 40001, 8082)

    def _window(self, clock=None, **kwargs):
        return TcpStreamWindow(now=clock or (lambda: 0.0), **kwargs)

    def test_out_of_order_segments_assemble_in_seq_order(self):
        w = self._window()
        self.assertEqual(w.add(self.FLOW, 100, b"AAA"), b"AAA")
        self.assertEqual(w.add(self.FLOW, 106, b"CCC"), b"CCC")   # 빈 구간 존재
        self.assertEqual(w.add(self.FLOW, 103, b"BBB"), b"AAABBBCCC")

    def test_pending_segment_returns_itself_only(self):
        """빈 구간이 남은 조각은 없는 인접성을 만들지 않는다"""
        w = self._window()
        w.add(self.FLOW, 100, b"AAA")
        self.assertEqual(w.add(self.FLOW, 200, b"ZZZ"), b"ZZZ")

    def test_overlapping_segment_keeps_first_content(self):
        w = self._window()
        w.add(self.FLOW, 100, b"AAAA")
        self.assertEqual(w.add(self.FLOW, 102, b"XXXX"), b"AAAAXX")

    def test_duplicate_segment_is_idempotent(self):
        w = self._window()
        w.add(self.FLOW, 100, b"AAA")
        w.add(self.FLOW, 103, b"BBB")
        self.assertEqual(w.add(self.FLOW, 100, b"AAA"), b"AAABBB")

    def test_ttl_expiry_restarts_window(self):
        clock = [0.0]
        w = self._window(clock=lambda: clock[0], ttl=5.0)
        w.add(self.FLOW, 100, b"AAA")
        clock[0] = 99.0
        self.assertEqual(w.add(self.FLOW, 103, b"BBB"), b"BBB")

    def test_cap_bounds_assembled_length(self):
        w = self._window(cap=16)
        w.add(self.FLOW, 100, b"A" * 12)
        self.assertEqual(w.add(self.FLOW, 112, b"B" * 12), b"B" * 12)

    def test_flow_table_respects_max_flows(self):
        w = self._window(max_flows=4)
        for index in range(40):
            flow = (4, 6, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", index, 8082)
            w.add(flow, 1, b"payload")
        self.assertLessEqual(len(w._flows), 4)

    def test_pending_segment_count_is_bounded(self):
        w = self._window(max_segments=8)
        for index in range(60):
            w.add(self.FLOW, 1000 + index * 10, b"XX")   # 계속 빈 구간을 남기는 조각
        self.assertLessEqual(len(w._flows[self.FLOW].pending), 8)


class TestPhase2Guards(unittest.TestCase):
    @staticmethod
    def _admin_packet(path="/admin"):
        token = base64.b64encode(
            b'{"user":"checker","role":"admin","is_admin":true}').decode()
        return packet_for(8083, path, cookie=f"session={token}")

    def test_admin_session_observed_without_drop(self):
        verdict, info = VerdictEngine([AuthSessionDetector(mode="observe")]).verdict(
            self._admin_packet())
        self.assertEqual(verdict, VERDICT_ACCEPT)
        evidence = next(item for item in info["evidence"]
                        if item["rule_id"] == "MCS-AUTH-SESSION-STRUCTURED")
        self.assertFalse(evidence["drop_eligible"])

    def test_admin_session_enforce_mode_drops(self):
        verdict, _ = VerdictEngine([AuthSessionDetector(mode="enforce")]).verdict(
            self._admin_packet())
        self.assertEqual(verdict, VERDICT_DROP)

    def test_spoofed_sla_user_agent_does_not_bypass_admin_guard(self):
        token = base64.b64encode(
            b'{"user":"checker","role":"admin","admin":true,"is_admin":true}').decode()
        packet = packet_for(
            8083, "/admin", cookie=f"session={token}",
            extra={"User-Agent": "lig-sla/1.0"})
        verdict, _ = VerdictEngine([AuthSessionDetector(mode="enforce")]).verdict(packet)
        self.assertEqual(verdict, VERDICT_DROP)

    def test_sla_user_agent_does_not_bypass_other_paths(self):
        token = base64.b64encode(b'{"role":"admin"}').decode()
        packet = packet_for(
            8083, "/openc3-api/admin/keyring", cookie=f"session={token}",
            extra={"User-Agent": "lig-sla/1.0"})
        verdict, _ = VerdictEngine([AuthSessionDetector(mode="enforce")]).verdict(packet)
        self.assertEqual(verdict, VERDICT_DROP)

    def test_octal_escaped_cookie_value_dropped(self):
        # 리허설 Round 17·18에서 관측된 형태: session="\145yJ..." (옥탈 이스케이프)
        packet = packet_for(
            8083, "/admin",
            cookie='session="\\145yJ1c2V\\171IjogImd1ZXN\\060IiwgInJvbGUiOiAiYWRtaW4ifQ=="')
        verdict, _ = VerdictEngine([AuthSessionDetector(mode="enforce")]).verdict(packet)
        self.assertEqual(verdict, VERDICT_DROP)

    def test_hex_escaped_cookie_value_dropped(self):
        token = base64.b64encode(b'{"user":"guest","role":"admin"}').decode()
        escaped = "".join(f"\\x{ord(c):02x}" if i % 3 == 0 else c
                          for i, c in enumerate(token))
        packet = packet_for(8083, "/admin", cookie=f'session="{escaped}"')
        verdict, _ = VerdictEngine([AuthSessionDetector(mode="enforce")]).verdict(packet)
        self.assertEqual(verdict, VERDICT_DROP)

    def test_unicode_escaped_cookie_value_dropped(self):
        token = base64.b64encode(b'{"user":"guest","role":"admin"}').decode()
        escaped = "".join(f"\\u{ord(c):04x}" if i % 3 == 0 else c
                          for i, c in enumerate(token))
        packet = packet_for(8083, "/admin", cookie=f'session="{escaped}"')
        verdict, _ = VerdictEngine([AuthSessionDetector(mode="enforce")]).verdict(packet)
        self.assertEqual(verdict, VERDICT_DROP)

    def test_normal_cookie_without_escapes_still_accepted(self):
        token = base64.b64encode(b'{"user":"guest","role":"user"}').decode()
        packet = packet_for(8083, "/admin", cookie=f"session={token}")
        verdict, _ = VerdictEngine([AuthSessionDetector(mode="enforce")]).verdict(packet)
        self.assertEqual(verdict, VERDICT_ACCEPT)

    def test_garbage_after_deescape_fails_open_to_accept(self):
        packet = packet_for(8083, "/admin", cookie='session="\\777not-base64\\xzz"')
        verdict, _ = VerdictEngine([AuthSessionDetector(mode="enforce")]).verdict(packet)
        self.assertEqual(verdict, VERDICT_ACCEPT)

    def test_script_flags_traversal_dropped(self):
        detector = McsScriptTraversalDetector()
        packet = packet_for(8083, "/script-api/scripts/mcs_ops/../../../../flags/l2")
        verdict, info = VerdictEngine([detector]).verdict(packet)
        self.assertEqual(verdict, VERDICT_DROP)
        self.assertEqual(info["evidence"][0]["rule_id"], "MCS-SCRIPT-TRAVERSAL")

    def test_normal_script_path_accepted(self):
        detector = McsScriptTraversalDetector()
        packet = packet_for(8083, "/script-api/scripts/mcs_ops/status")
        self.assertEqual(VerdictEngine([detector]).verdict(packet)[0], VERDICT_ACCEPT)


class TestStability(unittest.TestCase):
    """fail-open: 모든 이상 입력의 판정 지속과 ACCEPT 수렴"""

    def setUp(self):
        self.e = engine()

    def test_non_tcp_accepted(self):
        self.assertEqual(self.e.verdict(b"\x00" * 30)[0], VERDICT_ACCEPT)

    def test_truncated_packet_accepted(self):
        self.assertEqual(self.e.verdict(b"\x45\x00\x00")[0], VERDICT_ACCEPT)

    def test_empty_payload_accepted(self):
        self.assertEqual(self.e.verdict(build_packet(8084, b""))[0], VERDICT_ACCEPT)

    def test_udp_payload_is_parsed_and_checked(self):
        # protocol 중립: 방산 protocol 대비 UDP payload 파싱과 검사 대상 포함
        pkt = build_udp_packet(8084, b"q=1 union select sql from sqlite_master")
        self.assertEqual(self.e.verdict(pkt)[0], VERDICT_DROP)

    def test_udp_binary_benign_accepted(self):
        # 룰 미탐 binary UDP(telemetry 등) 통과와 proto field 노출
        v, info = self.e.verdict(build_udp_packet(9999, bytes(range(32))))
        self.assertEqual(v, VERDICT_ACCEPT)
        self.assertEqual(info.get("proto"), 17)

    def test_ipv6_tcp_is_parsed_and_checked(self):
        pkt = build_ipv6_packet(8084, b"GET /?id=1 union select sql HTTP/1.1\r\n\r\n")
        self.assertEqual(self.e.verdict(pkt)[0], VERDICT_DROP)

    def test_ipv4_fragment_is_accepted_without_partial_inspection(self):
        pkt = build_packet(8084, b"union select", frag=0x2000)  # more-fragments bit
        self.assertEqual(self.e.verdict(pkt)[0], VERDICT_ACCEPT)

    def test_split_tcp_signature_detected_on_contiguous_second_segment(self):
        part1 = b"GET /?id=1 uni"
        first = build_packet(8084, part1, seq=100)
        second = build_packet(8084, b"on select sql HTTP/1.1\r\n\r\n", seq=100 + len(part1))
        self.assertEqual(self.e.verdict(first)[0], VERDICT_ACCEPT)
        self.assertEqual(self.e.verdict(second)[0], VERDICT_DROP)

    def test_icmp_and_other_proto_accepted(self):
        # TCP/UDP 외 프로토콜은 검사 대상 아님 → 통과(fail-open)
        import struct
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 28, 0x1, 0, 64, 1, 0,
                         b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")  # proto=1(ICMP)
        self.assertEqual(self.e.verdict(ip + b"\x08\x00rest")[0], VERDICT_ACCEPT)

    def test_unsupported_version_fuzz_accepted(self):
        import os
        for _ in range(50):
            packet = bytearray(os.urandom(64))
            packet[0] &= 0x0F
            self.assertEqual(self.e.verdict(bytes(packet))[0], VERDICT_ACCEPT)


class TestPacketStructure(unittest.TestCase):
    """구조 위반과 캡처 불완전의 분리 및 판정 검증"""

    def setUp(self):
        self.e = VerdictEngine([])

    def test_invalid_ipv4_header_length_is_malformed_and_dropped(self):
        packet = bytearray(build_packet(8084, b"x"))
        packet[0] = 0x44
        verdict, info = self.e.verdict(bytes(packet))
        self.assertEqual(verdict, VERDICT_DROP)
        self.assertEqual(info["parse_status"], ParseStatus.MALFORMED.value)
        self.assertEqual(info["evidence"][0]["rule_id"], "IP4-01")

    def test_capture_shorter_than_ipv4_total_is_incomplete_and_accepted(self):
        packet = bytearray(build_packet(8084, b"x"))
        packet[2:4] = (len(packet) + 20).to_bytes(2, "big")
        verdict, info = self.e.verdict(bytes(packet))
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertEqual(info["parse_status"], ParseStatus.INCOMPLETE.value)

    def test_udp_length_mismatch_is_malformed_and_dropped(self):
        packet = bytearray(build_udp_packet(8084, b"abc"))
        packet[24:26] = (7).to_bytes(2, "big")
        verdict, info = self.e.verdict(bytes(packet))
        self.assertEqual(verdict, VERDICT_DROP)
        self.assertEqual(info["evidence"][0]["rule_id"], "L4-UDP-01")

    def test_tcp_null_flags_are_observation_only(self):
        packet = bytearray(build_packet(8084, b"x"))
        packet[33] = 0
        verdict, info = self.e.verdict(bytes(packet))
        self.assertEqual(verdict, VERDICT_ACCEPT)
        evidence = next(item for item in info["evidence"]
                        if item["rule_id"] == "L4-TCP-01")
        self.assertFalse(evidence["drop_eligible"])


class TestEvidenceGates(unittest.TestCase):
    """근거 등급과 프로토콜 식별 조건의 점수 반영 검증"""

    @staticmethod
    def _packet():
        return build_udp_packet(5000, b"x")

    def test_observation_only_never_contributes_drop_score(self):
        class Observe(Detector):
            def inspect(self, ctx):
                return [Evidence(9.0, "observation", rule_id="OBS-01",
                                 evidence_class=EvidenceClass.OBSERVATION_ONLY,
                                 identification_basis=IdentificationBasis.STRUCTURE_VERIFIED)]
        verdict, info = VerdictEngine([Observe()]).verdict(self._packet())
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertEqual(info["score"], 0.0)

    def test_unverified_identification_never_contributes_drop_score(self):
        class Unverified(Detector):
            def inspect(self, ctx):
                return [Evidence(9.0, "guess", rule_id="PROTO-01",
                                 evidence_class=EvidenceClass.ATTACK_PATTERN_CONFIRMED,
                                 identification_basis=IdentificationBasis.SCHEMA_DEPENDENT,
                                 identification_verified=False)]
        verdict, info = VerdictEngine([Unverified()]).verdict(self._packet())
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertFalse(info["evidence"][0]["drop_eligible"])

    def test_context_required_needs_satisfied_prerequisites(self):
        class MissingContext(Detector):
            def inspect(self, ctx):
                return [Evidence(1.0, "missing profile", rule_id="CTX-01",
                                 prerequisites_satisfied=False)]
        self.assertEqual(VerdictEngine([MissingContext()]).verdict(self._packet())[0],
                         VERDICT_ACCEPT)


class TestBoundedState(unittest.TestCase):
    """공통 상태 저장소의 key 상한과 TTL 검증"""

    def test_capacity_uses_lru_eviction(self):
        state = BoundedState(max_keys=2, ttl=10, now=lambda: 0)
        state.put("a", 1)
        state.put("b", 2)
        state.get("a")
        state.put("c", 3)
        self.assertEqual(len(state), 2)
        self.assertIsNone(state.get("b"))
        self.assertEqual(state.get("a"), 1)

    def test_ttl_expiration(self):
        clock = {"t": 0.0}
        state = BoundedState(max_keys=2, ttl=1, now=lambda: clock["t"])
        state.put("a", 1)
        clock["t"] = 1.1
        self.assertIsNone(state.get("a"))

    def test_access_refreshes_ttl(self):
        clock = {"t": 0.0}
        state = BoundedState(max_keys=2, ttl=1, now=lambda: clock["t"])
        state.put("a", 1)
        clock["t"] = 0.8
        self.assertEqual(state.get("a"), 1)
        clock["t"] = 1.5
        self.assertEqual(state.get("a"), 1)


class TestRuleLoadingAndBudget(unittest.TestCase):
    """룰 적재 실패 격리와 판정 시간 예산 검증"""

    def test_bad_signature_is_skipped_not_fatal(self):
        # 불량 룰(정규식 오류) 혼재 시 engine 기동과 나머지 룰 동작
        e = VerdictEngine.from_config([{"port": 8084, "pattern": r"("},   # 잘못된 정규식
                                       {"port": 8084, "pattern": r"union\s+select", "reason": "ok"}],
                                      [])
        self.assertEqual(e.rule_count, 1)
        self.assertEqual(e.verdict(packet_for(8084, "/p?id=1 union select 1"))[0], VERDICT_DROP)

    def test_nested_quantifier_signature_is_rejected(self):
        e = VerdictEngine.from_config([{"pattern": r"(a+)+$"}], [])
        self.assertEqual(e.rule_count, 0)

    def test_detector_budget_timeout_fails_open(self):
        class Slow(Detector):
            def inspect(self, ctx):
                time.sleep(0.05)
                return [Hit(1.0, "late")]
        e = VerdictEngine([Slow()], budget_ms=5)
        started = time.monotonic()
        verdict, info = e.verdict(packet_for(8084, "/"))
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertLess(time.monotonic() - started, 0.04)
        self.assertIn("budget_exceeded", info["reasons"])

    def test_engine_never_raises_on_empty_ruleset(self):
        e = VerdictEngine.from_config([], [])
        self.assertEqual(e.verdict(packet_for(8084, "/p?id=1 union select 1"))[0], VERDICT_ACCEPT)


class TestNormalization(unittest.TestCase):
    def test_double_unquote(self):
        self.assertEqual(normalize("%252e%252e%252f"), "../")

    def test_comment_strip_and_lower(self):
        # SQL comment의 공백 역할에 따른 keyword 사이 공백 복원
        self.assertEqual(normalize("UNION/**/SELECT"), "union select")
        self.assertEqual(normalize("1/**/UNION/**/SELECT/**/pw"), "1 union select pw")


class TestDetectorPlugins(unittest.TestCase):
    """검사기 plugin: 검사기 추가 기반 비웹 방산·이상 탐지 동작"""

    def test_param_range_detector_flags_out_of_range(self):
        # 방산: 제어 파라미터가 안전범위 밖(dahAgent PARAM_SET 안전범위의 HTTP판)
        # 서로 다른 두 요청이므로 각각 별도 flow로 보낸다. 같은 flow에 동일 seq로
        # 보내면 TCP 재조립이 재전송으로 간주해 먼저 도착한 내용을 유지한다.
        det = ParamRangeDetector({8085: {"gain": (0.0, 0.5, 1.0)}})
        e = VerdictEngine([det])
        attack = build_packet(8085, http_get("/ctrl?gain=9.99"), sport=40001)
        normal = build_packet(8085, http_get("/ctrl?gain=0.3"), sport=40002)
        self.assertEqual(e.verdict(attack)[0], VERDICT_DROP)
        self.assertEqual(e.verdict(normal)[0], VERDICT_ACCEPT)

    def test_rate_detector_flags_burst(self):
        # 이상: 포트별 요청 rate 급증(대량 명령 mass-push), now 주입으로 결정성 확보
        clock = {"t": 0.0}
        det = RequestBurstDetector(
            per_sec=3, window=1.0, weight=1.0, now=lambda: clock["t"])
        e = VerdictEngine([det])
        pkt = packet_for(8086, "/cmd")
        verdicts = [e.verdict(pkt)[0] for _ in range(5)]  # 같은 순간 5회 → 임계(3) 초과
        self.assertEqual(verdicts[:3], [VERDICT_ACCEPT, VERDICT_ACCEPT, VERDICT_ACCEPT])
        self.assertIn(VERDICT_DROP, verdicts[3:])

    def test_rate_is_scoped_per_flow_by_default(self):
        clock = {"t": 0.0}
        det = RequestBurstDetector(per_sec=2, now=lambda: clock["t"])
        e = VerdictEngine([det])
        packets = [build_packet(8086, b"x", sport=41000 + n) for n in range(4)]
        self.assertTrue(all(e.verdict(pkt)[0] == VERDICT_ACCEPT for pkt in packets))

    def test_legacy_rate_detector_alias(self):
        self.assertIs(RateDetector, RequestBurstDetector)

    def test_binary_udp_via_param_detector_no_text_cost(self):
        # 바이너리 UDP도 검사기 순회 대상, 텍스트 룰 없으면 정규화 비용 없이 통과
        e = VerdictEngine([ParamRangeDetector({})])
        self.assertEqual(e.verdict(build_udp_packet(5555, bytes(range(40))))[0], VERDICT_ACCEPT)

    def test_quorum_counts_independent_sources_not_duplicate_hits(self):
        class DuplicateEvidence(Detector):
            def inspect(self, ctx):
                return [Hit(0.6, "same observation 1", "one-source"),
                        Hit(0.6, "same observation 2", "one-source")]
        class IndependentEvidence(Detector):
            def inspect(self, ctx):
                return [Hit(0.5, "a", "source-a"), Hit(0.5, "b", "source-b")]
        pkt = build_udp_packet(5000, b"x")
        self.assertEqual(VerdictEngine([DuplicateEvidence()]).verdict(pkt)[0], VERDICT_ACCEPT)
        self.assertEqual(VerdictEngine([IndependentEvidence()]).verdict(pkt)[0], VERDICT_DROP)


def _mav2(seq=1, sysid=1, compid=1, msgid=76, payload=b"", signed=False,
          link_id=7, timestamp=1000, valid_crc=False):
    flags = 1 if signed else 0
    header = bytes([0xFD, len(payload), flags, 0, seq, sysid, compid]) + msgid.to_bytes(3, "little")
    crc = mavlink_frame_crc(2, header[1:] + payload, msgid) if valid_crc else None
    frame = header + payload + ((crc or 0).to_bytes(2, "little"))
    if signed:
        frame += bytes([link_id]) + timestamp.to_bytes(6, "little") + b"\x00" * 6
    return frame


def _mav1(seq=1, sysid=1, compid=1, msgid=23, payload=b""):
    return bytes([0xFE, len(payload), seq, sysid, compid, msgid]) + payload + b"\x00\x00"


class TestMavlinkDetector(unittest.TestCase):
    def _ctx(self, frame, port=14550):
        return PacketContext(17, port, frame, flow=(4, 17, b"a", b"b", 4000, port))

    def test_parser_extracts_v1_and_signed_v2(self):
        out = parse_mavlink_frames(_mav1(seq=9) + _mav2(seq=10, signed=True, timestamp=12345))
        self.assertEqual([f.version for f in out], [1, 2])
        self.assertEqual(out[1].sig_timestamp, 12345)
        self.assertEqual(out[1].link_id, 7)

    def test_random_magic_without_complete_structure_is_ignored(self):
        self.assertEqual(parse_mavlink_frames(b"text\xfd\xffshort\xfe"), [])

    def test_observe_mode_reports_but_never_drops(self):
        e = VerdictEngine([MavlinkDetector(mode="observe")])
        pkt = build_udp_packet(14550, _mav2(signed=True, timestamp=1000))
        self.assertEqual(e.verdict(pkt)[0], VERDICT_ACCEPT)
        verdict, info = e.verdict(pkt)
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertTrue(any("signature_replay" in r for r in info["reasons"]))
        self.assertEqual(info["score"], 0.0)

    def test_enforce_mode_drops_replayed_signed_timestamp(self):
        e = VerdictEngine([MavlinkDetector(mode="enforce", ports=[14550])])
        first = build_udp_packet(14550, _mav2(seq=1, signed=True, timestamp=1000))
        replayed = build_udp_packet(14550, _mav2(seq=2, signed=True, timestamp=1000))
        self.assertEqual(e.verdict(first)[0], VERDICT_ACCEPT)
        self.assertEqual(e.verdict(replayed)[0], VERDICT_DROP)

    def test_unsigned_sensitive_only_actionable_when_required(self):
        frame = build_udp_packet(14550, _mav2(msgid=76, signed=False))
        permissive = VerdictEngine([
            MavlinkDetector(mode="enforce", ports=[14550], require_signed=False)])
        strict = VerdictEngine([
            MavlinkDetector(mode="enforce", ports=[14550], require_signed=True)])
        self.assertEqual(permissive.verdict(frame)[0], VERDICT_ACCEPT)
        self.assertEqual(strict.verdict(frame)[0], VERDICT_DROP)

    def test_port_allowlist_avoids_unrelated_binary(self):
        e = VerdictEngine([MavlinkDetector(mode="enforce", ports=[14550], require_signed=True)])
        self.assertEqual(e.verdict(build_udp_packet(9999, _mav2(msgid=76)))[0], VERDICT_ACCEPT)

    def test_enforce_without_port_profile_remains_non_blocking(self):
        e = VerdictEngine([MavlinkDetector(mode="enforce", require_signed=True)])
        packet = build_udp_packet(14550, _mav2(msgid=76, signed=False))
        verdict, info = e.verdict(packet)
        self.assertEqual(verdict, VERDICT_ACCEPT)
        evidence = next(item for item in info["evidence"]
                        if item["rule_id"] == "MAV-02")
        self.assertFalse(evidence["identification_verified"])

    @staticmethod
    def _param_set(name, value, signed=True, seq=1):
        payload = struct.pack("<fBB16sB", value, 1, 1,
                              name.encode().ljust(16, b"\x00"), 9)
        return build_udp_packet(14550, _mav2(
            seq=seq, msgid=23, payload=payload, signed=signed,
            timestamp=1000 + seq, valid_crc=True))

    def test_param_set_out_of_range_dropped_from_decoded_float(self):
        detector = MavlinkDetector(
            mode="enforce", ports=[14550], require_signed=False,
            validate_crc=True, param_ranges={"EK3_ACC_P_NSE": (0.001, 1.0)})
        verdict, info = VerdictEngine([detector]).verdict(
            self._param_set("EK3_ACC_P_NSE", 999.0))
        self.assertEqual(verdict, VERDICT_DROP)
        self.assertTrue(any(item["rule_id"] == "MAV-PARAM-01" for item in info["evidence"]))

    def test_param_set_in_range_accepted(self):
        detector = MavlinkDetector(
            mode="enforce", ports=[14550], require_signed=False,
            validate_crc=True, param_ranges={"EK3_ACC_P_NSE": (0.001, 1.0)})
        self.assertEqual(VerdictEngine([detector]).verdict(
            self._param_set("EK3_ACC_P_NSE", 0.2))[0], VERDICT_ACCEPT)

    def test_param_violation_observe_mode_never_drops(self):
        detector = MavlinkDetector(
            mode="observe", ports=[14550],
            validate_crc=True, param_ranges={"EK3_ACC_P_NSE": (0.001, 1.0)})
        verdict, info = VerdictEngine([detector]).verdict(
            self._param_set("EK3_ACC_P_NSE", 999.0))
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertIn("mavlink_param_out_of_range", info["reasons"][0])
        self.assertEqual(info["score"], 0.0)

    @staticmethod
    def _param_read(param_index, seq=1):
        # PARAM_REQUEST_READ(msgid 20): <hBB16s = index, target_sys, target_comp, param_id
        payload = struct.pack("<hBB16s", param_index, 1, 1, b"\x00" * 16)
        return build_udp_packet(14550, _mav2(seq=seq, msgid=20, payload=payload))

    def test_single_param_read_leaves_no_signal(self):
        e = VerdictEngine([MavlinkDetector(mode="observe", ports=[14550])])
        _, info = e.verdict(self._param_read(0))
        self.assertEqual(info["reasons"], [])

    def test_param_read_sweep_reported_as_enumeration_observe_only(self):
        # attack-agent mavlink-telemetry-read: param 공간을 훑는 READ 스캔 → 관찰만
        det = MavlinkDetector(mode="enforce", ports=[14550], param_read_scan=4)
        e = VerdictEngine([det])
        verdict = info = None
        for idx in range(10):
            verdict, info = e.verdict(self._param_read(idx, seq=idx + 1))
        self.assertEqual(verdict, VERDICT_DROP)   # enforce+포트: telemetry-read 스캔 차단
        evidence = next(item for item in info["evidence"]
                        if item["rule_id"] == "MAV-READ-SCAN")
        self.assertTrue(evidence["drop_eligible"])
        self.assertIn("mavlink_param_read_enumeration", evidence["reason"])

    def test_msgid_profile_flags_novel_after_warmup(self):
        # ocslab MAVLink 데이터셋: 정상 미션은 안정된 msgid 집합, 인젝션은 예상 밖 msgid.
        det = MavlinkDetector(mode="observe", ports=[14550], msgid_warmup=6,
                              msgid_rate_limit=1000)
        e = VerdictEngine([det])
        info = None
        for i in range(12):                              # warmup 동안 msgid {0,30,33}만 학습
            info = e.verdict(build_udp_packet(
                14550, _mav2(seq=i % 256, msgid=[0, 30, 33][i % 3], payload=b"\x00" * 4)))[1]
        self.assertFalse(any("msgid_novel" in r for r in info["reasons"]))   # 학습된 집합은 무신호
        # 인젝션: 프로파일 밖 msgid 76(COMMAND_LONG)
        verdict, info = e.verdict(build_udp_packet(
            14550, _mav2(seq=200, msgid=76, payload=b"\x00" * 33)))
        self.assertEqual(verdict, VERDICT_ACCEPT)        # 관찰만, 차단 안 함
        self.assertTrue(any("mavlink_msgid_novel msgid=76" in r for r in info["reasons"]))

    def test_msgid_flood_observed_once_per_window(self):
        det = MavlinkDetector(mode="observe", ports=[14550], msgid_warmup=1000,
                              msgid_rate_limit=20)
        e = VerdictEngine([det])
        reasons = []
        for i in range(40):
            _, info = e.verdict(build_udp_packet(
                14550, _mav2(seq=i % 256, msgid=30, payload=bytes([i % 250 + 1]))))
            reasons.extend(info["reasons"])
        floods = [r for r in reasons if "mavlink_msgid_flood" in r]
        self.assertEqual(len(floods), 1)                 # 창당 1회만 보고
        self.assertIn("msgid=30", floods[0])

    def test_msgid_profile_evidence_is_observation_only(self):
        det = MavlinkDetector(mode="enforce", ports=[14550], msgid_warmup=2,
                              msgid_rate_limit=1000)
        e = VerdictEngine([det])
        for i in range(4):
            e.verdict(build_udp_packet(14550, _mav2(seq=i, msgid=0, payload=b"\x00" * 4)))
        _, info = e.verdict(build_udp_packet(14550, _mav2(seq=9, msgid=76, payload=b"\x00" * 33)))
        evidence = next(i for i in info["evidence"] if i["rule_id"] == "MAV-MSGID-PROFILE")
        self.assertFalse(evidence["drop_eligible"])       # enforce여도 차단 안 함

    def test_command_long_profile_decodes_command_id(self):
        payload = struct.pack("<7fHBBB", *(0.0,) * 7, 176, 1, 1, 0)
        detector = MavlinkDetector(
            mode="observe", ports=[14550], dangerous_commands=[176])
        verdict, info = VerdictEngine([detector]).verdict(
            build_udp_packet(14550, _mav2(msgid=76, payload=payload)))
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertTrue(any("mavlink_command_profile_match command=176" in reason
                            for reason in info["reasons"]))

    def test_command_long_trailing_zero_truncation_restored(self):
        full = struct.pack("<7fHBBB", *(0.0,) * 7, 176, 1, 1, 0)
        truncated = full.rstrip(b"\x00")
        detector = MavlinkDetector(
            mode="observe", ports=[14550], dangerous_commands=[176])
        verdict, info = VerdictEngine([detector]).verdict(
            build_udp_packet(14550, _mav2(msgid=76, payload=truncated, valid_crc=True)))
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertTrue(any("mavlink_command_profile_match command=176" in reason
                            for reason in info["reasons"]))

    def test_invalid_crc_cannot_trigger_semantic_drop(self):
        payload = struct.pack("<fBB16sB", 999.0, 1, 1,
                              b"EK3_ACC_P_NSE".ljust(16, b"\x00"), 9)
        detector = MavlinkDetector(
            mode="enforce", ports=[14550], validate_crc=True,
            param_ranges={"EK3_ACC_P_NSE": (0.001, 1.0)})
        verdict, info = VerdictEngine([detector]).verdict(
            build_udp_packet(14550, _mav2(msgid=23, payload=payload, valid_crc=False)))
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertTrue(any("mavlink_crc_invalid" in reason for reason in info["reasons"]))

    def test_mission_item_decodes_current_redirect(self):
        payload = struct.pack("<7fHHBBBBB", *(0.0,) * 7, 4, 16, 1, 1, 3, 1, 1)
        detector = MavlinkDetector(mode="observe", ports=[14550])
        verdict, info = VerdictEngine([detector]).verdict(
            build_udp_packet(14550, _mav2(msgid=39, payload=payload)))
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertTrue(any("mavlink_mission_current seq=4 command=16" in reason
                            for reason in info["reasons"]))

def _ccsds(seq=1, apid=42, payload=b"abc", fecf=False, corrupt=False):
    first = apid & 0x7FF
    sequence = (3 << 14) | (seq & 0x3FFF)
    packet = struct.pack(">HHH", first, sequence, len(payload) - 1) + payload
    if fecf:
        crc = crc16_ccitt(packet) ^ (1 if corrupt else 0)
        packet += crc.to_bytes(2, "big")
    return packet


def _ccsds_sdls(seq=1, apid=0x123, payload=b"DISABLE", key=None,
                counter=1, bad_mac=False):
    packet = _ccsds(seq=seq, apid=apid, payload=payload, fecf=True)
    if key is None:
        return packet
    ctr = counter.to_bytes(4, "big")
    mac = hmac.digest(key, packet + ctr, "sha256")
    if bad_mac:
        mac = bytes([mac[0] ^ 1]) + mac[1:]
    return packet + ctr + mac


class TestCcsdsDetector(unittest.TestCase):
    def test_parser_and_fecf(self):
        packet = parse_ccsds_packet(_ccsds(seq=7, fecf=True))
        self.assertIsNotNone(packet)
        self.assertEqual(packet.sequence_count, 7)
        self.assertTrue(packet.fecf_valid)

    def test_observe_reports_invalid_fecf_without_drop(self):
        e = VerdictEngine([CcsdsDetector(mode="observe")])
        verdict, info = e.verdict(build_udp_packet(10000, _ccsds(fecf=True, corrupt=True)))
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertIn("ccsds_fecf_invalid apid=42", info["reasons"])

    def test_enforce_detects_sequence_replay(self):
        e = VerdictEngine([CcsdsDetector(mode="enforce", ports=[10000])])
        pkt = build_udp_packet(10000, _ccsds(seq=9))
        self.assertEqual(e.verdict(pkt)[0], VERDICT_ACCEPT)
        # 첫 이상 관찰과 단기 구간 내 두 번째 동일 이상 확정
        self.assertEqual(e.verdict(pkt)[0], VERDICT_ACCEPT)
        self.assertEqual(e.verdict(pkt)[0], VERDICT_DROP)

    def test_enforce_without_port_profile_remains_observation_only(self):
        e = VerdictEngine([CcsdsDetector(mode="enforce")])
        pkt = build_udp_packet(10000, _ccsds(seq=9, fecf=True, corrupt=True))
        verdict, info = e.verdict(pkt)
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertFalse(info["evidence"][0]["identification_verified"])

    def test_sensitive_command_without_sdls_dropped(self):
        detector = CcsdsDetector(
            mode="enforce", ports=[5111], apids=[0x123],
            sensitive_commands=["DISABLE"], require_sdls=True)
        verdict, info = VerdictEngine([detector]).verdict(
            build_udp_packet(5111, _ccsds_sdls()))
        self.assertEqual(verdict, VERDICT_DROP)
        self.assertTrue(any(item["rule_id"] == "CCSDS-SDLS-01"
                            for item in info["evidence"]))

    def test_sensitive_command_with_valid_sdls_accepted(self):
        key = b"rehearsal-test-key"
        detector = CcsdsDetector(
            mode="enforce", ports=[5111], apids=[0x123],
            sensitive_commands=["DISABLE"], require_sdls=True, sdls_key=key)
        self.assertEqual(VerdictEngine([detector]).verdict(
            build_udp_packet(5111, _ccsds_sdls(key=key)))[0], VERDICT_ACCEPT)

    def test_invalid_sdls_mac_dropped(self):
        key = b"rehearsal-test-key"
        detector = CcsdsDetector(
            mode="enforce", ports=[5111], apids=[0x123],
            sensitive_commands=["DISABLE"], require_sdls=True, sdls_key=key)
        verdict, info = VerdictEngine([detector]).verdict(
            build_udp_packet(5111, _ccsds_sdls(key=key, bad_mac=True)))
        self.assertEqual(verdict, VERDICT_DROP)
        self.assertTrue(any("ccsds_sdls_mac_invalid" in reason for reason in info["reasons"]))

    def test_non_sensitive_command_without_sdls_accepted(self):
        detector = CcsdsDetector(
            mode="enforce", ports=[5111], apids=[0x123],
            sensitive_commands=["DISABLE"], require_sdls=True)
        self.assertEqual(VerdictEngine([detector]).verdict(
            build_udp_packet(5111, _ccsds_sdls(payload=b"STATUS")))[0], VERDICT_ACCEPT)

    def test_apid_sweep_reported_as_enumeration_observe_only(self):
        # attack-agent ccsds-tm-read: flag telemetry를 찾으려 APID 공간을 훑는 스캔
        det = CcsdsDetector(mode="enforce", ports=[10000], apid_scan_targets=4)
        e = VerdictEngine([det])
        verdict = info = None
        for apid in range(10):
            verdict, info = e.verdict(build_udp_packet(10000, _ccsds(seq=apid, apid=100 + apid)))
        self.assertEqual(verdict, VERDICT_DROP)   # enforce+포트: APID 스캔 차단
        evidence = next(item for item in info["evidence"]
                        if item["rule_id"] == "CCSDS-READ-SCAN")
        self.assertTrue(evidence["drop_eligible"])

    def test_repeated_apid_is_not_enumeration(self):
        det = CcsdsDetector(mode="observe", ports=[10000], apid_scan_targets=4)
        e = VerdictEngine([det])
        info = None
        for i in range(20):
            _, info = e.verdict(build_udp_packet(10000, _ccsds(seq=i, apid=42)))
        self.assertFalse(any("ccsds_apid_enumeration" in r for r in info["reasons"]))


def _rtps(guid=b"G" * 12, version=(2, 3), vendor=b"\x01\x0f", malformed=False):
    header = b"RTPS" + bytes(version) + vendor + guid
    size = 99 if malformed else 1
    return header + bytes([0x15, 0x01]) + size.to_bytes(2, "little") + b"x"


def _rtps_data(writer_id, reader_id=b"RRRR", guid=b"G" * 12):
    # DATA(0x15) 서브메시지: extraFlags(2) octetsToInlineQos(2) readerId(4) writerId(4) writerSN(8)
    header = b"RTPS" + bytes((2, 3)) + b"\x01\x0f" + guid
    body = b"\x00\x00" + b"\x00\x00" + reader_id + writer_id + b"\x00" * 8
    return header + bytes([0x15, 0x01]) + len(body).to_bytes(2, "little") + body


class TestRtpsDetector(unittest.TestCase):
    def test_parser_extracts_profile_and_guid(self):
        msg = parse_rtps_message(_rtps())
        self.assertEqual(msg.version, (2, 3))
        self.assertEqual(msg.guid_prefix, b"G" * 12)
        self.assertFalse(msg.malformed)

    def test_observe_reports_malformed_without_drop(self):
        e = VerdictEngine([RtpsDetector(mode="observe")])
        verdict, info = e.verdict(build_udp_packet(7400, _rtps(malformed=True)))
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertIn("rtps_submessage_malformed", info["reasons"])

    def test_enforce_can_detect_guid_churn_when_explicitly_enabled(self):
        det = RtpsDetector(mode="enforce", max_guids=2)
        e = VerdictEngine([det])
        for marker in (b"A", b"B"):
            self.assertEqual(e.verdict(build_udp_packet(7400, _rtps(guid=marker * 12)))[0],
                             VERDICT_ACCEPT)
        self.assertEqual(e.verdict(build_udp_packet(7400, _rtps(guid=b"C" * 12)))[0],
                         VERDICT_DROP)

    def test_parser_extracts_data_endpoints(self):
        msg = parse_rtps_message(_rtps_data(b"\x00\x00\x01\x03"))
        self.assertEqual(msg.endpoints, ((b"RRRR", b"\x00\x00\x01\x03"),))

    def test_topic_sweep_reported_as_enumeration_observe_only(self):
        # attack-agent ros2-topic-read: flag 담은 topic을 찾으려 여러 writerId를 훑는 스캔
        det = RtpsDetector(mode="enforce", ports=[7400], topic_scan=4)
        e = VerdictEngine([det])
        verdict = info = None
        for t in range(10):
            verdict, info = e.verdict(build_udp_packet(7400, _rtps_data(bytes([0, 0, t, 0x03]))))
        self.assertEqual(verdict, VERDICT_DROP)   # enforce+포트: topic 스캔 차단
        evidence = next(item for item in info["evidence"]
                        if item["rule_id"] == "RTPS-READ-SCAN")
        self.assertTrue(evidence["drop_eligible"])

    def test_repeated_topic_is_not_enumeration(self):
        det = RtpsDetector(mode="observe", ports=[7400], topic_scan=4)
        e = VerdictEngine([det])
        info = None
        for _ in range(20):
            _, info = e.verdict(build_udp_packet(7400, _rtps_data(b"\x00\x00\x01\x03")))
        self.assertFalse(any("rtps_topic_enumeration" in r for r in info["reasons"]))


def _mbap(pdu: bytes, unit: int = 1, tid: int = 1, proto_id: int = 0,
         length: int | None = None) -> bytes:
    """MBAP(7B) + PDU. length 생략 시 실제 PDU와 일치하는 정상 프레임 생성"""
    declared = length if length is not None else len(pdu) + 1
    return struct.pack(">HHHB", tid, proto_id, declared, unit) + pdu


class TestModbusDetector(unittest.TestCase):
    """attack-agent 분석(2026-08-18)에서 발견된 사각지대. 위협 카탈로그·prelim 연구
    어디에도 없던 프로토콜이며, 우리 자체 공격 에이전트가 P1로 지정해뒀다."""

    def _verdict(self, pdu, mode="observe", ports=(502,), port=502, **kw):
        e = VerdictEngine([ModbusDetector(mode=mode, ports=ports)])
        return e.verdict(build_packet(port, _mbap(pdu, **kw)))

    def test_read_holding_registers_accepted_both_modes(self):
        pdu = b"\x03\x00\x00\x00\x0a"   # FC03 read holding registers
        for mode in ("observe", "enforce"):
            with self.subTest(mode=mode):
                self.assertEqual(self._verdict(pdu, mode=mode)[0], VERDICT_ACCEPT)

    def test_write_single_register_observed_but_not_dropped_in_enforce(self):
        pdu = b"\x06\x00\x01\x00\x2a"   # FC06 write single register
        verdict, info = self._verdict(pdu, mode="enforce")
        self.assertEqual(verdict, VERDICT_ACCEPT)   # baseline 없어 강제 차단 안 함
        evidence = next(item for item in info["evidence"]
                        if item["rule_id"] == "MODBUS-WRITE-FC")
        self.assertFalse(evidence["drop_eligible"])

    def test_write_reported_in_observe_mode(self):
        pdu = b"\x10\x00\x01\x00\x02\x04\x00\x01\x00\x02"   # FC16 write multiple registers
        verdict, info = self._verdict(pdu, mode="observe")
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertIn("modbus_non_read_function_code 0x10", info["reasons"])

    def test_exception_response_bit_maps_to_base_function_code(self):
        pdu = b"\x83\x02"   # FC03 exception response (0x80 | 0x03)
        self.assertEqual(self._verdict(pdu, mode="observe")[0], VERDICT_ACCEPT)
        _, info = self._verdict(pdu, mode="observe")
        self.assertEqual(info["reasons"], [])   # 0x03은 read FC이므로 무보고

    def test_non_zero_protocol_id_ignored(self):
        pdu = b"\x06\x00\x01\x00\x2a"
        verdict, info = self._verdict(pdu, mode="observe", proto_id=1)
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertEqual(info["reasons"], [])

    def test_length_mismatch_deferred_not_flagged(self):
        # 파이프라이닝된 다음 요청이 같은 세그먼트에 섞여 들어온 것처럼 length를 어긋나게
        pdu = b"\x06\x00\x01\x00\x2a" + b"\x03\x00\x00\x00\x01"
        verdict, info = self._verdict(pdu, mode="observe", length=6)
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertEqual(info["reasons"], [])

    def test_wrong_port_ignored(self):
        pdu = b"\x06\x00\x01\x00\x2a"
        verdict, info = self._verdict(pdu, mode="observe", ports=(502,), port=9999)
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertEqual(info["reasons"], [])

    def test_no_port_profile_produces_no_evidence(self):
        pdu = b"\x06\x00\x01\x00\x2a"
        verdict, info = self._verdict(pdu, mode="enforce", ports=())
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertEqual(info["reasons"], [])

    def test_rule_count_reflects_mode(self):
        self.assertEqual(ModbusDetector(mode="off").rule_count, 0)
        self.assertEqual(ModbusDetector(mode="observe").rule_count, 1)
        self.assertEqual(ModbusDetector(mode="enforce").rule_count, 1)

    @staticmethod
    def _read(addr):
        return b"\x03" + addr.to_bytes(2, "big") + b"\x00\x01"   # FC03 read 1 reg @addr

    def test_single_read_leaves_no_signal(self):
        # 단일 read는 정상 폴링과 구분 불가 — 근거를 남기지 않는다
        _, info = self._verdict(b"\x03\x00\x00\x00\x0a", mode="observe")
        self.assertEqual(info["reasons"], [])

    def test_repeated_same_register_read_is_not_enumeration(self):
        # 같은 레지스터를 반복 폴링하는 정상 트래픽은 distinct 대상이 1이라 스캔이 아니다
        det = ModbusDetector(mode="observe", ports=[502], read_scan_targets=4)
        e = VerdictEngine([det])
        seq = 1
        for _ in range(30):
            frame = _mbap(b"\x03\x00\x00\x00\x0a")
            _, info = e.verdict(build_packet(502, frame, seq=seq))
            seq += len(frame)
        self.assertEqual(info["reasons"], [])

    def test_pipelined_address_sweep_reported_observe_only(self):
        # attack-agent modbus-read-regs: 한 연결에서 연속 read로 주소 공간을 훑는 스캔.
        # 연속 seq라 재조립되지만, 프레임을 훑어 집계 → 관찰만(차단 없음).
        det = ModbusDetector(mode="enforce", ports=[502], read_scan_targets=4)
        e = VerdictEngine([det])
        verdict = info = None
        seq = 1
        for addr in range(10):
            frame = _mbap(self._read(addr))
            verdict, info = e.verdict(build_packet(502, frame, seq=seq))
            seq += len(frame)
        self.assertEqual(verdict, VERDICT_DROP)   # enforce+포트: 스캔 차단(flag 유출 방지)
        evidence = next(item for item in info["evidence"]
                        if item["rule_id"] == "MODBUS-READ-SCAN")
        self.assertTrue(evidence["drop_eligible"])
        self.assertIn("modbus_read_enumeration", evidence["reason"])

    def test_scan_observed_not_dropped_in_observe_mode(self):
        det = ModbusDetector(mode="observe", ports=[502], read_scan_targets=4)
        e = VerdictEngine([det])
        verdict = info = None
        seq = 1
        for addr in range(10):
            frame = _mbap(self._read(addr))
            verdict, info = e.verdict(build_packet(502, frame, seq=seq))
            seq += len(frame)
        self.assertEqual(verdict, VERDICT_ACCEPT)   # observe는 관찰만
        self.assertTrue(any("modbus_read_enumeration" in r for r in info["reasons"]))

    def test_surgical_known_reads_pass_during_active_scan(self):
        # 프로토콜 통째 차단이 아니라 스캔을 확장하는 요청만 차단: 스캔 진행 중에도 정상
        # 클라이언트가 아는 레지스터를 재조회하는 요청은 통과한다.
        det = ModbusDetector(mode="enforce", ports=[502], read_scan_targets=4)
        e = VerdictEngine([det])
        seq = 1

        def rd(addr, sport):
            nonlocal seq
            v, _ = e.verdict(build_packet(502, _mbap(self._read(addr)), seq=seq, sport=sport))
            seq += 12
            return v
        rd(0, 40001)                                  # 정상 클라가 레지스터 0을 학습
        for a in range(1, 12):                        # 공격 스캔이 임계를 넘김
            rd(0x1000 + a, 41001)
        self.assertEqual(rd(0x2000, 41001), VERDICT_DROP)    # 새 주소 스캔 read → 차단
        self.assertEqual(rd(0, 40001), VERDICT_ACCEPT)       # 아는 레지스터 재조회 → 통과

    def test_reconnect_sweep_aggregated_by_service(self):
        # NAT/재접속: 연결마다 sport가 달라도 서비스(dst,dport) 단위로 스캔을 집계한다
        det = ModbusDetector(mode="observe", ports=[502], read_scan_targets=4)
        e = VerdictEngine([det])
        info = None
        for addr in range(10):
            _, info = e.verdict(build_packet(502, _mbap(self._read(addr)), sport=40001 + addr))
        self.assertTrue(any("modbus_read_enumeration" in r for r in info["reasons"]))


# ── 2026-08-20 attack-agent origin/main 신규 프로토콜(UDS/CAN·IEC-104·SNMP) ──
def _uds_can(pdu, arb=0x7DF):
    return struct.pack(">IB", arb & 0x1FFFFFFF, len(pdu) & 0xFF) + pdu


def _uds_rdbi(did):
    return b"\x22" + struct.pack(">H", did)         # ReadDataByIdentifier(0x22) + DID


def _iec104(ioa, ca=1, type_id=102, cot=5):
    asdu = bytes([type_id, 0x01]) + struct.pack("<H", cot) + struct.pack("<H", ca) \
        + (ioa & 0xFFFFFF).to_bytes(3, "little")
    return bytes([0x68, 4 + len(asdu)]) + b"\x00\x00\x00\x00" + asdu


def _ber(tag, val):
    return bytes([tag, len(val)]) + val             # short-form(길이<128) 전용 테스트 헬퍼


def _ber_oid(arcs):
    body = bytes([arcs[0] * 40 + arcs[1]])
    for a in arcs[2:]:
        if a < 128:
            body += bytes([a])
        else:
            s = [a & 0x7F]
            a >>= 7
            while a:
                s.insert(0, (a & 0x7F) | 0x80)
                a >>= 7
            body += bytes(s)
    return _ber(0x06, body)


def _snmp_get(oid, pdu_tag=0xA0, community=b"public"):
    vb = _ber(0x30, _ber_oid(oid) + _ber(0x05, b""))
    pdu = _ber(pdu_tag, _ber(0x02, b"\x01") + _ber(0x02, b"\x00") + _ber(0x02, b"\x00")
               + _ber(0x30, vb))
    return _ber(0x30, _ber(0x02, b"\x01") + _ber(0x04, community) + pdu)


class TestUdsCanDetector(unittest.TestCase):
    """UDS-over-CAN-over-TCP (attack-agent origin/main P1: can_uds_read)"""

    def test_single_read_leaves_no_signal(self):
        e = VerdictEngine([UdsCanDetector(mode="observe", ports=[6801])])
        _, info = e.verdict(build_packet(6801, _uds_can(_uds_rdbi(0xF190))))
        self.assertEqual(info["reasons"], [])

    def test_did_sweep_reported_observe_only(self):
        det = UdsCanDetector(mode="enforce", ports=[6801], read_scan_targets=4)
        e = VerdictEngine([det])
        verdict = info = None
        seq = 1
        for did in range(10):
            frame = _uds_can(_uds_rdbi(0xF000 + did))
            verdict, info = e.verdict(build_packet(6801, frame, seq=seq))
            seq += len(frame)
        self.assertEqual(verdict, VERDICT_DROP)   # enforce+포트: 스캔 차단
        evidence = next(i for i in info["evidence"] if i["rule_id"] == "UDS-READ-SCAN")
        self.assertTrue(evidence["drop_eligible"])

    def test_write_sid_observed_not_dropped(self):
        det = UdsCanDetector(mode="enforce", ports=[6801])
        e = VerdictEngine([det])
        verdict, info = e.verdict(build_packet(6801, _uds_can(b"\x2e\xf1\x90\x01")))  # WriteDataByIdentifier
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertTrue(any("uds_non_read_sid 0x2e" in r for r in info["reasons"]))

    def test_no_port_profile_no_evidence(self):
        e = VerdictEngine([UdsCanDetector(mode="enforce", ports=())])
        _, info = e.verdict(build_packet(6801, _uds_can(_uds_rdbi(0xF190))))
        self.assertEqual(info["reasons"], [])


class TestIec104Detector(unittest.TestCase):
    """IEC 60870-5-104 (attack-agent origin/main P2: iec104_read)"""

    def test_single_read_leaves_no_signal(self):
        e = VerdictEngine([Iec104Detector(mode="observe", ports=[2404])])
        _, info = e.verdict(build_packet(2404, _iec104(0)))
        self.assertEqual(info["reasons"], [])

    def test_ioa_sweep_reported_observe_only(self):
        det = Iec104Detector(mode="enforce", ports=[2404], read_scan_targets=4)
        e = VerdictEngine([det])
        verdict = info = None
        seq = 1
        for ioa in range(10):
            frame = _iec104(ioa)
            verdict, info = e.verdict(build_packet(2404, frame, seq=seq))
            seq += len(frame)
        self.assertEqual(verdict, VERDICT_DROP)   # enforce+포트: 스캔 차단
        evidence = next(i for i in info["evidence"] if i["rule_id"] == "IEC104-READ-SCAN")
        self.assertTrue(evidence["drop_eligible"])

    def test_control_command_observed_not_dropped(self):
        det = Iec104Detector(mode="enforce", ports=[2404])
        e = VerdictEngine([det])
        # type 45 = C_SC_NA_1 single command (제어)
        _, info = e.verdict(build_packet(2404, _iec104(1, type_id=45, cot=6)))
        self.assertTrue(any("iec104_control_command type=45" in r for r in info["reasons"]))

    def test_non_start_byte_ignored(self):
        e = VerdictEngine([Iec104Detector(mode="observe", ports=[2404])])
        _, info = e.verdict(build_packet(2404, b"\x00" + _iec104(0)))
        self.assertEqual(info["reasons"], [])


class TestSnmpDetector(unittest.TestCase):
    """SNMP v2c (attack-agent origin/main P2: snmp_v2c_get)"""

    def test_single_get_leaves_no_signal(self):
        e = VerdictEngine([SnmpDetector(mode="observe", ports=[161])])
        _, info = e.verdict(build_udp_packet(161, _snmp_get((1, 3, 6, 1, 2, 1, 1, 1))))
        self.assertEqual(info["reasons"], [])

    def test_oid_sweep_reported_observe_only(self):
        det = SnmpDetector(mode="enforce", ports=[161], read_scan_targets=4)
        e = VerdictEngine([det])
        verdict = info = None
        for i in range(10):
            verdict, info = e.verdict(build_udp_packet(161, _snmp_get((1, 3, 6, 1, 2, 1, 1, i + 1))))
        self.assertEqual(verdict, VERDICT_DROP)   # enforce+포트: 스캔 차단
        evidence = next(i for i in info["evidence"] if i["rule_id"] == "SNMP-READ-SCAN")
        self.assertTrue(evidence["drop_eligible"])

    def test_set_request_observed_not_dropped(self):
        det = SnmpDetector(mode="enforce", ports=[161])
        e = VerdictEngine([det])
        verdict, info = e.verdict(build_udp_packet(161, _snmp_get((1, 3, 6, 1), pdu_tag=0xA3)))
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertTrue(any("snmp_set_request" in r for r in info["reasons"]))

    def test_non_snmp_ber_ignored(self):
        e = VerdictEngine([SnmpDetector(mode="observe", ports=[161])])
        _, info = e.verdict(build_udp_packet(161, b"not-ber-data"))
        self.assertEqual(info["reasons"], [])


def _tls_client_hello(sni="finals.svc"):
    name = sni.encode()
    server_name = b"\x00" + len(name).to_bytes(2, "big") + name
    snl = len(server_name).to_bytes(2, "big") + server_name
    ext = b"\x00\x00" + len(snl).to_bytes(2, "big") + snl
    exts = len(ext).to_bytes(2, "big") + ext
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00" + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


class TestTlsObserveDetector(unittest.TestCase):
    """TLS 채널 관찰 — 암호화로 payload 기반 detector가 blind인 지점을 표시(차단 안 함)"""

    def test_client_hello_parsed_with_sni(self):
        from detectors import parse_tls_client_hello
        version, sni = parse_tls_client_hello(_tls_client_hello("ugv-gw.finals"))
        self.assertEqual(version, (3, 3))
        self.assertEqual(sni, "ugv-gw.finals")

    def test_non_tls_ignored(self):
        from detectors import parse_tls_client_hello
        self.assertIsNone(parse_tls_client_hello(b"GET / HTTP/1.1\r\n\r\n"))

    def test_channel_observed_never_dropped(self):
        e = VerdictEngine([TlsObserveDetector(mode="observe")])
        verdict, info = e.verdict(build_packet(8443, _tls_client_hello("svc")))
        self.assertEqual(verdict, VERDICT_ACCEPT)
        self.assertTrue(any("tls_channel" in r for r in info["reasons"]))
        evidence = next(i for i in info["evidence"] if i["rule_id"] == "TLS-CHANNEL-OBS")
        self.assertFalse(evidence["drop_eligible"])

    def test_reported_once_per_flow(self):
        e = VerdictEngine([TlsObserveDetector(mode="observe")])
        ch = _tls_client_hello("svc")
        e.verdict(build_packet(8443, ch))
        _, info = e.verdict(build_packet(8443, ch))
        self.assertEqual(info["reasons"], [])


class TestQAGates(unittest.TestCase):
    """AI 생성 코드 핵심 주장인 결정적 verdict와 AI 경로 격리의 회귀 검증"""

    @staticmethod
    def _scenario():
        detectors = [MavlinkDetector(mode="observe"), CcsdsDetector(mode="observe"),
                     RtpsDetector(mode="observe")]
        e = VerdictEngine.from_config(TEST_SIGNATURES, TEST_WHITELIST,
                                      extra_detectors=detectors)
        packets = [
            packet_for(8082, "/health"),
            packet_for(8084, "/product?id=1 union select sql"),
            build_udp_packet(14550, _mav2(seq=1, signed=True, timestamp=1000)),
            build_udp_packet(14550, _mav2(seq=2, signed=True, timestamp=1000)),
            build_udp_packet(10000, _ccsds(seq=3, fecf=True)),
            build_udp_packet(10000, _ccsds(seq=3, fecf=True)),
            build_udp_packet(7400, _rtps()),
            build_udp_packet(7400, _rtps(malformed=True)),
        ]
        return [(v, round(info.get("score", 0.0), 6), tuple(info["reasons"]))
                for v, info in (e.verdict(pkt) for pkt in packets)]

    def test_same_scenario_is_deterministic_across_fresh_engines(self):
        baseline = self._scenario()
        self.assertEqual(self._scenario(), baseline)
        self.assertEqual(self._scenario(), baseline)

    def test_team_rule_catalog_has_complete_coverage_status(self):
        import signatures
        active = [str(rule.get("id") or rule.get("rule_id") or "SIG-TEXT")
                  for rule in signatures.SIGNATURES]
        coverage = classify_rule_coverage(signatures, active)
        statuses = ("ENFORCED", "OBSERVED", "IMPLEMENTED_DISABLED",
                    "PREREQUISITE_MISSING", "PARSER_REQUIRED")
        self.assertEqual(coverage["TOTAL"], len(signatures.DETECTOR_RULES))
        self.assertEqual(sum(len(coverage[key]) for key in statuses), coverage["TOTAL"])
        assigned = [rule_id for key in statuses for rule_id in coverage[key]]
        self.assertEqual(len(assigned), len(set(assigned)))

    def test_phase3_operational_rules_block_product_union_sqli(self):
        # 룰 담당자가 레거시 L3-SQL 시그니처를 제거(Signatures repo, "mavlink rules enhanced").
        # SQLi 차단 능력은 구조형 L3ProductIdDetector가 유지하므로, 배포 엔진 전체로 검증한다.
        e = load_engine()
        packet = packet_for(
            8084,
            "/product?id=-1%20UNION%20SELECT%201,(SELECT%20v%20FROM%20app_meta%20WHERE%20k='deploy_token'),3--",
        )
        verdict, info = e.verdict(packet)
        self.assertEqual(verdict, VERDICT_DROP)
        self.assertIn("L3-PRODUCT-ID-STRUCTURE",
                      [item["rule_id"] for item in info["evidence"]])

    def test_phase3_operational_rules_accept_numeric_product_id(self):
        import signatures
        e = VerdictEngine.from_config(signatures.SIGNATURES, signatures.WHITELIST)
        verdict, _ = e.verdict(packet_for(8084, "/product?id=5"))
        self.assertEqual(verdict, VERDICT_ACCEPT)

    def test_phase3_operational_rules_block_encoded_comment_evasion(self):
        # 인라인 주석 회피(UnIoN/**/SeLeCt)도 구조형 L3ProductIdDetector가 배포 엔진에서 차단.
        e = load_engine()
        verdict, info = e.verdict(packet_for(
            8084, "/product?id=-1%20UnIoN/**/SeLeCt%201,2,3--"))
        self.assertEqual(verdict, VERDICT_DROP)
        self.assertIn("L3-PRODUCT-ID-STRUCTURE",
                      [item["rule_id"] for item in info["evidence"]])

    def test_phase3_structural_guard_decodes_plus_as_space(self):
        e = VerdictEngine([L3ProductIdDetector(mode="enforce")])
        verdict, info = e.verdict(packet_for(
            8084,
            "/product?id=-1+UNION+ALL+SELECT+1%2Cv%2C3+FROM+app_meta",
        ))
        self.assertEqual(verdict, VERDICT_DROP)
        self.assertIn(
            "L3-PRODUCT-ID-STRUCTURE",
            [item["rule_id"] for item in info["evidence"]],
        )

    def test_phase3_structural_guard_accepts_decimal_id(self):
        e = VerdictEngine([L3ProductIdDetector(mode="enforce")])
        self.assertEqual(e.verdict(packet_for(8084, "/product?id=2"))[0], VERDICT_ACCEPT)

    def test_phase3_structural_guard_ignores_irrelevant_parameter(self):
        e = VerdictEngine([L3ProductIdDetector(mode="enforce")])
        self.assertEqual(
            e.verdict(packet_for(8084, "/product?search=union+select"))[0],
            VERDICT_ACCEPT,
        )

    def test_defender_model_allowlist_excludes_deprecated_model(self):
        import defender
        self.assertEqual(defender.DEFENDER_LLM_MODELS, {"gpt-4.1-mini", "gpt-4.1"})
        self.assertNotIn("gpt-4o-mini", defender.DEFENDER_LLM_MODELS)

    def test_background_ai_failure_cannot_change_verdict(self):
        e = engine()
        pkt = packet_for(8084, "/product?id=1 union select sql")
        before = e.verdict(pkt)
        analyst = BackgroundAnalyst()
        with mock.patch("defender.urllib.request.urlopen", side_effect=TimeoutError("offline")):
            analyst._analyze({"proto": 6, "dport": 8084, "reasons": ["candidate"],
                              "snippet": "untrusted", "sample_hex": "00"})
        # engine 객체·verdict 상태 미전달 분석기의 완전 동일 결과 요구
        after = e.verdict(pkt)
        self.assertEqual(after[0], before[0])
        self.assertEqual(after[1].get("score"), before[1].get("score"))
        self.assertEqual(after[1]["reasons"], before[1]["reasons"])

    def test_background_ai_uses_selected_model_and_limits(self):
        import io
        import json

        analyst = BackgroundAnalyst()
        content = ('{"protocol_guess":"unknown","confidence":0.5,'
                   '"evidence":[],"detector_idea":"observe"}')
        response = io.BytesIO(json.dumps({"choices": [{"message": {"content": content}}],
                                          "usage": {"prompt_tokens": 10,
                                                    "completion_tokens": 5}}).encode())
        with (mock.patch("defender.LLM_MODEL", "team-selected-model"),
              mock.patch("defender.LLM_MAX_COMPLETION_TOKENS", 96),
              mock.patch("defender.LLM_TIMEOUT_SECONDS", 7.0),
              mock.patch("defender.urllib.request.urlopen", return_value=response) as call):
            analyst._analyze({"proto": 17, "dport": 14550, "reasons": ["candidate"],
                              "snippet": "telemetry", "sample_hex": "fe00"})
        request = call.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual(body["model"], "team-selected-model")
        self.assertEqual(body["max_completion_tokens"], 96)
        self.assertEqual(body["temperature"], 0)
        self.assertEqual(body["messages"][0]["role"], "system")
        self.assertEqual(body["messages"][1]["role"], "user")
        self.assertNotIn("telemetry", body["messages"][1]["content"])
        self.assertEqual(call.call_args.kwargs["timeout"], 7.0)

    def test_background_ai_reasoning_model_omits_temperature(self):
        import io
        import json

        analyst = BackgroundAnalyst()
        content = ('{"protocol_guess":"unknown","confidence":0.5,'
                   '"evidence":[],"detector_idea":"observe"}')
        response = io.BytesIO(json.dumps(
            {"choices": [{"message": {"content": content}}]}).encode())
        with (mock.patch("defender.LLM_MODEL", "gpt-5-mini"),
              mock.patch("defender.LLM_REASONING_EFFORT", "low"),
              mock.patch("defender.urllib.request.urlopen", return_value=response) as call):
            analyst._analyze({"proto": 17, "dport": 14550, "reasons": ["unknown"],
                              "snippet": "", "sample_hex": "fe00"})
        body = json.loads(call.call_args.args[0].data)
        self.assertEqual(body["reasoning_effort"], "low")
        self.assertNotIn("temperature", body)

    def test_llm_response_schema_is_strict(self):
        valid = ('```json\n{"protocol_guess":"mavlink","confidence":0.8,'
                 '"evidence":["magic"],"detector_idea":"check sequence"}\n```')
        self.assertEqual(_validate_llm_result(valid)["protocol_guess"], "mavlink")
        with self.assertRaises(ValueError):
            _validate_llm_result('{"protocol_guess":"safe"}')
        with self.assertRaises(ValueError):
            _validate_llm_result('{"protocol_guess":"x","confidence":2,'
                                 '"evidence":[],"detector_idea":"x"}')

    def test_llm_call_budget_and_port_cooldown(self):
        clock = [100.0]
        analyst = BackgroundAnalyst(now=lambda: clock[0])
        obs = {"proto": 17, "dport": 14550}
        with mock.patch("defender.LLM_PORT_COOLDOWN_SECONDS", 10.0):
            self.assertTrue(analyst._allow_call(obs)[0])
            self.assertEqual(analyst._allow_call(obs), (False, "port_cooldown"))
            clock[0] += 11.0
            self.assertTrue(analyst._allow_call(obs)[0])

    def test_unknown_sampler_is_bounded_and_skips_health(self):
        sampler = UnknownSampler(total_limit=2, per_port=1)
        self.assertIsNone(sampler.consider(packet_for(8082, "/health")))
        sample = sampler.consider(build_udp_packet(9999, b"unknown-binary-one"))
        self.assertEqual(sample["reasons"], ["bounded_unknown_sample"])
        self.assertIsNone(sampler.consider(build_udp_packet(9999, b"different")))
        self.assertIsNotNone(sampler.consider(build_udp_packet(9998, b"other")))
        self.assertIsNone(sampler.consider(build_udp_packet(9997, b"over-total")))


class TestPcap(unittest.TestCase):
    def test_pcap_write_read_roundtrip(self):
        import os
        import tempfile

        from tests.packet_util import write_pcap
        from tools.pcap_analyze import read_pcap

        recs = [(1000.0, packet_for(8084, "/p?id=1 union select 1")),
                (1000.2, build_udp_packet(9000, b"\xfe\x01binary"))]
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            write_pcap(path, recs)
            out = list(read_pcap(path))
            self.assertEqual(len(out), 2)                       # 두 패킷 복원
            self.assertIsNotNone(VerdictEngine.parse_l4(out[0][1]))  # IP 파싱 가능
            self.assertAlmostEqual(out[1][0], 1000.2, places=4)      # 타임스탬프 보존
        finally:
            os.remove(path)

    def test_gzip_pcap_read(self):
        import gzip
        import os
        import tempfile

        from tests.packet_util import write_pcap
        from tools.pcap_analyze import read_pcap

        with tempfile.TemporaryDirectory() as directory:
            plain = os.path.join(directory, "sample.pcap")
            compressed = plain + ".gz"
            write_pcap(plain, [(1000.0, packet_for(8082, "/health"))])
            with open(plain, "rb") as src, gzip.open(compressed, "wb") as dst:
                dst.write(src.read())
            out = list(read_pcap(compressed))
            self.assertEqual(len(out), 1)
            self.assertAlmostEqual(out[0][0], 1000.0, places=4)


class TestRoundReportBypassSample(unittest.TestCase):
    """round_report의 우회 샘플 표현이 텍스트/바이너리를 구분하는지 검증.

    본선 방산 프로토콜은 바이너리라, 기존의 첫 줄 latin-1 디코드는 깨진 문자만
    남겼다. 프로토콜 지문 + hex dump로 의미 있는 샘플을 남기는지 확인한다."""

    def test_http_text_shows_request_line(self):
        from tools.round_report import bypass_sample
        raw = b"GET /fetch?url=http://helper HTTP/1.1\r\nHost: t\r\n\r\n"
        self.assertEqual(bypass_sample(raw), "GET /fetch?url=http://helper HTTP/1.1")

    def test_binary_protocols_fingerprinted(self):
        from tools.round_report import _fingerprint
        # MBAP: tid(2) proto=0(2) length(2)=len(pdu)+1 unit(1) + FC03 read
        modbus = struct.pack(">HHHB", 1, 0, 6, 1) + b"\x03\x00\x00\x00\x0a"
        self.assertEqual(_fingerprint(modbus), "Modbus/TCP")
        self.assertEqual(_fingerprint(b"\xfd\x14\x00\x00\x00" + b"\x00" * 30), "MAVLink v2")
        self.assertEqual(_fingerprint(b"RTPS\x02\x03\x01\x0f" + b"\x00" * 16), "RTPS")

    def test_binary_sample_is_hex_not_garbage(self):
        from tools.round_report import bypass_sample
        modbus = struct.pack(">HHHB", 1, 0, 6, 1) + b"\x03\x00\x00\x00\x0a"
        sample = bypass_sample(modbus)
        self.assertIn("[Modbus/TCP]", sample)
        self.assertIn("03 00 00 00 0a", sample)   # hex dump 형태


class TestSuricataScan(unittest.TestCase):
    """오프라인 Suricata 분석 도구의 eve.json 집계 로직. Suricata 없이도 검증."""

    @staticmethod
    def _alert(sid, dport, detector, layer="L2_MCS", attack="x"):
        return {"event_type": "alert", "dest_port": dport,
                "alert": {"signature_id": sid, "signature": f"sig-{sid}",
                          "metadata": {"detector": [detector], "layer": [layer],
                                       "attack": [attack]}}}

    def test_non_alert_events_ignored(self):
        from tools.suricata_scan import summarize_eve
        s = summarize_eve([{"event_type": "flow"}, {"event_type": "stats"}])
        self.assertEqual(s["total_alerts"], 0)
        self.assertEqual(s["signatures"], [])

    def test_sid_maps_to_protocol_and_port_env(self):
        from tools.suricata_scan import summarize_eve
        events = ([self._alert(9000102, 502, "MODBUS-READ-SCAN")] * 20
                  + [self._alert(9000201, 14550, "MAV-READ-SCAN", "L3_UAV")] * 5
                  + [self._alert(9000401, 7400, "RTPS-READ-SCAN", "L4_UGV")] * 3)
        s = summarize_eve(events)
        self.assertEqual(s["total_alerts"], 28)
        settings = {x["setting"] for x in s["suggestions"]}
        self.assertIn("DEF_MODBUS_PORTS=502", settings)
        self.assertIn("DEF_MAVLINK_PORTS=14550", settings)
        self.assertIn("DEF_RTPS_PORTS=7400", settings)

    def test_signatures_sorted_by_hits(self):
        from tools.suricata_scan import summarize_eve
        events = [self._alert(9000201, 14550, "MAV-READ-SCAN")] + \
                 [self._alert(9000102, 502, "MODBUS-READ-SCAN")] * 3
        s = summarize_eve(events)
        self.assertEqual(s["signatures"][0]["protocol"], "Modbus")   # 3건 > 1건
        self.assertEqual(s["signatures"][0]["hits"], 3)


class TestBrokerContract(unittest.TestCase):
    def test_packet_verdict_and_heartbeat_frames(self):
        if not hasattr(socket, "SOCK_SEQPACKET"):
            self.skipTest("SOCK_SEQPACKET unavailable")
        try:
            agent, broker = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        except OSError as e:
            self.skipTest(f"SOCK_SEQPACKET unavailable: {e}")
        stop = threading.Event()
        analyst = BackgroundAnalyst()
        lock = threading.Lock()
        worker = threading.Thread(target=main_loop,
                                  args=(agent, engine(), analyst, lock, stop), daemon=True)
        heart = threading.Thread(target=heartbeat_loop,
                                 args=(agent, lock, stop), daemon=True)
        worker.start(); heart.start()
        try:
            pkt = packet_for(8084, "/product?id=1 union select 1")
            broker.send(struct.pack(">BQH", MSG_PACKET, 77, len(pkt)) + pkt)
            broker.settimeout(2.0)
            seen_verdict = seen_heartbeat = False
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and not (seen_verdict and seen_heartbeat):
                data = broker.recv(64)
                if data[0] == MSG_VERDICT:
                    msg_type, pkt_id, verdict = struct.unpack(">BQB", data)
                    seen_verdict = msg_type == MSG_VERDICT and pkt_id == 77 and verdict == VERDICT_DROP
                elif data[0] == MSG_HEARTBEAT:
                    seen_heartbeat = True
            self.assertTrue(seen_verdict)
            self.assertTrue(seen_heartbeat)
        finally:
            stop.set()
            broker.close(); agent.close()
            worker.join(timeout=1); heart.join(timeout=1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
