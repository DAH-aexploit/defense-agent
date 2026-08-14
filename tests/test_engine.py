"""VerdictEngine 단위 테스트, socket 불필요·macOS 실행 가능

  python3 -m unittest tests.test_engine -v
"""

from __future__ import annotations

import socket
import struct
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import signatures
from defender import (MSG_HEARTBEAT, MSG_PACKET, MSG_VERDICT, VERDICT_ACCEPT,
                      VERDICT_DROP, BackgroundAnalyst, UnknownSampler,
                      VerdictEngine, _validate_llm_result, heartbeat_loop,
                      main_loop)
from detectors import (CcsdsDetector, Detector, Hit, MavlinkDetector,
                       PacketContext, ParamRangeDetector, RateDetector,
                       RtpsDetector, SignatureDetector, crc16_ccitt, normalize,
                       parse_ccsds_packet, parse_mavlink_frames,
                       parse_rtps_message)
from tests.packet_util import (build_ipv6_packet, build_packet, build_udp_packet,
                               http_get, packet_for)


def engine() -> VerdictEngine:
    return VerdictEngine.from_config(signatures.SIGNATURES, signatures.WHITELIST)


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

    def test_garbage_bytes_accepted(self):
        import os
        for _ in range(50):
            self.assertEqual(self.e.verdict(os.urandom(64))[0], VERDICT_ACCEPT)

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
        det = ParamRangeDetector({8085: {"gain": (0.0, 0.5, 1.0)}})
        e = VerdictEngine([det])
        self.assertEqual(e.verdict(packet_for(8085, "/ctrl?gain=9.99"))[0], VERDICT_DROP)
        self.assertEqual(e.verdict(packet_for(8085, "/ctrl?gain=0.3"))[0], VERDICT_ACCEPT)

    def test_rate_detector_flags_burst(self):
        # 이상: 포트별 요청 rate 급증(대량 명령 mass-push), now 주입으로 결정성 확보
        clock = {"t": 0.0}
        det = RateDetector(per_sec=3, window=1.0, weight=1.0, now=lambda: clock["t"])
        e = VerdictEngine([det])
        pkt = packet_for(8086, "/cmd")
        verdicts = [e.verdict(pkt)[0] for _ in range(5)]  # 같은 순간 5회 → 임계(3) 초과
        self.assertEqual(verdicts[:3], [VERDICT_ACCEPT, VERDICT_ACCEPT, VERDICT_ACCEPT])
        self.assertIn(VERDICT_DROP, verdicts[3:])

    def test_rate_is_scoped_per_flow_by_default(self):
        clock = {"t": 0.0}
        det = RateDetector(per_sec=2, now=lambda: clock["t"])
        e = VerdictEngine([det])
        packets = [build_packet(8086, b"x", sport=41000 + n) for n in range(4)]
        self.assertTrue(all(e.verdict(pkt)[0] == VERDICT_ACCEPT for pkt in packets))

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
          link_id=7, timestamp=1000):
    flags = 1 if signed else 0
    header = bytes([0xFD, len(payload), flags, 0, seq, sysid, compid]) + msgid.to_bytes(3, "little")
    frame = header + payload + b"\x00\x00"  # 구조 테스트: CRC-extra 미확정이라 값은 사용 안 함
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
        e = VerdictEngine([MavlinkDetector(mode="enforce")])
        first = build_udp_packet(14550, _mav2(seq=1, signed=True, timestamp=1000))
        replayed = build_udp_packet(14550, _mav2(seq=2, signed=True, timestamp=1000))
        self.assertEqual(e.verdict(first)[0], VERDICT_ACCEPT)
        self.assertEqual(e.verdict(replayed)[0], VERDICT_DROP)

    def test_unsigned_sensitive_only_actionable_when_required(self):
        frame = build_udp_packet(14550, _mav2(msgid=76, signed=False))
        permissive = VerdictEngine([MavlinkDetector(mode="enforce", require_signed=False)])
        strict = VerdictEngine([MavlinkDetector(mode="enforce", require_signed=True)])
        self.assertEqual(permissive.verdict(frame)[0], VERDICT_ACCEPT)
        self.assertEqual(strict.verdict(frame)[0], VERDICT_DROP)

    def test_port_allowlist_avoids_unrelated_binary(self):
        e = VerdictEngine([MavlinkDetector(mode="enforce", ports=[14550], require_signed=True)])
        self.assertEqual(e.verdict(build_udp_packet(9999, _mav2(msgid=76)))[0], VERDICT_ACCEPT)


def _ccsds(seq=1, apid=42, payload=b"abc", fecf=False, corrupt=False):
    first = apid & 0x7FF
    sequence = (3 << 14) | (seq & 0x3FFF)
    packet = struct.pack(">HHH", first, sequence, len(payload) - 1) + payload
    if fecf:
        crc = crc16_ccitt(packet) ^ (1 if corrupt else 0)
        packet += crc.to_bytes(2, "big")
    return packet


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
        e = VerdictEngine([CcsdsDetector(mode="enforce")])
        pkt = build_udp_packet(10000, _ccsds(seq=9))
        self.assertEqual(e.verdict(pkt)[0], VERDICT_ACCEPT)
        # 첫 이상 관찰과 단기 구간 내 두 번째 동일 이상 확정
        self.assertEqual(e.verdict(pkt)[0], VERDICT_ACCEPT)
        self.assertEqual(e.verdict(pkt)[0], VERDICT_DROP)


def _rtps(guid=b"G" * 12, version=(2, 3), vendor=b"\x01\x0f", malformed=False):
    header = b"RTPS" + bytes(version) + vendor + guid
    size = 99 if malformed else 1
    return header + bytes([0x15, 0x01]) + size.to_bytes(2, "little") + b"x"


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


class TestQAGates(unittest.TestCase):
    """AI 생성 코드 핵심 주장인 결정적 verdict와 AI 경로 격리의 회귀 검증"""

    @staticmethod
    def _scenario():
        detectors = [MavlinkDetector(mode="observe"), CcsdsDetector(mode="observe"),
                     RtpsDetector(mode="observe")]
        e = VerdictEngine.from_config(signatures.SIGNATURES, signatures.WHITELIST,
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
