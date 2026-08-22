"""검사기 플러그인 — 엔진과 분리된 탐지 로직 모듈

핵심: 프로토콜·공격별 `Detector` 추가를 통한 엔진 순회
당일 pcap 기반 신규 Detector 추가와 특정 프로토콜 종속 배제

이 파일은 본선 방산 프로토콜과 프로토콜 무관 공통 검사기만 담는다.
리허설 스켈레톤(L1 SSRF·L2 세션 위조·L3 SQLi) 전용 검사기는
`rehearsal_web_detectors.py`로 분리했다 — 본선과 무관하다는 것이
`DAH2026_본선_에이전트_구현가이드.md` §5에 명시돼 있다.

내장 검사기:
  - SignatureDetector : 텍스트(HTTP 등) 정규식 시그니처, 정규화(URL/base64/SQL주석) 포함
  - ParamRangeDetector: 제어 파라미터 안전범위 이탈 → hit, dahAgent PARAM_SET의 HTTP 버전
  - RequestBurstDetector: flow별 packet activity 급증 관찰, 정상 baseline 확인 후 활성화
  - MavlinkDetector  : MAVLink 1/2 구조·sequence·signed timestamp·ID/replay 상태 관찰
  - CcsdsDetector    : CCSDS Space Packet header·sequence·선택적 FECF 상태 관찰
  - RtpsDetector     : RTPS header·submessage 경계·profile·participant GUID 변화 관찰
모든 검사기의 내부 예외 처리, fail-open 기반 검사기 오류 격리
"""

from __future__ import annotations

import base64
import collections
import hmac
import os
import re
import struct
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field
from enum import StrEnum

# 정규화용 정규식 (텍스트 검사기 전용)
_SQL_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_WS_RE = re.compile(r"\s+")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_KV_RE = re.compile(r"[?&]([a-z0-9_.\-]+)=([^&\s]+)")
# 옥탈(\NNN)·hex(\xNN)·유니코드(\uNNNN) 문자 이스케이프 리터럴
_ESCAPE_RE = re.compile(r"\\(?:([0-7]{3})|x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))")


def _deescape(value: str) -> str:
    """문자 이스케이프 리터럴을 실제 문자로 치환

    base64 토큰을 `\\145`(옥탈)·`\\x65`(hex)·`\\u0065`(유니코드) 같은 리터럴로
    감싸면 base64.b64decode(validate=False)가 백슬래시만 버리고 남은 숫자를
    base64 문자로 오인해 디코딩 결과가 원문과 어긋난다. 디코딩 전에 이 이스케이프를
    먼저 해석해 원래 문자로 되돌린다.
    """
    def _sub(m: re.Match) -> str:
        octal, hexd, uni = m.groups()
        code = int(octal, 8) if octal else int(hexd, 16) if hexd else int(uni, 16)
        return chr(code)
    return _ESCAPE_RE.sub(_sub, value)


def _b64_expand(text: str) -> str:
    """긴 base64 토큰(쿠키/JWT)의 소문자 평문 decode, best-effort·최대 8개"""
    out: list[str] = []
    for m in list(_B64_RE.finditer(text))[:8]:
        tok = m.group(0)
        try:
            s = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=False).decode("utf-8")
        except Exception:  # noqa: BLE001
            continue
        if s.isprintable():
            out.append(s.lower())
    return " ".join(out)


def normalize(text: str) -> str:
    """소문자·이중 URL decode·SQL 주석 공백화·base64 확장·공백 정리"""
    extras = _b64_expand(text)
    t = text.lower()
    for _ in range(2):
        if "%" not in t:
            break
        try:
            dec = urllib.parse.unquote(t)
        except Exception:  # noqa: BLE001
            break
        if dec == t:
            break
        t = dec
    t = _SQL_COMMENT_RE.sub(" ", t)
    if extras:
        t = t + " " + extras
    return _WS_RE.sub(" ", t)


# ── 검사 컨텍스트 / 결과 ─────────────────────────────────────────────────────
@dataclass
class PacketContext:
    """단일 패킷 검사 입력, raw/norm 지연 계산과 바이너리 검사기 정규화 비용 0"""

    proto: int          # 6=TCP, 17=UDP
    dport: int
    payload: bytes
    payload_cap: int = 16384
    flow: tuple | None = None
    ip_version: int = 4
    segment_payload: bytes | None = None
    transport_seq: int | None = None
    transport_flags: int = 0
    _raw: str | None = field(default=None, repr=False)
    _norm: str | None = field(default=None, repr=False)

    @property
    def raw(self) -> str:
        if self._raw is None:
            self._raw = self.payload[:self.payload_cap].decode("latin-1", "ignore")
        return self._raw

    @property
    def norm(self) -> str:
        if self._norm is None:
            self._norm = normalize(self.raw)
        return self._norm


class EvidenceClass(StrEnum):
    """탐지 근거만으로 확정 가능한 판정 수준"""

    ATTACK_PATTERN_CONFIRMED = "attack_pattern_confirmed"
    VIOLATION_CONFIRMED = "violation_confirmed"
    CONTEXT_REQUIRED = "context_required"
    OBSERVATION_ONLY = "observation_only"


class IdentificationBasis(StrEnum):
    """프로토콜 식별에 필요한 최소 근거"""

    STRUCTURE_VERIFIED = "structure_verified"
    PROFILE_BOUND = "profile_bound"
    SCHEMA_DEPENDENT = "schema_dependent"


@dataclass
class Evidence:
    """detector가 반환하는 구조화된 탐지 근거"""

    weight: float
    reason: str
    # 같은 근거가 여러 번 보였다고 독립 근거 여러 개로 오인해 합산하지 않도록 하는 키
    source: str = ""
    rule_id: str = ""
    evidence_class: EvidenceClass = EvidenceClass.CONTEXT_REQUIRED
    identification_basis: IdentificationBasis = IdentificationBasis.PROFILE_BOUND
    identification_verified: bool = True
    prerequisites_satisfied: bool = True
    packet_complete: bool = True

    @property
    def drop_eligible(self) -> bool:
        """현재 근거의 DROP 점수 반영 가능 여부"""
        if not self.identification_verified:
            return False
        if self.evidence_class is EvidenceClass.OBSERVATION_ONLY:
            return False
        if self.evidence_class is EvidenceClass.VIOLATION_CONFIRMED:
            return self.packet_complete
        if self.evidence_class is EvidenceClass.CONTEXT_REQUIRED:
            return self.prerequisites_satisfied
        return self.prerequisites_satisfied


# 기존 detector와 외부 테스트의 positional 생성 방식 호환
Hit = Evidence


class BoundedState:
    """TTL과 key 상한을 공통 적용하는 LRU 상태 저장소"""

    def __init__(self, max_keys=4096, ttl=120.0, now=None):
        self.max_keys = max(1, int(max_keys))
        self.ttl = max(0.001, float(ttl))
        self._now = now or time.monotonic
        self._data: collections.OrderedDict = collections.OrderedDict()

    def _expire(self, now):
        cutoff = now - self.ttl
        while self._data:
            key = next(iter(self._data))
            if self._data[key][0] >= cutoff:
                break
            self._data.popitem(last=False)

    def get(self, key, default=None, now=None):
        current = self._now() if now is None else now
        self._expire(current)
        item = self._data.get(key)
        if item is None:
            return default
        self._data[key] = (current, item[1])
        self._data.move_to_end(key)
        return item[1]

    def put(self, key, value, now=None):
        current = self._now() if now is None else now
        self._expire(current)
        self._data[key] = (current, value)
        self._data.move_to_end(key)
        while len(self._data) > self.max_keys:
            self._data.popitem(last=False)
        return value

    def get_or_create(self, key, factory, now=None):
        current = self._now() if now is None else now
        value = self.get(key, None, current)
        if value is None:
            value = factory()
        return self.put(key, value, current)

    def discard(self, key):
        self._data.pop(key, None)

    def __len__(self):
        return len(self._data)


class Detector:
    """inspect(ctx) 기반 Evidence 목록 반환용 검사기 base"""

    name = "base"

    def inspect(self, ctx: PacketContext) -> list[Evidence]:  # noqa: ARG002
        return []


class EvidenceDebouncer:
    """단기 구간 내 동일 상태 이상 반복 시 enforce하는 bounded debounce"""

    def __init__(self, confirmations=2, window=3.0, max_keys=4096):
        self.confirmations, self.window = max(1, int(confirmations)), float(window)
        self.max_keys = max(32, int(max_keys))
        self._seen = BoundedState(self.max_keys, max(self.window * 2, 1.0))

    def confirmed(self, key, now):
        q = self._seen.get(key, None, now) or collections.deque()
        q.append(now)
        while q and q[0] < now - self.window:
            q.popleft()
        self._seen.put(key, q, now)
        return len(q) >= self.confirmations


# 1) 텍스트 시그니처 (HTTP 등 텍스트 프로토콜용)
class SignatureDetector(Detector):
    name = "signature"

    def __init__(self, signatures_raw=None) -> None:
        self._by_port: dict[int, list] = {}
        self._any: list = []
        for sig in signatures_raw or []:
            try:
                entry = self._compile(sig)
            except (KeyError, TypeError, ValueError, re.error):
                continue
            if sig.get("port") is not None:
                try:
                    self._by_port.setdefault(int(sig["port"]), []).append(entry)
                    continue
                except (TypeError, ValueError):
                    pass
            self._any.append(entry)

    _UNSAFE_RE = re.compile(
        r"\([^)]*(?:[+*]|\{\d*,?\d*\})[^)]*\)(?:[+*]|\{\d*,?\d*\})"
    )

    @staticmethod
    def _compile(sig: dict) -> dict:
        pattern = sig["pattern"]
        # Python stdlib re의 portable per-match timeout 부재
        # 대표 catastrophic-backtracking 형태인 중첩 수량자의 적재 단계 거부
        if SignatureDetector._UNSAFE_RE.search(pattern):
            raise ValueError("unsafe nested regex quantifier")
        return {"rx": re.compile(pattern),
                "reason": str(sig.get("reason", "")),
                "weight": float(sig.get("weight", 1.0)),
                "rule_id": str(sig.get("id") or sig.get("rule_id") or "SIG-TEXT"),
                "target": str(sig.get("target", "both")).lower()}

    @property
    def rule_count(self) -> int:
        return sum(len(v) for v in self._by_port.values()) + len(self._any)

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        hits: list[Evidence] = []
        for entry in self._by_port.get(ctx.dport, []) + self._any:
            rx, target = entry["rx"], entry["target"]
            matched = ((target in ("norm", "both") and rx.search(ctx.norm))
                       or (target in ("raw", "both") and rx.search(ctx.raw)))
            if matched:
                reason = entry["reason"] or rx.pattern
                hits.append(Evidence(
                    entry["weight"], reason, f"signature:{reason}", entry["rule_id"],
                    EvidenceClass.ATTACK_PATTERN_CONFIRMED,
                    IdentificationBasis.PROFILE_BOUND,
                    True, True, True))
        return hits


# 2) 제어 파라미터 안전범위 (방산 시나리오: 제어값 조작)
class ParamRangeDetector(Detector):
    """HTTP 쿼리 파라미터가 안전범위를 벗어나면 hit

    dahAgent의 `PARAM_SET` 안전범위 검사(예: MC_ROLLRATE_P ∈ [0,0.5])를 HTTP로 옮긴 것
    rules = { port: { "param": (lo, hi, weight) } }, 실제 파라미터/범위는 당일 확정
    바이너리 프로토콜용 별도 Detector 기반 동일 개념 구현
    """

    name = "param_range"

    def __init__(self, rules: dict | None = None) -> None:
        self.rules = rules or {}

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        port_rules = self.rules.get(ctx.dport)
        if not port_rules:
            return []
        hits: list[Evidence] = []
        for pm, val in _KV_RE.findall(ctx.raw.lower()):
            spec = port_rules.get(pm)
            if not spec:
                continue
            lo, hi, weight = spec
            try:
                v = float(val)
            except (TypeError, ValueError):
                continue
            if not (lo <= v <= hi):
                hits.append(Evidence(
                    weight, f"{pm}={v} out of [{lo},{hi}]", f"param:{pm}",
                    f"PARAM:{pm}", EvidenceClass.VIOLATION_CONFIRMED,
                    IdentificationBasis.PROFILE_BOUND, True, True, True))
        return hits


# 3) packet activity burst 관찰, 기본 flow 단위·선택적 port 전체
class RequestBurstDetector(Detector):
    """flow별 packet activity 임계 초과 Evidence

    단일 verdict thread용 상태 기반 검사기
    다수 정상 송신자 합산 오탐 방지용 기본 flow scope
    정상 baseline 확인 후에만 사용할 destination port 합산 scope
    테스트 결정성 확보용 now() 주입과 실사용 time.monotonic
    """

    name = "request_burst"

    def __init__(self, per_sec: float = 50.0, window: float = 1.0,
                 weight: float = 1.0, now=None, scope: str = "flow",
                 max_keys: int = 4096) -> None:
        self.per_sec = per_sec
        self.window = window
        self.weight = weight
        self.scope = scope if scope in ("flow", "port") else "flow"
        self.max_keys = max(16, int(max_keys))
        self._now = now or time.monotonic
        self._hits = BoundedState(self.max_keys, max(self.window * 2, 1.0), self._now)

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        t = self._now()
        key = ctx.dport if self.scope == "port" or not ctx.flow else ctx.flow
        q = self._hits.get(key, None, t) or []
        q.append(t)
        cutoff = t - self.window
        while q and q[0] < cutoff:
            q.pop(0)
        self._hits.put(key, q, t)
        if len(q) > self.per_sec * self.window:
            return [Evidence(
                self.weight, f"rate {len(q)}/{self.window}s on :{ctx.dport} ({self.scope})",
                f"request_burst:{self.scope}:{ctx.dport}", "BURST-01",
                EvidenceClass.CONTEXT_REQUIRED, IdentificationBasis.PROFILE_BOUND,
                True, True, True)]
        return []


# 기존 외부 구성과 import 경로 호환용 별칭
RateDetector = RequestBurstDetector


@dataclass(frozen=True)
class MavFrame:
    version: int
    seq: int
    sysid: int
    compid: int
    msgid: int
    signed: bool
    link_id: int | None
    sig_timestamp: int | None
    crc_valid: bool | None
    payload: bytes = field(repr=False)
    raw: bytes = field(repr=False)


_MAVLINK_CRC_EXTRA = {
    23: 168,   # PARAM_SET
    39: 254,   # MISSION_ITEM
    44: 221,   # MISSION_COUNT
    45: 232,   # MISSION_CLEAR_ALL
    75: 158,   # COMMAND_INT
    76: 152,   # COMMAND_LONG
}


def mavlink_x25_crc(data: bytes, initial: int = 0xFFFF) -> int:
    """MAVLink X.25 CRC 누산"""
    crc = initial
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp ^= (tmp << 4) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def mavlink_frame_crc(version: int, header_and_payload: bytes, msgid: int) -> int | None:
    """지원 메시지의 MAVLink checksum 계산"""
    extra = _MAVLINK_CRC_EXTRA.get(msgid)
    if extra is None:
        return None
    crc = mavlink_x25_crc(header_and_payload)
    return mavlink_x25_crc(bytes([extra]), crc)


def parse_mavlink_frames(data: bytes, current_tail: int | None = None,
                         max_frames: int = 64) -> list[MavFrame]:
    """MAVLink1/2 후보 frame의 구조적 분리, CRC-extra 검증 전 후보 단계"""
    frames: list[MavFrame] = []
    n, off = len(data), 0
    new_from = max(0, n - current_tail) if current_tail is not None else 0
    while off < n and len(frames) < max_frames:
        positions = [p for p in (data.find(b"\xfe", off), data.find(b"\xfd", off)) if p >= 0]
        if not positions:
            break
        p = min(positions)
        version = 1 if data[p] == 0xFE else 2
        header = 6 if version == 1 else 10
        if p + header > n:
            break
        plen = data[p + 1]
        signed = version == 2 and bool(data[p + 2] & 0x01)
        end = p + header + plen + 2 + (13 if signed else 0)
        if end > n:
            off = p + 1
            continue
        raw = data[p:end]
        if version == 1:
            seq, sysid, compid, msgid = data[p + 2:p + 6]
            link_id = sig_ts = None
        else:
            seq, sysid, compid = data[p + 4:p + 7]
            msgid = int.from_bytes(data[p + 7:p + 10], "little")
            if signed:
                sig_off = p + 10 + plen + 2
                link_id = data[sig_off]
                sig_ts = int.from_bytes(data[sig_off + 1:sig_off + 7], "little")
            else:
                link_id = sig_ts = None
        checksum_offset = header + plen
        expected_crc = mavlink_frame_crc(version, raw[1:header + plen], msgid)
        wire_crc = int.from_bytes(raw[checksum_offset:checksum_offset + 2], "little")
        crc_valid = None if expected_crc is None else expected_crc == wire_crc
        if current_tail is None or end > new_from:
            payload = raw[header:header + plen]
            frames.append(MavFrame(version, seq, sysid, compid, msgid,
                                   signed, link_id, sig_ts, crc_valid, payload, raw))
        off = end
    return frames


class MavlinkDetector(Detector):
    """MAVLink 상태형 Detector, 기본 observe mode의 weight=0과 차단 제외"""

    name = "mavlink"
    _SENSITIVE_MSGIDS = frozenset({23, 39, 44, 45, 75, 76})

    def __init__(self, mode: str = "observe", ports=None, weight: float = 1.0,
                 require_signed: bool = False, freshness_10us: int = 6_000_000,
                 state_ttl: float = 120.0, max_keys: int = 4096,
                 id_window: float = 10.0, max_ids: int = 32,
                 repeat_window: float = 2.0, repeat_limit: int = 4,
                 param_read_window: float = 10.0, param_read_scan: int = 12,
                 msgid_warmup: int = 40, msgid_rate_window: float = 2.0,
                 msgid_rate_limit: int = 60,
                 validate_crc: bool = False,
                 param_ranges: dict | None = None,
                 dangerous_commands=None, now=None) -> None:
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        self.ports = {int(p) for p in (ports or [])}
        self.weight, self.require_signed = float(weight), bool(require_signed)
        self.freshness_10us = int(freshness_10us)
        self.state_ttl, self.max_keys = float(state_ttl), max(32, int(max_keys))
        self.id_window, self.max_ids = float(id_window), int(max_ids)
        self.repeat_window, self.repeat_limit = float(repeat_window), int(repeat_limit)
        self.param_read_window = float(param_read_window)
        self.param_read_scan = max(1, int(param_read_scan))
        # message-ID 프로파일 관찰: HITL MAVLink 데이터셋(ocslab GUIDE, message-ID sequence로
        # False Injection 탐지) 근거. 정상 미션은 안정된 msgid 집합·cadence를 갖고, 인젝션은
        # 예상 밖 msgid나 특정 msgid flooding으로 이를 교란한다. warmup 동안 flow별 msgid 집합을
        # 자가학습하고, 이후 신규 msgid/과도한 msgid rate를 관찰만 남긴다(baseline 없이 차단 금지).
        # 룰 담당자 신규 룰 UAV-MAV-021(msgid별 요청률)과도 같은 방향의 관찰 신호.
        self.msgid_warmup = max(1, int(msgid_warmup))
        self.msgid_rate_window = float(msgid_rate_window)
        self.msgid_rate_limit = max(1, int(msgid_rate_limit))
        self.validate_crc = bool(validate_crc)
        self.param_ranges = {
            str(name): (float(spec[0]), float(spec[1]))
            for name, spec in (param_ranges or {}).items()
            if isinstance(spec, (tuple, list)) and len(spec) >= 2
        }
        self.dangerous_commands = {int(command) for command in (dangerous_commands or [])}
        self._now = now or time.monotonic
        self._seq = BoundedState(self.max_keys, self.state_ttl, self._now)
        self._sig_ts = BoundedState(self.max_keys, self.state_ttl, self._now)
        self._max_ts = BoundedState(self.max_keys, self.state_ttl, self._now)
        self._ids = BoundedState(self.max_keys, self.state_ttl, self._now)
        self._repeat = BoundedState(self.max_keys, self.state_ttl, self._now)
        self._param_reads = BoundedState(self.max_keys, self.state_ttl, self._now)
        self._msg_profile = BoundedState(self.max_keys, self.state_ttl, self._now)
        self._msg_rate = BoundedState(self.max_keys, max(self.msgid_rate_window * 2, 1.0), self._now)
        self._msg_flood_seen = BoundedState(self.max_keys, self.msgid_rate_window, self._now)

    @property
    def rule_count(self) -> int:
        return 0 if self.mode == "off" else 1

    def _hit(self, reason: str, actionable: bool = True) -> Evidence:
        family = reason.split(" ", 1)[0]
        rule_id = {
            "mavlink_signature_replay": "MAV-02",
            "mavlink_signature_stale": "MAV-02",
            "mavlink_unsigned_sensitive": "MAV-02",
            "mavlink_sequence_duplicate": "MAV-SEQ-01",
            "mavlink_sequence_regression": "MAV-SEQ-01",
            "mavlink_id_churn": "MAV-03",
            "mavlink_frame_repeat": "MAV-REPLAY-01",
            "mavlink_crc_invalid": "MAV-CRC-01",
            "mavlink_param_out_of_range": "MAV-PARAM-01",
            "mavlink_command_profile_match": "MAV-CMD-01",
            "mavlink_mission_current": "MAV-MISSION-01",
            "mavlink_param_read_enumeration": "MAV-READ-SCAN",
            "mavlink_msgid_novel": "MAV-MSGID-PROFILE",
            "mavlink_msgid_flood": "MAV-MSGID-RATE",
        }.get(family, "MAV-OBS")
        enabled = self.mode == "enforce" and actionable
        return Evidence(
            self.weight if enabled else 0.0, reason, f"mavlink:{family}", rule_id,
            EvidenceClass.CONTEXT_REQUIRED if enabled else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.PROFILE_BOUND,
            bool(self.ports), enabled, True)

    @staticmethod
    def _payload(frame: MavFrame, size: int) -> bytes | None:
        """MAVLink 2 trailing-zero truncation 복원과 MAVLink 1 엄격 길이 확인"""
        if len(frame.payload) >= size:
            return frame.payload
        if frame.version == 2:
            return frame.payload.ljust(size, b"\x00")
        return None

    @staticmethod
    def _param_set(frame: MavFrame):
        """MAVLink common.xml PARAM_SET wire 필드 추출"""
        payload = MavlinkDetector._payload(frame, 23)
        if frame.msgid != 23 or payload is None:
            return None
        value, target_system, target_component, raw_name, param_type = struct.unpack_from(
            "<fBB16sB", payload)
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", "ignore")
        return name, value, target_system, target_component, param_type

    @staticmethod
    def _param_request_read(frame: MavFrame):
        """MAVLink common.xml PARAM_REQUEST_READ(msgid 20) wire 필드 추출

        <hBB16s: param_index(음수면 param_id로 조회), target_sys, target_comp, param_id.
        attack-agent의 mavlink-telemetry-read 기술이 쓰는 READ 요청이다."""
        payload = MavlinkDetector._payload(frame, 20)
        if frame.msgid != 20 or payload is None:
            return None
        param_index, target_system, target_component, raw_name = struct.unpack_from(
            "<hBB16s", payload)
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", "ignore")
        return param_index, name, target_system, target_component

    @staticmethod
    def _command_long(frame: MavFrame):
        """MAVLink common.xml COMMAND_LONG wire 필드 추출"""
        payload = MavlinkDetector._payload(frame, 33)
        if frame.msgid != 76 or payload is None:
            return None
        values = struct.unpack_from("<7fHBBB", payload)
        return values[7], values[:7], values[8], values[9], values[10]

    @staticmethod
    def _mission_item(frame: MavFrame):
        """MAVLink common.xml MISSION_ITEM wire 핵심 필드 추출"""
        payload = MavlinkDetector._payload(frame, 37)
        if frame.msgid != 39 or payload is None:
            return None
        values = struct.unpack_from("<7fHHBBBBB", payload)
        return {
            "seq": values[7], "command": values[8], "target_system": values[9],
            "target_component": values[10], "frame": values[11],
            "current": values[12], "autocontinue": values[13],
        }

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or (self.ports and ctx.dport not in self.ports):
            return []
        segment = ctx.segment_payload if ctx.segment_payload is not None else ctx.payload
        tail = len(segment) if ctx.proto == 6 and segment is not ctx.payload else None
        frames = parse_mavlink_frames(ctx.payload, current_tail=tail)
        if not frames:
            return []
        now, hits = self._now(), []
        flow = ctx.flow or (ctx.proto, ctx.dport)
        for frame in frames:
            if self.validate_crc and frame.crc_valid is False:
                hits.append(self._hit(
                    f"mavlink_crc_invalid msgid={frame.msgid}", actionable=False))
                continue
            seq_key = (flow, frame.sysid, frame.compid)
            previous = self._seq.get(seq_key, None, now)
            if previous is not None:
                delta = (frame.seq - previous) & 0xFF
                if delta == 0:
                    hits.append(self._hit(f"mavlink_sequence_duplicate sys={frame.sysid} comp={frame.compid}"))
                elif delta > 128:
                    hits.append(self._hit(f"mavlink_sequence_regression last={previous} current={frame.seq}"))
            self._seq.put(seq_key, frame.seq, now)

            if frame.signed and frame.sig_timestamp is not None:
                sig_key = (flow, frame.link_id, frame.sysid, frame.compid)
                last = self._sig_ts.get(sig_key, None, now)
                if last is not None and frame.sig_timestamp <= last:
                    hits.append(self._hit(f"mavlink_signature_replay ts={frame.sig_timestamp} last={last}"))
                max_key = (flow, frame.link_id)
                maximum = self._max_ts.get(max_key, None, now)
                if maximum is not None and maximum - frame.sig_timestamp > self.freshness_10us:
                    hits.append(self._hit(f"mavlink_signature_stale ts={frame.sig_timestamp} max={maximum}"))
                self._sig_ts.put(sig_key, max(last or 0, frame.sig_timestamp), now)
                self._max_ts.put(max_key, max(maximum or 0, frame.sig_timestamp), now)
            elif self.require_signed and frame.msgid in self._SENSITIVE_MSGIDS:
                hits.append(self._hit(f"mavlink_unsigned_sensitive msgid={frame.msgid}"))

            param = self._param_set(frame)
            if param is not None:
                name, value, _target_system, _target_component, _param_type = param
                limits = self.param_ranges.get(name)
                if limits is not None and not (limits[0] <= value <= limits[1]):
                    hits.append(self._hit(
                        f"mavlink_param_out_of_range name={name} value={value:g} "
                        f"range=[{limits[0]:g},{limits[1]:g}]"))

            command = self._command_long(frame)
            if command is not None and command[0] in self.dangerous_commands:
                hits.append(self._hit(
                    f"mavlink_command_profile_match command={command[0]}",
                    actionable=self.require_signed and not frame.signed))

            mission = self._mission_item(frame)
            if mission is not None and mission["current"]:
                hits.append(self._hit(
                    f"mavlink_mission_current seq={mission['seq']} command={mission['command']}",
                    actionable=self.require_signed and not frame.signed))

            # PARAM_REQUEST_READ 열거 관찰: 정상 클라이언트는 필요한 소수 파라미터만
            # 읽지만, telemetry-read 탈취는 flag를 찾으려 param 공간을 훑는다. 짧은 창에서
            # 서로 다른 param 대상이 임계 초과면 스캔으로 관찰만 남긴다(actionable=False).
            pread = self._param_request_read(frame)
            if pread is not None:
                param_index, pname = pread[0], pread[1]
                target = pname if param_index < 0 and pname else param_index
                # 서비스 단위 집계 + surgical(스캔 확장 요청만 근거). 아는 param 재조회는 통과.
                svc = (flow[3], flow[5]) if isinstance(flow, tuple) and len(flow) == 6 else flow
                distinct = _track_scan(self._param_reads, svc, [target], now,
                                       self.param_read_window, self.param_read_scan)
                if distinct:
                    hits.append(self._hit(
                        f"mavlink_param_read_enumeration distinct={distinct}",
                        actionable=True))   # enforce+포트에서 telemetry-read 스캔 차단

            ids = self._ids.get(flow, None, now) or collections.deque()
            ids.append((now, (frame.sysid, frame.compid)))
            while ids and ids[0][0] < now - self.id_window:
                ids.popleft()
            self._ids.put(flow, ids, now)
            if len({item[1] for item in ids}) > self.max_ids:
                hits.append(self._hit(f"mavlink_id_churn unique>{self.max_ids}"))

            fp = zlib.crc32(frame.raw)
            repeat_key = (flow, fp)
            repeats = self._repeat.get(repeat_key, None, now) or collections.deque()
            repeats.append((now, frame.seq))
            while repeats and repeats[0][0] < now - self.repeat_window:
                repeats.popleft()
            self._repeat.put(repeat_key, repeats, now)
            if len(repeats) > self.repeat_limit:
                hits.append(self._hit(f"mavlink_frame_repeat count={len(repeats)} msgid={frame.msgid}"))

            # message-ID 프로파일: warmup 동안 flow별 msgid 집합을 자가학습하고, 이후 신규
            # msgid 등장을 관찰만 남긴다(정상 미션은 안정된 msgid 집합 — ocslab MAVLink 데이터셋).
            profile = self._msg_profile.get(flow, None, now)
            if profile is None:
                profile = {"seen": set(), "count": 0}
            if frame.msgid not in profile["seen"]:
                if profile["count"] >= self.msgid_warmup:
                    hits.append(self._hit(
                        f"mavlink_msgid_novel msgid={frame.msgid} (프로파일 밖)",
                        actionable=False))
                profile["seen"].add(frame.msgid)
            profile["count"] += 1
            self._msg_profile.put(flow, profile, now)

            # msgid별 rate: 특정 msgid flooding(인젝션 증폭, UAV-MAV-021 방향) 관찰. 창당 1회 보고.
            rate_key = (flow, frame.msgid)
            stamps = self._msg_rate.get(rate_key, None, now) or collections.deque()
            stamps.append(now)
            while stamps and stamps[0] < now - self.msgid_rate_window:
                stamps.popleft()
            self._msg_rate.put(rate_key, stamps, now)
            if len(stamps) > self.msgid_rate_limit and self._msg_flood_seen.get(rate_key, None, now) is None:
                self._msg_flood_seen.put(rate_key, True, now)
                hits.append(self._hit(
                    f"mavlink_msgid_flood msgid={frame.msgid} count={len(stamps)}"
                    f"/{self.msgid_rate_window:g}s", actionable=False))
        return hits


# ── CCSDS Space Packet 관찰기 ───────────────────────────────────────────────
@dataclass(frozen=True)
class CcsdsPacket:
    packet_type: int
    secondary_header: bool
    apid: int
    sequence_flags: int
    sequence_count: int
    payload: bytes = field(repr=False)
    has_fecf: bool = False
    fecf_valid: bool | None = None
    sdls_trailer: bytes = field(default=b"", repr=False)
    raw: bytes = field(default=b"", repr=False)


def crc16_ccitt(data: bytes, initial: int = 0xFFFF) -> int:
    crc = initial
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def parse_ccsds_packet(data: bytes, sdls_trailer_len: int = 36) -> CcsdsPacket | None:
    """엄격한 길이 일치 기반 CCSDS Space Packet primary header 후보 파싱

    끝 2byte 추가 시에만 FECF(CRC-16/CCITT) 후보 처리
    CRC의 무결성 검사 한정과 본선 profile 부재 시 SDLS 유무 판단 배제
    """
    if len(data) < 7:
        return None
    first, sequence, length_field = struct.unpack_from(">HHH", data)
    if ((first >> 13) & 0x07) != 0:
        return None
    packet_end = 6 + length_field + 1
    tails = (0, 2, 2 + max(0, int(sdls_trailer_len)))
    remaining = len(data) - packet_end
    if packet_end < 7 or remaining not in tails:
        return None
    has_fecf = remaining >= 2
    valid = None
    if has_fecf:
        valid = crc16_ccitt(data[:packet_end]) == int.from_bytes(data[packet_end:packet_end + 2], "big")
    trailer = data[packet_end + 2:] if remaining > 2 else b""
    return CcsdsPacket((first >> 12) & 1, bool((first >> 11) & 1), first & 0x7FF,
                       (sequence >> 14) & 3, sequence & 0x3FFF, data[6:packet_end],
                       has_fecf, valid, trailer, data)


class CcsdsDetector(Detector):
    """CCSDS 구조·순서 관찰기, 기본 observe와 SDLS 인증 추측 배제"""

    name = "ccsds"

    def __init__(self, mode="observe", ports=None, weight=1.0, max_keys=4096,
                 state_ttl=120.0, confirmations=2, confirm_window=3.0,
                 apids=None, sensitive_commands=None, require_sdls=False,
                 sdls_trailer_len=36, sdls_key: bytes | None = None,
                 apid_scan_window=10.0, apid_scan_targets=8, now=None) -> None:
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        self.ports = {int(p) for p in (ports or [])}
        self.weight, self.max_keys, self.state_ttl = float(weight), max(32, int(max_keys)), float(state_ttl)
        self._now = now or time.monotonic
        self._seq = BoundedState(self.max_keys, self.state_ttl, self._now)
        self._debounce = EvidenceDebouncer(confirmations, confirm_window, self.max_keys)
        # APID 열거 관찰: 정상 telemetry는 안정된 소수 APID를 반복하지만, ccsds-tm-read
        # 탈취는 flag telemetry를 찾으려 APID 공간을 훑는다. 서비스 단위 distinct APID가
        # 임계 초과면 스캔으로 관찰만 남긴다(actionable=False).
        self.apid_scan_window = float(apid_scan_window)
        self.apid_scan_targets = max(1, int(apid_scan_targets))
        self._apid_scan = BoundedState(self.max_keys, max(self.apid_scan_window * 2, 1.0), self._now)
        self.apids = {int(apid) for apid in (apids or [])}
        self.sensitive_commands = {str(command).upper() for command in (sensitive_commands or [])}
        self.require_sdls = bool(require_sdls)
        self.sdls_trailer_len = max(0, int(sdls_trailer_len))
        self.sdls_key = sdls_key
        self._sdls_counter = BoundedState(self.max_keys, self.state_ttl, self._now)

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    def _hit(self, reason, actionable=True):
        family = reason.split(" ", 1)[0]
        rule_id = ("CCSDS-FECF-01" if family == "ccsds_fecf_invalid" else
                   "CCSDS-02" if family.startswith("ccsds_sequence_") else
                   "CCSDS-SDLS-01" if family.startswith("ccsds_sdls_") else
                   "CCSDS-CMD-01" if family == "ccsds_sensitive_command" else
                   "CCSDS-READ-SCAN" if family == "ccsds_apid_enumeration" else "CCSDS-OBS")
        enabled = self.mode == "enforce" and actionable
        return Evidence(
            self.weight if enabled else 0.0, reason, f"ccsds:{family}", rule_id,
            EvidenceClass.CONTEXT_REQUIRED if enabled else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.PROFILE_BOUND,
            bool(self.ports), enabled, True)

    def inspect(self, ctx):
        if self.mode == "off" or (self.ports and ctx.dport not in self.ports):
            return []
        packet = parse_ccsds_packet(ctx.segment_payload or ctx.payload, self.sdls_trailer_len)
        if packet is None:
            return []
        if self.apids and packet.apid not in self.apids:
            return []
        now, hits = self._now(), []
        flow = ctx.flow or (ctx.proto, ctx.dport)
        key = (flow, packet.apid, packet.packet_type)
        old = self._seq.get(key, None, now)
        if old is not None:
            delta = (packet.sequence_count - old) & 0x3FFF
            # sequence duplicate/regression은 **observe 전용**(actionable=False). 정상 클라이언트가
            # 같은 read 요청을 반복하면 sequence_count가 그대로라 duplicate로 보이는데(2026-08-20
            # bansan 통합 테스트에서 SLA prober의 CCSDS 반복 read를 전부 오탐·차단해 SLA를 깎는
            # 것을 확인), 정상 재조회와 replay를 sequence만으로는 구분할 수 없다. 강한 replay
            # 근거는 SDLS counter(아래)뿐이다.
            if delta == 0:
                self._debounce.confirmed((key, "duplicate"), now)
                hits.append(self._hit(f"ccsds_sequence_duplicate apid={packet.apid}", actionable=False))
            elif delta > 0x2000:
                self._debounce.confirmed((key, "regression"), now)
                hits.append(self._hit(
                    f"ccsds_sequence_regression last={old} current={packet.sequence_count}",
                    actionable=False))
        self._seq.put(key, packet.sequence_count, now)
        # APID 열거: 서비스 단위 + surgical(APID 공간을 확장하는 요청만 근거). 아는 APID
        # telemetry 재수신은 통과. NAT/재접속 대비 서비스(dst,dport) 키.
        svc = (flow[3], flow[5]) if isinstance(flow, tuple) and len(flow) == 6 else flow
        distinct = _track_scan(self._apid_scan, svc, [packet.apid], now,
                               self.apid_scan_window, self.apid_scan_targets)
        if distinct:
            hits.append(self._hit(
                f"ccsds_apid_enumeration distinct={distinct}", actionable=True))
        if packet.has_fecf and packet.fecf_valid is False:
            hits.append(self._hit(f"ccsds_fecf_invalid apid={packet.apid}"))
        command = packet.payload.rstrip(b"\x00").decode("ascii", "ignore").strip().upper()
        sensitive = command in self.sensitive_commands
        if sensitive:
            hits.append(self._hit(
                f"ccsds_sensitive_command apid={packet.apid} command={command}",
                actionable=False))
        if self.require_sdls and sensitive and not packet.sdls_trailer:
            hits.append(self._hit(
                f"ccsds_sdls_missing apid={packet.apid} command={command}"))
        if packet.sdls_trailer and len(packet.sdls_trailer) >= 4:
            counter = int.from_bytes(packet.sdls_trailer[:4], "big")
            counter_key = (flow, packet.apid)
            old_counter = self._sdls_counter.get(counter_key, None, now)
            if old_counter is not None and counter <= old_counter:
                hits.append(self._hit(
                    f"ccsds_sdls_counter_replay apid={packet.apid} counter={counter}"))
            self._sdls_counter.put(counter_key, max(old_counter or 0, counter), now)
            if self.sdls_key is not None and len(packet.sdls_trailer) == 36:
                frame_end = len(packet.raw) - len(packet.sdls_trailer)
                expected = hmac.digest(
                    self.sdls_key, packet.raw[:frame_end] + packet.sdls_trailer[:4], "sha256")
                if not hmac.compare_digest(expected, packet.sdls_trailer[4:]):
                    hits.append(self._hit(f"ccsds_sdls_mac_invalid apid={packet.apid}"))
        return hits


# ── RTPS/DDS 관찰기 ─────────────────────────────────────────────────────────
_RTPS_DATA_KINDS = frozenset({0x15, 0x16})   # DATA, DATA_FRAG


@dataclass(frozen=True)
class RtpsMessage:
    version: tuple[int, int]
    vendor: bytes
    guid_prefix: bytes
    submessages: tuple[tuple[int, int], ...]
    malformed: bool = False
    # DATA/DATA_FRAG 서브메시지에서 뽑은 (readerId, writerId) 목록. topic/reader 열거 관찰용.
    endpoints: tuple[tuple[bytes, bytes], ...] = ()


def parse_rtps_message(data: bytes) -> RtpsMessage | None:
    if len(data) < 20 or data[:4] != b"RTPS":
        return None
    off, submessages, endpoints, malformed = 20, [], [], False
    while off < len(data):
        if off + 4 > len(data):
            malformed = True
            break
        kind, flags = data[off], data[off + 1]
        endian = "little" if flags & 0x01 else "big"
        size = int.from_bytes(data[off + 2:off + 4], endian)
        body_end = len(data) if size == 0 else off + 4 + size
        if body_end > len(data):
            malformed = True
            break
        submessages.append((kind, body_end - off - 4))
        if kind in _RTPS_DATA_KINDS:
            # DATA 본문: extraFlags(2) octetsToInlineQos(2) readerId(4) writerId(4) ...
            body = data[off + 4:body_end]
            if len(body) >= 12:
                endpoints.append((body[4:8], body[8:12]))   # readerId, writerId(=topic)
        off = body_end
    return RtpsMessage((data[4], data[5]), data[6:8], data[8:20],
                       tuple(submessages), malformed, tuple(endpoints))


class RtpsDetector(Detector):
    """RTPS 구조·participant 변화 관찰기, type 정보 부재 시 topic 의미 추측 배제"""

    name = "rtps"

    def __init__(self, mode="observe", ports=None, weight=1.0, guid_window=10.0,
                 max_guids=32, max_keys=4096, topic_window=10.0, topic_scan=16, now=None) -> None:
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        self.ports = {int(p) for p in (ports or [])}
        self.weight, self.guid_window = float(weight), float(guid_window)
        self.max_guids, self.max_keys = int(max_guids), max(32, int(max_keys))
        self._now = now or time.monotonic
        ttl = max(self.guid_window * 2, 1.0)
        self._guids = BoundedState(self.max_keys, ttl, self._now)
        self._profile = BoundedState(self.max_keys, ttl, self._now)
        # topic 열거 관찰: SPDP discovery는 소수 builtin writer를 반복하지만, ros2-topic-read
        # 탈취는 flag 담은 topic을 찾으려 여러 topic(writerId)을 훑는다. 서비스 단위 distinct
        # writerId가 임계 초과면 스캔으로 관찰만 남긴다(actionable=False).
        self.topic_window = float(topic_window)
        self.topic_scan = max(1, int(topic_scan))
        self._topics = BoundedState(self.max_keys, max(self.topic_window * 2, 1.0), self._now)

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    def _hit(self, reason, actionable=True):
        family = reason.split(" ", 1)[0]
        rule_id = {
            "rtps_submessage_malformed": "RTPS-02",
            "rtps_profile_changed": "RTPS-PROFILE-01",
            "rtps_guid_churn": "RTPS-DISCOVERY-OBS-01",
            "rtps_topic_enumeration": "RTPS-READ-SCAN",
        }.get(family, "RTPS-OBS")
        enabled = self.mode == "enforce" and actionable
        return Evidence(
            self.weight if enabled else 0.0, reason, f"rtps:{family}", rule_id,
            EvidenceClass.CONTEXT_REQUIRED if enabled else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.PROFILE_BOUND if self.ports else IdentificationBasis.STRUCTURE_VERIFIED,
            True, enabled, True)

    def inspect(self, ctx):
        if self.mode == "off" or (self.ports and ctx.dport not in self.ports):
            return []
        msg = parse_rtps_message(ctx.segment_payload or ctx.payload)
        if msg is None:
            return []
        now, hits = self._now(), []
        flow = ctx.flow or (ctx.proto, ctx.dport)
        if msg.malformed:
            hits.append(self._hit("rtps_submessage_malformed"))
        old = self._profile.get(flow, None, now)
        profile = (msg.version, msg.vendor)
        if old is not None and old != profile:
            hits.append(self._hit(f"rtps_profile_changed {old!r}->{profile!r}"))
        self._profile.put(flow, profile, now)
        q = self._guids.get(flow, None, now) or collections.deque()
        q.append((now, msg.guid_prefix))
        while q and q[0][0] < now - self.guid_window:
            q.popleft()
        self._guids.put(flow, q, now)
        if len({guid for _, guid in q}) > self.max_guids:
            hits.append(self._hit(f"rtps_guid_churn unique>{self.max_guids}"))
        if msg.endpoints:
            # topic 열거: 서비스 단위 + surgical(새 topic writerId를 도입하는 요청만 근거).
            # 아는 topic 재구독은 통과. SPDP discovery(소수 builtin writer 반복)도 무신호.
            svc = (flow[3], flow[5]) if isinstance(flow, tuple) and len(flow) == 6 else flow
            writers = [writer for _reader, writer in msg.endpoints]
            distinct = _track_scan(self._topics, svc, writers, now,
                                   self.topic_window, self.topic_scan)
            if distinct:
                hits.append(self._hit(
                    f"rtps_topic_enumeration distinct={distinct}", actionable=True))
        return hits


# Modbus/TCP 읽기 함수 코드(우리 자체 attack-agent가 read-only 실행 계획으로 사용하는 목록)
# FC01/02 read coils/discrete inputs, 03/04 read holding/input registers, 07 read exception
# status, 0B/0C get comm event counter/log, 11 report server id, 2B encapsulated interface
_MODBUS_READ_FCS = frozenset({0x01, 0x02, 0x03, 0x04, 0x07, 0x0B, 0x0C, 0x11, 0x2B})
_MODBUS_EXCEPTION_BIT = 0x80


class ModbusDetector(Detector):
    """Modbus/TCP MBAP 구조 검증과 쓰기 함수 코드 관찰

    83개 위협 카탈로그와 예선 연구(dahAgent/data/techniques.yaml)에 없던 프로토콜.
    2026-08-18 attack-agent 레포 분석에서 발견 — 우리 팀 공격 에이전트가 스스로
    "P1, TCP-testable, no CRC"로 지정해 실행 가능 기술로 준비해뒀다(agents/team1/
    attacker/protocols.py, knowledge.py). L2_MCS·L4_UGV 양쪽에서 ICS 스타일 제어
    포트로 쓰일 수 있다는 것도 attack-agent의 knowledge.py 자체 코멘트로 확인됨.

    MBAP(Modbus Application Protocol) header 7byte:
      TransactionId(2,BE) | ProtocolId(2,BE,=0) | Length(2,BE,=1+len(PDU)) | UnitId(1)
    ProtocolId에 매직 넘버가 없어 이 두 byte가 우연히 0인 다른 프로토콜과 구분할
    방법이 없다. CCSDS와 동일하게 port profile을 identification 전제조건으로 두어
    port 설정 전에는 어떤 근거도 생성하지 않는다.

    쓰기 함수 코드(공식 스펙상 05/06/0F/10/16/17 등)는 정상 제어 트래픽인지 공격인지
    구분할 baseline이 없어 관찰만 한다. 정상 baseline 확인 전 강제 판정 금지 원칙에
    따라 `enforce`에서도 이 항목은 강제하지 않는다.
    """

    name = "modbus"
    # FC01/02 read coils·discrete, 03/04 read holding·input registers는 PDU가
    # FC(1)+시작주소(2)+수량(2) 구조라 스캔 대상(주소)을 뽑을 수 있다.
    _MODBUS_ADDR_FCS = frozenset({0x01, 0x02, 0x03, 0x04})

    def __init__(self, mode="observe", ports=None, weight=1.0,
                 read_window=5.0, read_scan_targets=16, max_read_qty=0,
                 max_keys=4096, now=None) -> None:
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        self.ports = {int(p) for p in (ports or [])}
        self.weight = float(weight)
        # 블록 read 상한: flag가 여러 레지스터에 걸치면 공격자는 큰 블록(qty)을 한 번에 읽어야
        # 하지만 정상 폴링은 소수만 읽는다(2026-08-20 bansan 통합 테스트: 공격 qty=16 vs 정상 qty=1).
        # max_read_qty>0이면 그 초과 read 요청을 baseline 위반으로 차단(DEF_MODBUS_MAX_READ_QTY). 0=비활성.
        self.max_read_qty = max(0, int(max_read_qty))
        # read enumeration 관찰: 정상 폴링은 소수의 고정 레지스터를 반복 조회하지만,
        # attack-agent의 modbus-read-regs(P1)는 flag를 찾으려 주소 공간을 훑는다. 짧은
        # 창 안에서 서로 다른 read 대상이 임계 초과로 관측되면 스캔으로 관찰만 남긴다
        # (baseline 없이 강제 차단하지 않는다 — actionable=False, 규칙 4).
        self.read_window = float(read_window)
        self.read_scan_targets = max(1, int(read_scan_targets))
        self._now = now or time.monotonic
        self._reads = BoundedState(max(32, int(max_keys)),
                                   max(self.read_window * 2, 1.0), self._now)

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    def _hit(self, reason, rule_id, actionable=True):
        enabled = self.mode == "enforce" and actionable
        return Evidence(
            self.weight if enabled else 0.0, reason, f"modbus:{rule_id}", rule_id,
            EvidenceClass.CONTEXT_REQUIRED if enabled else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.PROFILE_BOUND,
            bool(self.ports), enabled, True)

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or not self.ports or ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        payload = ctx.payload
        if len(payload) < 8:                        # MBAP(7) + function code(1) 미만
            return []
        tid, proto_id, length, unit = struct.unpack(">HHHB", payload[:7])
        if proto_id != 0:                            # ProtocolId!=0 → Modbus 아님, 판정 보류
            return []
        hits: list[Evidence] = []
        # 쓰기 관찰(보수적 경로): 선언 Length와 실제 남은 byte 수가 정확히 일치할 때만
        # well-formed 단일 프레임으로 취급한다. Modbus/TCP는 pipelining이 가능해, 불일치를
        # 곧장 구조 위반으로 판정하면 정상 트래픽을 오탐할 위험이 있어 판정을 보류한다.
        # 쓰기·진단 함수 코드는 baseline 없이 강제 차단하지 않으므로 관찰만(actionable=False).
        pdu = payload[7:]
        if length == len(pdu) + 1 and pdu:
            fc = pdu[0] & ~_MODBUS_EXCEPTION_BIT
            if fc not in _MODBUS_READ_FCS:
                hits.append(self._hit(f"modbus_non_read_function_code 0x{fc:02x}",
                                      "MODBUS-WRITE-FC", actionable=False))
        # 블록 read 상한 위반 차단: flag가 여러 레지스터에 걸치면 큰 qty를 한 번에 읽어야 한다.
        # max_read_qty>0(운영자가 정상 최대 qty로 설정)이면 그 초과 read를 baseline 위반으로 차단.
        if self.max_read_qty:
            over = self._oversized_read_qty(payload)
            if over is not None:
                hits.append(self._hit(
                    f"modbus_read_qty_over_baseline qty={over}>{self.max_read_qty}",
                    "MODBUS-READ-QTY", actionable=True))
        # read enumeration(관찰 전용): 재조립 버퍼 안의 연속 MBAP 프레임을 훑어 read 대상을
        # 집계한다. 관찰 전용이라 pipelining 버퍼를 훑어도 차단 위험이 없어, 보수적 단일
        # 프레임 경로가 놓치는 "한 연결에서 연속 read로 주소 공간을 훑는" 실제 스캔을 잡는다.
        hits += self._read_enumeration(ctx, payload)
        return hits

    def _oversized_read_qty(self, payload: bytes):
        """연속 MBAP 프레임을 훑어 max_read_qty를 초과하는 read qty가 있으면 그 qty를 반환."""
        off, count = 0, 0
        while off + 7 <= len(payload) and count < 64:
            proto_id, length = struct.unpack_from(">HH", payload, off + 2)
            if proto_id != 0 or length < 2:
                break
            frame_end = off + 6 + length
            if frame_end > len(payload):
                break
            pdu = payload[off + 7:frame_end]
            if pdu:
                fc = pdu[0] & ~_MODBUS_EXCEPTION_BIT
                if fc in self._MODBUS_ADDR_FCS and len(pdu) >= 5:   # FC01-04: fc addr(2) qty(2)
                    qty = int.from_bytes(pdu[3:5], "big")
                    if qty > self.max_read_qty:
                        return qty
            off, count = frame_end, count + 1
        return None

    def _read_targets(self, payload: bytes) -> list[tuple[int, int | None]]:
        """재조립 버퍼의 연속 MBAP 프레임을 훑어 read (fc, addr) 대상을 순서대로 반환.

        선언 Length가 남은 byte를 벗어나거나 ProtocolId!=0이면 그 지점에서 중단한다
        (부분 프레임·다른 프로토콜을 스캔 대상으로 오인하지 않는다). 프레임 수는 상한을
        둬 재조립 버퍼가 커도 비용이 제한되게 한다."""
        off, targets, count = 0, [], 0
        while off + 7 <= len(payload) and count < 64:
            proto_id, length = struct.unpack_from(">HH", payload, off + 2)
            if proto_id != 0 or length < 2:
                break
            frame_end = off + 6 + length          # tid2+proto2+len2 + length(=unit+pdu)
            if frame_end > len(payload):
                break
            pdu = payload[off + 7:frame_end]
            if pdu:
                fc = pdu[0] & ~_MODBUS_EXCEPTION_BIT
                if fc in _MODBUS_READ_FCS:
                    addr = (int.from_bytes(pdu[1:3], "big")
                            if fc in self._MODBUS_ADDR_FCS and len(pdu) >= 5 else None)
                    targets.append((fc, addr))
            off, count = frame_end, count + 1
        return targets

    def _service_key(self, ctx: PacketContext):
        """집계 키. NAT로 source IP가 무의미하고 스캐너가 재접속할 수 있어, 연결(5-tuple)이
        아니라 서비스(dst, dport) 단위로 묶는다."""
        flow = ctx.flow
        if flow and len(flow) == 6:
            return (flow[3], flow[5])              # dst, dport
        return (ctx.proto, ctx.dport)

    def _read_enumeration(self, ctx: PacketContext, payload: bytes) -> list[Evidence]:
        """서비스 단위 read 주소 스캔 관찰. 스캔을 확장하는 요청만 근거를 남긴다(surgical).

        정상 클라이언트가 아는 레지스터를 재조회하는 요청은, 다른 누군가 스캔 중이라도 새 대상을
        도입하지 않으므로 통과한다. `_track_scan`이 확장 요청에서만 distinct를 반환한다."""
        targets = self._read_targets(payload)
        if not targets:
            return []
        distinct = _track_scan(self._reads, self._service_key(ctx), targets, self._now(),
                               self.read_window, self.read_scan_targets)
        if distinct:
            return [self._hit(f"modbus_read_enumeration distinct={distinct}",
                              "MODBUS-READ-SCAN", actionable=True)]
        return []


# ── 새 방산 프로토콜 공통 유틸 (UDS/CAN, IEC-104, SNMP) ─────────────────────────
# 2026-08-20 attack-agent origin/main(PR #19~#25) 분석에서 추가로 확인된 실행 가능 프로토콜.
# 셋 다 read-only 탈취이고 attack-agent가 read recast만 실행 계획으로 둔다(제24조). 우리는
# Modbus와 동일한 보수적 doctrine으로 관찰만: 포트 profile 요구, 열거는 OBSERVATION_ONLY.
def _svc_key(ctx: PacketContext):
    """열거 집계 키. NAT로 source IP가 무의미하고 스캐너가 재접속하므로 서비스(dst,dport) 단위."""
    flow = ctx.flow
    if isinstance(flow, tuple) and len(flow) == 6:
        return (flow[3], flow[5])
    return (ctx.proto, ctx.dport)


def _track_scan(state: BoundedState, key, targets, now, window, threshold):
    """{target: 마지막 관측 시각} dict + TTL로 distinct 대상 추적. **surgical** 버전.

    임계를 넘고 **이번 요청이 스캔을 확장할 때만**(창 안에서 처음 보는 대상을 도입) distinct
    수를 반환, 아니면 None. 즉 정상 클라이언트가 이미 아는 대상을 재조회하는 요청은, 다른
    누군가 스캔 중이라 서비스 distinct가 임계를 넘었더라도 근거를 만들지 않아 통과한다.
    "프로토콜을 통째로 막는" 게 아니라 스캔을 확장하는 요청만 잡기 위한 것이다.
    상한(cap)으로 메모리를 제한한다. Modbus/MAVLink/CCSDS/RTPS도 같은 방식.
    """
    prev = state.get(key, None, now) or {}
    expanded = any(target not in prev for target in targets)   # 창 안에서 처음 보는 대상?
    seen = dict(prev)
    for target in targets:
        seen[target] = now
    cutoff = now - window
    seen = {t: ts for t, ts in seen.items() if ts >= cutoff}
    cap = threshold * 8
    if len(seen) > cap:
        seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-cap:])
    state.put(key, seen, now)
    return len(seen) if (len(seen) > threshold and expanded) else None


# UDS(ISO 14229) 읽기 SID — attack-agent가 read recast로 실행하는 목록
#   0x22 ReadDataByIdentifier, 0x19 ReadDTCInformation, 0x3E TesterPresent,
#   0x1A ReadDataByLocalId(legacy), 0x23 ReadMemoryByAddress
_UDS_READ_SIDS = frozenset({0x22, 0x19, 0x3E, 0x1A, 0x23})


class UdsCanDetector(Detector):
    """UDS-over-CAN-over-TCP 게이트웨이 관찰 (L4 UGV 차량 버스)

    2026-08-20 attack-agent origin/main 분석에서 확인 — `protocols.py`의 `can_uds_read`가
    P1로 지정. CloudCar/ASRG류 CTF처럼 텔레메틱스/teleop 게이트웨이가 차량 CAN 버스를 노출하고,
    UDS ReadDataByIdentifier(0x22)로 DID(예: VIN 0xF190)를 읽어 flag를 탈취한다.

    게이트웨이 wire: `arbitration_id(4,BE,29bit) | len(1) | payload(len)`. CAN에는 magic이 없어
    Modbus와 동일하게 port profile을 identification 전제조건으로 둔다(포트 설정 전 무증거).
    쓰기·루틴 SID(0x2E/0x2F/0x31/0x34 등)는 정상 진단 트래픽과 구분할 baseline이 없어 관찰만.
    """

    name = "uds_can"

    def __init__(self, mode="observe", ports=None, weight=1.0,
                 read_window=5.0, read_scan_targets=16, did_allowlist=None, max_keys=4096, now=None) -> None:
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        self.ports = {int(p) for p in (ports or [])}
        self.weight = float(weight)
        self.read_window = float(read_window)
        self.read_scan_targets = max(1, int(read_scan_targets))
        # 단일 read 구분자(당일 baseline 확인 후 활성). 비어 있으면 OFF(모든 DID 통과). 정상 폴이
        # 읽는 DID만 넣으면, 목록 밖 DID의 ReadDataByIdentifier(0x22)만 드랍한다. Modbus qty와 대칭.
        self.did_allowlist = {int(d) for d in (did_allowlist or [])}
        self._now = now or time.monotonic
        self._reads = BoundedState(max(32, int(max_keys)), max(self.read_window * 2, 1.0), self._now)

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    def _hit(self, reason, rule_id, actionable=True):
        enabled = self.mode == "enforce" and actionable
        return Evidence(
            self.weight if enabled else 0.0, reason, f"uds:{rule_id}", rule_id,
            EvidenceClass.CONTEXT_REQUIRED if enabled else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.PROFILE_BOUND, bool(self.ports), enabled, True)

    def _frames(self, payload: bytes):
        """CAN-over-TCP 연속 프레임 walk. 선언 길이를 벗어나면 그 지점에서 중단."""
        off, out, count = 0, [], 0
        while off + 5 <= len(payload) and count < 64:
            plen = payload[off + 4]
            end = off + 5 + plen
            if plen == 0 or end > len(payload):
                break
            out.append(payload[off + 5:end])           # UDS PDU
            off, count = end, count + 1
        return out

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or not self.ports or ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        hits, read_targets = [], []
        for pdu in self._frames(ctx.payload):
            if not pdu:
                continue
            sid = pdu[0]
            if sid in _UDS_READ_SIDS:
                did = int.from_bytes(pdu[1:3], "big") if sid == 0x22 and len(pdu) >= 3 else None
                read_targets.append((sid, did))
                if self.did_allowlist and did is not None and did not in self.did_allowlist:
                    hits.append(self._hit(f"uds_read_did_not_in_allowlist did=0x{did:04x}",
                                          "UDS-READ-DID", actionable=True))
            elif sid < 0x40:                            # 요청 SID(응답 0x40+/0x7F 제외) 중 비-read
                hits.append(self._hit(f"uds_non_read_sid 0x{sid:02x}", "UDS-WRITE-SID",
                                      actionable=False))
        if read_targets:
            distinct = _track_scan(self._reads, _svc_key(ctx), read_targets, self._now(),
                                   self.read_window, self.read_scan_targets)
            if distinct:
                hits.append(self._hit(f"uds_did_enumeration distinct={distinct}",
                                      "UDS-READ-SCAN", actionable=True))
        return hits


# IEC 60870-5-104 읽기/심문 type id — attacker-finals iec104.json read_types 기준
#   100 C_IC_NA_1(general interrogation), 101 C_CI_NA_1(counter interrogation),
#   102 C_RD_NA_1(read by IOA). 제어(45~51 등)는 관찰만.
_IEC104_READ_TYPES = frozenset({100, 101, 102})


class Iec104Detector(Detector):
    """IEC 60870-5-104 관찰 (OT/지상 관제)

    2026-08-20 attack-agent 분석에서 확인 — `iec104_read`(P2). C_RD_NA_1(102)/C_IC_NA_1(100)로
    IOA(정보객체주소)를 읽어 flag를 탈취한다. APCI I-format: `0x68 | len | ctrl(4) | ASDU`.
    ASDU: type_id(1) | VSQ(1) | COT(2,LE) | CA(2,LE) | IOA(3,LE) ... 제어 명령은 관찰만.
    magic 0x68이 있지만 1byte라 약해, Modbus와 동일하게 port profile을 전제조건으로 둔다.
    """

    name = "iec104"

    def __init__(self, mode="observe", ports=None, weight=1.0,
                 read_window=5.0, read_scan_targets=16, ioa_allowlist=None, max_keys=4096, now=None) -> None:
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        self.ports = {int(p) for p in (ports or [])}
        self.weight = float(weight)
        self.read_window = float(read_window)
        self.read_scan_targets = max(1, int(read_scan_targets))
        # 단일 read 구분자(당일 baseline 확인 후 활성). 비면 OFF(모든 IOA 통과). 정상 폴이 읽는
        # IOA만 넣으면, 목록 밖 IOA의 C_RD(type 102) 타겟 read만 드랍한다. UDS DID allowlist와 대칭.
        # C_IC(type 100) general interrogation은 IOA가 고정이라 게이팅 대상에서 제외.
        self.ioa_allowlist = {int(i) for i in (ioa_allowlist or [])}
        self._now = now or time.monotonic
        self._reads = BoundedState(max(32, int(max_keys)), max(self.read_window * 2, 1.0), self._now)

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    def _hit(self, reason, rule_id, actionable=True):
        enabled = self.mode == "enforce" and actionable
        return Evidence(
            self.weight if enabled else 0.0, reason, f"iec104:{rule_id}", rule_id,
            EvidenceClass.CONTEXT_REQUIRED if enabled else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.PROFILE_BOUND, bool(self.ports), enabled, True)

    def _apdus(self, payload: bytes):
        """연속 APCI APDU walk. start(0x68)·길이가 어긋나면 그 지점에서 중단. ASDU만 반환."""
        off, out, count = 0, [], 0
        while off + 6 <= len(payload) and count < 64:
            if payload[off] != 0x68:
                break
            length = payload[off + 1]
            end = off + 2 + length
            if length < 4 or end > len(payload):
                break
            ctrl = payload[off + 2:off + 6]
            asdu = payload[off + 6:end]
            if not (ctrl[0] & 0x01):                    # I-format(bit0=0)만 ASDU를 나른다
                out.append(asdu)
            off, count = end, count + 1
        return out

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or not self.ports or ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        hits, read_targets = [], []
        for asdu in self._apdus(ctx.payload):
            if len(asdu) < 9:                           # type+VSQ+COT(2)+CA(2)+IOA(3)
                continue
            type_id = asdu[0]
            ioa = int.from_bytes(asdu[6:9], "little")
            if type_id in _IEC104_READ_TYPES:
                read_targets.append((type_id, ioa))
                if self.ioa_allowlist and type_id == 102 and ioa not in self.ioa_allowlist:
                    hits.append(self._hit(f"iec104_read_ioa_not_in_allowlist ioa={ioa}",
                                          "IEC104-READ-IOA", actionable=True))
            elif 45 <= type_id <= 69:                   # C_SC/C_DC/C_RC/C_SE 등 제어 명령대
                hits.append(self._hit(f"iec104_control_command type={type_id}",
                                      "IEC104-CTRL", actionable=False))
        if read_targets:
            distinct = _track_scan(self._reads, _svc_key(ctx), read_targets, self._now(),
                                   self.read_window, self.read_scan_targets)
            if distinct:
                hits.append(self._hit(f"iec104_ioa_enumeration distinct={distinct}",
                                      "IEC104-READ-SCAN", actionable=True))
        return hits


def _ber_tlv(data: bytes, off: int):
    """BER TLV 하나를 읽어 (tag, value_start, value_end, next_off) 반환. 파싱 실패 시 None."""
    if off + 2 > len(data):
        return None
    tag = data[off]
    length = data[off + 1]
    vstart = off + 2
    if length & 0x80:                                   # long-form length
        nbytes = length & 0x7F
        if nbytes == 0 or nbytes > 4 or vstart + nbytes > len(data):
            return None
        length = int.from_bytes(data[vstart:vstart + nbytes], "big")
        vstart += nbytes
    vend = vstart + length
    if vend > len(data):
        return None
    return tag, vstart, vend, vend


# SNMP PDU tag — 읽기: GetRequest/GetNext/GetBulk. 쓰기: SetRequest(0xA3).
_SNMP_READ_PDUS = frozenset({0xA0, 0xA1, 0xA5})
_SNMP_SET_PDU = 0xA3


class SnmpDetector(Detector):
    """SNMP v1/v2c 관찰 (지상/NOC 장비 M&C 읽기)

    2026-08-20 attack-agent 분석에서 확인 — `snmp_v2c_get`(P2). GetRequest로 OID를 읽어 flag를
    탈취한다(satcom 지상장비 모니터링). BER: `SEQUENCE{ version(INT), community(OCTETSTRING),
    PDU }`. PDU tag가 0xA0/0xA1/0xA5면 읽기, 0xA3(SetRequest)면 쓰기(관찰만). BER 0x30이 흔해
    Modbus와 동일하게 port profile을 전제조건으로 둔다(SNMP는 보통 UDP/161).
    """

    name = "snmp"

    def __init__(self, mode="observe", ports=None, weight=1.0,
                 read_window=10.0, read_scan_targets=16, max_oids=0, max_keys=4096, now=None) -> None:
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        self.ports = {int(p) for p in (ports or [])}
        self.weight = float(weight)
        self.read_window = float(read_window)
        self.read_scan_targets = max(1, int(read_scan_targets))
        # 단일 read 구분자(당일 baseline 확인 후 활성). 0 = OFF(개수 무제한). 정상 폴이 OID 1개면
        # DEF_SNMP_MAX_OIDS=1 로 다중 OID 배치(스윕)만 드랍한다. Modbus max_read_qty와 대칭.
        self.max_oids = max(0, int(max_oids))
        self._now = now or time.monotonic
        self._reads = BoundedState(max(32, int(max_keys)), max(self.read_window * 2, 1.0), self._now)

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    def _hit(self, reason, rule_id, actionable=True):
        enabled = self.mode == "enforce" and actionable
        return Evidence(
            self.weight if enabled else 0.0, reason, f"snmp:{rule_id}", rule_id,
            EvidenceClass.CONTEXT_REQUIRED if enabled else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.PROFILE_BOUND, bool(self.ports), enabled, True)

    @staticmethod
    def _oids(pdu_value: bytes) -> list[bytes]:
        """PDU 값에서 varbindlist를 찾아 각 varbind의 OID(tag 0x06) 바이트를 반환."""
        oids: list[bytes] = []
        # PDU: request_id(INT) error_status(INT) error_index(INT) varbindlist(SEQUENCE)
        off = 0
        vbl = None
        for _ in range(4):
            tlv = _ber_tlv(pdu_value, off)
            if tlv is None:
                break
            tag, vs, ve, nxt = tlv
            if tag == 0x30:                             # varbindlist SEQUENCE
                vbl = (vs, ve)
                break
            off = nxt
        if vbl is None:
            return oids
        off, end = vbl
        while off < end and len(oids) < 64:
            vb = _ber_tlv(pdu_value, off)               # varbind SEQUENCE
            if vb is None or vb[0] != 0x30:
                break
            _t, vs, ve, nxt = vb
            oid = _ber_tlv(pdu_value, vs)               # 첫 요소 = OID
            if oid is not None and oid[0] == 0x06:
                oids.append(pdu_value[oid[1]:oid[2]])
            off = nxt
        return oids

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or not self.ports or ctx.dport not in self.ports:
            return []
        data = ctx.segment_payload or ctx.payload
        outer = _ber_tlv(data, 0)
        if outer is None or outer[0] != 0x30 or outer[2] != len(data):
            return []                                   # 최상위 SEQUENCE가 전체와 일치할 때만
        off = outer[1]
        version = _ber_tlv(data, off)                   # INTEGER version
        if version is None or version[0] != 0x02:
            return []
        community = _ber_tlv(data, version[3])          # OCTET STRING community
        if community is None or community[0] != 0x04:
            return []
        pdu = _ber_tlv(data, community[3])
        if pdu is None:
            return []
        tag = pdu[0]
        if tag == _SNMP_SET_PDU:
            return [self._hit("snmp_set_request", "SNMP-SET", actionable=False)]
        if tag not in _SNMP_READ_PDUS:
            return []
        oids = self._oids(data[pdu[1]:pdu[2]])
        if not oids:
            return []
        hits = []
        if self.max_oids and len(oids) > self.max_oids:
            hits.append(self._hit(
                f"snmp_read_oids_over_baseline n={len(oids)}>{self.max_oids}",
                "SNMP-READ-OIDS", actionable=True))
        distinct = _track_scan(self._reads, _svc_key(ctx), oids, self._now(),
                               self.read_window, self.read_scan_targets)
        if distinct:
            hits.append(self._hit(f"snmp_oid_enumeration distinct={distinct}",
                                  "SNMP-READ-SCAN", actionable=True))
        return hits


def parse_tls_client_hello(data: bytes):
    """TLS ClientHello에서 (version(major,minor), sni) 추출. TLS/ClientHello가 아니면 None.

    구조 근거만 사용(payload 복호화 아님). SNI 파싱 실패 시 (version, None)을 반환한다.
    """
    if len(data) < 43 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
        return None                                     # record 0x16 handshake, 0x03 TLS1.x, hs 0x01 ClientHello
    version = (data[9], data[10])                       # client_version
    off = 43                                            # 5(record) + 4(hs hdr) + 2(ver) + 32(random)
    try:
        sid_len = data[off]
        off += 1 + sid_len
        cs_len = int.from_bytes(data[off:off + 2], "big")
        off += 2 + cs_len
        comp_len = data[off]
        off += 1 + comp_len
        ext_total = int.from_bytes(data[off:off + 2], "big")
        off += 2
        end = min(len(data), off + ext_total)
        while off + 4 <= end:
            etype = int.from_bytes(data[off:off + 2], "big")
            elen = int.from_bytes(data[off + 2:off + 4], "big")
            body = data[off + 4:off + 4 + elen]
            if etype == 0x0000 and len(body) >= 5:      # server_name extension
                name_len = int.from_bytes(body[3:5], "big")
                return version, body[5:5 + name_len].decode("ascii", "ignore")
            off += 4 + elen
    except (IndexError, ValueError):
        pass
    return version, None


class TlsObserveDetector(Detector):
    """TLS 채널 관찰기 — 암호화로 payload 기반 방산 detector가 무력화되는 지점을 표시

    2026-08-20 attack-agent origin/main 분석에서 확인 — harness가 verify-off TLS 컨텍스트로
    raw-TLS/https probe를 보낸다(`import ssl`). 방산 프로토콜이 TLS로 감싸지면 우리 payload
    파서는 암호문만 보므로 구조적으로 탐지 불가하다. 복호화는 불가능하니, 최소한 "이 포트는
    암호화 채널(SNI=…)이라 protocol detector가 blind"임을 ClientHello에서 관찰해 운영자에게
    알린다. 항상 관찰 전용(actionable=False) — 차단하지 않는다.
    """

    name = "tls_observe"

    def __init__(self, mode="observe", ports=None, weight=1.0,
                 max_keys=4096, state_ttl=300.0, now=None) -> None:
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        self.ports = {int(p) for p in (ports or [])}
        self.weight = float(weight)
        self._now = now or time.monotonic
        # 같은 flow의 ClientHello를 한 번만 보고(핸드셰이크 반복 로그 방지)
        self._seen = BoundedState(max(32, int(max_keys)), float(state_ttl), self._now)

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    def _hit(self, reason):
        return Evidence(
            0.0, reason, "tls:channel", "TLS-CHANNEL-OBS",
            EvidenceClass.OBSERVATION_ONLY, IdentificationBasis.STRUCTURE_VERIFIED,
            True, False, True)

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or (self.ports and ctx.dport not in self.ports):
            return []
        parsed = parse_tls_client_hello(ctx.segment_payload or ctx.payload)
        if parsed is None:
            return []
        flow = ctx.flow or (ctx.proto, ctx.dport)
        now = self._now()
        if self._seen.get(flow, None, now) is not None:
            return []                                   # flow당 1회만
        self._seen.put(flow, True, now)
        (major, minor), sni = parsed
        return [self._hit(
            f"tls_channel version={major}.{minor} port={ctx.dport} "
            f"sni={sni or '?'} (payload 기반 detector blind)")]


# ── gRPC(h2c 평문) 진단 경로/번들 경로 이탈 차단 (본선 L1, P1-R2·P2-R5 승리벡터) ──────
# protobuf length-delimited(문자열/bytes) 필드 태그: (field_num<<3)|2 = 필드 1~15.
# P2-R5: ExportDiagnosticBundle이 민감 path를 필드 2/3/4(0x12/0x1a/0x22)에 실어 우회 → 전 필드 스캔.
_PB_STR_RE = re.compile(
    rb"[\x0a\x12\x1a\x22\x2a\x32\x3a\x42\x4a\x52\x5a\x62\x6a\x72\x7a]([\x01-\x7f])([ -~]{1,128})")


class GrpcDiagGuardDetector(Detector):
    """본선 L1 gateway의 평문 h2c gRPC TailDiagnosticLog 경로 이탈 차단 — P1-R2 승리벡터 대응.

    9000은 평문 h2c gRPC(`/satdiag.v1.SatDiag/TailDiagnosticLog`)로, TailDiagnosticLog{path}가
    진단 로그를 tail한다. 정상 path는 상대 `*.log`(gateway.log·telemetry.log·routing.log…),
    공격은 `path:"/flag"`(절대 flag 파일)·traversal(`../flag`)·민감파일로 flag를 탈취한다.
    구분자: 상대 `.log`만 허용, 절대·비-log·traversal·민감키워드는 차단. 포트 gating(9000).
    암호화(TLS) 프레임엔 gRPC 마커가 안 보여 판정 보류(blind). 정상 로그 tail은 통과.
    """

    name = "grpc_diag_guard"

    _SENSITIVE = ("flag", "secret", "token", "passwd", "shadow", "/etc/",
                  "/proc/", "/root/", ".ssh", "credential", "private")
    _METHOD_MARK = ("satdiag", ".v1.", "/taildiagnosticlog", "grpc.reflection")

    def __init__(self, ports=(9000,), mode="enforce") -> None:
        self.ports = {int(p) for p in ports}
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    def _is_attack(self, path: str) -> bool:
        p = path.lower()
        if ".." in p:                                       # traversal
            return True
        if any(k in p for k in self._SENSITIVE):            # 민감 대상(flag/secret/etc…)
            return True
        if any(c in path for c in (";", "|", "`", "$(", "&&", "\n", "\r")):  # 명령주입
            return True
        # 절대경로면서 .log가 아닌 파일 = 로그 tail 계약 이탈. 공백/'*'는 제외(응답 CSS 등 오탐 방지)
        if (p.startswith("/") and len(p) > 1 and not p.endswith(".log")
                and " " not in p and "*" not in p):
            return True
        return False

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        data = ctx.payload or b""
        low = data.lower()
        # 평문 gRPC/h2 마커가 없으면(암호화 TLS 등) 판정 보류 — payload blind
        if b"grpc" not in low and b"satdiag" not in low and b"taildiagnosticlog" not in low:
            return []
        # HTTP/2면 DATA 프레임만 de-framing해 스캔한다(HEADERS 제외 → user-agent·accept-language
        # 등 헤더값 오탐 방지). P2-R5 실측 1-byte-per-frame 분할 회피도 여기서 복원된다.
        # 비-h2(인라인) payload는 프레임이 없어 de-framed가 비므로 raw를 스캔한다.
        deframed = self._deframe_h2_data(data)
        payloads = [deframed] if deframed else [data]
        for payload in payloads:
            for match in _PB_STR_RE.finditer(payload):
                declared = match.group(1)[0]
                body = match.group(2)
                if len(body) < declared:
                    continue
                candidate = body[:declared].decode("latin-1", "ignore")
                low_c = candidate.lower()
                if any(mark in low_c for mark in self._METHOD_MARK):
                    continue                                # gRPC 메서드 경로 자체는 제외
                if self._is_attack(candidate):
                    enforce = self.mode == "enforce"
                    return [Evidence(
                        1.0 if enforce else 0.0,
                        f"gRPC diagnostic escapes to sensitive path: {candidate[:48]}",
                        "grpc_diag:path", "SAT-GRPC-DIAG-PATH",
                        EvidenceClass.ATTACK_PATTERN_CONFIRMED if enforce
                        else EvidenceClass.OBSERVATION_ONLY,
                        IdentificationBasis.STRUCTURE_VERIFIED,
                        True, enforce, True)]
        return []

    @staticmethod
    def _deframe_h2_data(data: bytes) -> bytes:
        """HTTP/2 DATA 프레임(type 0)의 payload를 이어붙인다 — 1-byte-per-frame 분할 회피 복원.
        9바이트 프레임 헤더(len3·type1·flags1·streamid4) 파싱. 프레임 수·출력 크기 상한(비용 제한)."""
        start = 0
        pre = data.find(b"PRI * HTTP/2")
        if pre != -1:
            sm = data.find(b"SM\r\n\r\n", pre)
            start = sm + 6 if sm != -1 else pre
        out = bytearray()
        i, n, frames = start, len(data), 0
        while i + 9 <= n and frames < 8192 and len(out) < 65536:
            flen = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
            ftype = data[i + 3]
            i += 9
            if i + flen > n:
                break
            if ftype == 0x00:                               # DATA
                out += data[i:i + flen]
            i += flen
            frames += 1
        return bytes(out)


# ── MQTT 관찰기 (UGV 브로커, attacker-finals UGV-MQTT) ──────────────────────────
# read-only 탈취: SUBSCRIBE(type 8)로 여러 topic을 구독해 flag 담긴 메시지를 읽는다. 여러 topic을
# 훑는 것이 read 스캔이다. CONNECT/PUBLISH도 파싱하되 topic 열거만 차단 대상으로 둔다. MQTT는
# magic이 없어(고정헤더 1byte + VBI) port profile을 전제조건으로 둔다(보통 1883/8883).
class MqttDetector(Detector):
    """MQTT 3.1.1/5.0 고정헤더·VBI 구조 관찰과 SUBSCRIBE topic 열거"""

    name = "mqtt"

    def __init__(self, mode="observe", ports=None, weight=1.0,
                 read_window=5.0, read_scan_targets=16, max_keys=4096, now=None,
                 broad_enforce=None) -> None:
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        self.ports = {int(p) for p in (ports or [])}
        self.weight = float(weight)
        self.read_window = float(read_window)
        self.read_scan_targets = max(1, int(read_scan_targets))
        self._now = now or time.monotonic
        self._reads = BoundedState(max(32, int(max_keys)), max(self.read_window * 2, 1.0), self._now)
        # broad-wildcard(exact `#` 등) 단일 구독 차단은 기본 observe다. 정상 모니터/SLA 프로버가
        # `#`·`$SYS/#`로 구독하는 경우가 흔해 enforce 시 SLA 오탐 위험이 있다(공격자의 #와 바이트
        # 동일해 구분 불가). 열거(read-scan)는 여전히 enforce라 다중 broad 토픽 스캔 공격은 차단된다.
        # 프로버가 #를 안 쓴다고 확인되면 DEF_MQTT_BROAD_ENFORCE=1로 즉시 enforce 전환(가역적).
        self.broad_enforce = (broad_enforce if broad_enforce is not None
                              else os.environ.get("DEF_MQTT_BROAD_ENFORCE", "0") == "1")

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    def _hit(self, reason, rule_id, actionable=True):
        enabled = self.mode == "enforce" and actionable
        return Evidence(
            self.weight if enabled else 0.0, reason, f"mqtt:{rule_id}", rule_id,
            EvidenceClass.CONTEXT_REQUIRED if enabled else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.PROFILE_BOUND, bool(self.ports), enabled, True)

    @staticmethod
    def _vbi(data: bytes, off: int):
        """MQTT Variable Byte Integer(remaining length). (값, 다음 off) 또는 None(비정규/초과)."""
        mult, val, i = 1, 0, off
        for _ in range(4):
            if i >= len(data):
                return None
            b = data[i]
            val += (b & 0x7F) * mult
            i += 1
            if not (b & 0x80):
                return val, i
            mult <<= 7
        return None                                     # 4byte 초과 = 비정규 인코딩

    @staticmethod
    def _topics(body: bytes, has_qos: bool):
        """SUBSCRIBE/UNSUBSCRIBE payload에서 length-prefixed topic filter를 뽑는다."""
        out, i = [], 2                                  # packet identifier(2) 건너뜀
        while i + 2 <= len(body) and len(out) < 64:
            ln = int.from_bytes(body[i:i + 2], "big")
            i += 2
            if i + ln > len(body):
                break
            out.append(bytes(body[i:i + ln]))
            i += ln + (1 if has_qos else 0)             # SUBSCRIBE는 각 필터 뒤 QoS 1byte
        return out

    @staticmethod
    def _broad_wildcard(topic: bytes) -> bool:
        """전체 namespace를 root부터 읽는 broad-global wildcard 구독인지 구조적으로 판정한다.
        exact `#`, `+/#`, `+/+/#`, `$share/<group>/#`(shared) = broad(즉시 enforce 후보).
        `uav/#`·`uav/telemetry/#`처럼 concrete 접두가 있으면 scoped → broad 아님(정상 wildcard 통과).
        `#`는 마지막 단독 레벨이어야 유효(MQTT 규격)."""
        try:
            t = topic.decode("utf-8")
        except UnicodeDecodeError:
            return False
        if t.startswith("$share/"):                     # shared subscription → group 뒤 filter만 평가
            parts = t.split("/", 2)
            if len(parts) < 3 or not parts[1]:
                return False
            t = parts[2]
        if not t or t[-1] != "#":
            return False
        levels = t.split("/")
        if levels[-1] != "#":                            # # 는 마지막 단독 레벨
            return False
        return all(lv == "+" for lv in levels[:-1])      # # 앞 모든 레벨이 wildcard(+) = broad-global

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or not self.ports or ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        # VerdictEngine은 현재 TCP connection generation에서 연속으로 재조립한
        # stream prefix를 payload로 전달한다. segment를 우선하면 MQTT fixed
        # header/VBI/topic이 TCP 경계에 걸린 실제 R10 SUBSCRIBE #를 놓친다.
        data = ctx.payload or ctx.segment_payload or b""
        # P2-R3 실측: MQTT 포트(8082)에 HTTP/GraphQL이 공존한다. 명백한 HTTP 요청/응답은 MQTT
        # 고정헤더로 오분류(mqtt_length_over_buffer 등)하지 않도록 파싱에서 제외한다 — MQTT
        # 제어패킷 첫 byte(0x10/0x30/0x82 등)는 아래 ASCII 메서드 문자열과 겹치지 않는다.
        if data.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                            b"PATCH ", b"OPTIONS ", b"HTTP/")):
            return []
        hits, topics, off, count = [], [], 0, 0
        while off + 2 <= len(data) and count < 32:
            ptype = data[off] >> 4
            parsed = self._vbi(data, off + 1)
            if parsed is None:
                hits.append(self._hit("mqtt_malformed_vbi", "MQTT-MALFORMED", actionable=False))
                break
            rem, body_off = parsed
            end = body_off + rem
            if ptype == 0 or ptype > 15 or end > len(data):
                if end > len(data):
                    hits.append(self._hit(f"mqtt_length_over_buffer rem={rem}",
                                          "MQTT-MALFORMED", actionable=False))
                break
            if ptype in (8, 10):                        # SUBSCRIBE / UNSUBSCRIBE
                tp = self._topics(data[body_off:end], has_qos=(ptype == 8))
                topics += tp
                if ptype == 8:                          # SUBSCRIBE만 broad-wildcard 평가
                    for t in tp:
                        if self._broad_wildcard(t):
                            # exact `#`/shared-global 등 전체 namespace 구독. 단일 filter라도 broad-read
                            # primitive지만, 정상 프로버 오탐 방지를 위해 기본 observe(actionable=broad_enforce).
                            hits.append(self._hit(
                                "mqtt_broad_wildcard_subscribe filter=" + t.decode("latin-1", "ignore")[:64],
                                "MQTT-BROAD-SUBSCRIBE", actionable=self.broad_enforce))
                            break
            off, count = end, count + 1
        if topics:
            # MQTT broker에는 정상 subscriber가 동시에 많이 붙는다. 서비스(dst,dport) 하나로
            # 합산하면 서로 무관한 client의 exact/scoped 구독이 임계를 넘어 정상 세션을 DROP한다
            # (P4-R11 실측 MQTT-READ-SCAN 오탐). 열거는 한 TCP flow 안에서만 집계한다.
            # root-global `#`는 별도 MQTT-BROAD-SUBSCRIBE가 즉시 차단하므로 방어 공백이 없다.
            scan_key = ctx.flow if isinstance(ctx.flow, tuple) and len(ctx.flow) == 6 else _svc_key(ctx)
            distinct = _track_scan(self._reads, scan_key, topics, self._now(),
                                   self.read_window, self.read_scan_targets)
            if distinct:
                hits.append(self._hit(f"mqtt_topic_enumeration distinct={distinct}",
                                      "MQTT-READ-SCAN", actionable=True))
        return hits


# ── DNS 관찰기 (MCS resolver, attacker-finals MCS-DNS) ─────────────────────────
# read 탈취: 여러 QNAME 조회로 내부 정보·flag 서브도메인을 열거한다. 구조 위반(압축 포인터
# 루프/과도 depth, 섹션 경계 초과)도 관찰한다. DNS는 magic이 없어 port profile 전제(보통 53).
class DnsDetector(Detector):
    """DNS 헤더·question 구조 관찰과 QNAME 열거, 압축 포인터 루프 탐지"""

    name = "dns"

    def __init__(self, mode="observe", ports=None, weight=1.0,
                 read_window=5.0, read_scan_targets=24, max_keys=4096, now=None) -> None:
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        self.ports = {int(p) for p in (ports or [])}
        self.weight = float(weight)
        self.read_window = float(read_window)
        self.read_scan_targets = max(1, int(read_scan_targets))
        self._now = now or time.monotonic
        self._reads = BoundedState(max(32, int(max_keys)), max(self.read_window * 2, 1.0), self._now)

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    def _hit(self, reason, rule_id, actionable=True):
        enabled = self.mode == "enforce" and actionable
        return Evidence(
            self.weight if enabled else 0.0, reason, f"dns:{rule_id}", rule_id,
            EvidenceClass.CONTEXT_REQUIRED if enabled else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.PROFILE_BOUND, bool(self.ports), enabled, True)

    @staticmethod
    def _qname(data: bytes, off: int):
        """QNAME을 읽어 (name_bytes, 다음 off, malformed?) 반환. 압축 포인터 루프/depth 방어."""
        labels, seen, hops = [], set(), 0
        i, end_after_ptr = off, None
        while i < len(data):
            length = data[i]
            if length == 0:
                i += 1
                break
            if length & 0xC0 == 0xC0:                   # 압축 포인터(2byte)
                if i + 1 >= len(data):
                    return None, i, True
                ptr = ((length & 0x3F) << 8) | data[i + 1]
                if ptr in seen or ptr >= len(data) or hops > 16:
                    return b".".join(labels), i + 2, True   # 루프/과도 depth = malformed
                seen.add(ptr)
                hops += 1
                if end_after_ptr is None:
                    end_after_ptr = i + 2
                i = ptr
                continue
            if length & 0xC0:                           # 예약 비트 = malformed
                return b".".join(labels), i + 1, True
            if i + 1 + length > len(data):
                return None, i, True
            labels.append(bytes(data[i + 1:i + 1 + length]))
            i += 1 + length
        return b".".join(labels), (end_after_ptr if end_after_ptr is not None else i), False

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or not self.ports or ctx.dport not in self.ports:
            return []
        data = ctx.segment_payload or ctx.payload
        if len(data) < 12:
            return []
        qd = int.from_bytes(data[4:6], "big")
        flags = int.from_bytes(data[2:4], "big")
        if flags & 0x8000 or qd == 0 or qd > 64:        # 응답(QR=1)·비정상 QDCOUNT는 무시
            return []
        hits, names, off = [], [], 12
        for _ in range(min(qd, 64)):
            name, nxt, bad = self._qname(data, off)
            if bad:
                hits.append(self._hit("dns_malformed_qname (압축 루프/경계)",
                                      "DNS-MALFORMED", actionable=False))
                break
            if name is None or nxt + 4 > len(data):
                break
            names.append(name.lower())
            off = nxt + 4                               # QTYPE(2)+QCLASS(2)
        if names:
            distinct = _track_scan(self._reads, _svc_key(ctx), names, self._now(),
                                   self.read_window, self.read_scan_targets)
            if distinct:
                hits.append(self._hit(f"dns_qname_enumeration distinct={distinct}",
                                      "DNS-READ-SCAN", actionable=True))
        return hits
