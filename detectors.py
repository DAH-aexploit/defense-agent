"""검사기 플러그인 — 엔진과 분리된 탐지 로직 모듈

핵심: 프로토콜·공격별 `Detector` 추가를 통한 엔진 순회
웹 시그니처는 여러 검사기 중 하나(SignatureDetector)로 한정
당일 pcap 기반 신규 Detector 추가와 특정 프로토콜 종속 배제

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
    raw: bytes = field(repr=False)


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
        if current_tail is None or end > new_from:
            frames.append(MavFrame(version, seq, sysid, compid, msgid,
                                   signed, link_id, sig_ts, raw))
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
                 repeat_window: float = 2.0, repeat_limit: int = 4, now=None) -> None:
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        self.ports = {int(p) for p in (ports or [])}
        self.weight, self.require_signed = float(weight), bool(require_signed)
        self.freshness_10us = int(freshness_10us)
        self.state_ttl, self.max_keys = float(state_ttl), max(32, int(max_keys))
        self.id_window, self.max_ids = float(id_window), int(max_ids)
        self.repeat_window, self.repeat_limit = float(repeat_window), int(repeat_limit)
        self._now = now or time.monotonic
        self._seq = BoundedState(self.max_keys, self.state_ttl, self._now)
        self._sig_ts = BoundedState(self.max_keys, self.state_ttl, self._now)
        self._max_ts = BoundedState(self.max_keys, self.state_ttl, self._now)
        self._ids = BoundedState(self.max_keys, self.state_ttl, self._now)
        self._repeat = BoundedState(self.max_keys, self.state_ttl, self._now)

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
        }.get(family, "MAV-OBS")
        enabled = self.mode == "enforce" and actionable
        return Evidence(
            self.weight if enabled else 0.0, reason, f"mavlink:{family}", rule_id,
            EvidenceClass.CONTEXT_REQUIRED if enabled else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.PROFILE_BOUND,
            bool(self.ports), enabled, True)

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
    raw: bytes = field(default=b"", repr=False)


def crc16_ccitt(data: bytes, initial: int = 0xFFFF) -> int:
    crc = initial
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def parse_ccsds_packet(data: bytes) -> CcsdsPacket | None:
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
    if packet_end < 7 or len(data) not in (packet_end, packet_end + 2):
        return None
    has_fecf = len(data) == packet_end + 2
    valid = None
    if has_fecf:
        valid = crc16_ccitt(data[:packet_end]) == int.from_bytes(data[packet_end:], "big")
    return CcsdsPacket((first >> 12) & 1, bool((first >> 11) & 1), first & 0x7FF,
                       (sequence >> 14) & 3, sequence & 0x3FFF, data[6:packet_end],
                       has_fecf, valid, data)


class CcsdsDetector(Detector):
    """CCSDS 구조·순서 관찰기, 기본 observe와 SDLS 인증 추측 배제"""

    name = "ccsds"

    def __init__(self, mode="observe", ports=None, weight=1.0, max_keys=4096,
                 state_ttl=120.0, confirmations=2, confirm_window=3.0, now=None) -> None:
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        self.ports = {int(p) for p in (ports or [])}
        self.weight, self.max_keys, self.state_ttl = float(weight), max(32, int(max_keys)), float(state_ttl)
        self._now = now or time.monotonic
        self._seq = BoundedState(self.max_keys, self.state_ttl, self._now)
        self._debounce = EvidenceDebouncer(confirmations, confirm_window, self.max_keys)

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    def _hit(self, reason, actionable=True):
        family = reason.split(" ", 1)[0]
        rule_id = ("CCSDS-FECF-01" if family == "ccsds_fecf_invalid" else
                   "CCSDS-02" if family.startswith("ccsds_sequence_") else "CCSDS-OBS")
        enabled = self.mode == "enforce" and actionable
        return Evidence(
            self.weight if enabled else 0.0, reason, f"ccsds:{family}", rule_id,
            EvidenceClass.CONTEXT_REQUIRED if enabled else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.PROFILE_BOUND,
            bool(self.ports), enabled, True)

    def inspect(self, ctx):
        if self.mode == "off" or (self.ports and ctx.dport not in self.ports):
            return []
        packet = parse_ccsds_packet(ctx.segment_payload or ctx.payload)
        if packet is None:
            return []
        now, hits = self._now(), []
        flow = ctx.flow or (ctx.proto, ctx.dport)
        key = (flow, packet.apid, packet.packet_type)
        old = self._seq.get(key, None, now)
        if old is not None:
            delta = (packet.sequence_count - old) & 0x3FFF
            if delta == 0:
                confirmed = self._debounce.confirmed((key, "duplicate"), now)
                hits.append(self._hit(f"ccsds_sequence_duplicate apid={packet.apid}", confirmed))
            elif delta > 0x2000:
                confirmed = self._debounce.confirmed((key, "regression"), now)
                hits.append(self._hit(
                    f"ccsds_sequence_regression last={old} current={packet.sequence_count}", confirmed))
        self._seq.put(key, packet.sequence_count, now)
        if packet.has_fecf and packet.fecf_valid is False:
            hits.append(self._hit(f"ccsds_fecf_invalid apid={packet.apid}"))
        return hits


# ── RTPS/DDS 관찰기 ─────────────────────────────────────────────────────────
@dataclass(frozen=True)
class RtpsMessage:
    version: tuple[int, int]
    vendor: bytes
    guid_prefix: bytes
    submessages: tuple[tuple[int, int], ...]
    malformed: bool = False


def parse_rtps_message(data: bytes) -> RtpsMessage | None:
    if len(data) < 20 or data[:4] != b"RTPS":
        return None
    off, submessages, malformed = 20, [], False
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
        off = body_end
    return RtpsMessage((data[4], data[5]), data[6:8], data[8:20],
                       tuple(submessages), malformed)


class RtpsDetector(Detector):
    """RTPS 구조·participant 변화 관찰기, type 정보 부재 시 topic 의미 추측 배제"""

    name = "rtps"

    def __init__(self, mode="observe", ports=None, weight=1.0, guid_window=10.0,
                 max_guids=32, max_keys=4096, now=None) -> None:
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        self.ports = {int(p) for p in (ports or [])}
        self.weight, self.guid_window = float(weight), float(guid_window)
        self.max_guids, self.max_keys = int(max_guids), max(32, int(max_keys))
        self._now = now or time.monotonic
        ttl = max(self.guid_window * 2, 1.0)
        self._guids = BoundedState(self.max_keys, ttl, self._now)
        self._profile = BoundedState(self.max_keys, ttl, self._now)

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    def _hit(self, reason, actionable=True):
        family = reason.split(" ", 1)[0]
        rule_id = {
            "rtps_submessage_malformed": "RTPS-02",
            "rtps_profile_changed": "RTPS-PROFILE-01",
            "rtps_guid_churn": "RTPS-DISCOVERY-OBS-01",
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
        return hits
