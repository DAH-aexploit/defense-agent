#!/usr/bin/env python3
"""공격 성공 → 방어 커버리지 자동 검증 (오프라인 · verdict 무영향 · 결정론적).

우리 공격 에이전트가 확정 성공시킨 기법을, 실제 wire framing 기준으로 우리 방어
엔진이 차단하는지 검증한다. 개별 공격 후 시그니처를 붙이는 흐름을, "성공한 공격은
반드시 방어된다"는 회귀로 자동화한다.

- 확정 성공 기준: attacker 로그의 `[intel:submit] status=accepted, correct=true` +
  `CAPTURE ... status=accepted` + `[intel:recipe]` 가 모두 있는 (victim, port) 기법.
  timeout/warn/시도/LLM 추측은 성공으로 세지 않는다.
- 우리 성공 요청 자체(team9→상대)는 team9 인바운드 PCAP에 없다. 대신 **같은 기법이
  타팀→team9 인바운드로 실제 캡처된 framing**을 추출해 sanitize 후 재생한다.
  이는 synthetic 수기 생성이 아니라 실제 wire framing이다(actual_sanitized).
- 실제 flag/token/key는 절대 출력하지 않는다. path는 sensitive 값이면 synthetic으로 치환.
- verdict 경로 외부 조회·LLM 없음.

coverage:
  covered  : 실제 framing fixture가 load_engine()에서 DROP
  partial  : 실제 framing을 못 구하고 synthetic 유사 요청만 DROP
  missing  : 실제 framing fixture가 ACCEPT
  unknown  : 요청 복원 불가
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import struct
import sys
from pathlib import Path

# 재생 엔진이 배포 이미지(Dockerfile) 포트 프로파일을 반영하도록 한다. MQTT는 코드 기본 포트가
# 없어(_env_ports 기본 []) env 미설정 시 1883에서 비활성 → 실제 배포와 달리 coverage가 잘못 missing이
# 된다. 배포 Dockerfile의 DEF_MQTT_PORTS와 동일하게 맞춘다(이미 설정돼 있으면 존중).
os.environ.setdefault("DEF_MQTT_PORTS", "8082,1883")
# 배포 Dockerfile과 동일한 root-global wildcard 정책으로 replay한다. 이 값이
# 빠지면 실제 이미지에서는 DROP하는 SUBSCRIBE #를 로컬 gate가 observe/ACCEPT로
# 판정해 deployment parity가 깨진다.
os.environ.setdefault("DEF_MQTT_BROAD_ENFORCE", "1")

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from defender import VERDICT_DROP, load_engine  # noqa: E402
from detectors import MqttDetector as _MqttDet  # noqa: E402
from tools.pcap_analyze import read_pcap  # noqa: E402

_SUBMIT_RE = re.compile(r"\[intel:submit\][^\n]*?body=(\{[^\n]*\})")
_CAPTURE_RE = re.compile(r"CAPTURE victim=(\S+) port=(\d+)[^\n]*status=accepted")
_RECIPE_RE = re.compile(
    r"\[intel:recipe\] host=(\S+) port=(\d+) layer=(\S+) proto=(\S+)"
    r" transport=(\S+) technique=(\S+) method=(\S+) path=(\S+)")


def _read_text(path: Path) -> str:
    if str(path).endswith(".gz"):
        with gzip.open(path, "rt", errors="replace") as f:
            return f.read()
    return path.read_text(errors="replace")


def collect_successes(attacker_log: Path) -> list[dict]:
    """확정 성공(victim, port, proto, method) 목록. 결정론적으로 정렬해 반환."""
    text = _read_text(attacker_log)
    has_accepted = False
    for m in _SUBMIT_RE.finditer(text):
        try:
            body = json.loads(m.group(1))
        except ValueError:
            continue
        if (body.get("status") == "accepted" and body.get("correct") is True
                and body.get("captured", {}).get("flag_env")):
            has_accepted = True
            break
    if not has_accepted:
        return []
    recipes = {}
    for m in _RECIPE_RE.finditer(text):
        recipes[(m.group(1), int(m.group(2)))] = {
            "layer": m.group(3), "proto": m.group(4), "transport": m.group(5),
            "technique": m.group(6), "method": m.group(7), "path": m.group(8)}
    flags: dict = {}                                    # (victim,port) → accepted capture(=flag) 수
    for m in _CAPTURE_RE.finditer(text):
        key = (m.group(1), int(m.group(2)))
        flags[key] = flags.get(key, 0) + 1
    out = {}
    for key, cnt in flags.items():
        rec = recipes.get(key)
        if rec:
            out[key] = {"victim": key[0], "port": key[1], "flags": cnt, **rec}
    return [out[k] for k in sorted(out)]


def _tcp_streams(pcap_paths: list[Path], dport: int) -> dict:
    """dport로 가는 c2s 스트림을 flow별 seq정렬 재조립. 결정론적."""
    streams: dict = {}
    for pf in pcap_paths:
        for _ts, ip in read_pcap(str(pf)):
            if (ip[0] >> 4) != 4 or ip[9] != 6:
                continue
            ihl = (ip[0] & 0xF) * 4
            tcp = ip[ihl:]
            if len(tcp) < 20:
                continue
            sp, dp, seq = struct.unpack_from(">HHI", tcp, 0)
            if dp != dport:
                continue
            payload = tcp[(tcp[12] >> 4) * 4:]
            if not payload:
                continue
            key = (bytes(ip[12:16]), sp)
            streams.setdefault(key, {}).setdefault(seq, payload)
    return {k: b"".join(v[q] for q in sorted(v)) for k, v in streams.items()}


def extract_grpc_fixture(pcap_paths: list[Path], engine=None) -> dict | None:
    """port 9000 인바운드에서 TailDiagnosticLog 요청 framing(HEADERS marker + DATA protobuf path)을
    추출한다. 완전한 요청(protobuf path 존재)만 fixture로 쓰고, 실제 공격 경로(sensitive) flow를
    우선 선택한다. sensitive path는 synthetic sensitive 값으로 치환(실제 flag값 아님). 결정론적.
    완전 복원 불가(HEADERS-only 등)면 None → unknown."""
    streams = _tcp_streams(pcap_paths, 9000)
    candidates = []
    for key in sorted(streams):
        data = streams[key]
        low = data.lower()
        if b"taildiagnosticlog" not in low and b"satdiag" not in low:
            continue
        m = re.search(rb"\x0a([\x01-\x40])([ -~]{1,64})", data)
        if not m:                                       # DATA/path 없음(HEADERS-only) → 불완전
            continue
        ln = m.group(1)[0]
        path = m.group(2)[:ln]
        if any(mk in path.lower() for mk in (b"satdiag", b".v1.", b"taildiagnosticlog")):
            continue                                    # gRPC 메서드 경로는 제외
        sensitive = (b".." in path or b"flag" in path.lower()
                     or (path.startswith(b"/") and not path.lower().endswith(b".log")))
        synthetic = b"/svc/diag/SENSITIVE"              # synthetic sensitive path(secret 아님)
        sanitized = data[:m.start()] + b"\x0a" + bytes([len(synthetic)]) + synthetic + data[m.end():]
        candidates.append({"framing": sanitized, "flow_fp": key[1],
                           "path_kind": "sensitive" if sensitive else "log",
                           "bytes": len(sanitized)})
    if not candidates:
        return None
    # 실제 공격(sensitive origin) flow를 우선, 없으면 정상-framing에 synthetic path 주입
    candidates.sort(key=lambda c: (c["path_kind"] != "sensitive", c["flow_fp"]))
    if engine is not None:
        # 재구성한 fixture가 실제로 DROP되는 것만 actual로 인정(replacement 위치 오류 등 아티팩트 배제).
        for c in candidates:
            if replay(engine, c["framing"], 9000) == VERDICT_DROP:
                return c
        return None                                     # 정확한 actual fixture 복원 실패 → unknown
    return candidates[0]


def _sanitize_http(req: bytes) -> bytes:
    """host·sessionToken·cookie 값을 synthetic으로 치환(HTTP·chunk framing·query 구조는 유지).
    flag는 응답에 있어 요청 fixture엔 애초에 없다."""
    req = re.sub(rb"(?im)^(host:[ \t]*)[^\r\n]*", rb"\1synthetic.internal:8082", req)
    req = re.sub(rb"(?i)sessiontoken=[^ &\"\r\n]+", b"sessionToken=SYNTH", req)
    req = re.sub(rb"(?im)^(cookie:[ \t]*)[^\r\n]*", rb"\1session=SYNTH", req)
    return req


def extract_graphql_fixture(pcap_paths: list[Path]) -> dict | None:
    """port 8082 인바운드에서 flag 응답과 연결된 POST /graphql 요청(chunked 우회 우선)을 추출.
    host/token은 synthetic 치환, HTTP chunk framing·query 구조는 실제 캡처 그대로. 없으면 None."""
    fwd, rev = {}, {}
    for pf in pcap_paths:
        for _ts, ip in read_pcap(str(pf)):
            if (ip[0] >> 4) != 4 or ip[9] != 6:
                continue
            ihl = (ip[0] & 0xF) * 4
            tcp = ip[ihl:]
            if len(tcp) < 20:
                continue
            sp, dp, seq = struct.unpack_from(">HHI", tcp, 0)
            payload = tcp[(tcp[12] >> 4) * 4:]
            if not payload:
                continue
            if dp == 8082:
                fwd.setdefault((bytes(ip[12:16]), sp), {}).setdefault(seq, payload)
            elif sp == 8082:
                rev.setdefault((bytes(ip[16:20]), dp), {}).setdefault(seq, payload)
    flag_re = re.compile(rb"LAYER\d[_A-Z0-9]*FLAG|FLAG\{|[0-9a-f]{24,}")
    chunked, plain = [], []
    for key in sorted(fwd):
        req = b"".join(fwd[key][q] for q in sorted(fwd[key]))
        if b"/graphql" not in req:
            continue
        resp = b"".join(rev.get(key, {}).get(q, b"") for q in sorted(rev.get(key, {})))
        if not flag_re.search(resp):
            continue
        fixture = _sanitize_http(req)
        (chunked if re.search(rb"(?i)transfer-encoding:[^\r\n]*chunked", req) else plain).append(fixture)
    pick = chunked or plain
    if not pick:
        return None
    return {"framing": pick[0], "bytes": len(pick[0]), "chunked": bool(chunked)}


_FLAG_RESP = re.compile(rb"LAYER\d[_A-Z0-9]*FLAG|FLAG\{|flag-[0-9a-f]{8}|[0-9a-f]{32}")


def _reassemble(segs: list) -> bytes:
    if not segs:
        return b""
    base = min(s for s, _ in segs)
    buf: dict = {}
    for s, p in segs:
        buf.setdefault((s - base) & 0xFFFFFFFF, p)     # overlap=first-seen
    return b"".join(buf[o] for o in sorted(buf))


def _graphql_flows(pcap_paths: list[Path]) -> list[dict]:
    """8082 c2s 요청과 s2c 응답을 flow별 재조립. flag 응답과 연결된 /graphql flow만 반환한다.
    각 flow에 세그먼트 수·재정렬 여부(재조립 회피 신호)를 함께 기록한다. 결정론적."""
    fwd, rev = {}, {}
    for pf in pcap_paths:
        for _ts, ip in read_pcap(str(pf)):
            if (ip[0] >> 4) != 4 or ip[9] != 6:
                continue
            ihl = (ip[0] & 0xF) * 4
            tcp = ip[ihl:]
            if len(tcp) < 20:
                continue
            sp, dp, seq = struct.unpack_from(">HHI", tcp, 0)
            payload = tcp[(tcp[12] >> 4) * 4:]
            if not payload:
                continue
            if dp == 8082:
                fwd.setdefault((bytes(ip[12:16]), sp), []).append((seq, payload))
            elif sp == 8082:
                rev.setdefault((bytes(ip[16:20]), dp), []).append((seq, payload))
    flows = []
    for key in sorted(fwd):
        segs = fwd[key]
        req = _reassemble(segs)
        if b"/graphql" not in req:
            continue
        if not _FLAG_RESP.search(_reassemble(rev.get(key, []))):
            continue                                    # flag 응답과 연결된 flow만
        seqs = [s for s, _ in segs]
        reordered = any(seqs[i] > seqs[i + 1] for i in range(len(seqs) - 1))
        flows.append({"req": req, "seg_count": len(segs), "reordered": reordered})
    return flows


def _graphql_cluster(flow: dict) -> tuple:
    """flow의 구조 특성 cluster 키(대표 fixture 하나로 전체를 판정하지 않기 위한 축)."""
    req = flow["req"]
    sep = req.find(b"\r\n\r\n")
    hdr = req[:sep] if sep >= 0 else req
    body = req[sep + 4:] if sep >= 0 else b""
    framing = ("chunked" if re.search(rb"(?i)transfer-encoding:[^\r\n]*chunked", hdr)
               else "content-length" if re.search(rb"(?i)^content-length:", hdr) else "none")
    bstrip = body.lstrip(b" \t\r\n\x00")
    batch = bstrip[:1] == b"["
    mq = re.search(rb'"(?:qu\\u0065ry|\\u0071uery|query)"[ \t]*:[ \t]*(.)', body)
    qtype = ("array" if (mq and mq.group(1) == b"[")
             else "string" if (mq and mq.group(1) == b'"')
             else "batch" if batch else "unknown")
    escaped_key = bool(re.search(rb'"[^"\r\n]*\\u[0-9a-fA-F]{4}[^"\r\n]*"[ \t]*:', body[:1024]))
    escaped = b"\\u" in body[:2048]
    # pipelined 여러 transaction(첫 요청 라인 이후 또 다른 요청 라인)
    txn = "multi" if len(re.findall(rb"(?im)^(?:POST|GET|PUT|PATCH|DELETE)[ \t]+\S+[ \t]+HTTP/1\.", req)) > 1 else "single"
    seg = flow["seg_count"]
    segbucket = "seg1" if seg == 1 else "seg2-3" if seg <= 3 else "seg4-15" if seg <= 15 else "seg16+"
    return (framing, qtype, "esc_key" if escaped_key else ("esc" if escaped else "noesc"),
            "reorder" if flow["reordered"] else "inorder", segbucket, txn)


def replay_ev(engine, framing: bytes, dport: int) -> tuple:
    """fixture를 고유 flow로 재생하고 (verdict, rule_ids)를 반환. rule_ids는 실제 verdict
    evidence에서 수집한다(예상값 하드코딩 금지)."""
    _SPORT[0] += 1
    v, info = engine.verdict(_packet(dport, framing, sport=_SPORT[0], seq=1))
    rids = sorted({e.get("rule_id") for e in info.get("evidence", [])
                   if e.get("rule_id") and (e.get("weight", 0) or 0) > 0})
    return v, rids


def _paired_normal_graphql(chunked: bool) -> bytes:
    """같은 전송방식의 정상 systemStatus 대조 fixture(민감 resolver 없음 → ACCEPT 기대)."""
    body = b'{"query":"{ systemStatus { service version } }"}'
    head = (b"POST /graphql HTTP/1.1\r\nHost: synthetic.internal:8082\r\n"
            b"Content-Type: application/json\r\n")
    if not chunked:
        return head + b"\r\n" + body
    parts = b""
    for i in range(0, len(body), 3):
        c = body[i:i + 3]
        parts += ("%x\r\n" % len(c)).encode() + c + b"\r\n"
    return head + b"Transfer-Encoding: chunked\r\n\r\n" + parts + b"0\r\n\r\n"


def _packet(dport: int, payload: bytes, sport: int = 40001, seq: int = 1) -> bytes:
    ip = bytearray(20)
    ip[0] = 0x45
    total = 20 + 20 + len(payload)
    ip[2:4] = total.to_bytes(2, "big")
    ip[9] = 6
    ip[12:16] = bytes([10, 9, 30, 4])
    ip[16:20] = bytes([10, 9, 0, 4])
    tcp = bytearray(20)
    tcp[0:2] = sport.to_bytes(2, "big")
    tcp[2:4] = dport.to_bytes(2, "big")
    tcp[4:8] = seq.to_bytes(4, "big")
    tcp[12] = 5 << 4
    tcp[13] = 0x18
    return bytes(ip) + bytes(tcp) + payload


def _mqtt_vbi(data: bytes, off: int):
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
    return None


def _mqtt_subscribe_frames(data: bytes, max_frames: int = 64) -> list:
    """스트림에서 SUBSCRIBE(0x8x) 프레임 원본 바이트와 topic filter 목록을 추출(bounded)."""
    out, i, n, count = [], 0, len(data), 0
    while i + 2 <= n and count < max_frames:
        if (data[i] >> 4) != 8:                        # SUBSCRIBE만
            # 다른 프레임은 VBI로 건너뛴다(정상 스트림: CONNECT→SUBSCRIBE)
            parsed = _mqtt_vbi(data, i + 1)
            if parsed is None:
                break
            rem, body_off = parsed
            if body_off + rem > n:
                break
            i = body_off + rem
            count += 1
            continue
        parsed = _mqtt_vbi(data, i + 1)
        if parsed is None:
            break
        rem, body_off = parsed
        end = body_off + rem
        if end > n:
            break
        frame = data[i:end]
        body = data[body_off:end]
        topics, k = [], 2                              # packet identifier(2) 건너뜀
        while k + 2 <= len(body) and len(topics) < 64:
            ln = int.from_bytes(body[k:k + 2], "big")
            k += 2
            if k + ln > len(body):
                break
            topics.append(bytes(body[k:k + ln]))
            k += ln + 1                                # SUBSCRIBE QoS 1byte
        out.append((frame, topics))
        i = end
        count += 1
    return out


def _mqtt_topic_class(topic: bytes) -> str:
    """topic filter 구조 분류(cluster 축). broad-global은 detector와 동일 기준(_broad_wildcard) 사용."""
    if _MqttDet._broad_wildcard(topic):
        t = topic.decode("latin-1", "ignore")
        if t.startswith("$share/"):
            return "shared_global"
        return "exact_hash" if t == "#" else "root_broad"
    t = topic.decode("latin-1", "ignore")
    if "#" in t or "+" in t:
        return "scoped_wildcard"
    return "exact_normal"


def _mqtt_flows(l3_pcaps: list[Path]) -> list[dict]:
    """port 1883 c2s 재조립 후 SUBSCRIBE 프레임을 fixture로 추출. actual wire framing(고정헤더·VBI·
    packet id·topic length·QoS) 유지. SUBSCRIBE 프레임엔 secret이 없다(client id/pw는 CONNECT). 결정론적."""
    streams = _tcp_streams(l3_pcaps, 1883)
    flows = []
    for key in sorted(streams):
        data = streams[key]
        for frame, topics in _mqtt_subscribe_frames(data):
            if not topics:
                continue
            classes = sorted({_mqtt_topic_class(t) for t in topics})
            flows.append({"frame": frame, "topics": topics, "classes": classes,
                          "multi": len(topics) > 1})
    return flows


def _paired_normal_mqtt() -> bytes:
    """정상 exact-topic SUBSCRIBE 대조 fixture(민감 broad 아님 → ACCEPT 기대). synthetic control."""
    topic = b"uav/node/config"
    payload = b"\x00\x01" + len(topic).to_bytes(2, "big") + topic + b"\x00"
    return bytes([0x82, len(payload)]) + payload


_SPORT = [41000]


def replay(engine, framing: bytes, dport: int) -> int:
    """fixture를 독립 flow(고유 sport)로 재생 — 이전 재생과 재조립 오염을 막는다. 결정론적(호출 순서 고정)."""
    _SPORT[0] += 1
    return engine.verdict(_packet(dport, framing, sport=_SPORT[0], seq=1))[0]


_GRAPHQL_RULE = "MCS-GRAPHQL-MISSIONAUDIT"
_FOREIGN_RULE_RE = re.compile(r"HTTP-SSRF|RSC|GATEWAY|TEMPLATE|SAT-GRPC")


def _graphql_isolate(req: bytes):
    """flow에서 /graphql transaction 하나만 격리해 (isolated_bytes, sensitive) 반환한다.
    앞·뒤의 SSRF/RSC 등 다른 transaction을 제거해 rule_id 오염을 막고, query가 민감 resolver를
    선택하는지(=실제 GraphQL 공격)를 detector 파서로 판정한다. /graphql 없으면 None."""
    from rehearsal_web_detectors import GraphqlGuardDetector as _G
    det = _G(ports=[8082], mode="enforce")
    raw = req.decode("latin-1")
    for m in det._req_re.finditer(raw):
        try:
            url = __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(m.group(1))
        except ValueError:
            continue
        if url.path.lower() != "/graphql":
            continue
        hdr_end = raw.find("\r\n\r\n", m.start())
        if hdr_end == -1:
            continue
        body = det._transaction_body(raw, m.start())
        if body is None:
            continue
        sensitive = any(det._field_re.search(q[:8192]) for q in det._graphql_queries(body))
        headers = raw[m.start():hdr_end]
        # chunked면 dechunk된 body로 재구성하며 TE 헤더 제거(재생 시 raw_decode가 JSON을 파싱).
        if re.search(r"(?im)^transfer-encoding:[^\r\n]*chunked", headers):
            # headers slice는 마지막 header의 종단 CRLF 직전에서 끝날 수 있다. TE가 마지막
            # 줄이면 `$`도 허용해야 dechunk된 body를 다시 chunked로 오해하지 않는다.
            headers = re.sub(r"(?im)^transfer-encoding:[^\r\n]*(?:\r\n|$)", "", headers)
        txn = (headers + "\r\n\r\n" + body[:262144]).encode("latin-1")
        return _sanitize_http(txn), sensitive
    return None


def _assess_graphql(l2_pcaps: list[Path], engine) -> dict:
    """GraphQL 기법을 변형 cluster 전면 검증한다 — 대표 fixture 하나로 covered 판정하지 않는다.
    flag-returning /graphql flow에서 **/graphql transaction만 격리**해 다른 기법(SSRF/RSC) flow 오염을
    제거하고, query가 민감 resolver를 선택하는 flow만 GraphQL candidate로 삼는다. cluster별 실제 framing
    재생: 하나라도 ACCEPT면 missing, paired-normal DROP·이질 rule_id(SSRF/RSC 등)면 false_positive."""
    flows = _graphql_flows(l2_pcaps)
    candidates, ignored_other = [], 0
    for f in flows:
        iso = _graphql_isolate(f["req"])
        if iso is None or not iso[1]:                       # /graphql 없음 또는 민감 resolver 아님
            ignored_other += 1
            continue
        g = dict(f)
        g["req"], g["_iso"] = iso[0], iso[0]
        candidates.append(g)
    if not candidates:
        return {"fixture_kind": "unknown", "coverage": "unknown", "rule_ids": [],
                "flag_flows": len(flows), "matched_candidates": 0,
                "ignored_other_technique": ignored_other, "classified_clusters": 0}
    clusters: dict = {}
    for f in candidates:
        try:
            ck = _graphql_cluster(f)
        except Exception:                                   # noqa: BLE001
            ck = ("unclassified",)
        clusters.setdefault(ck, []).append(f)
    classified = sum(len(v) for k, v in clusters.items() if k != ("unclassified",))
    rule_ids, foreign, detail = set(), set(), []
    covered = missing = unsupported = fp = 0
    for ck, cands in sorted(clusters.items(), key=lambda kv: str(kv[0])):
        chunked = ck[0] == "chunked"
        verdicts, cl_rules = [], set()
        for c in cands[:4]:                                 # cluster당 대표 최대 4개 재생(격리된 framing)
            v, r = replay_ev(load_engine(), c["_iso"], 8082)
            verdicts.append(v)
            cl_rules |= set(r)
        rule_ids |= cl_rules
        foreign |= {r for r in cl_rules if _FOREIGN_RULE_RE.search(r)}
        pn_v, _ = replay_ev(load_engine(), _paired_normal_graphql(chunked), 8082)
        all_drop = bool(verdicts) and all(v == VERDICT_DROP for v in verdicts)
        if pn_v == VERDICT_DROP:
            status = "false_positive"; fp += 1
        elif all_drop:
            status = "covered"; covered += 1
        elif ck == ("unclassified",):
            status = "unsupported_variant"; unsupported += 1
        else:
            status = "missing"; missing += 1
        detail.append({"cluster": "|".join(map(str, ck)), "flows": len(cands),
                       "attack_verdict": "DROP" if all_drop else "ACCEPT",
                       "paired_normal": "DROP" if pn_v == VERDICT_DROP else "ACCEPT",
                       "status": status})
    if fp or foreign:                                       # 이질 rule_id 섞이면 오염 → 검증 실패
        coverage = "false_positive"
    elif missing or unsupported or classified != len(candidates):
        coverage = "missing"
    elif covered == len(clusters) and covered > 0:
        coverage = "covered"
    else:
        coverage = "partial"
    return {"fixture_kind": "actual_sanitized", "coverage": coverage,
            "rule_ids": sorted(rule_ids), "foreign_rule_ids": sorted(foreign),
            "flag_flows": len(flows), "matched_candidates": len(candidates),
            "ignored_other_technique": ignored_other, "classified_clusters": len(clusters),
            "covered_clusters": covered, "missing_clusters": missing,
            "unsupported_clusters": unsupported, "false_positive_clusters": fp,
            "cluster_detail": detail}


def _assess_mqtt(l3_pcaps: list[Path], engine) -> dict:
    """MQTT 기법을 실제 SUBSCRIBE framing으로 검증한다. broad-global wildcard(#·+/#·+/+/#·$share/g/#)는
    DROP(MQTT-BROAD-SUBSCRIBE), scoped/exact-normal은 ACCEPT여야 한다(정상 오탐 금지). paired-normal
    exact topic도 함께 ACCEPT 확인. rule_ids는 실제 verdict evidence에서 수집."""
    flows = _mqtt_flows(l3_pcaps)
    if not flows:
        return {"fixture_kind": "unknown", "coverage": "unknown", "rule_ids": [],
                "candidates": 0, "classified_clusters": 0}
    broad = {"exact_hash", "root_broad", "shared_global"}
    clusters: dict = {}
    for f in flows:
        clusters.setdefault((tuple(f["classes"]), f["multi"]), []).append(f)
    rule_ids, detail = set(), []
    covered = missing = fp = 0
    for ck, cands in sorted(clusters.items(), key=lambda kv: str(kv[0])):
        is_broad = bool(set(ck[0]) & broad)
        verdicts = []
        for c in cands[:4]:
            v, r = replay_ev(load_engine(), c["frame"], 1883)
            verdicts.append(v)
            rule_ids |= set(r)
        all_drop = bool(verdicts) and all(v == VERDICT_DROP for v in verdicts)
        if is_broad:
            status = "covered" if all_drop else "missing"
            covered += all_drop
            missing += (not all_drop)
        else:                                               # scoped/exact-normal: DROP이면 오탐
            status = "false_positive" if all_drop else "covered"
            fp += all_drop
            covered += (not all_drop)
        detail.append({"cluster": "|".join(ck[0]) + ("|multi" if ck[1] else ""),
                       "flows": len(cands), "broad": is_broad,
                       "attack_verdict": "DROP" if all_drop else "ACCEPT", "status": status})
    pn_v, _ = replay_ev(load_engine(), _paired_normal_mqtt(), 1883)
    if pn_v == VERDICT_DROP:
        fp += 1
        detail.append({"cluster": "paired_normal_exact_topic", "flows": 1, "broad": False,
                       "attack_verdict": "DROP", "status": "false_positive"})
    coverage = ("false_positive" if fp else "missing" if missing
                else "covered" if covered else "partial")
    return {"fixture_kind": "actual_sanitized", "coverage": coverage,
            "rule_ids": sorted(rule_ids), "candidates": len(flows),
            "classified_clusters": len(clusters), "covered_clusters": covered,
            "missing_clusters": missing, "false_positive_clusters": fp,
            "paired_normal": "DROP" if pn_v == VERDICT_DROP else "ACCEPT",
            "cluster_detail": detail}


def assess_round(round_dir: Path, round_name: str) -> list[dict]:
    atk = next(round_dir.glob(f"{round_name}-attacker.log.gz"), None)
    if atk is None:
        return []
    successes = collect_successes(atk)
    grpc_pcaps = sorted(round_dir.glob(f"{round_name}-l1-*.pcap.gz"))
    engine = load_engine()
    # 기법 = (proto, method, port). 같은 기법의 여러 victim/flag를 합산한다(대표 하나로 잃지 않음).
    techs: dict = {}
    for s in successes:
        tk = (s["proto"], s["method"], s["port"])
        info = techs.setdefault(tk, {"victims": set(), "flags": 0, "sample": s})
        info["victims"].add(s["victim"])
        info["flags"] += s.get("flags", 1)
    results = []
    for tk, info in sorted(techs.items()):
        s = info["sample"]
        entry = {"round": round_name, "proto": s["proto"], "method": s["method"],
                 "port": s["port"], "technique": s["technique"],
                 "victims": sorted(info["victims"]), "success_victim_count": len(info["victims"]),
                 "flag_count": info["flags"]}
        if s["proto"] == "grpc" and s["port"] == 9000:
            fx = extract_grpc_fixture(grpc_pcaps, engine)
            if fx is None:
                entry.update(fixture_kind="unknown", coverage="unknown", rule_ids=[])
            else:
                v, rids = replay_ev(load_engine(), fx["framing"], 9000)
                entry.update(
                    fixture_kind="actual_sanitized", verdict="DROP" if v == VERDICT_DROP else "ACCEPT",
                    coverage="covered" if v == VERDICT_DROP else "missing",
                    fixture_bytes=fx["bytes"], path_kind=fx["path_kind"], rule_ids=rids)
        elif s["proto"] in ("mcs", "http") and s.get("path", "").lower() == "/graphql":
            entry.update(_assess_graphql(
                sorted(round_dir.glob(f"{round_name}-l2-*.pcap.gz")), engine))
        elif s["proto"] == "mqtt":
            entry.update(_assess_mqtt(
                sorted(round_dir.glob(f"{round_name}-l3-*.pcap.gz")), engine))
        else:
            entry.update(fixture_kind="none", coverage="unknown", rule_ids=[])
        results.append(entry)
    return results


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="공격 성공 → 방어 커버리지 검증")
    ap.add_argument("source", help="라운드 자료 디렉터리")
    ap.add_argument("--round", action="append", help="검사할 라운드(반복 가능). 생략 시 자동 발견")
    ap.add_argument("--gate", action="store_true", help="actual 성공 fixture ACCEPT/paired-normal DROP면 실패")
    ap.add_argument("--strict", action="store_true", help="지원 기법인데 actual fixture 복원 실패(unknown)도 실패")
    args = ap.parse_args(argv)
    src = Path(args.source)
    rounds = args.round or sorted({p.name.split("-attacker")[0]
                                   for p in src.glob("*-attacker.log.gz")})
    all_results = []
    for rn in rounds:
        all_results.extend(assess_round(src, rn))
    print(json.dumps(all_results, ensure_ascii=False, indent=1))
    # --gate 실패: missing/false_positive/unsupported_variant(→coverage=missing). --strict 추가: partial/unknown.
    hard = [r for r in all_results if r.get("coverage") in ("missing", "false_positive")]
    soft = [r for r in all_results if r.get("coverage") in ("partial", "unknown")]
    covered = sum(1 for r in all_results if r.get("coverage") == "covered")
    victims = sorted({v for r in all_results for v in r.get("victims", [])})  # 전체 고유 victim
    flag_count = sum(r.get("flag_count", 0) or 0 for r in all_results)        # 성공 flag 수(≠victim 수)
    clusters = sum(r.get("classified_clusters", 0) or 0 for r in all_results)
    covered_cl = sum(r.get("covered_clusters", 0) or 0 for r in all_results)
    missing_cl = sum(r.get("missing_clusters", 0) or 0 for r in all_results)
    unsupported_cl = sum(r.get("unsupported_clusters", 0) or 0 for r in all_results)
    foreign = sorted({x for r in all_results for x in r.get("foreign_rule_ids", [])})
    print(f"# techniques={len(all_results)} success_victims={len(victims)} success_flags={flag_count} "
          f"covered={covered} missing/false_positive={len(hard)} partial/unknown={len(soft)} "
          f"clusters={clusters} covered_clusters={covered_cl} missing_clusters={missing_cl} "
          f"unsupported_clusters={unsupported_cl}", file=sys.stderr)
    for r in all_results:
        vic = ",".join(r.get("victims", []))
        print(f"#   {r['proto']}/{r['port']}/{r['method']}: coverage={r.get('coverage')} "
              f"victims={r.get('success_victim_count')}({vic}) flags={r.get('flag_count')} "
              f"rule_ids={r.get('rule_ids')}", file=sys.stderr)
    if foreign:                                            # GraphQL coverage에 SSRF/RSC 등 이질 rule 혼입 = 오염
        print(f"# WARNING: foreign rule_ids in technique coverage (contamination): {foreign}", file=sys.stderr)
    if args.gate and (hard or foreign or (soft and args.strict)):
        print("COVERAGE GATE FAIL: variant cluster ACCEPTed / paired-normal DROPed / count mismatch / "
              "foreign-rule contamination" + (", or partial/unknown(strict)" if args.strict else ""),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
