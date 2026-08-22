"""라운드 자료 자동 분석 — defender 로그와 PCAP을 한 번에 읽어 방어 실적·우회 경로 산출

대회 자료 파일명 규칙 `<TEAM>-<PHASE>-<ROUND>-{attacker,defender}.log.gz`와
`<TEAM>-<PHASE>-<ROUND>-<layer>-<timestamp>.pcap.gz`를 그대로 사용한다.

서비스 포트는 하드코딩하지 않고 PCAP에서 자동 추론한다. 본선 포트가 리허설과 다르거나
사전에 공개되지 않아도 동일한 절차로 분석하기 위한 설계다.

  python3 tools/round_report.py <자료디렉터리> [--round TEAM9-P4-R3] [--out <경로>]

산출: 기동 이미지 판정, 포트별·룰별 DROP, flag 반환 연결의 재판정, 우회 요청의 분할 여부
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import gzip
import json
import os
import re
import sys
from pathlib import Path

# 오프라인 replay도 배포 Dockerfile의 detector/port profile과 같아야 한다. 그렇지
# 않으면 8080 SSRF·1883 MQTT·9000 gRPC를 로컬에서는 비활성으로 재생해 가짜 우회를
# 만든다. 명시된 호출자 환경은 존중한다.
_DEPLOYMENT_DEFAULTS = {
    "DEF_MQTT_PORTS": "8082,1883",
    "DEF_MQTT_BROAD_ENFORCE": "1",
    "DEF_URL_GUARD_PORTS": "8082,8080,9000",
    "DEF_GRPC_PORTS": "9000",
    "DEF_GATEWAY_TRAVERSAL_PORTS": "8080,8082,8410,8420",
    "DEF_GRAPHQL_PORTS": "8082",
    "DEF_P4_WEB_MODE": "enforce",
    "DEF_OBSERVE_RULE_IDS": "UAV-MQTT-001",
}
for _name, _value in _DEPLOYMENT_DEFAULTS.items():
    os.environ.setdefault(_name, _value)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defender import VERDICT_DROP, VerdictEngine, load_engine   # noqa: E402
from tools.pcap_analyze import read_pcap                        # noqa: E402
from tools.tcp_correlate import (correlate, fingerprint as safe_fingerprint,
                                 parse_tcp, split_http_transactions)           # noqa: E402

FLAG_RE = re.compile(rb"FLAG\{[^}]{0,120}\}")
ROUND_RE = re.compile(r"^(?P<round>.+?)-(?:attacker|defender)\.log\.gz$")
PCAP_RE = re.compile(r"^(?P<round>.+?)-(?P<layer>[a-z0-9]+)-\d+\.pcap\.gz$")
DROP_RE = re.compile(r'"event":"verdict_drop"')
DPORT_RE = re.compile(r'"dport":(\d+)')
RULES_RE = re.compile(r'"rule_ids":\[([^\]]*)\]')
READY_RE = re.compile(r"(?:engine ready|signatures loaded): (\d+) rule\(s\)")
COVERAGE_RE = re.compile(r"rule coverage: total=(\d+) enforced=(\d+) observed=(\d+)")
TROUBLE_RE = re.compile(r"traceback|budget exceeded|fail-open|reconnect", re.IGNORECASE)
# 구버전 에이전트만 남기는 흔적
LEGACY_RE = re.compile(r"DROP port=|signatures loaded:|signature policy")


# ──────────────────────────────────────────────────────────────────────
#  자료 탐색
# ──────────────────────────────────────────────────────────────────────
def discover(source: Path) -> dict[str, dict]:
    """디렉터리에서 라운드별 자료 묶음 수집"""
    rounds: dict[str, dict] = collections.defaultdict(
        lambda: {"defender_log": None, "attacker_log": None, "pcaps": collections.defaultdict(list)})
    for path in sorted(source.iterdir()):
        if not path.is_file():
            continue
        m = ROUND_RE.match(path.name)
        if m:
            key = "defender_log" if "defender" in path.name else "attacker_log"
            rounds[m.group("round")][key] = path
            continue
        m = PCAP_RE.match(path.name)
        if m:
            rounds[m.group("round")]["pcaps"][m.group("layer")].append(path)
    return dict(rounds)


def latest_round(rounds: dict) -> str | None:
    """라운드 번호 기준 최신 키 반환"""
    def order(key: str):
        nums = [int(n) for n in re.findall(r"\d+", key)]
        return (nums, key)
    complete = [k for k, v in rounds.items() if v["defender_log"] or v["pcaps"]]
    return max(complete, key=order) if complete else None


# ──────────────────────────────────────────────────────────────────────
#  defender 로그
# ──────────────────────────────────────────────────────────────────────
def read_text(path: Path) -> str:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", errors="replace") as f:
        return f.read()


def analyze_log(path: Path | None) -> dict:
    """실행 이미지 식별과 실제 DROP 실적 집계"""
    if not path or not path.exists():
        return {"available": False}
    text = read_text(path)
    lines = text.splitlines()
    ready = READY_RE.search(text)
    coverage = COVERAGE_RE.search(text)
    ports: collections.Counter = collections.Counter()
    rules: collections.Counter = collections.Counter()
    drops = 0
    for line in lines:
        if not DROP_RE.search(line):
            continue
        drops += 1
        p = DPORT_RE.search(line)
        if p:
            ports[int(p.group(1))] += 1
        r = RULES_RE.search(line)
        if r and r.group(1):
            for rule in r.group(1).replace('"', "").split(","):
                if rule.strip():
                    rules[rule.strip()] += 1
    rule_count = int(ready.group(1)) if ready else None
    # 세 가지 상태로 구분한다. 근거가 없으면 반영됐다고 단정하지 않는다.
    if coverage:
        image_state = "신규 이미지 반영"
    elif LEGACY_RE.search(text) or (rule_count is not None and "DEFENDER_EVENT" not in text):
        image_state = "구버전 이미지 실행"
    else:
        image_state = "판정 불가 (근거 부족)"
    return {
        "available": True,
        "path": path.name,
        "lines": len(lines),
        "rule_count": rule_count,
        "has_coverage_log": bool(coverage),
        "coverage": {"total": int(coverage.group(1)), "enforced": int(coverage.group(2)),
                     "observed": int(coverage.group(3))} if coverage else None,
        "image_state": image_state,
        "legacy_image": image_state == "구버전 이미지 실행",
        "accept_all": rule_count == 0,
        "drops": drops,
        "ports": dict(ports.most_common()),
        "rules": dict(rules.most_common()),
        "trouble": len([ln for ln in lines if TROUBLE_RE.search(ln)]),
        "first_line": lines[0][:200] if lines else "",
    }


# ──────────────────────────────────────────────────────────────────────
#  우회 샘플 표현 — 텍스트/바이너리 자동 판별
# ──────────────────────────────────────────────────────────────────────
def _printable_ratio(data: bytes) -> float:
    """출력 가능 문자 비율. HTTP 등 텍스트 프로토콜 판별용."""
    if not data:
        return 1.0
    ok = sum(1 for b in data if b in (0x09, 0x0A, 0x0D) or 0x20 <= b < 0x7F)
    return ok / len(data)


# 방산 바이너리 프로토콜 지문 — attack-agent의 판별 방식과 동일한 근거(구조 자체)
#   RTPS: 매직 "RTPS"  ·  MAVLink v2/v1: 0xFD/0xFE 시작
#   Modbus/TCP: MBAP ProtocolId==0 이면서 Length가 나머지 바이트와 일치
#   CCSDS SPP: version 000 이면서 packet length 필드가 전체 길이와 일치
_PROTO_HINTS = (
    ("RTPS", lambda d: d[:4] == b"RTPS"),
    ("MAVLink v2", lambda d: d[:1] == b"\xfd"),
    ("MAVLink v1", lambda d: d[:1] == b"\xfe"),
    ("Modbus/TCP", lambda d: len(d) >= 8 and d[2:4] == b"\x00\x00"
        and int.from_bytes(d[4:6], "big") == len(d) - 6),
    ("CCSDS SPP", lambda d: len(d) >= 7 and (d[0] >> 5) == 0
        and int.from_bytes(d[4:6], "big") == len(d) - 7),
)


def _fingerprint(data: bytes) -> str | None:
    """재조립된 페이로드의 프로토콜 지문을 구조 근거로 추정. 미상이면 None."""
    for name, test in _PROTO_HINTS:
        try:
            if test(data):
                return name
        except (IndexError, ValueError):
            continue
    return None


def _hexdump(data: bytes, limit: int = 48) -> str:
    chunk = data[:limit]
    hexpart = chunk.hex(" ")
    ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
    tail = " …" if len(data) > limit else ""
    return f"{hexpart}  |{ascii_part}|{tail}"


def bypass_sample(data: bytes) -> str:
    """우회 요청 샘플을 텍스트/바이너리에 맞춰 표현한다.

    HTTP 등 텍스트 프로토콜은 요청 첫 줄을, 방산 바이너리 프로토콜(MAVLink/CCSDS/
    Modbus/RTPS)은 프로토콜 지문 + hex dump를 반환한다. 첫 줄을 그대로 latin-1로
    디코드하던 기존 방식은 바이너리에서 깨진 문자만 남아 본선 트래픽 분석에 쓸 수 없었다.
    """
    # 출력 가능한 바이트 비율만으로 text를 고르면 MQTT CONNECT의 username/password나
    # opaque token이 그대로 노출된다. 검증된 HTTP/RTSP request/status line만 text로 표시한다.
    first = data.split(b"\r\n", 1)[0][:180]
    if re.match(rb"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/1\.[01]$", first):
        return data.split(b"\r\n", 1)[0][:180].decode("latin-1", "ignore")
    proto = _fingerprint(data)
    label = proto or "binary"
    # MQTT CONNECT에는 client id/username/password가, h2 DATA에는 token이 들어갈 수
    # 있으므로 보고서에 raw hex/ascii를 싣지 않는다. 구조 지문·길이·digest만 남긴다.
    return f"[{label}] bytes={len(data)} sha256={safe_fingerprint(data)}"


# ──────────────────────────────────────────────────────────────────────
#  PCAP
# ──────────────────────────────────────────────────────────────────────
KNOWN_LAYER_PORTS = {
    "l1": (8080, 9000),
    "l2": (8082,),
    "l3": (1883, 8554, 9090),
    "l4": (8410, 8420),
}


def infer_service_ports(events: list, layer: str) -> list[int]:
    """레이어의 모든 service port 추론.

    공개/실측 포트를 우선하되 양방향 패킷이 실제로 존재할 때만 선택한다. 알려지지
    않은 다음 phase 포트는 다수 inbound와 server response가 모두 있는 경우에만 추가해
    ephemeral client port를 service로 오인하지 않는다.
    """
    inbound: collections.Counter = collections.Counter()
    outbound: collections.Counter = collections.Counter()
    clients: dict[int, set] = collections.defaultdict(set)
    for _ts, ip in events:
        p = parse_tcp(ip)
        if p is None:
            continue
        _ver, _proto, src, sport, _dst, dport, _seq, _flags, _payload = p
        inbound[dport] += 1
        outbound[sport] += 1
        clients[dport].add((src, sport))
    known = [p for p in KNOWN_LAYER_PORTS.get(layer, ()) if inbound[p] and outbound[p]]
    inferred = [p for p, n in inbound.items()
                if p not in known and n >= 100 and outbound[p] >= 10 and len(clients[p]) >= 3
                and p in {8080, 8082, 8410, 8420, 8554, 9000, 9090, 1883}]
    return sorted(set(known + inferred))


def _analyze_service(events: list, port: int, engine_factory) -> dict:
    """단일 service port를 재생하고 TCP generation 단위로 flag 응답을 귀속."""
    engine = engine_factory()
    inbound = dropped = 0
    rules: collections.Counter = collections.Counter()
    observations: collections.Counter = collections.Counter()
    drop_times: dict[tuple, list[float]] = collections.defaultdict(list)

    for ts, ip in events:
        p = parse_tcp(ip)
        if p is None:
            continue
        _ver, _proto, src, sport, dst, dport, _seq, _flags, _payload = p
        if dport != port:
            continue
        verdict, info = engine.verdict(ip)
        inbound += 1
        base5 = (src, sport, dst, dport)
        if verdict == VERDICT_DROP:
            dropped += 1
            drop_times[base5].append(ts)
        for item in info.get("evidence", []):
            rid = item.get("rule_id")
            if not rid:
                continue
            (rules if item.get("drop_eligible") else observations)[rid] += 1

    successes = [c for c in correlate(events, port) if FLAG_RE.search(c.s2c)]
    blocked = bypassed = segmented = reordered = 0
    samples: collections.Counter = collections.Counter()
    for conn in successes:
        base5 = (conn.client[0], conn.client[1], conn.server[0], conn.server[1])
        was_dropped = any(conn.first_ts <= ts <= conn.last_ts + 1.0
                          for ts in drop_times.get(base5, ()))
        if was_dropped:
            blocked += 1
            continue
        bypassed += 1
        if len(conn._c2s) > 1:
            segmented += 1
        seqs = list(conn._c2s)
        if conn._c2s_base is not None and seqs != sorted(
                seqs, key=lambda seq: (seq - conn._c2s_base) & 0xFFFFFFFF):
            reordered += 1
        txns = split_http_transactions(conn.c2s)
        if txns:
            for tx in txns[-3:]:
                suffix = "" if tx["complete"] else " [불완전]"
                samples[f'{tx["method"]} {tx["target"]} HTTP/1.x{suffix}'] += 1
        else:
            samples[bypass_sample(conn.c2s)] += 1

    return {
        "available": True, "service_port": port,
        "inbound_packets": inbound, "replay_drops": dropped,
        "replay_rules": dict(rules.most_common()),
        "observations": dict(observations.most_common()),
        "flag_responses": len(successes), "blocked_connections": blocked,
        "bypassed_connections": bypassed, "bypass_segmented": segmented,
        "bypass_reordered": reordered, "bypass_samples": samples.most_common(8),
    }


def analyze_layer(paths: list[Path], engine_factory, layer: str = "") -> dict:
    """레이어 PCAP 재생 — 모든 service port를 독립 분석."""
    events = []
    for path in paths:
        try:
            events.extend(read_pcap(str(path)))
        except (OSError, ValueError) as e:
            print(f"[skip] {path.name}: {e}", file=sys.stderr)
    if not events:
        return {"available": False}
    events.sort(key=lambda x: x[0])
    ports = infer_service_ports(events, layer)
    if not ports:
        return {"available": False}
    return {"available": True, "files": [p.name for p in paths],
            "services": [_analyze_service(events, p, engine_factory) for p in ports]}


# ──────────────────────────────────────────────────────────────────────
#  보고서
# ──────────────────────────────────────────────────────────────────────
def render(round_key: str, log: dict, layers: dict) -> str:
    out = [f"# {round_key} 라운드 분석", "",
           f"- 생성: {dt.datetime.now().astimezone().isoformat(timespec='seconds')}", ""]

    out += ["## 1. 실행 이미지 판정", ""]
    if not log.get("available"):
        out += ["- defender 로그 미확보, 실행 이미지 판정 불가", ""]
    else:
        out += [f"- 적재 룰 수: {log['rule_count'] if log['rule_count'] is not None else '미확인'}",
                f"- `rule coverage` 출력: {'있음' if log['has_coverage_log'] else '없음'}"]
        if log.get("coverage"):
            c = log["coverage"]
            out.append(f"- 룰 커버리지: total={c['total']} enforced={c['enforced']} observed={c['observed']}")
        out.append(f"- 판정: **{log['image_state']}**")
        if log.get("accept_all"):
            out.append("- **경고: 적재 룰 0개. 실질 ACCEPT-all 상태다. "
                       "`PORT_BINDINGS` 확인이 최우선이다.**")
        out.append(f"- 로그 {log['lines']}줄 · 구조화 DROP {log['drops']}건 · 이상 로그 {log['trouble']}건")
        out.append("")
        if log["ports"]:
            out += ["| 포트 | 실측 DROP |", "|---|---:|"]
            out += [f"| {p} | {n:,} |" for p, n in log["ports"].items()]
            out.append("")
        if log["rules"]:
            out += ["| 룰 ID | 실측 적중 |", "|---|---:|"]
            out += [f"| `{r}` | {n:,} |" for r, n in log["rules"].items()]
            out.append("")

    out += ["## 2. 레이어별 PCAP 재생", ""]
    if not layers:
        out += ["- PCAP 미확보", ""]
    out += ["| 레이어 | 포트 | 인바운드 | 재생 DROP | flag 응답 | 차단 | 우회 |",
            "|---|---:|---:|---:|---:|---:|---:|"]
    for name in sorted(layers):
        d = layers[name]
        if not d.get("available"):
            out.append(f"| {name} | - | - | - | - | - | - |")
            continue
        for service in d["services"]:
            out.append(f"| {name} | {service['service_port']} | {service['inbound_packets']:,} | "
                       f"{service['replay_drops']:,} | {service['flag_responses']} | "
                       f"{service['blocked_connections']} | **{service['bypassed_connections']}** |")
    out.append("")

    for name in sorted(layers):
        d = layers[name]
        if not d.get("available"):
            continue
        for service in d["services"]:
            if not service["bypassed_connections"]:
                continue
            out += [f"### {name}/{service['service_port']} 우회 {service['bypassed_connections']}건", "",
                    f"- 세그먼트 분할 {service['bypass_segmented']}건 · "
                    f"순서 뒤섞임 {service['bypass_reordered']}건", ""]
            if service["bypass_reordered"]:
                out += ["> 순서 뒤섞임은 TCP 재조립 회피다. seq 정렬 시 완전한 공격 요청이 복원된다.", ""]
            out += ["```text"]
            out += [f"{n}회  {line}" for line, n in service["bypass_samples"]]
            out += ["```", ""]

    obs_layers = [n for n in sorted(layers) if layers[n].get("available") and any(
        service.get("observations") for service in layers[n]["services"])]
    if obs_layers:
        out += ["## 2-1. 관찰 신호 (차단 안 함 · enforce 전환 판단용)", "",
                "> observe 모드의 관찰 전용 근거다. 점수·차단에 영향은 없지만, 어떤 flow가",
                "> read 열거·쓰기 등으로 탐침 중인지 보여준다. 정상 baseline과 대조해 enforce",
                "> 전환 여부를 판단한다. 단일 조회는 신호를 남기지 않는다(임계 초과 시에만).", "",
                "| 레이어 | 관찰 룰 ID | 관측 |", "|---|---|---:|"]
        for name in obs_layers:
            for service in layers[name]["services"]:
                for rid, n in service["observations"].items():
                    out.append(f"| {name}/{service['service_port']} | `{rid}` | {n:,} |")
        out.append("")

    out += ["## 3. 판단 기준", "",
            "- `rule coverage` 부재와 낮은 적재 룰 수는 구버전 이미지 실행을 의미한다",
            "- flag 응답 수는 PCAP 캡처 지점과 NAT 포트 재사용의 영향을 받으므로 추정치로 읽는다",
            "- 우회 0건과 `Flags stolen` 0은 별개다. 지표는 레이어별 1회 탈취 여부를 센다", ""]
    return "\n".join(out)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="대회 라운드 자료 자동 분석")
    parser.add_argument("source", help="자료 디렉터리")
    parser.add_argument("--round", help="분석할 라운드 키, 생략 시 최신")
    parser.add_argument("--out", help="Markdown 저장 경로")
    parser.add_argument("--json", action="store_true", help="원자료 JSON 출력")
    args = parser.parse_args(argv)

    source = Path(args.source).expanduser()
    if not source.is_dir():
        print(f"자료 디렉터리 없음: {source}", file=sys.stderr)
        return 2
    rounds = discover(source)
    if not rounds:
        print(f"라운드 자료 없음: {source}", file=sys.stderr)
        return 2
    key = args.round or latest_round(rounds)
    if key not in rounds:
        print(f"라운드 키 없음: {key} (확보: {', '.join(sorted(rounds))})", file=sys.stderr)
        return 2

    bundle = rounds[key]
    log = analyze_log(bundle["defender_log"])
    layers = {name: analyze_layer(paths, load_engine, name)
              for name, paths in sorted(bundle["pcaps"].items())}

    report = render(key, log, layers)
    out = Path(args.out) if args.out else ROOT / "qa-results" / "rounds" / f"{key}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")

    if args.json:
        print(json.dumps({"round": key, "log": log, "layers": layers},
                         ensure_ascii=False, indent=2))
    else:
        print(report)
    print(f"\n저장: {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
