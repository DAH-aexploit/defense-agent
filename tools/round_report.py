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
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defender import VERDICT_DROP, VerdictEngine, load_engine   # noqa: E402
from tools.pcap_analyze import read_pcap                        # noqa: E402

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
#  PCAP
# ──────────────────────────────────────────────────────────────────────
def infer_service_port(events: list) -> int | None:
    """서비스 진입 포트 추론 — 요청·응답 양방향에 가장 많이 등장하는 포트

    본선 포트가 사전에 공개되지 않아도 동작하도록 포트 하드코딩을 피한다.
    """
    counter: collections.Counter = collections.Counter()
    for _ts, ip in events:
        parsed = VerdictEngine.parse_l4(ip)
        if not parsed:
            continue
        meta = parsed[3]
        counter[meta[4]] += 1      # sport
        counter[meta[5]] += 1      # dport
    return counter.most_common(1)[0][0] if counter else None


def analyze_layer(paths: list[Path], engine_factory) -> dict:
    """레이어 PCAP 재생 — 인바운드 전수 판정과 flag 반환 연결 역추적"""
    events = []
    for path in paths:
        try:
            events.extend(read_pcap(str(path)))
        except (OSError, ValueError) as e:
            print(f"[skip] {path.name}: {e}", file=sys.stderr)
    if not events:
        return {"available": False}
    events.sort(key=lambda x: x[0])
    port = infer_service_port(events)
    if port is None:
        return {"available": False}

    engine = engine_factory()
    conns: dict = collections.defaultdict(list)
    successes = []
    inbound = dropped = 0
    rules: collections.Counter = collections.Counter()

    for ts, ip in events:
        parsed = VerdictEngine.parse_l4(ip)
        if not parsed:
            continue
        _proto, dport, payload, meta = parsed
        _v, _p, src, dst, sport, dport2 = meta[:6]
        seq = meta[6]
        if dport == port:
            verdict, info = engine.verdict(ip)
            inbound += 1
            if verdict == VERDICT_DROP:
                dropped += 1
                for item in info.get("evidence", []):
                    if item.get("drop_eligible") and item.get("rule_id"):
                        rules[item["rule_id"]] += 1
            if payload:
                conns[(src, sport)].append((ts, seq, payload, verdict))
        elif sport == port and payload and FLAG_RE.search(payload):
            successes.append((ts, (dst, dport2)))

    blocked = bypassed = 0
    segmented = reordered = 0
    samples: collections.Counter = collections.Counter()
    for ts, conn in successes:
        segs = [s for s in conns.get(conn, []) if s[0] <= ts]
        if not segs:
            continue
        if any(s[3] == VERDICT_DROP for s in segs):
            blocked += 1
            continue
        bypassed += 1
        if len(segs) > 1:
            segmented += 1
        arrival = b"".join(s[2] for s in segs)
        by_seq = b"".join(s[2] for s in sorted(segs, key=lambda s: s[1]))
        if arrival != by_seq:
            reordered += 1
        line = by_seq.split(b"\r\n")[0][:180].decode("latin-1", "ignore")
        samples[f"{line}  [세그먼트 {len(segs)}]"] += 1

    return {
        "available": True,
        "files": [p.name for p in paths],
        "service_port": port,
        "inbound_packets": inbound,
        "replay_drops": dropped,
        "replay_rules": dict(rules.most_common()),
        "flag_responses": len(successes),
        "blocked_connections": blocked,
        "bypassed_connections": bypassed,
        "bypass_segmented": segmented,
        "bypass_reordered": reordered,
        "bypass_samples": samples.most_common(8),
    }


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
        out.append(f"| {name} | {d['service_port']} | {d['inbound_packets']:,} | "
                   f"{d['replay_drops']:,} | {d['flag_responses']} | "
                   f"{d['blocked_connections']} | **{d['bypassed_connections']}** |")
    out.append("")

    for name in sorted(layers):
        d = layers[name]
        if not d.get("available") or not d["bypassed_connections"]:
            continue
        out += [f"### {name} 우회 {d['bypassed_connections']}건", "",
                f"- 세그먼트 분할 {d['bypass_segmented']}건 · 순서 뒤섞임 {d['bypass_reordered']}건", ""]
        if d["bypass_reordered"]:
            out += ["> 순서 뒤섞임은 TCP 재조립 회피다. seq 정렬 시 완전한 공격 요청이 복원된다.", ""]
        out += ["```text"]
        out += [f"{n}회  {line}" for line, n in d["bypass_samples"]]
        out += ["```", ""]

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
    layers = {name: analyze_layer(paths, load_engine)
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
