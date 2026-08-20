"""라운드 PCAP 오프라인 Suricata 분석 — 방산 프로토콜·포트 식별과 detector 교차 확인

운영자 로컬 전용. 대회 배포 이미지에는 넣지 않는다(Suricata=GPLv2, 대회규정 제14조상
배포 이미지 번들 불가). 라운드 PCAP를 로컬 Suricata로 스캔해 어떤 포트에서 무슨 방산
프로토콜이 오갔는지 독립적으로 확인하고, 그 포트를 `DEF_*_PORTS`에 넣어 enforce 전환을
판단하는 데 쓴다. 우리 엔진의 read enumeration detector와 같은 신호를 Suricata로 한 번 더
교차 확인하는 목적도 있다.

  python3 tools/suricata_scan.py <pcap> [--rules <경로>] [--suricata <바이너리>] [--json]

Suricata가 설치돼 있지 않으면 설치 안내만 출력하고 종료한다(에러 아님). eve.json 파싱은
`summarize_eve()`로 분리해 Suricata 없이도 단위 테스트가 가능하다.
"""

from __future__ import annotations

import argparse
import collections
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RULES_DEFAULT = Path(__file__).resolve().parent / "suricata" / "dah-defense.rules"

# signature_id 대역 → (프로토콜, enforce 전환 시 설정할 포트 환경변수)
SID_PROTOCOL = [
    (9000100, 9000199, "Modbus", "DEF_MODBUS_PORTS"),
    (9000200, 9000299, "MAVLink", "DEF_MAVLINK_PORTS"),
    (9000300, 9000399, "CCSDS", "DEF_CCSDS_PORTS"),
    (9000400, 9000499, "RTPS", "DEF_RTPS_PORTS"),
    (9000500, 9000599, "UDS/CAN", "DEF_UDS_CAN_PORTS"),
    (9000600, 9000699, "IEC-104", "DEF_IEC104_PORTS"),
    (9000700, 9000799, "SNMP", "DEF_SNMP_PORTS"),
    (9000800, 9000899, "TLS", ""),   # 암호화 채널 — enforce 대상 아님(관찰만), 포트 제안 없음
]


def sid_protocol(sid: int) -> tuple[str, str]:
    for low, high, proto, env in SID_PROTOCOL:
        if low <= sid <= high:
            return proto, env
    return "기타", ""


def _first(meta: dict, key: str) -> str:
    value = meta.get(key)
    if isinstance(value, list):
        return value[0] if value else ""
    return value or ""


def summarize_eve(events) -> dict:
    """eve.json alert 이벤트 목록 → 프로토콜·시그니처·포트 집계

    events: eve.json을 줄 단위 JSON으로 파싱한 dict의 iterable.
    Suricata 없이도 테스트할 수 있도록 순수 함수로 둔다.
    """
    by_sid: dict = {}
    proto_ports: dict = collections.defaultdict(lambda: collections.Counter())
    proto_env: dict = {}
    total_alerts = 0
    for event in events:
        if event.get("event_type") != "alert":
            continue
        alert = event.get("alert", {})
        sid = int(alert.get("signature_id", 0))
        total_alerts += 1
        proto, env = sid_protocol(sid)
        if env:
            proto_env[proto] = env
        meta = alert.get("metadata", {}) or {}
        entry = by_sid.setdefault(sid, {
            "signature": alert.get("signature", ""),
            "protocol": proto,
            "detector": _first(meta, "detector"),
            "layer": _first(meta, "layer"),
            "attack": _first(meta, "attack"),
            "hits": 0,
            "dest_ports": collections.Counter(),
        })
        entry["hits"] += 1
        dport = event.get("dest_port")
        if dport is not None:
            entry["dest_ports"][int(dport)] += 1
            proto_ports[proto][int(dport)] += 1

    # 프로토콜별 enforce 전환 제안(가장 많이 관측된 목적지 포트 기준)
    suggestions = []
    for proto, ports in proto_ports.items():
        env = proto_env.get(proto, "")
        if not env or not ports:
            continue
        top = [str(p) for p, _ in ports.most_common(4)]
        suggestions.append({"protocol": proto, "env": env, "ports": top,
                            "setting": f"{env}={','.join(top)}"})
    return {
        "total_alerts": total_alerts,
        "signatures": [dict(v, dest_ports=dict(v["dest_ports"].most_common()))
                       for v in sorted(by_sid.values(), key=lambda x: -x["hits"])],
        "suggestions": suggestions,
    }


def render(summary: dict, pcap: str) -> str:
    out = [f"# Suricata 오프라인 분석 — {pcap}", "",
           f"- 총 alert: {summary['total_alerts']}건", ""]
    if not summary["signatures"]:
        out += ["방산 프로토콜 시그니처 미검출. (해당 PCAP에 Modbus/MAVLink/CCSDS/RTPS가 없거나,",
                "포트/페이로드가 룰 가정과 다를 수 있음 — round_report의 포트 자동추론과 대조.)", ""]
        return "\n".join(out)
    out += ["| 프로토콜 | 시그니처 | 적중 | 목적지 포트 | detector | 공격기술 |",
            "|---|---|---:|---|---|---|"]
    for s in summary["signatures"]:
        ports = ", ".join(f"{p}({n})" for p, n in s["dest_ports"].items()) or "-"
        out.append(f"| {s['protocol']} | {s['signature']} | {s['hits']} | {ports} | "
                   f"`{s['detector']}` | {s['attack']} |")
    out.append("")
    if summary["suggestions"]:
        out += ["## enforce 전환 후보 (포트 확인 후 판단)", "",
                "> Suricata가 아래 포트에서 해당 프로토콜을 봤다. 정상 baseline을 대조한 뒤",
                "> `DEF_*_PORTS`에 넣고 enforce 전환을 판단한다(추측성 enforce 금지 — 규칙 4).", ""]
        for s in summary["suggestions"]:
            out.append(f"- {s['protocol']}: `{s['setting']}`")
        out.append("")
    return "\n".join(out)


def run_suricata(pcap: Path, rules: Path, suricata: str) -> list:
    """Suricata를 오프라인(-r)으로 실행하고 eve.json alert 이벤트 목록 반환"""
    with tempfile.TemporaryDirectory() as workdir:
        cmd = [suricata, "-r", str(pcap), "-S", str(rules), "-l", workdir,
               "--set", "outputs.1.eve-log.enabled=yes"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        eve = Path(workdir) / "eve.json"
        if not eve.exists():
            print("Suricata 실행은 됐으나 eve.json이 없다. stderr:\n" + proc.stderr[-2000:],
                  file=sys.stderr)
            return []
        events = []
        for line in eve.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
        return events


INSTALL_HINT = """Suricata가 설치돼 있지 않다(오프라인 분석 전용, 이미지에는 넣지 않는다).
설치 후 다시 실행:
  macOS:  brew install suricata
  Ubuntu: sudo apt-get install -y suricata
룰셋은 이미 준비돼 있다: {rules}
Suricata 없이도 이 도구의 집계 로직은 tests에서 검증된다(summarize_eve)."""


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="라운드 PCAP 오프라인 Suricata 분석")
    parser.add_argument("pcap", help="분석할 PCAP 경로")
    parser.add_argument("--rules", default=str(RULES_DEFAULT), help="Suricata 룰셋 경로")
    parser.add_argument("--suricata", default=None, help="Suricata 바이너리 경로(기본: PATH 탐색)")
    parser.add_argument("--out", help="Markdown 저장 경로")
    parser.add_argument("--json", action="store_true", help="집계 JSON 출력")
    args = parser.parse_args(argv)

    pcap = Path(args.pcap).expanduser()
    rules = Path(args.rules).expanduser()
    if not pcap.exists():
        print(f"PCAP 없음: {pcap}", file=sys.stderr)
        return 2
    if not rules.exists():
        print(f"룰셋 없음: {rules}", file=sys.stderr)
        return 2

    suricata = args.suricata or shutil.which("suricata")
    if not suricata:
        print(INSTALL_HINT.format(rules=rules), file=sys.stderr)
        return 0

    events = run_suricata(pcap, rules, suricata)
    summary = summarize_eve(events)
    report = render(summary, pcap.name)
    if args.out:
        Path(args.out).expanduser().write_text(report, encoding="utf-8")
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
