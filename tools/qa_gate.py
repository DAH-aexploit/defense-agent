"""재현 가능한 로컬 QA gate와 Markdown/JSON 증적 생성기

실행 위치와 무관한 defense-agent 저장소 기준 검사, 외부 package·network 사용 제외
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DAH = ROOT.parent
DEPLOY = DAH / "deploy" / "agents" / "team1" / "defender"
RESULTS = ROOT / "qa-results"


def run(name: str, command: list[str]) -> dict:
    """단일 검사 명령 실행과 종료 code·전체 출력의 증적용 dict 반환"""
    started = dt.datetime.now(dt.timezone.utc)
    p = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    output = (p.stdout + p.stderr).strip()
    return {"name": name, "command": command, "passed": p.returncode == 0,
            "returncode": p.returncode, "started_utc": started.isoformat(), "output": output}


def digest(path: Path) -> str:
    """개발본·배포본 byte 단위 비교용 SHA-256 계산"""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parity() -> dict:
    """핵심 engine file의 local 개발본·Docker 배포본 동일성 검사"""
    pairs = [(ROOT / "defender.py", DEPLOY / "defender.py"),
             (ROOT / "detectors.py", DEPLOY / "detectors.py"),
             (ROOT / "rehearsal_web_detectors.py", DEPLOY / "rehearsal_web_detectors.py"),
             (ROOT / "protocol_profiles.py", DEPLOY / "protocol_profiles.py")]
    details = [{"development": str(a.relative_to(DAH)), "deployment": str(b.relative_to(DAH)),
                "sha256_development": digest(a), "sha256_deployment": digest(b),
                "equal": a.read_bytes() == b.read_bytes()} for a, b in pairs]
    return {"name": "deployment parity", "passed": all(x["equal"] for x in details),
            "details": details}


def main() -> int:
    """전체 gate 실행과 ``qa-results/latest.json``·``latest.md`` 생성"""
    RESULTS.mkdir(exist_ok=True)
    checks = [
        run("compile", [sys.executable, "-m", "py_compile", "defender.py", "detectors.py",
                        "rehearsal_web_detectors.py",
                        "protocol_profiles.py",
                        "tests/packet_util.py", "tests/rule_fixtures.py",
                        "tools/pcap_analyze.py", "tools/round_report.py",
                        "tools/round_watch.py", "tools/image_verify.py",
                        "tools/suricata_scan.py", "tools/bansan_sim.py",
                        "tools/dependency_audit.py"]),
        run("dependency and license policy", [sys.executable, "tools/dependency_audit.py"]),
        run("unit and safety tests", [sys.executable, "-m", "unittest", "discover",
                                      "-s", "tests", "-v"]),
        run("deterministic synthetic pcap replay", [sys.executable, "tests/qa_replay.py"]),
        run("performance", [sys.executable, "tools/bench.py"]),
        parity(),
    ]
    bench = next(x for x in checks if x["name"] == "performance")
    tests = next(x for x in checks if x["name"] == "unit and safety tests")
    match = re.search(r"p99=([0-9.]+)ms", bench.get("output", ""))
    p99 = float(match.group(1)) if match else None
    ran = re.search(r"Ran (\d+) tests?", tests.get("output", ""))
    skipped = re.search(r"skipped=(\d+)", tests.get("output", ""))
    test_count = int(ran.group(1)) if ran else None
    skip_count = int(skipped.group(1)) if skipped else 0
    if p99 is None or p99 >= 50.0:
        bench["passed"] = False
        bench["gate_reason"] = "p99 must be below the internal 50ms verdict budget"

    passed = all(x["passed"] for x in checks)
    now = dt.datetime.now().astimezone()
    evidence = {
        "schema": 1,
        "generated_at": now.isoformat(),
        "result": "PASS" if passed else "FAIL",
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(),
                        "cwd": str(ROOT), "bg_analysis_env": os.getenv("DEF_BG_ANALYSIS", "0")},
        "performance_p99_ms": p99,
        "tests": {"count": test_count, "skipped": skip_count,
                  "failed": 0 if tests["passed"] else None},
        "checks": checks,
        "scope": {"verified": "local deterministic engine, tests, performance, deploy parity, dependency policy",
                  "not_verified": "Linux NFQUEUE/broker runtime and real competition pcap"},
    }
    latest_json = RESULTS / "latest.json"
    latest_md = RESULTS / "latest.md"
    latest_json.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")

    lines = ["# DAH 방어 에이전트 로컬 QA 결과", "", f"- 결과: **{evidence['result']}**",
             f"- 생성: {evidence['generated_at']}", f"- Python: {evidence['environment']['python']}",
             f"- 플랫폼: {evidence['environment']['platform']}",
             f"- 테스트: {test_count if test_count is not None else '집계 실패'}개, "
             f"skip {skip_count}, {'FAIL 0' if tests['passed'] else 'FAIL 발생'}",
             f"- verdict p99: {p99 if p99 is not None else '측정 실패'} ms", "",
             "## Gate 결과", "", "| Gate | 결과 |", "|---|---|"]
    for check in checks:
        lines.append(f"| {check['name']} | {'PASS' if check['passed'] else 'FAIL'} |")
    lines += ["", "## 검증 범위", "", f"- 확인: {evidence['scope']['verified']}",
              f"- 미확인: {evidence['scope']['not_verified']}", "",
              "## 재현 명령", "", "```bash", "cd DAH/defense-agent", "make qa", "```", "",
              "> Linux/GCP 통합은 `cd DAH/deploy && make qa-linux`로 별도 확인해야 한다.", ""]
    latest_md.write_text("\n".join(lines))
    print(latest_md)
    print(f"QA {evidence['result']}: " + ", ".join(
        f"{x['name']}={'PASS' if x['passed'] else 'FAIL'}" for x in checks))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
