"""라운드 자료 도착 감시 — 새 자료가 완성되는 즉시 자동 분석

대회 자료는 라운드 종료 후 여러 파일이 나뉘어 도착한다. 파일 크기가 안정될 때까지 기다린 뒤
`round_report.py`를 실행해 세션에서 바로 읽을 수 있는 요약을 표준 출력으로 남긴다.

  python3 tools/round_watch.py ~/Downloads/DAH-본선            # 새 라운드 1개 처리 후 종료
  python3 tools/round_watch.py ~/Downloads/DAH-본선 --follow   # 계속 감시

`--follow` 없이 실행하면 새 라운드를 하나 처리한 즉시 종료한다. 배경 실행 시 종료가
세션 알림으로 이어지므로 기본값으로 둔다.

이미 처리한 라운드는 상태 파일에 기록해 재실행 시 중복 분석하지 않는다.
`--replay-latest`로 상태와 무관하게 최신 라운드를 다시 분석할 수 있다.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.round_report import (analyze_layer, analyze_log, discover,  # noqa: E402
                                latest_round, render)
from defender import load_engine                                       # noqa: E402

STATE = ROOT / "qa-results" / "rounds" / ".seen.json"
SETTLE_SECONDS = 6.0
POLL_SECONDS = 20.0


def load_seen() -> set[str]:
    try:
        return set(json.loads(STATE.read_text()))
    except (OSError, ValueError):
        return set()


def save_seen(seen: set[str]) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(sorted(seen), ensure_ascii=False, indent=2) + "\n")


def bundle_files(bundle: dict) -> list[Path]:
    files = [bundle["defender_log"], bundle["attacker_log"]]
    for paths in bundle["pcaps"].values():
        files.extend(paths)
    return [f for f in files if f]


def settled(bundle: dict, settle: float) -> bool:
    """모든 파일의 크기가 settle초 동안 변하지 않으면 전송 완료로 간주"""
    files = bundle_files(bundle)
    if not files:
        return False
    first = {f: f.stat().st_size for f in files if f.exists()}
    time.sleep(settle)
    for f, size in first.items():
        if not f.exists() or f.stat().st_size != size:
            return False
    return True


def process(round_key: str, bundle: dict) -> str:
    log = analyze_log(bundle["defender_log"])
    layers = {name: analyze_layer(paths, load_engine)
              for name, paths in sorted(bundle["pcaps"].items())}
    report = render(round_key, log, layers)
    out = ROOT / "qa-results" / "rounds" / f"{round_key}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")

    alerts = []
    if log.get("available") and log.get("accept_all"):
        alerts.append("적재 룰 0개. 실질 ACCEPT-all 상태다. PORT_BINDINGS를 즉시 확인한다.")
    if log.get("available") and log.get("legacy_image"):
        alerts.append("실행 이미지가 구버전이다. 코드가 아니라 배포 경로부터 확인한다.")
    if log.get("available") and log.get("image_state", "").startswith("판정 불가"):
        alerts.append("실행 이미지를 판정할 근거가 부족하다. 기동 로그를 직접 확인한다.")
    if log.get("available") and log.get("trouble"):
        alerts.append(f"에이전트 이상 로그 {log['trouble']}건이 있다.")
    for name, d in layers.items():
        if d.get("available") and d.get("bypassed_connections"):
            detail = ""
            if d["bypass_reordered"]:
                detail = f" (순서 뒤섞임 {d['bypass_reordered']}건)"
            alerts.append(f"{name} 우회 {d['bypassed_connections']}건{detail}")

    head = [f"══ 새 라운드 자료 분석 완료: {round_key} ══", f"보고서: {out}"]
    if alerts:
        head += ["", "즉시 확인:"] + [f"  - {a}" for a in alerts]
    head += ["", report]
    return "\n".join(head)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="라운드 자료 도착 감시와 자동 분석")
    parser.add_argument("source", help="자료 디렉터리")
    parser.add_argument("--follow", action="store_true", help="종료하지 않고 계속 감시")
    parser.add_argument("--poll", type=float, default=POLL_SECONDS, help="확인 주기(초)")
    parser.add_argument("--settle", type=float, default=SETTLE_SECONDS,
                        help="파일 크기 안정 대기(초)")
    parser.add_argument("--replay-latest", action="store_true",
                        help="상태와 무관하게 최신 라운드 재분석 후 종료")
    parser.add_argument("--backfill", action="store_true",
                        help="이미 받아둔 과거 라운드도 처리한다")
    args = parser.parse_args(argv)

    source = Path(args.source).expanduser()
    source.mkdir(parents=True, exist_ok=True)
    seen = load_seen()

    if args.replay_latest:
        rounds = discover(source)
        key = latest_round(rounds)
        if not key:
            print("라운드 자료 없음", file=sys.stderr)
            return 2
        print(process(key, rounds[key]), flush=True)
        seen.add(key)
        save_seen(seen)
        return 0

    # 감시는 "새로 도착하는" 자료를 대상으로 한다. 이미 받아둔 과거 라운드를 하나씩
    # 되짚으면 정작 새 라운드 처리가 밀리므로, 시작 시점의 자료는 기준선으로 기록만 한다.
    existing = set(discover(source))
    if not args.backfill:
        baseline = existing - seen
        if baseline:
            seen |= baseline
            save_seen(seen)
            print(f"기존 자료 {len(baseline)}개를 기준선으로 기록 (분석 제외): "
                  f"{', '.join(sorted(baseline))}", file=sys.stderr, flush=True)
            print("과거 라운드를 분석하려면 --backfill 또는 make round 를 사용한다.",
                  file=sys.stderr, flush=True)

    print(f"감시 시작: {source} (주기 {args.poll:.0f}s, 처리 완료 {len(seen)}개)",
          file=sys.stderr, flush=True)
    while True:
        rounds = discover(source)
        fresh = [k for k in sorted(rounds) if k not in seen]
        for key in fresh:
            if not settled(rounds[key], args.settle):
                continue                       # 전송 중, 다음 주기에 재확인
            print(process(key, rounds[key]), flush=True)
            seen.add(key)
            save_seen(seen)
            if not args.follow:
                return 0
        time.sleep(args.poll)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        raise SystemExit(130)
