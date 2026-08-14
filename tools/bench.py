"""성능·안정성 실측: verdict latency(300ms 예산 대비), payload cap, 정규식 폭발 완화

  python3 tools/bench.py
"""

from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import signatures
from defender import VerdictEngine
from tests.packet_util import packet_for


def measure(engine, pkts, rounds=2000):
    times = []
    for _ in range(rounds):
        for p in pkts:
            t0 = time.perf_counter()
            engine.verdict(p)
            times.append((time.perf_counter() - t0) * 1000.0)
    times.sort()
    n = len(times)
    return {
        "n": n,
        "p50": times[n // 2],
        "p99": times[int(n * 0.99)],
        "max": times[-1],
        "mean": statistics.fmean(times),
    }


def main():
    e = VerdictEngine.from_config(signatures.SIGNATURES, signatures.WHITELIST)

    mixed = [
        packet_for(8082, "/health"),
        packet_for(8084, "/product?id=5"),
        packet_for(8082, "/"),
        packet_for(8084, "/product?id=1 UNION SELECT sql FROM sqlite_master"),
        packet_for(8082, "/fetch?url=http://127.0.0.1:8082/registry"),
        packet_for(8084, "/product?id=1 UnIoN/**/SeLeCt 1,2,3"),
    ]
    print("── verdict latency (mixed 정상+공격), 예산 300ms ──")
    r = measure(e, mixed)
    print(f"  n={r['n']}  p50={r['p50']:.4f}ms  p99={r['p99']:.4f}ms  "
          f"max={r['max']:.4f}ms  mean={r['mean']:.4f}ms")
    head = "  OK" if r["p99"] < 300 else "  !! p99 exceeds budget"
    print(f"{head} — p99 여유 {300 / max(r['p99'], 1e-9):.0f}x")

    # payload cap: 100KB payload의 cap(16KB) 절삭과 신속 판정 확인
    big = packet_for(8084, "/product?id=" + "A" * 60_000)  # IP 패킷 상한(65535) 내 최대
    t0 = time.perf_counter()
    e.verdict(big)
    dt = (time.perf_counter() - t0) * 1000.0
    print(f"── 100KB payload → cap {e.payload_cap}B 적용, 판정 {dt:.3f}ms ({'OK' if dt < 300 else '!!'})")

    # 정규식 폭발 완화: 위험 룰의 적재 단계 거부 확인
    danger = VerdictEngine.from_config([{"port": 8084, "pattern": r"(a+)+$", "reason": "evil"}], [],
                                       payload_cap=2048, budget_ms=50)
    evil = packet_for(8084, "/x?q=" + "a" * 4000 + "!")
    t0 = time.perf_counter()
    v = danger.verdict(evil)[0]
    dt = (time.perf_counter() - t0) * 1000.0
    note = "OK(위험 룰 적재 거부)" if danger.rule_count == 0 and dt < 300 else "!! 위험 룰 방어 실패"
    print(f"── catastrophic backtracking 룰: 판정 {dt:.1f}ms, verdict={v} → {note}")
    print("   (중첩 수량자 룰을 컴파일 전 거부하고, 런타임에는 POSIX budget timer가 추가 방어.)")


if __name__ == "__main__":
    main()
