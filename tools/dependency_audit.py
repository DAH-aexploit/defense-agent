"""제출 방어 image의 의존성·금지 분석기·base 고정 정적 검증"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DAH = ROOT.parent
DEPLOY = DAH / "deploy" / "agents" / "team1" / "defender"
APP_FILES = [DEPLOY / "defender.py", DEPLOY / "detectors.py",
             DEPLOY / "rehearsal_web_detectors.py",
             DEPLOY / "protocol_profiles.py", DEPLOY / "signatures.py"]
LOCAL_MODULES = {p.stem for p in APP_FILES}
BANNED = {"tshark", "wireshark", "pyshark", "scapy", "dpkt", "tcpdump"}


def imported_modules(path: Path) -> set[str]:
    """Python AST의 최상위 import module명 추출

    comment·문자열 속 package 이름 오탐 방지를 위한 문자열 검색 대신 AST 사용
    """
    tree = ast.parse(path.read_text(), filename=str(path))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
    return found


def main() -> int:
    """제출 image의 재현성·license 정책 검사와 JSON 결과 출력

    베이스 이미지 digest 고정, 빌드 중 패키지 설치 부재, 표준 라이브러리 외 import 부재,
    금지 분석 도구 부재, 의존성 고지 문서 존재의 전체 충족을 성공 기준으로 적용
    """
    dockerfile = (DEPLOY / "Dockerfile").read_text()
    imports = sorted(set().union(*(imported_modules(p) for p in APP_FILES)))
    third_party = sorted(m for m in imports
                         if m not in sys.stdlib_module_names and m not in LOCAL_MODULES)
    pinned = bool(re.search(r"^FROM\s+python:3\.12-slim@sha256:[0-9a-f]{64}$",
                            dockerfile, re.MULTILINE))
    no_install = "apt-get install" not in dockerfile and not re.search(
        r"\bpip(?:3)?\s+install\b", dockerfile)
    banned_hits = sorted(word for word in BANNED
                         if re.search(rf"\b{re.escape(word)}\b", dockerfile.lower()))
    required = [DEPLOY / "DEPENDENCIES.md", DEPLOY / "THIRD_PARTY_NOTICES.md"]
    result = {"base_digest_pinned": pinned, "no_package_install": bool(no_install),
              "imports": imports, "third_party_imports": third_party,
              "banned_analyzers_in_dockerfile": banned_hits,
              "notices_present": all(p.is_file() for p in required)}
    passed = (pinned and no_install and not third_party and not banned_hits
              and result["notices_present"])
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
