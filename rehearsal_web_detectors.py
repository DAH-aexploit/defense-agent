"""리허설 스켈레톤 챌린지 전용 검사기 — 본선 방산 프로토콜과 무관

`DAH2026_본선_에이전트_구현가이드.md` §5, `DAH2026_리허설_정보수집.md` §1·§7에 명시된 대로
리허설 챌린지(L1 SSRF, L2 admin 세션 위조, L3 SQLi)는 본선 챌린지 및 실제 프로토콜과 무관하다.
이 파일의 검사기는 그 리허설 스켈레톤을 대상으로 만들어졌으며, 본선 진입점이 동일한 형태의
HTTP 서비스를 노출하지 않는 한 재사용되지 않는다.

core 엔진(`detectors.py`)과 분리해두는 이유는 두 가지다.
  - 본선 방산 프로토콜 검사기 개발 시 이 파일을 참고·수정할 필요가 없다.
  - `defender.py`에서 이 모듈의 import 자체를 끊으면 리허설 전용 판정 경로가
    코드베이스에서 완전히 빠진다는 것을 파일 경계로 확인할 수 있다.

내장 검사기:
  - UrlSsrGuardDetector       : L1 `/fetch` URL의 구조 기반 SSRF 차단
  - L3ProductIdDetector       : L3 `/product?id=` 숫자 ID 계약 검사
  - AuthSessionDetector       : L2 Base64 JSON 세션의 권한 상승 필드 관찰
  - McsScriptTraversalDetector: L2 script API의 flags 경로 이탈 차단
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import urllib.parse

from detectors import Detector, Evidence, EvidenceClass, IdentificationBasis, PacketContext, _deescape


class UrlSsrGuardDetector(Detector):
    """HTTP fetch URL의 구조 기반 SSRF 차단

    리허설에서 확인된 loopback·내부 hostname·비허용 scheme 대상
    HTTP request line의 지정 경로와 query parameter에만 적용되는 오탐 제한형 검사
    """

    name = "url_ssrf_guard"

    def __init__(self, ports=(8082,), paths=("/fetch",), params=("url", "uri"),
                 internal_hosts=("localhost", "helper-box"),
                 allowed_schemes=("http", "https"), weight=1.0) -> None:
        self.ports = {int(port) for port in ports}
        self.paths = tuple(str(path).lower() for path in paths)
        self.params = {str(param).lower() for param in params}
        self.internal_hosts = {str(host).lower().rstrip(".") for host in internal_hosts}
        self.allowed_schemes = {str(scheme).lower() for scheme in allowed_schemes}
        self.weight = float(weight)

    @staticmethod
    def _decode(value: str, rounds=4) -> str:
        current = value[:4096]
        for _ in range(rounds):
            decoded = urllib.parse.unquote_plus(current)
            if decoded == current:
                break
            current = decoded[:4096]
        return current.strip()

    @staticmethod
    def _numeric_ip(host: str):
        candidate = host.strip("[]").rstrip(".")
        try:
            return ipaddress.ip_address(candidate)
        except ValueError:
            pass

        def legacy_int(part: str) -> int:
            if part.lower().startswith("0x"):
                return int(part[2:], 16)
            if len(part) > 1 and part.startswith("0"):
                return int(part[1:], 8)
            return int(part, 10)

        try:
            if "." not in candidate:
                value = legacy_int(candidate)
                if 0 <= value <= 0xFFFFFFFF:
                    return ipaddress.ip_address(value)
            parts = candidate.split(".")
            if 1 <= len(parts) <= 4:
                nums = [legacy_int(part) for part in parts]
                widths = {2: (8, 24), 3: (8, 8, 16), 4: (8, 8, 8, 8)}.get(len(nums))
                if widths and all(0 <= value < (1 << width)
                                  for value, width in zip(nums, widths)):
                    address = 0
                    for value, width in zip(nums, widths):
                        address = (address << width) | value
                    return ipaddress.ip_address(address)
        except ValueError:
            pass
        return None

    def _evidence(self, rule_id: str, reason: str) -> list[Evidence]:
        return [Evidence(
            self.weight, reason, f"url_ssrf_guard:{rule_id}", rule_id,
            EvidenceClass.ATTACK_PATTERN_CONFIRMED,
            IdentificationBasis.STRUCTURE_VERIFIED,
            True, True, True)]

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        first_line = ctx.raw.splitlines()[0] if ctx.raw else ""
        parts = first_line.split(" ", 2)
        if len(parts) != 3 or not parts[2].lower().startswith("http/"):
            return []
        method, request_target = parts[0].upper(), parts[1]
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
            return []
        try:
            request = urllib.parse.urlsplit(request_target)
        except ValueError:
            return []
        # 경로는 percent 디코딩 후 비교한다. `/%66%65%74%63%68` 같은 인코딩 경로가
        # 검사 대상에서 빠져나가는 우회가 실제 트래픽에서 확인됐다.
        request_path = self._decode(request.path).lower()
        if not any(request_path == path or request_path.startswith(path + "/")
                   for path in self.paths):
            return []
        try:
            query = urllib.parse.parse_qs(request.query, keep_blank_values=True,
                                         max_num_fields=64)
        except ValueError:
            return []
        for key, values in query.items():
            # parse_qs가 1회 디코딩하므로 남은 이중 인코딩만 추가로 푼다
            if self._decode(key).lower() not in self.params:
                continue
            for raw_value in values[:4]:
                value = self._decode(raw_value)
                try:
                    target = urllib.parse.urlsplit(value)
                    host = (target.hostname or "").lower().rstrip(".")
                    scheme = target.scheme.lower()
                except ValueError:
                    return self._evidence("HTTP-SSRF-MALFORMED", "malformed URL in fetch parameter")
                if scheme and scheme not in self.allowed_schemes:
                    return self._evidence(
                        "HTTP-SSRF-SCHEME",
                        f"non-allowlisted URL scheme in fetch parameter: {scheme}")
                if not scheme:
                    continue
                if host in self.internal_hosts:
                    return self._evidence(
                        "HTTP-SSRF-INTERNAL-HOST",
                        "fetch parameter targets an internal service hostname")
                address = self._numeric_ip(host)
                if address is not None and not address.is_global:
                    return self._evidence(
                        "HTTP-SSRF-NON-GLOBAL-IP",
                        "fetch parameter targets a non-global IP address")
        return []


class L3ProductIdDetector(Detector):
    """리허설 Layer 3 상품 endpoint의 숫자 ID 계약 검사"""

    name = "l3_product_id"

    def __init__(self, ports=(8084,), mode="enforce") -> None:
        self.ports = {int(port) for port in ports}
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        first_line = ctx.raw.splitlines()[0] if ctx.raw else ""
        parts = first_line.split(" ", 2)
        if len(parts) != 3 or parts[0].upper() not in {"GET", "HEAD"}:
            return []
        try:
            request = urllib.parse.urlsplit(parts[1])
            path = UrlSsrGuardDetector._decode(request.path).lower()
            query = urllib.parse.parse_qs(
                request.query, keep_blank_values=True, max_num_fields=64)
        except ValueError:
            return []
        if path != "/product" or "id" not in {key.lower() for key in query}:
            return []
        values = [value for key, items in query.items() if key.lower() == "id"
                  for value in items[:4]]
        if values and all(value.isdecimal() and 1 <= len(value) <= 10 for value in values):
            return []
        enabled = self.mode == "enforce"
        return [Evidence(
            1.0 if enabled else 0.0,
            "Layer 3 product id violates the decimal identifier contract",
            "l3_product_id:non_decimal", "L3-PRODUCT-ID-STRUCTURE",
            EvidenceClass.ATTACK_PATTERN_CONFIRMED if enabled else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.STRUCTURE_VERIFIED,
            True, enabled, True)]


class AuthSessionDetector(Detector):
    """Base64 JSON 세션의 권한 상승 필드 구조 관찰"""

    name = "auth_session"

    def __init__(self, ports=(8083,), mode="enforce") -> None:
        self.ports = {int(port) for port in ports}
        self.mode = mode

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        privileged = False
        for line in ctx.raw.splitlines()[:96]:
            if not line.lower().startswith("cookie:"):
                continue
            for item in line.split(":", 1)[1].split(";")[:16]:
                if "=" not in item:
                    continue
                _name, value = item.strip().split("=", 1)
                # 값을 감싼 따옴표와 문자 이스케이프 리터럴을 해석한 뒤 디코딩한다.
                # 리허설 Round 17에서 `session="\145yJ..."` 형태로 base64 디코딩
                # 결과를 깨뜨려 탐지를 피하는 우회가 관측됐다.
                value = _deescape(value.strip('"').strip("'"))
                try:
                    decoded = base64.b64decode(
                        value + "=" * (-len(value) % 4), validate=False)[:4096]
                    obj = json.loads(decoded.decode("utf-8"))
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if not isinstance(obj, dict):
                    continue
                role = str(obj.get("role", "")).lower()
                privileged = privileged or role == "admin"
                privileged = privileged or any(
                    obj.get(key) is True or str(obj.get(key, "")).lower() == "true"
                    for key in ("admin", "is_admin"))
        if not privileged:
            return []
        enforce = self.mode == "enforce"
        return [Evidence(
            1.0 if enforce else 0.0,
            "privileged fields in client-controlled Base64 JSON session",
            "auth_session:privileged", "MCS-AUTH-SESSION-STRUCTURED",
            EvidenceClass.ATTACK_PATTERN_CONFIRMED if enforce
            else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.STRUCTURE_VERIFIED,
            True, True, True)]


class McsScriptTraversalDetector(Detector):
    """MCS script API의 flags 경로 이탈 공격 차단"""

    name = "mcs_script_traversal"

    def __init__(self, ports=(8083,), mode="enforce") -> None:
        self.ports = {int(port) for port in ports}
        self.mode = mode

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        first = ctx.raw.splitlines()[0].split(" ", 2) if ctx.raw else []
        if len(first) != 3:
            return []
        target = urllib.parse.unquote(first[1]).lower()
        if not target.startswith("/script-api/scripts/"):
            return []
        if ".." not in target or not re.search(r"(?:^|/)flags(?:/|$)", target):
            return []
        enforce = self.mode == "enforce"
        return [Evidence(
            1.0 if enforce else 0.0,
            "script API path escapes the allowed root toward flags",
            "mcs_script_traversal:flags", "MCS-SCRIPT-TRAVERSAL",
            EvidenceClass.ATTACK_PATTERN_CONFIRMED if enforce
            else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.STRUCTURE_VERIFIED,
            True, True, True)]
