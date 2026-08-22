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

    def __init__(self, ports=(8082,), paths=("/fetch",),
                 params=("url", "uri", "proxy", "next", "redirect", "dest",
                         "destination", "target", "callback", "fetch", "u",
                         "link", "forward", "continue", "return", "returnurl",
                         "goto", "to", "out"),
                 internal_hosts=("localhost", "helper-box"),
                 allowed_schemes=("http", "https"),
                 rebind_suffixes=("nip.io", "sslip.io", "xip.io", "localtest.me"),
                 internal_suffixes=(".internal", ".local", ".lan", ".localhost"),
                 weight=1.0) -> None:
        self.ports = {int(port) for port in ports}
        self.paths = tuple(str(path).lower() for path in paths)
        self.params = {str(param).lower() for param in params}
        self.internal_hosts = {str(host).lower().rstrip(".") for host in internal_hosts}
        self.allowed_schemes = {str(scheme).lower() for scheme in allowed_schemes}
        self.rebind_suffixes = tuple(str(s).lower().rstrip(".") for s in rebind_suffixes)
        self.internal_suffixes = tuple(str(s).lower() for s in internal_suffixes)
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
        # R2 실측 우회 대응: url/uri 외에 proxy= 등 흔한 SSRF 파라미터도 검사(allowlist).
        for key, values in query.items():
            if self._decode(key).lower() not in self.params:
                continue
            for raw_value in values[:4]:
                value = self._decode(raw_value)
                low = value.lower()
                if "://" not in low and not low.startswith("//"):
                    continue
                evidence = self._check_url(value)
                if evidence:
                    return evidence
        return []

    def _check_url(self, value: str) -> list[Evidence]:
        try:
            target = urllib.parse.urlsplit(value)
            host = (target.hostname or "").lower().rstrip(".")
            scheme = target.scheme.lower()
        except ValueError:
            return self._evidence("HTTP-SSRF-MALFORMED", "malformed URL in fetch parameter")
        if scheme and scheme not in self.allowed_schemes:
            return self._evidence(
                "HTTP-SSRF-SCHEME", f"non-allowlisted URL scheme: {scheme}")
        if not host:
            return []
        # 1) 숫자 IP(모든 인코딩: dotted·hex·decimal·IPv6/매핑) — non-global이면 차단, global이면 허용
        address = self._numeric_ip(host)
        if address is not None:
            if not address.is_global:
                return self._evidence(
                    "HTTP-SSRF-NON-GLOBAL-IP", "fetch targets a non-global IP address")
            return []
        # 2) 명시 내부 호스트
        if host in self.internal_hosts:
            return self._evidence(
                "HTTP-SSRF-INTERNAL-HOST", "fetch targets an internal service hostname")
        # 3) 내부 IP로 해석되는 DNS-rebind resolver (nip.io/sslip.io/localtest.me 등)
        if any(host == suffix or host.endswith("." + suffix)
               for suffix in self.rebind_suffixes):
            return self._evidence(
                "HTTP-SSRF-REBIND-DNS", f"fetch targets a DNS-rebind resolver host: {host}")
        # 4) 내부 도메인 suffix(.internal 등) 또는 single-label 호스트(공인 TLD 없음).
        #    R2 실측: can-bridge·helper-box 같은 내부 서비스명. 공인 URL은 항상 점 포함 도메인.
        if any(host.endswith(suffix) for suffix in self.internal_suffixes) or "." not in host:
            return self._evidence(
                "HTTP-SSRF-INTERNAL-HOST", f"fetch targets an internal-only hostname: {host}")
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


class GatewayTraversalDetector(Detector):
    """본선 L1 게이트웨이(HTTP)의 경로 traversal·LFI 차단 — P1-R1 실측 공격 대응.

    R1 attacker 로그의 8080 HTTP 공격: `/../flag.txt`, `/../../../../etc/passwd`,
    percent·이중 인코딩(`%2e%2e`, `%252e`) traversal. 정상 요청(`/`, `/health` 등)엔
    `..`나 시스템 파일 경로가 없어 오탐 위험이 낮다. percent 4회 디코딩 후 판정한다.
    HTTP 파서·`_decode` 재사용 때문에 이 파일에 두되, 본선 L1 전용이다(리허설 무관).
    """

    name = "gateway_traversal"

    _LFI_TARGETS = ("/etc/passwd", "/etc/shadow", "/proc/self/", "win.ini",
                    "/root/", ".ssh/", "/flags/", "telemetry/flag")
    # P2-R3 실측: 실제 flag 탈취는 `?file=/flag`·`?file=/flags/LAYER2_CHALL1_FLAG` 등 파라미터 LFI
    _LFI_PARAMS = ("file", "path", "page", "template", "doc", "document", "download",
                   "view", "read", "load", "include", "resource", "f", "filename",
                   "filepath", "src", "name", "attachment", "archive")
    _SAFE_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                 ".woff", ".woff2", ".html", ".htm", ".json")
    # 'flag'/'flags' 경로 세그먼트(뒤 영숫자 불허 → flagship 등 제외). _norm이 소문자화.
    _FLAG_SEG_RE = re.compile(r"(?:^|/)flags?(?![a-z0-9])")
    # P2-R4 실측: /portal/feedback?service_id=vulncheck 가 flag 담긴 피드백을 누출. service_id는
    # 정상 값이 없고 vulncheck(취약점스캔 프로브)만 등장 → 이 프로브 값만 차단(정상 service_id는 통과).
    # P4-R12 06:40 실측: telemetry 값도 /portal/feedback에서 flag를 반환했다. 정상 portal
    # 본문/telemetry API 전체가 아니라 이 feedback selector의 exact 값만 차단한다.
    _PROBE_SERVICE_IDS = ("vulncheck", "vulnscan", "pentest", "sqlmap", "nikto", "acunetix",
                          "telemetry")

    def __init__(self, ports=(8080,), mode="enforce") -> None:
        self.ports = {int(port) for port in ports}
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"

    @staticmethod
    def _norm(value: str) -> str:
        # percent 4회 디코딩으로 단일·이중 인코딩 우회를 편다. `\`도 `/`로 통일.
        return UrlSsrGuardDetector._decode(value).lower().replace("\\", "/")

    def _check(self, value: str, in_param: bool):
        v = self._norm(value)
        if "../" in v or v.endswith("/..") or v == "..":
            return ("GATEWAY-PATH-TRAVERSAL", "path traversal sequence")
        for target in self._LFI_TARGETS:
            if target in v:
                return ("GATEWAY-LFI", f"sensitive file target: {target}")
        # 일반화된 flag-route 가드: 경로/파라미터에 'flag'·'flags' 세그먼트가 있으면 차단한다.
        # route별(예 /telemetry/flag, /svc/flag-<uuid>) 룰 대신 한 규칙으로 신규 flag 경로까지 커버.
        # 세그먼트 경계 매칭(뒤에 영숫자 불허) → flagship·conflagration 등은 오탐 안 함. 이 앱 정상
        # 경로엔 flag 세그먼트가 없어 FP 낮음. flag값이 아니라 flag-'경로'만 대상.
        if self._FLAG_SEG_RE.search(v):
            return ("GATEWAY-FLAG-ROUTE", "request path references a flag-named segment")
        # 파라미터 값에 한해 절대경로 파일 읽기(LFI) 차단(요청 경로는 항상 '/' 시작이라 제외)
        if in_param:
            if "flag" in v:
                return ("GATEWAY-LFI", "flag file reference in parameter")
            if v.startswith("/") and not v.endswith(self._SAFE_EXT):
                return ("GATEWAY-LFI-ABS", f"absolute filesystem path in parameter: {v[:40]}")
        return None

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        first = ctx.raw.splitlines()[0].split(" ", 2) if ctx.raw else []
        if len(first) != 3 or not first[2].lower().startswith("http/"):
            return []
        if first[0].upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
            return []
        try:
            request = urllib.parse.urlsplit(first[1])
        except ValueError:
            return []
        hit = self._check(request.path, in_param=False)       # 요청 경로 traversal/LFI
        if hit is None:                                        # L2 실측: ?file=/flag 등 파라미터 LFI
            try:
                query = urllib.parse.parse_qs(request.query, keep_blank_values=True,
                                              max_num_fields=64)
            except ValueError:
                query = {}
            for key, values in query.items():
                dkey = UrlSsrGuardDetector._decode(key).lower()
                if dkey in ("service_id", "service", "svc") and any(
                        UrlSsrGuardDetector._decode(v).lower() in self._PROBE_SERVICE_IDS
                        for v in values[:4]):
                    hit = ("GATEWAY-FEEDBACK-PROBE", "vuln-scan service_id probe value")
                    break
                if dkey not in self._LFI_PARAMS:
                    continue
                for raw in values[:4]:
                    hit = self._check(raw, in_param=True)
                    if hit:
                        break
                if hit:
                    break
        if hit is None:
            return []
        rule_id, reason = hit
        enforce = self.mode == "enforce"
        return [Evidence(
            1.0 if enforce else 0.0,
            reason, f"gateway_traversal:{rule_id}", rule_id,
            EvidenceClass.ATTACK_PATTERN_CONFIRMED if enforce
            else EvidenceClass.OBSERVATION_ONLY,
            IdentificationBasis.STRUCTURE_VERIFIED,
            True, enforce, True)]


class GraphqlGuardDetector(Detector):
    """본선 L2 mission-c2(8082 HTTP/GraphQL)의 민감 resolver 접근 차단 — P2-R3 실측 6-flow 대응.

    실측(TCP 재조립 복원): POST /graphql 바디 `{"query":"{ missionAudit … }"}`가 flag를
    반환한다(정상 UI 쿼리는 `{ systemStatus { service version } }`뿐). `missionAudit`이
    flag resolver이므로 **그 필드를 선택하는 쿼리만** 차단하고, `/graphql` 전체·정상
    systemStatus·평범한 `GET /`·`GET /health`는 통과시킨다.

    강건성: HTTP 구조 확인(아니면 MQTT 등 보류) → `/graphql`·`"query"` GraphQL 컨텍스트에서만
    검사 → `\\uXXXX`·escape·공백/개행 정규화 후 필드 토큰 경계 매칭(alias `x: missionAudit`,
    batch JSON array, `__typename` 혼합에도 필드명은 그대로 남아 잡힌다). 스캔 크기 상한(_MAX_SCAN),
    파싱 실패 시 서비스 전체 차단 금지(무증거). 결정론적 — LLM·네트워크 조회 없음.
    분할/out-of-order는 엔진의 기존 TcpStreamWindow 재조립에 의존한다(중복 구현 안 함).
    """

    name = "graphql_guard"

    # PCAP 실측 민감 resolver: missionAudit(flag 반환) + systemConfig(mqtt broker password 등
    # 자격증명 탈취, 공격자 `{ systemConfig { mqtt … password } }` 시도). 정상 UI는 systemStatus만 사용.
    _SENSITIVE_FIELDS = ("missionAudit", "systemConfig")
    _MAX_SCAN = 65536                              # 전체 스캔 비용 상한(문자)
    _MAX_QUERIES = 256                             # 후보 query 문자열 상한(batch/array 합산, bounded)
    _MAX_QLEN = 8192                               # 개별 query 문자열 검사 상한
    _JSON_MAX_BODY = 262144                        # bounded JSON 파싱 대상 body 상한(문자)
    _JSON_MAX_ELEMS = 4096                         # 배열/top-level batch 방문 원소 상한
    _MAX_TXN = 16                                  # 한 stream에서 검사할 HTTP transaction 상한(pipelining)

    def __init__(self, ports=(8082,), mode="enforce", sensitive_fields=None) -> None:
        self.ports = {int(p) for p in ports}
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"
        fields = tuple(sensitive_fields) if sensitive_fields else self._SENSITIVE_FIELDS
        self.fields = fields
        # GraphQL 필드명은 case-sensitive. 식별자 경계로 매칭(missionAuditLog·premissionAudit 제외).
        self._field_re = re.compile(
            r"(?<![A-Za-z0-9_])(?:" + "|".join(re.escape(f) for f in fields)
            + r")(?![A-Za-z0-9_])")
        # 요청 라인의 method·target·version을 분리해 target을 구조적으로 파싱한다(문자열 치환 아님).
        # P2-R4 다중 공백/HTAB + P2-R5 absolute-form(`POST http://host:8082/graphql …`) 모두 대응.
        # 토큰 사이 SP/HTAB 1~16개 허용(상한), target은 공백 없는 1~2300자.
        self._req_re = re.compile(
            r"(?:POST|GET|PUT|PATCH)[ \t]{1,16}(\S{1,2300})[ \t]{1,16}HTTP/1\.[01]", re.I)
        # JSON "query" 필드의 문자열 값만 추출한다 — header·variables·무관 값의 missionAudit 오탐을 막는다.
        self._query_re = re.compile(r'"query"\s*:\s*"((?:[^"\\]|\\.)*)"')
        self._u_re = re.compile(r"\\u([0-9a-fA-F]{4})")

    def _unescape(self, s: str) -> str:
        """GraphQL query 문자열의 JSON escape 정규화(\\uXXXX·\\/·\\n 등). 결정론적·비용 상한."""
        s = s[:self._MAX_QLEN]
        try:
            s = self._u_re.sub(lambda m: chr(int(m.group(1), 16)), s)
        except ValueError:
            pass
        for a, b in (('\\"', '"'), ("\\/", "/"), ("\\n", " "), ("\\t", " "),
                     ("\\r", " "), ("\\\\", "\\")):
            s = s.replace(a, b)
        return s

    _CHUNK_MAX_CHUNKS = 4096
    _CHUNK_MAX_BODY = 131072

    @staticmethod
    def _dechunk(body: str, max_chunks: int, max_body: int) -> str:
        """HTTP chunked body 복원(bounded). chunk-size hex + optional `;ext`, CRLF, 0-size 종료.
        malformed/incomplete는 예외·무한루프 없이 그 지점까지 복원한다(파싱 실패를 DROP 근거로 쓰지 않음)."""
        out, i, n, total, count = [], 0, len(body), 0, 0
        while i < n and count < max_chunks and total < max_body:
            j = body.find("\r\n", i)
            if j == -1:
                break
            size_token = body[i:j].split(";", 1)[0].strip()      # chunk-extension 제거
            try:
                size = int(size_token, 16)
            except ValueError:
                break
            i = j + 2
            if size == 0:
                break                                            # 마지막 0-size chunk
            chunk = body[i:i + size]
            out.append(chunk)
            if len(chunk) < size:
                break                                            # 불완전 — 있는 만큼만
            total += size
            count += 1
            i += size + (2 if body[i + size:i + size + 2] == "\r\n" else 0)
        return "".join(out)

    def _dechunked_body(self, raw: str) -> "str | None":
        """Transfer-Encoding 최종 coding이 chunked면 복원한 body를 반환, 아니면 None.
        header/body 경계와 헤더 토큰을 구조적으로 확인(대소문자 무관·comma 목록)."""
        sep = raw.find("\r\n\r\n")
        if sep == -1:
            return None
        m = re.search(r"(?im)^transfer-encoding:[ \t]*([^\r\n]{1,256})$", raw[:sep])
        if not m:
            return None
        codings = [c.strip().lower() for c in m.group(1).split(",") if c.strip()]
        if not codings or codings[-1] != "chunked":
            return None
        return self._dechunk(raw[sep + 4:], self._CHUNK_MAX_CHUNKS, self._CHUNK_MAX_BODY)

    def _request_body(self, raw: str) -> "str | None":
        """헤더/보디 경계 이후의 완전한 요청 body를 반환. chunked면 복원, 아니면 그대로.
        경계 없음(요청 미완성)이면 None → 무증거(성급 DROP 금지)."""
        sep = raw.find("\r\n\r\n")
        if sep == -1:
            return None
        body = self._dechunked_body(raw)
        return body if body is not None else raw[sep + 4:]

    def _collect_queries(self, obj, out: list) -> None:
        """단일 JSON 값에서 query 문자열 후보를 out에 모은다(상한 적용).
        표준 {"query": ...}의 query 프로퍼티, 또는 top-level batch array 각 object의 query만
        본다 — variables·무관 프로퍼티의 "missionAudit"은 대상 아님. query 값은 문자열/문자열
        배열만 인정, 그 외 타입은 무증거."""
        def take(value) -> None:
            if len(out) >= self._MAX_QUERIES:
                return
            if isinstance(value, str):
                out.append(value)
            elif isinstance(value, list):
                for el in value[:self._JSON_MAX_ELEMS]:
                    if isinstance(el, str):
                        out.append(el)
                    if len(out) >= self._MAX_QUERIES:
                        break

        if isinstance(obj, dict):
            if isinstance(obj.get("query"), (str, list)):
                take(obj["query"])
        elif isinstance(obj, list):
            for el in obj[:self._JSON_MAX_ELEMS]:
                if isinstance(el, dict) and isinstance(el.get("query"), (str, list)):
                    take(el["query"])
                if len(out) >= self._MAX_QUERIES:
                    break

    def _graphql_queries(self, body: str) -> list:
        """bounded JSON 구조 해석으로 GraphQL query 문자열 후보를 추출한다(literal `"query"` regex 대체).

        JSON decoder가 key·value의 `\\uXXXX` escape를 규칙대로 복원하므로 `qu\\u0065ry`→`query`,
        `mission\\u0041udit`→`missionAudit`로 인식된다(P3-R7 실측 escaped-key/resolver 우회 차단).
        query 값 지원: 문자열 / 문자열 배열 / top-level GraphQL batch array 각 object의 query.

        raw_decode로 첫 JSON 값을 파싱하고 뒤따르는 바이트는 무시한다 — 실측 R7 body는 끝에
        NUL 패딩이 붙어 있어 엄격한 json.loads면 정상 missionAudit까지 무증거가 되어 회귀한다.
        값 사이 공백/NUL을 건너뛰며 bounded 루프로 pipelined·혼합 세그먼트의 여러 top-level 값도
        각각 검사한다. 상한: body 문자수·top-level 값 수·배열 원소 수·후보 수. malformed/미완성/
        과대 nesting은 예외 없이 [](무증거). 결정론적."""
        b = body[:self._JSON_MAX_BODY]
        dec = json.JSONDecoder()
        out: list = []
        idx, n, vals = 0, len(b), 0
        while idx < n and vals < self._MAX_QUERIES and len(out) < self._MAX_QUERIES:
            while idx < n and b[idx] in " \t\r\n\x00":   # 값 사이 공백/NUL 패딩 건너뜀
                idx += 1
            if idx >= n or b[idx] not in "{[":           # JSON object/array 시작 아님 → 중단
                break
            try:
                obj, end = dec.raw_decode(b, idx)
            except Exception:                            # noqa: BLE001 - 미완성/malformed/과대는 무증거
                break
            if end <= idx:                               # 진행 없음 → 무한루프 방지
                break
            idx = end
            vals += 1
            self._collect_queries(obj, out)
        return out[:self._MAX_QUERIES]

    def _transaction_body(self, raw: str, start: int) -> "str | None":
        """`start`의 요청 라인에 해당하는 HTTP transaction의 body를 framing으로 분리한다.
        Transfer-Encoding: chunked면 0-chunk까지 복원, Content-Length면 정확히 그 길이만,
        둘 다 없으면 첫 JSON 값까지(raw_decode가 trailing 무시). 다음 pipelined 요청 바이트가
        body에 섞이지 않게 한다. 헤더 미완성이면 None."""
        hdr_end = raw.find("\r\n\r\n", start)
        if hdr_end == -1:
            return None
        headers = raw[start:hdr_end]
        body_start = hdr_end + 4
        te = re.search(r"(?im)^transfer-encoding:[ \t]*([^\r\n]{1,256})$", headers)
        if te:
            codings = [c.strip().lower() for c in te.group(1).split(",") if c.strip()]
            if codings and codings[-1] == "chunked":
                return self._dechunk(raw[body_start:], self._CHUNK_MAX_CHUNKS, self._CHUNK_MAX_BODY)
        cl = re.search(r"(?im)^content-length:[ \t]*(\d{1,9})", headers)
        if cl:
            length = min(int(cl.group(1)), self._JSON_MAX_BODY)
            return raw[body_start:body_start + length]
        return raw[body_start:body_start + self._JSON_MAX_BODY]

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        raw = (ctx.raw or "")[:self._MAX_SCAN]
        # 재조립 stream의 각 HTTP transaction을 요청 라인 단위로 분리해 검사한다(bounded, keep-alive/
        # pipelining 대응 — 첫 요청 라인만 보고 전체를 한 요청으로 오판하지 않는다). /graphql 요청만
        # 대상: target을 urlsplit으로 구조 파싱(origin·absolute-form, path==/graphql, 비-http scheme·
        # userinfo/fragment 우회 신호 제외). 해당 transaction의 body를 framing(Content-Length/chunked)으로
        # 정확히 분리한 뒤 bounded JSON 구조 해석으로 query 후보를 얻는다 — JSON decoder가 escaped
        # key/value를 복원(P3-R7 `qu\\u0065ry`·`mission\\u0041udit`, 문자열 배열, batch array 우회 차단),
        # dechunk가 chunked 분할 복원(P2-R6). variables·header·무관 프로퍼티의 "missionAudit"은 query
        # 값이 아니라 검사 대상 아님. body 미완성·malformed·비-JSON은 무증거(성급한 DROP 금지).
        count = 0
        for match in self._req_re.finditer(raw):
            try:
                url = urllib.parse.urlsplit(match.group(1))
            except ValueError:
                continue
            if url.scheme and url.scheme.lower() not in ("http", "https"):
                continue
            if url.path.lower() != "/graphql":
                continue
            count += 1
            if count > self._MAX_TXN:
                break
            body = self._transaction_body(raw, match.start())
            if body is None:
                continue
            for query in self._graphql_queries(body):
                hit = self._field_re.search(query[:self._MAX_QLEN])
                if hit:
                    enforce = self.mode == "enforce"
                    return [Evidence(
                        1.0 if enforce else 0.0,
                        f"GraphQL query selects sensitive resolver '{hit.group(0)}' on mission-c2 (L2)",
                        "graphql_guard:sensitive_field", "MCS-GRAPHQL-MISSIONAUDIT",
                        EvidenceClass.ATTACK_PATTERN_CONFIRMED if enforce
                        else EvidenceClass.OBSERVATION_ONLY,
                        IdentificationBasis.STRUCTURE_VERIFIED,
                        True, enforce, True)]
        return []


class P4WebExploitGuardDetector(Detector):
    """P4 실측 HTTP/WebSocket 성공 공격의 인바운드 primitive만 surgical 차단."""

    name = "p4_web_exploit_guard"

    def __init__(self, ports=(8082, 9090, 8410, 8420), mode="enforce") -> None:
        self.ports = {int(p) for p in ports}
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"

    def _hit(self, rule_id: str, reason: str):
        enforce = self.mode == "enforce"
        return [Evidence(1.0 if enforce else 0.0, reason,
                         f"p4_web:{rule_id}", rule_id,
                         EvidenceClass.ATTACK_PATTERN_CONFIRMED if enforce
                         else EvidenceClass.OBSERVATION_ONLY,
                         IdentificationBasis.STRUCTURE_VERIFIED,
                         True, enforce, True)]

    @staticmethod
    def _ws_messages(data: bytes):
        """HTTP upgrade 뒤 client WebSocket frame을 bounded unmask/reassemble."""
        sep = data.find(b"\r\n\r\n")
        if sep < 0 or b"/ws/mission-feed" not in data[:sep].lower():
            return []
        out, partial, i, frames = [], bytearray(), sep + 4, 0
        while i + 2 <= len(data) and frames < 128 and sum(map(len, out)) + len(partial) < 131072:
            b0, b1 = data[i], data[i + 1]
            fin, opcode, masked, ln = bool(b0 & 0x80), b0 & 0x0f, bool(b1 & 0x80), b1 & 0x7f
            i += 2
            if ln == 126:
                if i + 2 > len(data): break
                ln = int.from_bytes(data[i:i + 2], "big"); i += 2
            elif ln == 127:
                if i + 8 > len(data): break
                ln = int.from_bytes(data[i:i + 8], "big"); i += 8
            if ln > 65536: break
            if not masked or i + 4 + ln > len(data): break
            key, i = data[i:i + 4], i + 4
            payload = bytes(b ^ key[j & 3] for j, b in enumerate(data[i:i + ln])); i += ln
            if opcode in (1, 2): partial = bytearray(payload)
            elif opcode == 0: partial.extend(payload)
            else:
                frames += 1; continue
            if fin:
                out.append(bytes(partial)); partial.clear()
            frames += 1
        return out

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        data = (ctx.payload or b"")[:131072]
        low = data.lower()
        if ctx.dport == 8082:
            for msg in self._ws_messages(data):
                try:
                    obj = json.loads(msg.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(obj, dict) and obj.get("type") == "admin_fleet_request":
                    return self._hit("MCS-WS-ADMIN-FLEET",
                                     "unauthorized admin_fleet_request on mission feed")
        if ctx.dport == 9090 and low.startswith(b"post "):
            line = low.split(b"\r\n", 1)[0]
            if b" /api/imagery/ingest" in line:
                sep = data.find(b"\r\n\r\n")
                body = data[sep + 4:] if sep >= 0 else b""
                body_low = body.lower()
                # P4-R13 실측 공격은 올바른 DjVu 매직을 가진 파일을
                # application/octet-stream으로 보내 선언 Content-Type 검사를 우회했다.
                # 업로드 전체를 막지 않고, 선언 타입 또는 검증 가능한 파일 매직과
                # 실행 표현식이 함께 있을 때만 차단한다.
                djvu_magic = body.startswith(b"AT&TFORM") and b"DJVU" in body[:32]
                declared_djvu = b"content-type: image/vnd.djvu" in low[:sep if sep >= 0 else len(low)]
                if (djvu_magic or declared_djvu) and b"${system(" in body_low:
                    return self._hit("UAV-DJVU-SYSTEM-RCE",
                                     "DjVu imagery metadata contains system expression")
            if b" /api/tasking" in line:
                sep = data.find(b"\r\n\r\n")
                if sep >= 0:
                    try: obj = json.loads(data[sep + 4:].decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError): obj = None
                    if isinstance(obj, dict) and any(
                            isinstance(obj.get(k), str) and obj[k].strip().lower().startswith("file:")
                            for k in ("plan", "source", "uri", "url")):
                        return self._hit("UAV-TASKING-FILE-URI",
                                         "mission tasking references a local file URI")
        if ctx.dport in (8410, 8420) and b"g2dds.v1.layer4service/exchange" in low:
            # P4-R12 flag-bearing Exchange 실측: protobuf message 안의 Python 실행/환경·파일
            # read primitive. Exchange 전체는 정상 제어에 필요하므로 method+primitive 결합만 차단.
            code_exec = (b"__import__" in low or
                         (b"builtins" in low and (b"eval" in low or b"exec" in low)))
            sensitive_read = (b"/proc/self/environ" in low or
                              (b"open" in low and b"read" in low and
                               (b"/flag" in low or b"../" in low)))
            # P4 payload가 code field를 base64로 감싸는 변형도 bounded decode한다. protobuf 전체를
            # 무차별 decode하지 않고 ASCII base64 후보(24..8192B, 최대 32개)만 strict 검증한다.
            decoded = []
            for token in re.findall(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,8192}={0,2}", data)[:32]:
                try:
                    blob = base64.b64decode(token, validate=True)[:16384].lower()
                except (ValueError, TypeError):
                    continue
                decoded.append(blob)
            code_exec = code_exec or any(
                b"__import__" in blob or
                (b"builtins" in blob and (b"eval" in blob or b"exec" in blob))
                for blob in decoded)
            sensitive_read = sensitive_read or any(
                b"/proc/self/environ" in blob or
                (b"open" in blob and b"read" in blob and
                 (b"/flag" in blob or b"../" in blob))
                for blob in decoded)
            # P4-R13의 새 변형은 경로 문자열을 런타임에 만들고 glob/open/read로
            # 파일을 수집해 기존의 literal /flag·../ 조건을 피했다. Exchange method와
            # 파일 열거/읽기 primitive의 강한 조합만 잡아 정상 telemetry는 보존한다.
            def file_harvest(blob: bytes) -> bool:
                glob_reader = (b"glob.glob" in blob and
                               (b"io.open" in blob or b"open" in blob) and
                               (b"handle.read" in blob or b".read" in blob))
                indirect_reader = (b"lambda" in blob and b"getattr" in blob and
                                   b"open" in blob and b"read" in blob)
                return glob_reader or indirect_reader

            harvest = file_harvest(low) or any(file_harvest(blob) for blob in decoded)
            if code_exec or sensitive_read or harvest:
                return self._hit("UGV-EXCHANGE-CODE-EXEC",
                                 "UGV Exchange carries Python execution or file-harvest primitive")
        return []


def _http_request_line(raw: str):
    """재조립 스트림 첫 HTTP 요청 라인을 (method, target) 로 파싱(다중 공백/HTAB 허용, 상한).
    실패 시 None. body/header를 요청 라인으로 오인하지 않도록 첫 줄만 본다."""
    line = raw.split("\r\n", 1)[0][:8192]
    parts = line.split()
    if len(parts) != 3 or not parts[2].lower().startswith("http/1."):
        return None
    if parts[0].upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
        return None
    if not parts[1].startswith("/"):
        return None
    return parts[0].upper(), parts[1]


def _dechunked_http_body(raw: str) -> "str | None":
    """공용: Transfer-Encoding 최종 coding이 chunked면 복원한 body를 반환, 아니면 None.
    body를 스캔하는 검사기(RSC 등)가 chunked-body 우회를 닫는 데 쓴다. GraphqlGuardDetector의
    검증된 `_dechunk`와 상한을 그대로 재사용한다(단일 구현). 파싱 실패는 DROP 근거로 쓰지 않는다."""
    sep = raw.find("\r\n\r\n")
    if sep == -1:
        return None
    m = re.search(r"(?im)^transfer-encoding:[ \t]*([^\r\n]{1,256})$", raw[:sep])
    if not m:
        return None
    codings = [c.strip().lower() for c in m.group(1).split(",") if c.strip()]
    if not codings or codings[-1] != "chunked":
        return None
    return GraphqlGuardDetector._dechunk(
        raw[sep + 4:], GraphqlGuardDetector._CHUNK_MAX_CHUNKS,
        GraphqlGuardDetector._CHUNK_MAX_BODY)


def _http_body(raw: str, start: int, max_body: int) -> "str | None":
    """공용: `start`의 요청 라인에 해당하는 HTTP transaction body를 framing으로 분리한다.
    Transfer-Encoding: chunked면 0-chunk까지 복원, Content-Length면 정확히 그 길이만, 둘 다
    없으면 max_body까지. 다음 pipelined 요청 바이트가 body에 섞이지 않게 한다. 헤더 미완성이면 None.
    GraphQL·RSC 등 body 기반 검사기가 transaction 경계를 공유하기 위한 단일 구현."""
    hdr_end = raw.find("\r\n\r\n", start)
    if hdr_end == -1:
        return None
    headers = raw[start:hdr_end]
    body_start = hdr_end + 4
    te = re.search(r"(?im)^transfer-encoding:[ \t]*([^\r\n]{1,256})$", headers)
    if te:
        codings = [c.strip().lower() for c in te.group(1).split(",") if c.strip()]
        if codings and codings[-1] == "chunked":
            return GraphqlGuardDetector._dechunk(
                raw[body_start:], GraphqlGuardDetector._CHUNK_MAX_CHUNKS,
                GraphqlGuardDetector._CHUNK_MAX_BODY)
    cl = re.search(r"(?im)^content-length:[ \t]*(\d{1,9})", headers)
    if cl:
        return raw[body_start:body_start + min(int(cl.group(1)), max_body)]
    return raw[body_start:body_start + max_body]


def _first_json_value(body: str, max_body: int):
    """공용: body의 첫 JSON 값을 raw_decode로 파싱해 반환(trailing 바이트·NUL 무시). object/array로
    시작하지 않거나 malformed/미완성이면 None(성급한 DROP 금지). 결정론적·bounded."""
    b = body[:max_body].lstrip(" \t\r\n\x00")
    if not b or b[0] not in "{[":
        return None
    try:
        obj, _end = json.JSONDecoder().raw_decode(b)
    except Exception:                                  # noqa: BLE001 - 미완성/malformed/과대는 None
        return None
    return obj


class TemplateInjectionGuardDetector(Detector):
    """L2(8082) 쿼리 파라미터의 서버측 템플릿 표현식 주입(SSTI) 차단 — P2-R4 실측 probe.

    실측: /css/style.css?q=<%= 7*7 %> / ${7*7} / {{7*7}} / #{7*7} (EJS·EL·Handlebars·Ruby 다엔진 probe).
    표현식 델리미터 **안에 산술/논리 연산이나 민감 primitive가 있을 때만** 차단한다 —
    정상 q=dark·q=검색어·{{user.name}} 같은 단순 참조는 통과(스펙: q 전체·`<`·`{{` 자체 차단 금지).
    반복 URL 디코딩 상한·표현식 길이 상한·ReDoS 안전(고정 상한 수량자).
    """

    name = "template_injection_guard"
    _MAX_SCAN = 16384
    _EXPR_RE = re.compile(
        r"<%[=\-]?\s{0,8}(.{1,200}?)\s{0,8}%>|\$\{\s{0,8}(.{1,200}?)\s{0,8}\}"
        r"|\{\{\s{0,8}(.{1,200}?)\s{0,8}\}\}|#\{\s{0,8}(.{1,200}?)\s{0,8}\}")
    _EVAL_RE = re.compile(
        r"[*/%^]|\d\s{0,4}[-+]\s{0,4}\d|process|require|child_process|global"
        r"|constructor|__proto__|eval|Function|import|exec|runtime|system|\benv\b|spawn",
        re.I)

    def __init__(self, ports=(8082,), mode="enforce") -> None:
        self.ports = {int(p) for p in ports}
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        parsed = _http_request_line((ctx.raw or "")[:self._MAX_SCAN])
        if parsed is None:
            return []
        try:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(parsed[1]).query,
                                          keep_blank_values=True, max_num_fields=64)
        except ValueError:
            return []
        for _key, values in query.items():
            for raw_value in values[:4]:
                val = UrlSsrGuardDetector._decode(raw_value)
                m = self._EXPR_RE.search(val)
                if not m:
                    continue
                inner = next((g for g in m.groups() if g), "")
                if self._EVAL_RE.search(inner):
                    enforce = self.mode == "enforce"
                    return [Evidence(
                        1.0 if enforce else 0.0,
                        "server-side template expression with eval primitive in query parameter",
                        "template_injection:expr", "MCS-TEMPLATE-EXPRESSION",
                        EvidenceClass.ATTACK_PATTERN_CONFIRMED if enforce
                        else EvidenceClass.OBSERVATION_ONLY,
                        IdentificationBasis.STRUCTURE_VERIFIED,
                        True, enforce, True)]
        return []


class RscActionGuardDetector(Detector):
    """L2(8082) /api/rsc-action의 base64 `ref` 내 코드 주입 차단 — P2-R4.

    정상 ref = base64(`JSON.stringify({service:'mission-console', … , ok:true})`) — 순수 데이터 직렬화.
    공격 = ref 안에 eval·Function·constructor·process·require·child_process 등 **실행 primitive**.
    ref 문자열만 base64 디코딩(최대 2회·길이 상한) 후 primitive를 구조적으로 확인해 차단한다 —
    /api/rsc-action 전체·ref 존재·token 존재·Base64 자체·POST 전체 차단 금지(스펙). 파싱 실패는 무증거.
    """

    name = "rsc_action_guard"
    _MAX_SCAN = 32768
    _MAX_REF = 12288
    _MAX_JSON_BODY = 262144
    _MAX_TXN = 16
    _REQLINE_RE = re.compile(
        r"(?:POST)[ \t]{1,16}(\S{1,2300})[ \t]{1,16}HTTP/1\.[01]", re.I)
    _WS_RE = re.compile(r"[ \t\r\n]")
    _B64_ALPHABET_RE = re.compile(r"\A[A-Za-z0-9+/]*={0,2}\Z")
    _DANGER_RE = re.compile(
        r"\beval\b|\bFunction\b|child_process|require\s*\(|process\s*[.\[]|global\s*[.\[]"
        r"|__proto__|constructor\s*[.(\[]|\bexec\b|\bimport\s*\(|\.env\b|spawn|execSync"
        r"|\brequire\b|Deno\b|globalThis", re.I)

    def __init__(self, ports=(8082,), mode="enforce") -> None:
        self.ports = {int(p) for p in ports}
        self.mode = mode if mode in ("off", "observe", "enforce") else "observe"

    @property
    def rule_count(self):
        return 0 if self.mode == "off" else 1

    @staticmethod
    def _b64_decode(value: str) -> str:
        """standard/URL-safe base64를 최대 2회 디코딩(중첩 대비). 실패 지점까지의 결과 반환."""
        out = value
        for _ in range(2):
            s = out.strip()
            pad = "=" * (-len(s) % 4)
            try:
                decoded = base64.b64decode(s.replace("-", "+").replace("_", "/") + pad,
                                           validate=False)
            except (ValueError, Exception):  # noqa: B014 - best effort, 절대 verdict 밖 예외 금지
                break
            try:
                text = decoded.decode("utf-8", "replace")
            except Exception:
                break
            out = text
            # 더 디코딩할 base64처럼 안 보이면 중단
            if not re.fullmatch(r"[A-Za-z0-9+/=_\-]{8,}", out.strip() or "x"):
                break
        return out

    def _ref_is_dangerous(self, ref: str) -> bool:
        """JSON-decoded ref 문자열이 base64 실행 primitive를 담는지 구조적으로 확인한다.
        ASCII whitespace(SP/HTAB/CR/LF)를 bounded 제거(P3-R8: base64 안에 JSON escape newline을
        끼워 regex 추출을 피하는 우회) 후, 정규화된 alphabet/padding을 검증하고 base64 디코딩한다."""
        cleaned = self._WS_RE.sub("", ref[:self._MAX_REF])
        if len(cleaned) < 8:
            return False
        norm = cleaned.replace("-", "+").replace("_", "/")
        norm += "=" * (-len(norm) % 4)
        if not self._B64_ALPHABET_RE.match(norm):        # 정규화 후 허용 alphabet/padding 검증
            return False
        return bool(self._DANGER_RE.search(self._b64_decode(cleaned)))

    def inspect(self, ctx: PacketContext) -> list[Evidence]:
        if self.mode == "off" or ctx.proto != 6 or ctx.dport not in self.ports:
            return []
        raw = (ctx.raw or "")[:self._MAX_SCAN]
        # 재조립 stream의 각 POST /api/rsc-action transaction을 분리해 검사한다(bounded, pipelining/
        # keep-alive 대응 — 앞선 GET /uplink·정상 요청 뒤에 붙은 RSC 공격을 놓치지 않는다). body를
        # framing으로 정확히 분리한 뒤 bounded JSON 구조로 해석한다: JSON decoder가 escaped key를
        # 복원(P3-R8 `ref`→`ref`)하고, ref 문자열의 whitespace를 제거해 base64-embedded newline
        # 우회를 닫는다. ref가 문자열이 아니면(array/object/number/null) 공격 추정 없이 무증거.
        count = 0
        for m in self._REQLINE_RE.finditer(raw):
            try:
                path = urllib.parse.urlsplit(m.group(1)).path.lower()
            except ValueError:
                continue
            if path != "/api/rsc-action":
                continue
            count += 1
            if count > self._MAX_TXN:
                break
            body = _http_body(raw, m.start(), self._MAX_JSON_BODY)
            if body is None:
                continue
            obj = _first_json_value(body, self._MAX_JSON_BODY)
            if not isinstance(obj, dict):
                continue                                    # JSON object 아님 → 무증거
            ref = obj.get("ref")
            if not isinstance(ref, str):
                continue                                    # ref가 string이 아니면 무증거
            if self._ref_is_dangerous(ref):
                enforce = self.mode == "enforce"
                return [Evidence(
                    1.0 if enforce else 0.0,
                    "executable code primitive in base64 ref of RSC action (mission-c2)",
                    "rsc_action:code_primitive", "MCS-RSC-ACTION-INJECTION",
                    EvidenceClass.ATTACK_PATTERN_CONFIRMED if enforce
                    else EvidenceClass.OBSERVATION_ONLY,
                    IdentificationBasis.STRUCTURE_VERIFIED,
                    True, enforce, True)]
        return []
