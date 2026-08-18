# defense-agent

Deterministic packet defense agent for the DAH NFQUEUE / broker runtime.

Linux 커널의 NFQUEUE로 전달된 패킷을 검사해 `ACCEPT` 또는 `DROP`을 반환한다. 여기서 deterministic은 같은 초기 상태와 같은 패킷 입력에 항상 같은 판정 결과를 반환한다는 의미다.

- IPv4 / IPv6, TCP / UDP packet inspection
- Weighted signatures with normalization and independent-evidence quorum
- MAVLink, CCSDS, RTPS / DDS state-aware detectors
- Optional asynchronous LLM analysis for unknown traffic

> [!IMPORTANT]
> DAH 대회 실행 노드는 `linux/amd64`다. Apple Silicon Mac에서 플랫폼을 지정하지 않고 빌드하면 `linux/arm64` 이미지가 생성되어 ACR Push는 성공해도 대회 노드에서 적용되지 않는다. 대회 배포에는 일반 `docker build`, 플랫폼 미지정 `docker compose build`, 수동 tag/push를 사용하지 않고 반드시 `make competition-push`를 사용한다.

## Contents

- [Architecture](#architecture)
- [Runtime](#runtime)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Rules](#rules)
- [Protocol Detectors](#protocol-detectors)
- [LLM Analysis](#llm-analysis)
- [Configuration](#configuration)
- [Safety Boundaries](#safety-boundaries)
- [Competition Deployment](#competition-deployment)
- [Project Structure](#project-structure)

## Architecture

구성 요소의 역할은 다음과 같다.

- **NFQUEUE** Linux 커널이 iptables/nftables로 선별한 패킷을 사용자 공간 프로그램에 전달하는 기능
- **broker** NFQUEUE 패킷을 에이전트에 전달하고 에이전트의 verdict를 다시 커널에 적용하는 중계 프로그램
- **defense agent** broker가 전달한 패킷을 검사해 `ACCEPT` 또는 `DROP`을 반환하는 판정 프로그램
- **detector** 시그니처, 요청률 또는 프로토콜 상태 이상처럼 하나의 탐지 기준을 구현한 검사기

에이전트가 받는 raw IP packet은 Ethernet header 없이 IP header부터 시작한다. L3/L4 parse는 각각 IP 계층과 TCP·UDP 전송 계층의 header를 읽어 주소, port, protocol과 payload를 분리하는 과정이다.

각 detector는 문자열 대신 룰 ID, 근거 등급, 프로토콜 식별 근거와 선행 조건을 포함한 구조화된 `Evidence`를 반환한다. 독립 근거를 합산하는 방식을 independent-evidence quorum이라고 한다. 기본 DROP 임계값은 `1.0`이며, 동일한 `source`의 반복 탐지는 한 번만 반영한다. 같은 탐지의 반복 횟수가 아니라 서로 다른 근거가 함께 발견됐을 때 차단 신뢰도가 높아지는 구조다.

근거 등급은 다음 네 가지다.

- `ATTACK_PATTERN_CONFIRMED` inbound packet에서 공격 패턴 자체가 확인된 근거
- `VIOLATION_CONFIRMED` 완전한 패킷에서 프로토콜 구조 위반이 확인된 근거
- `CONTEXT_REQUIRED` 포트·운영 profile·상태 이력 같은 선행 조건이 충족돼야 하는 근거
- `OBSERVATION_ONLY` 기록과 후속 분석에만 사용하며 DROP 점수에서 제외하는 근거

프로토콜 식별 근거는 `STRUCTURE_VERIFIED`, `PROFILE_BOUND`, `SCHEMA_DEPENDENT`로 구분한다. 각각 패킷 구조만으로 식별 가능한 경우, 포트나 운영 profile이 함께 필요한 경우, 별도 schema나 dialect 정보가 필요한 경우를 의미한다. 식별 또는 선행 조건이 확인되지 않은 Evidence는 weight와 관계없이 DROP 점수에 포함되지 않는다.

```text
Network packet
  → NFQUEUE / broker
  → L3/L4 parse + structural validation
  → whitelist
  → signature + stateful detectors
  → evidence score
  → ACCEPT / DROP

Suspicious or unknown sample
  → bounded background queue
  → optional LLM analysis
  → DEFENDER_EVENT log
```

## Runtime

broker와 에이전트는 Unix domain `SOCK_SEQPACKET`으로 통신한다. 이 socket은 TCP와 달리 한 번 보낸 메시지의 경계를 보존하므로 broker frame을 정확히 한 단위씩 읽을 수 있다. frame은 broker와 에이전트 사이에서 교환하는 하나의 메시지다.

| frame | 방향 | 내용 |
|---|---|---|
| `PACKET` (`0x01`) | broker → agent | packet ID와 raw IP packet |
| `VERDICT` (`0x02`) | agent → broker | packet ID와 ACCEPT / DROP |
| `HEARTBEAT` (`0x05`) | agent → broker | 에이전트가 실행 중임을 알리는 주기적 생존 신호 |

### 300ms verdict contract

broker는 패킷을 전달한 뒤 300ms 안에 verdict를 받아 커널에 적용해야 한다. 이 제한은 에이전트가 느려져 전체 네트워크 처리가 정지하는 상황을 막기 위한 runtime 계약이다.

에이전트의 내부 판정 예산은 기본 50ms다. 남은 시간은 broker 통신, process scheduling과 커널 적용 지연을 위한 여유로 둔다. 패킷 처리 순서는 `parse → structural validation → whitelist → detectors → evidence gate → score → verdict`다. 캡처가 잘린 `INCOMPLETE`와 검사 대상이 아닌 `UNSUPPORTED`는 ACCEPT한다. 완전한 패킷에서 확인된 길이·헤더 위반인 `MALFORMED`는 구조 위반 Evidence로 평가한다. detector 예외 또는 판정 예산 초과는 서비스 가용성을 위해 ACCEPT한다.

## Installation

Python >= 3.12. 엔진 코드는 macOS와 Linux에서 확인할 수 있지만 NFQUEUE와 broker를 포함한 실제 packet 처리는 Linux 환경이 필요하다.

```bash
git clone git@github.com:DAH-aexploit/defense-agent.git
cd defense-agent
cp signatures.py.example signatures.py
```

룰 파일은 사용 목적에 따라 다음과 같이 준비한다.

- 독립적인 코드 확인: `signatures.py.example`을 `signatures.py`로 복사
- 팀 통합 및 실제 실행: 별도 룰 저장소에서 관리하는 `signatures.py` 사용
- 공통 원칙: 실제 `signatures.py`는 이 저장소에 커밋하지 않음

## Quick Start

### Direct runtime

Linux에서 NFQUEUE와 broker가 먼저 실행되어 `AGENT_SOCKET`의 Unix socket을 생성해야 한다. 에이전트만 단독 실행하면 연결할 broker가 없어 종료된다.

```bash
AGENT_SOCKET=/run/agent.sock python3 defender.py
```

### Docker Compose integration

DAH 통합 배포 프로젝트에서는 이 저장소의 `defender.py`, `detectors.py`, `protocol_profiles.py`와 실제 `signatures.py`를 `deploy/agents/team1/defender/`에 반영한 뒤 combat profile로 실행한다.

```bash
cd ../deploy
docker compose --profile combat build team1-defender
docker compose --profile combat up -d team1-router team1-defender
docker compose logs -f team1-router team1-defender
```

`team1-router`가 NFQUEUE와 broker를 소유하고 `team1-defender`가 공유 Unix socket에 연결한다. 실제 service 이름과 경로는 통합 배포 프로젝트의 `docker-compose.yml`을 기준으로 한다.

## Competition Deployment

대회 레지스트리에 올리는 이미지는 반드시 `linux/amd64` 단일 플랫폼으로 생성한다. `make competition-push`는 다음 절차를 한 번에 수행한다.

- 전체 QA 통과 확인
- `linux/amd64` 강제 빌드
- 불필요한 provenance·SBOM manifest 제외
- ACR `latest` Push
- `linux/amd64` 지정 재Pull
- 실제 이미지 OS·아키텍처 검사
- digest와 생성 시각 출력

```bash
make competition-push
```

기본 이미지 주소는 `ligacr.azurecr.io/team9/defender:latest`다. 다른 태그가 필요하면 명시적으로 덮어쓴다.

```bash
make competition-push \
  COMPETITION_IMAGE=ligacr.azurecr.io/team9/defender:phase2-backup
```

이미 올라간 이미지의 플랫폼만 다시 검사하려면 다음 명령을 사용한다.

```bash
make competition-image-check
```

배포 후에는 Make 출력의 digest를 기록하고 다음 자동 Pull 이후 에이전트 기동 로그의 버전 식별자와 비교한다. ACR Push 성공만으로 대회 적용 성공을 판단하지 않는다.

### 금지되는 대회 배포 방식

```bash
# Apple Silicon에서 arm64 이미지가 생성될 수 있는 방식
docker build -t ligacr.azurecr.io/team9/defender:latest .
docker compose build team1-defender
docker tag local-image ligacr.azurecr.io/team9/defender:latest
docker push ligacr.azurecr.io/team9/defender:latest
```

위 명령은 로컬 데모 빌드에는 사용할 수 있지만, 그 결과를 대회 레지스트리에 Push하지 않는다.

## Rules

### Signatures

텍스트 룰은 `signatures.py`의 `SIGNATURES`에 작성한다.

```python
SIGNATURES = [
    {
        "port": 8084,
        "pattern": r"union\s+select",
        "reason": "SQLi UNION",
        "weight": 1.0,
        "target": "both",
    },
]
```

| 필드 | 필수 | 기본값 | 의미 |
|---|:---:|---:|---|
| `pattern` | O | 없음 | Python 정규식 |
| `id` | X | `SIG-TEXT` | 로그와 Evidence에 기록할 룰 식별자 |
| `port` | X | 모든 포트 | 목적지 포트 제한 |
| `reason` | X | `pattern` 문자열 | 로그 분류명과 독립 근거 식별자 |
| `weight` | X | `1.0` | 탐지 근거의 가중치 |
| `target` | X | `both` | `raw`, `norm`, `both` 중 검사 대상 |

`port`를 생략한 룰은 모든 목적지 포트에 적용된다. `reason`은 화면에 표시하는 설명인 동시에 점수 중복을 제거하는 `source` 생성에 사용된다. 서로 다른 룰을 독립 근거로 합산하려면 서로 다른 `reason`을 사용해야 한다.

`target`은 원문 `raw`, 정규화 결과 `norm`, 또는 둘 다 검사하는 `both`만 사용한다. 정규화는 소문자화, 이중 URL decode, SQL comment 제거, Base64 token 확장과 공백 정리를 수행한다. `(a+)+`, `(.*)*` 같은 중첩 수량자는 적재 단계에서 거부한다.

### Whitelist

```python
WHITELIST = [
    {"port": 8082, "pattern": r"^get /health"},
]
```

| 필드 | 필수 | 기본값 | 의미 |
|---|:---:|---:|---|
| `pattern` | O | 없음 | 즉시 ACCEPT할 Python 정규식 |
| `port` | X | 모든 포트 | 목적지 포트 제한 |

whitelist match는 즉시 ACCEPT된다. `port`를 생략하면 모든 목적지 포트에 적용되므로 공격 traffic의 우회 경로가 되지 않도록 port와 요청 형태를 좁게 지정해야 한다.

### Parameter and Packet Burst Policies

```python
PARAM_RANGES = {
    8085: {
        "gain": (0.0, 0.5, 1.0),  # min, max, weight
    },
}

RATE_LIMIT = {
    "per_sec": 50,
    "window": 1.0,
    "weight": 1.0,
    "scope": "flow",
    "max_keys": 4096,
}
```

`PARAM_RANGES`는 `{목적지 포트: {파라미터 이름: (최솟값, 최댓값, weight)}}` 구조다. 현재 HTTP query 또는 form 형태의 숫자 값만 검사하며, 바이너리 프로토콜의 필드 범위 검사는 별도 detector가 필요하다.

| `RATE_LIMIT` 필드 | 기본값 | 의미 |
|---|---:|---|
| `per_sec` | `50.0` | 초당 허용 요청 수 |
| `window` | `1.0` | 요청 수를 계산할 시간 구간(초) |
| `weight` | `1.0` | 기준 초과 시 탐지 점수 |
| `scope` | `flow` | `flow` 또는 `port` 집계 |
| `max_keys` | `4096` | 메모리에 보존할 상태 key 상한 |

rate의 기본 scope는 송신·수신 IP, 송신·수신 port와 transport protocol을 묶은 `flow`다. 여러 정상 송신자의 traffic이 합산되는 `port` scope는 정상 환경에서 측정한 요청량과 변동 범위인 burst baseline을 확인한 후에만 사용한다.

`RATE_LIMIT`은 운영 인프라의 신규 TCP connection 제한이 아니다. 방어 에이전트에 전달된 packet activity를 세는 `RequestBurstDetector` 설정이며 정상 baseline 확인 전에는 설정하지 않는 것이 기본 정책이다. 기존 룰 파일과의 호환을 위해 설정 이름 `RATE_LIMIT`과 import 별칭 `RateDetector`만 유지한다.

룰 적용 전 실제 TCP/UDP transport와 port, 정상 PCAP의 오탐, 정상 burst, 재연결과 sequence reset을 확인한다. sequence reset은 장비 재시작이나 재연결로 순번이 정상적으로 초기화되는 상황이다. 애매한 단일 신호는 `1.0`으로 즉시 차단하지 않고 서로 다른 근거로 조합한다.

## Protocol Detectors

MAVLink, CCSDS와 RTPS detector는 `off`, `observe`, `enforce` 모드를 지원한다. `observe`는 탐지와 기록만 수행하고, `enforce`는 탐지 점수를 실제 DROP 판단에 반영한다. 기본 `observe`에서는 weight가 `0`이므로 차단하지 않는다.

```env
DEF_MAVLINK_MODE=observe
DEF_MAVLINK_PORTS=14550
DEF_MAVLINK_REQUIRE_SIGNED=0

DEF_CCSDS_MODE=observe
DEF_CCSDS_PORTS=5111
# DEF_CCSDS_SDLS_KEY_HEX=hex-encoded-shared-key

DEF_RTPS_MODE=observe
DEF_RTPS_PORTS=7400
```

- **MAVLink** version, system/component ID, message ID, sequence, signed timestamp와 설정된 `PARAM_SET` 안전 범위 관찰. `COMMAND_LONG`과 `MISSION_ITEM` 핵심 필드 추출 포함. CRC-extra는 message 종류별 checksum 계산에 추가되는 값
- **CCSDS** primary header, APID, sequence, packet length, 선택적 FECF와 설정된 민감 TC 명령 관찰. 예선 SDLS 프로파일 사용 시 counter replay 및 선택적 HMAC-SHA256 검증 포함. FECF는 전송 오류를 검출하는 frame checksum이며 송신자 인증 기능은 아님
- **RTPS / DDS** protocol profile, vendor, participant GUID와 submessage boundary 관찰. participant GUID는 DDS 참여자의 식별자이고 submessage boundary는 한 메시지 안의 세부 단위 경계

현재 MAVLink parser는 프로파일에 등록된 message ID의 CRC-X25와 CRC_EXTRA를 검증한다. 등록되지 않은 message와 본선에서 추가되는 dialect 고유 message는 CRC_EXTRA를 알 수 없으므로 의미 기반 차단 대상으로 사용하지 않는다. CCSDS FECF 역시 무결성 오류를 찾을 뿐 패킷 송신자를 인증하지 않는다.

프로토콜 의미 검사는 정규식 룰과 분리된 `protocol_profiles.py`에서 설정한다. 아래 값은 예선 `dahAgent`에서 확인한 프로파일이며 본선 값으로 간주하지 않는다. 엔진은 이 파일을 실제 런타임에 읽지만 기본 모드가 `observe`이므로 명시적인 port와 `enforce` 설정 전에는 차단하지 않는다.

```python
MAVLINK_PROFILE = {
    "validate_crc": True,
    "param_ranges": {
        "EK3_ACC_P_NSE": (0.001, 1.0),
        "ATC_RAT_PIT_P": (0.0, 0.5),
    },
    "dangerous_commands": [176],
}

CCSDS_PROFILE = {
    "apids": [0x123],
    "sensitive_commands": ["DISABLE"],
    "require_sdls": True,
    "sdls_trailer_len": 36,
}
```

MAVLink 안전 범위 위반은 CRC-X25와 지원 message의 CRC_EXTRA를 확인한 뒤 payload의 `param_value`와 `param_id`를 디코딩한 결과다. MAVLink 2가 생략한 payload 끝의 zero 필드는 message 정의 길이까지 복원한다. 현재 CRC_EXTRA 목록은 예선 탐지 대상인 `PARAM_SET`, `MISSION_ITEM`, `MISSION_COUNT`, `MISSION_CLEAR_ALL`, `COMMAND_INT`, `COMMAND_LONG`에 한정된다.

CCSDS `require_sdls`는 민감 명령에 예선 형식의 SDLS trailer를 요구한다. `DEF_CCSDS_SDLS_KEY_HEX`가 설정된 경우에만 HMAC의 암호학적 유효성까지 검증하며, 키가 없으면 trailer 존재와 counter 순서만 검사한다.

MAVLink와 CCSDS는 `enforce`로 설정해도 각각 `DEF_MAVLINK_PORTS`, `DEF_CCSDS_PORTS`의 명시적 port profile이 없으면 Evidence를 DROP 점수에 반영하지 않는다. 본선 port를 확인하기 전에는 기본 `observe`를 유지한다. RTPS는 고유 `RTPS` magic으로 구조 식별이 가능하지만 본선 초기 운영 정책은 동일하게 `observe`다.

## LLM Analysis

OpenAI-compatible은 OpenAI 자체 서비스만이 아니라 동일한 `/v1/chat/completions` 요청 형식을 제공하는 LiteLLM 또는 Azure gateway도 사용할 수 있다는 의미다. endpoint와 API key를 환경변수로 주입하면 미확인 또는 의심 패킷 표본을 비동기로 분석한다.

```env
DEF_BG_ANALYSIS=1
DEF_LLM_MODEL=gpt-4.1-mini
LLM_BASE_URL=http://litellm-gw:4000
LLM_API_KEY=your-local-gateway-key
```

허용 모델은 `gpt-4.1-mini`와 `gpt-4.1`이다. 제한된 패킷 미리보기만 Base64와 hex로 전달하고, 패킷 내용을 모델 지시문으로 오인하지 않도록 분석 지시를 담은 system prompt와 신뢰할 수 없는 packet data를 분리한다.

응답은 다음 필드만 허용하는 JSON object로 검증한다.

- `protocol_guess`
- `confidence`
- `evidence`
- `detector_idea`

결과, 지연시간과 token usage는 `DEFENDER_EVENT`에 기록된다.

```bash
docker compose logs -f team1-defender | grep DEFENDER_EVENT
```

모델 오류, timeout, 잘못된 JSON과 호출량 제한은 verdict에 영향을 주지 않는다. 분석 결과도 자동으로 룰에 반영하지 않는다.

## Configuration

| 변수 | 기본값 | 의미 |
|---|---:|---|
| `AGENT_SOCKET` | `/run/agent.sock` | broker Unix socket 경로 |
| `DEF_DROP_THRESHOLD` | `1.0` | DROP 점수 임계값 |
| `DEF_PAYLOAD_CAP` | `16384` | 검사할 payload 최대 byte |
| `DEF_VERDICT_BUDGET_MS` | `50` | 패킷별 내부 판정 예산 |
| `DEF_STREAM_WINDOW` | `32768` | flow별 TCP 연속 payload 보존 상한 |
| `DEF_STREAM_TTL` | `5.0` | TCP window 유지시간(초) |
| `DEF_MAVLINK_MODE` | `observe` | MAVLink detector의 `off`, `observe`, `enforce` 모드 |
| `DEF_MAVLINK_PORTS` | 빈 값 | 쉼표로 구분한 MAVLink 목적지 포트 profile |
| `DEF_MAVLINK_REQUIRE_SIGNED` | `0` | 중요 MAVLink message의 서명 요구 여부 |
| `DEF_CCSDS_MODE` | `observe` | CCSDS detector의 `off`, `observe`, `enforce` 모드 |
| `DEF_CCSDS_PORTS` | 빈 값 | 쉼표로 구분한 CCSDS 목적지 포트 profile |
| `DEF_CCSDS_SDLS_KEY_HEX` | 빈 값 | SDLS HMAC 검증용 hex key, 코드나 Git에 저장하지 않음 |
| `DEF_RTPS_MODE` | `observe` | RTPS detector의 `off`, `observe`, `enforce` 모드 |
| `DEF_RTPS_PORTS` | 빈 값 | 쉼표로 구분한 RTPS 목적지 포트 profile |
| `DEF_BG_ANALYSIS` | `0` | 백그라운드 LLM 분석 활성화 여부 |
| `LLM_BASE_URL` | `http://litellm.lig.internal:4000` | OpenAI-compatible gateway 주소 |
| `LLM_API_KEY` | 빈 값 | gateway 인증 key. 코드나 Git에 저장하지 않음 |
| `DEF_LLM_MODEL` | `gpt-4.1-mini` | LLM 분석 모델 |
| `DEF_LLM_TIMEOUT_SECONDS` | `20` | LLM 요청 제한시간(초) |
| `DEF_LLM_MAX_COMPLETION_TOKENS` | `120` | LLM 최대 출력 token |
| `DEF_LLM_CALLS_PER_MINUTE` | `6` | 분당 LLM 호출 상한 |
| `DEF_LLM_CALLS_PER_RUN` | `60` | 실행당 LLM 호출 상한 |
| `DEF_LLM_PORT_COOLDOWN_SECONDS` | `10` | 동일 protocol·port 재호출 대기시간 |
| `DEF_LLM_QUEUE_MAX_AGE_SECONDS` | `30` | 분석 대기열 항목 최대 수명 |
| `DEF_UNKNOWN_SAMPLE_LIMIT` | `24` | 실행당 미확인 표본 상한 |
| `DEF_UNKNOWN_SAMPLES_PER_PORT` | `2` | protocol·port별 표본 상한 |

## Safety Boundaries

- 캡처 불완전 packet과 지원하지 않는 protocol은 ACCEPT
- 완전한 packet의 IPv4·IPv6·TCP·UDP 구조 위반은 Evidence gate와 임계값에 따라 DROP
- IPv4 / IPv6 fragment는 완전 재조립 없이 ACCEPT
- TCP는 같은 flow의 연속 sequence만 제한된 window로 결합
- detector 예외와 verdict timeout은 ACCEPT
- LLM 지연과 실패는 300ms 안에 verdict를 반환하는 fast path에서 격리
- 미확인 표본 추출, 크기가 제한된 대기열, 분당 호출과 실행당 호출에 상한 적용
- packet 원문 대신 제한된 미리보기 또는 SHA-256 식별자를 로그에 기록

fail-open은 에이전트 장애가 전체 서비스 중단으로 이어지는 것을 막기 위해 오류가 발생한 패킷을 차단하지 않는 정책이다. 이는 해당 패킷이 검사 없이 통과할 수 있다는 의미이기도 하다. 운영 중 broker 연결, 판정 예산 초과, `analysis_error`와 프로세스 재시작을 함께 모니터링해야 한다.

## Project Structure

```text
defender.py                  broker runtime, verdict engine, background analyst
detectors.py                 normalization and finals-relevant detector plugins
rehearsal_web_detectors.py   rehearsal-skeleton-only detectors (SSRF/session/traversal/SQLi
                              structure guard) — irrelevant to the finals, kept separate so
                              finals protocol work never has to touch this file
protocol_profiles.py         preliminary binary protocol policy profiles
signatures.py.example        rule configuration example
tests/
  test_engine.py             unit, safety and broker-contract tests
  packet_util.py             synthetic raw packet builder
  qa_replay.py                deterministic PCAP regression
tools/
  bench.py                   verdict performance checks
  pcap_analyze.py             classic PCAP analyzer
  round_report.py            round artefact analysis (auto-detects service port)
  round_watch.py             watches for new round artefacts and analyzes them
  image_verify.py            verdict checks inside the pushed image
  qa_gate.py                  local QA orchestration and evidence
  dependency_audit.py         deployment dependency policy check
Makefile                     QA and deployment command shortcuts (see `make ship`)
```
