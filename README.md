# defense-agent

Deterministic packet defense agent for the DAH NFQUEUE / broker runtime.

Linux 커널의 NFQUEUE로 전달된 인바운드 패킷을 검사해 `ACCEPT`/`DROP`을 반환한다. deterministic은 같은 초기 상태와 같은 입력에 항상 같은 판정을 낸다는 의미다.

- IPv4/IPv6, TCP/UDP 패킷 검사, 정규화 + independent-evidence quorum 시그니처
- 방산 프로토콜 detector: MAVLink · CCSDS · RTPS/DDS · Modbus/TCP · UDS-over-CAN · IEC-104 · SNMP, TLS 채널 관찰
- 단일-read 구분자 knob: 정상과 구조적으로 다른 공격 read만 차단(Modbus qty · SNMP OID수 · UDS DID · IEC-104 IOA)
- 미확인 트래픽에 대한 선택적 비동기 LLM 분석

## At a glance

| | |
|---|---|
| **역할** | broker가 NFQUEUE로 넘긴 인바운드 패킷을 300ms 안에 `ACCEPT`/`DROP` |
| **채점** | `(공격 + 방어) × SLA`. 불필요하게 막으면 SLA가 깎이므로 애매하면 `observe` |
| **인바운드 전용** | 방어자는 서비스로 가는 **요청**만 본다. flag가 실린 **응답은 못 본다**. flag를 읽는 요청을 응답 전에 막는 것이 유일한 수단 |
| **정책** | read-scan detector 기본 **`enforce`** + 포트 gating. 쓰기·제어·인젝션·TLS는 `observe` |
| **배포** | 대회 노드는 `linux/amd64`. 배포는 **`make ship` 하나로만** (arm64 무음 미반영 방지) |
| **예산** | `DEF_BG_ANALYSIS=0`(기본)이면 LLM 호출 없음, 비용 ~$0 |

## Contents

[Architecture](#architecture) · [Threat Model](#threat-model) · [Runtime](#runtime) · [Installation](#installation) · [Quick Start](#quick-start) · [Rules](#rules) · [Protocol Detectors](#protocol-detectors) · [LLM Analysis](#llm-analysis) · [Configuration](#configuration) · [Safety Boundaries](#safety-boundaries) · [Competition Deployment](#competition-deployment) · [Project Structure](#project-structure)

## Architecture

- **NFQUEUE**: 커널이 iptables/nftables로 선별한 패킷을 사용자 공간에 전달
- **broker**: NFQUEUE 패킷을 에이전트에 넘기고 verdict를 커널에 적용하는 중계
- **defense agent**: 패킷을 검사해 `ACCEPT`/`DROP`을 반환하는 판정 프로그램
- **detector**: 시그니처·요청률·프로토콜 상태 이상 등 하나의 탐지 기준을 구현한 검사기

에이전트는 Ethernet 없이 IP header부터 시작하는 raw IP packet을 받아 L3/L4 parse로 주소·port·protocol·payload를 분리한다. 각 detector는 문자열이 아니라 룰 ID·근거 등급·식별 근거·선행 조건을 담은 구조화된 `Evidence`를 반환하고, 서로 다른 `source`의 독립 근거만 합산한다(independent-evidence quorum). 기본 DROP 임계값은 `1.0`이며, 같은 탐지의 반복이 아니라 다른 근거가 함께 나올 때 신뢰도가 오른다.

근거 등급: `ATTACK_PATTERN_CONFIRMED`(공격 패턴 확인) · `VIOLATION_CONFIRMED`(구조 위반 확인) · `CONTEXT_REQUIRED`(포트·profile·상태 등 선행 조건 필요) · `OBSERVATION_ONLY`(기록 전용, DROP 점수 제외). 식별·선행 조건이 확인되지 않은 Evidence는 weight와 무관하게 점수에 포함되지 않는다.

```text
Network packet → NFQUEUE/broker → L3/L4 parse + 구조 검증 → whitelist
              → signature + stateful detectors → evidence score → ACCEPT/DROP
의심/미확인 표본 → bounded 백그라운드 큐 → (선택) LLM 분석 → DEFENDER_EVENT 로그
```

## Threat Model

본선 공격 표면은 방산 프로토콜의 **read-only flag 탈취**다. 공격자는 주소·DID·OID·APID·IOA·topic 공간을 훑어 flag가 실린 값을 읽는다.

방어자는 요청만 보고 응답(flag)은 못 보므로, 대응은 flag를 읽는 **요청**을 응답 전에 막는 것뿐이다. 그래서 승부는 **공격 read가 정상 read와 구분되는가**로 갈린다.

| 구분 | 조건 | 예시 | 대응 |
|---|---|---|---|
| ✅ 구분 가능 → 차단 | 공격 read가 정상과 구조적으로 다름 | Modbus qty=16 블록(정상 qty=1), OID·DID·IOA·주소 스윕, SNMP PEN walk | read-scan enforce + 구분자 knob |
| ❌ 동일 → 구조적 불가 | 공격 read가 정상과 바이트 동일 | UDS VIN `0xF190`, SNMP `sysDescr` 단건 | 차단 불가(flag가 응답에, 인바운드 blind) |
| ◐ 다운링크 blind | flag가 응답/텔레메트리에 실림 | CCSDS TM, MAVLink MISSION_ITEM, RTPS user DATA | 관찰만(구조적 한계) |

**운영 원칙**: 라운드마다 정상 read baseline 관찰 → 공격 read의 차이 식별 → 해당 [구분자 knob](#protocol-detectors) 설정. SLA가 떨어지면 그 프로토콜만 `DEF_<P>_MODE=observe`로 즉시 롤백.

## Runtime

broker와 에이전트는 메시지 경계를 보존하는 Unix domain `SOCK_SEQPACKET`으로 frame을 한 단위씩 교환한다.

| frame | 방향 | 내용 |
|---|---|---|
| `PACKET` (`0x01`) | broker → agent | packet ID + raw IP packet |
| `VERDICT` (`0x02`) | agent → broker | packet ID + ACCEPT/DROP |
| `HEARTBEAT` (`0x05`) | agent → broker | 주기적 생존 신호 |

broker는 300ms 안에 verdict를 받아 커널에 적용해야 한다(runtime 계약). 에이전트 내부 판정 예산은 기본 50ms이고, 나머지는 통신·스케줄링·적용 지연 여유다. 처리 순서는 `parse → 구조 검증 → whitelist → detectors → evidence gate → score → verdict`. 잘린 캡처(`INCOMPLETE`)·검사 대상 아님(`UNSUPPORTED`)·detector 예외·예산 초과는 가용성을 위해 ACCEPT, 완전한 패킷의 길이·헤더 위반(`MALFORMED`)은 구조 위반 Evidence로 평가한다.

## Installation

Python >= 3.12. 엔진 코드는 macOS/Linux에서 확인 가능하나 NFQUEUE·broker 실동작은 Linux가 필요하다.

```bash
git clone git@github.com:DAH-aexploit/defense-agent.git
cd defense-agent
cp signatures.py.example signatures.py    # 독립 코드 확인용. 실제 실행은 룰 저장소의 signatures.py 사용
```

`signatures.py`는 별도의 저장소에서 관리된다.

## Quick Start

```bash
# 단독 실행 (Linux에서 NFQUEUE·broker가 먼저 AGENT_SOCKET을 만든 뒤여야 함)
AGENT_SOCKET=/run/agent.sock python3 defender.py

# DAH 통합 배포 (deploy/agents/team1/defender/ 에 반영 후)
cd ../deploy
docker compose --profile combat up -d team1-router team1-defender
docker compose logs -f team1-router team1-defender
```

`team1-router`가 NFQUEUE·broker를 소유하고 `team1-defender`가 공유 Unix socket에 연결한다.

## Rules

룰은 `signatures.py`에 작성한다.

```python
SIGNATURES = [
    {"port": 8084, "pattern": r"union\s+select", "reason": "SQLi UNION", "weight": 1.0, "target": "both"},
]
WHITELIST = [{"port": 8082, "pattern": r"^get /health"}]   # match 시 즉시 ACCEPT
```

| `SIGNATURES` 필드 | 필수 | 기본값 | 의미 |
|---|:---:|---:|---|
| `pattern` | O | 없음 | Python 정규식 |
| `id` | X | `SIG-TEXT` | 로그·Evidence 식별자 |
| `port` | X | 모든 포트 | 목적지 포트 제한 |
| `reason` | X | `pattern` | 로그 분류명 + 중복 제거용 독립 근거 `source` |
| `weight` | X | `1.0` | 근거 가중치 |
| `target` | X | `both` | `raw`/`norm`/`both` 검사 대상 |

정규화는 소문자화·이중 URL decode·SQL comment 제거·Base64 확장·공백 정리를 하며, `(a+)+` 같은 중첩 수량자 룰은 적재 단계에서 거부한다. `port`를 생략하면 전체 포트에 적용되므로 whitelist는 우회 경로가 되지 않게 좁게 지정한다. 서로 다른 룰을 독립 근거로 합산하려면 `reason`을 다르게 둔다.

숫자 파라미터 범위(`PARAM_RANGES = {포트: {이름: (min, max, weight)}}`, 현재 HTTP query/form만)와 패킷 버스트(`RATE_LIMIT`, `RequestBurstDetector`, 기본 scope `flow`)도 룰 파일에서 설정하되, 정상 baseline·오탐·재연결·sequence reset을 확인하기 전에는 켜지 않는다. 애매한 단일 신호는 `1.0`으로 즉시 차단하지 않고 다른 근거와 조합한다.

## Protocol Detectors

각 방산 detector는 `off`/`observe`/`enforce` 모드를 지원한다. `observe`는 탐지·기록만(weight 0), `enforce`는 점수를 DROP 판단에 반영한다.

**정책 (flag 유출 차단 1순위)**: read 열거(스캔) detector 기본은 **`enforce`**이며, 세 안전장치로 오탐을 막는다.

1. **포트 gating**: `DEF_*_PORTS` 미설정 시 Evidence를 만들지 않는다(포트 확인 후 발동).
2. **surgical**: 스캔을 확장하는(창 안에서 처음 보는 대상을 도입) 요청만 차단한다. 정상 클라이언트의 아는 대상 재조회는 스캔 중에도 통과한다.
3. **쓰기·제어·인젝션·TLS는 `observe`**: baseline이 없거나(쓰기·제어) 복호화가 불가(TLS)해 차단하지 않는다.

| detector | rule ID(read-scan) | 기본 | 포트 env | 구분자 knob |
|---|---|---|---|---|
| MAVLink | `MAV-READ-SCAN`, `MAV-MSGID-PROFILE` | `enforce`* | `DEF_MAVLINK_PORTS` | 없음 (다운링크 blind) |
| CCSDS | `CCSDS-READ-SCAN` | `enforce`* | `DEF_CCSDS_PORTS` | 없음 (다운링크 blind) |
| RTPS/DDS | `RTPS-READ-SCAN` | `enforce`* | `DEF_RTPS_PORTS` | 없음 (UDP·다운링크) |
| Modbus/TCP | `MODBUS-READ-SCAN` | `enforce`* | `DEF_MODBUS_PORTS` | `DEF_MODBUS_MAX_READ_QTY` |
| UDS-over-CAN | `UDS-READ-SCAN` | `enforce`* | `DEF_UDS_CAN_PORTS` | `DEF_UDS_DID_ALLOWLIST` |
| IEC-104 | `IEC104-READ-SCAN` | `enforce`* | `DEF_IEC104_PORTS` | `DEF_IEC104_IOA_ALLOWLIST` |
| SNMP v1/v2c | `SNMP-READ-SCAN` | `enforce`* | `DEF_SNMP_PORTS` | `DEF_SNMP_MAX_OIDS` |
| TLS 관찰기 | `TLS-CHANNEL-OBS` | `observe` | 없음 (포트 무관) | 없음 (복호화 불가) |

`*` enforce가 기본이지만 포트 env가 비면 미발동. 포트 확인 후에만 실제 차단한다.

**단일-read 구분자 knob** (전부 기본 OFF, 당일 baseline 확인 후 값만 채워 활성):

- `DEF_MODBUS_MAX_READ_QTY=<정상 최대 qty>`: FC01-04 read qty 초과 시 DROP(`MODBUS-READ-QTY`).
- `DEF_SNMP_MAX_OIDS=<요청당 정상 최대 OID>`: 초과 배치 스윕만 DROP(`SNMP-READ-OIDS`).
- `DEF_UDS_DID_ALLOWLIST=0xF190,0x0100`: 목록 밖 DID의 RDBI만 DROP(`UDS-READ-DID`). 비면 전체 통과.
- `DEF_IEC104_IOA_ALLOWLIST=100,101`: 목록 밖 IOA의 C_RD만 DROP(`IEC104-READ-IOA`). 비면 전체 통과.

```env
# 포트 확인 후 (기본 enforce이므로 MODE 생략 가능)
DEF_MODBUS_PORTS=502
DEF_UDS_CAN_PORTS=6801
DEF_IEC104_PORTS=2404
DEF_SNMP_PORTS=161
# baseline 확인 후 구분자 knob (선택)
DEF_MODBUS_MAX_READ_QTY=1
DEF_UDS_DID_ALLOWLIST=0xF190
```

배포 후 `make ship` 기동 로그의 `detectors: …`, `distinguisher knobs: …` 두 줄로 포트·knob 반영을 확인한다.

프로토콜 의미 검사(CRC-X25/CRC_EXTRA, CCSDS FECF·SDLS trailer, MAVLink 파라미터 범위)는 `protocol_profiles.py`에서 설정한다. 값은 예선 프로파일이며 본선 값이 아니다. 등록되지 않은 dialect message는 CRC_EXTRA를 몰라 의미 기반 차단에 쓰지 않고, FECF는 무결성만 확인하며 송신자를 인증하지 않는다.

## LLM Analysis

`DEF_BG_ANALYSIS=1`이면 미확인·의심 표본을 OpenAI-compatible gateway(LiteLLM/Azure 등)로 비동기 분석한다. 기본은 꺼져 있어 비용 0.

```env
DEF_BG_ANALYSIS=1
DEF_LLM_MODEL=gpt-4.1-mini            # 허용: gpt-4.1-mini, gpt-4.1
LLM_BASE_URL=http://litellm-gw:4000
LLM_API_KEY=your-local-gateway-key
```

제한된 미리보기만 Base64/hex로 전달하고, 신뢰할 수 없는 packet data를 system prompt와 분리한다. 응답은 `protocol_guess`·`confidence`·`evidence`·`detector_idea`만 허용하는 JSON으로 검증한다. 모델 오류·timeout·JSON 오류·호출량 제한은 verdict에 영향을 주지 않으며, 결과는 `DEFENDER_EVENT`에 기록될 뿐 자동으로 룰에 반영되지 않는다.

## Configuration

| 변수 | 기본값 | 의미 |
|---|---:|---|
| `AGENT_SOCKET` | `/run/agent.sock` | broker Unix socket 경로 |
| `DEF_DROP_THRESHOLD` | `1.0` | DROP 점수 임계값 |
| `DEF_PAYLOAD_CAP` | `16384` | 검사할 payload 최대 byte |
| `DEF_VERDICT_BUDGET_MS` | `50` | 패킷별 내부 판정 예산 |
| `DEF_STREAM_WINDOW` / `DEF_STREAM_TTL` | `32768` / `5.0` | flow별 TCP 재조립 window 상한 / 유지시간(초) |
| `DEF_<P>_MODE` | `enforce` | 방산 detector 모드(`off`/`observe`/`enforce`). `<P>` = `MAVLINK`·`CCSDS`·`RTPS`·`MODBUS`·`UDS_CAN`·`IEC104`·`SNMP` |
| `DEF_<P>_PORTS` | 빈 값 | 쉼표 구분 목적지 포트 profile. **미설정 시 미발동** |
| `DEF_MODBUS_MAX_READ_QTY` | `0` | 0=OFF. FC01-04 read의 초과 qty DROP |
| `DEF_SNMP_MAX_OIDS` | `0` | 0=OFF. 요청당 OID 초과 배치 DROP |
| `DEF_UDS_DID_ALLOWLIST` | 빈 값 | 정상 DID 목록(예: `0xF190`). 목록 밖 RDBI DROP. 비면 전체 통과 |
| `DEF_IEC104_IOA_ALLOWLIST` | 빈 값 | 정상 IOA 목록(예: `100,101`). 목록 밖 C_RD DROP. 비면 전체 통과 |
| `DEF_MAVLINK_REQUIRE_SIGNED` | `0` | 중요 MAVLink message의 서명 요구 |
| `DEF_CCSDS_SDLS_KEY_HEX` | 빈 값 | SDLS HMAC 검증용 hex key(코드·Git에 저장 안 함) |
| `DEF_TLS_MODE` | `observe` | TLS 채널 관찰(차단 안 함, 포트 무관) |
| `DEF_BG_ANALYSIS` | `0` | 백그라운드 LLM 분석 활성화 |
| `LLM_BASE_URL` / `LLM_API_KEY` / `DEF_LLM_MODEL` | 게이트웨이 / 빈 값 / `gpt-4.1-mini` | LLM 접속·모델 |
| `DEF_LLM_*` | 코드 참조 | timeout·토큰·호출 상한·쿨다운·표본 상한 등 백그라운드 분석 튜닝 |

## Safety Boundaries

- 불완전 캡처·미지원 protocol·detector 예외·verdict timeout은 ACCEPT (fail-open)
- 완전한 패킷의 IPv4/IPv6/TCP/UDP 구조 위반은 Evidence gate·임계값에 따라 DROP
- IP fragment는 완전 재조립 없이 ACCEPT, TCP는 같은 flow 연속 sequence만 제한 window로 결합
- LLM 지연·실패는 300ms fast path에서 격리, 표본·큐·호출량에 상한 적용
- 로그에는 packet 원문 대신 제한된 미리보기 또는 SHA-256 식별자만 기록

fail-open은 에이전트 장애가 서비스 중단으로 번지지 않게 오류 패킷을 차단하지 않는 정책이며, 그만큼 검사 없이 통과할 수 있다. 운영 중 broker 연결·판정 예산 초과·`analysis_error`·프로세스 재시작을 함께 모니터링한다.

## Competition Deployment

배포는 **`make ship` 하나로만** 한다. 개발본 동기화, QA, `linux/amd64` Push, 플랫폼 검증, 이미지 내부 판정 검증, 이력 기록을 한 번에 수행한다.

```bash
make ship NOTE="R2 modbus/iec104 ports + qty knob"
# 태그 지정: make ship COMPETITION_IMAGE=ligacr.azurecr.io/team9/defender:phase2-backup
```

기본 이미지는 `ligacr.azurecr.io/team9/defender:latest`. 배포 후 Make 출력 digest를 기록하고 다음 자동 Pull 이후 기동 로그와 대조한다. **ACR Push 성공만으로 대회 적용 성공을 판단하지 않는다.**

아래는 arm64 이미지를 만들 수 있어 **대회 레지스트리에 쓰지 않는다**(로컬 데모 전용).

```bash
docker build -t …:latest . ; docker compose build team1-defender
docker tag local-image …:latest ; docker push …:latest
```

## Project Structure

```text
defender.py                  broker runtime, verdict engine, background analyst
detectors.py                 normalization + finals 방산 detector plugins
rehearsal_web_detectors.py   rehearsal-skeleton-only detectors (본선 무관, 분리 보관)
protocol_profiles.py         preliminary binary protocol policy profiles
signatures.py.example        rule configuration example
tests/test_engine.py         unit·safety·broker-contract tests
tools/image_verify.py        pushed image 내부 판정 검증
tools/qa_gate.py             local QA orchestration (make qa)
Makefile                     QA·deployment shortcuts (see make ship)
```
