FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

LABEL org.opencontainers.image.title="DAH Team 9 Defender" \
      org.opencontainers.image.description="Standard-library-only defensive packet agent"

WORKDIR /app

COPY defender.py detectors.py rehearsal_web_detectors.py protocol_profiles.py signatures.py ./

RUN dpkg-query -W -f='${binary:Package}\t${Version}\n' > /app/system-packages.tsv \
 && python -m pip list --format=json > /app/python-packages.json

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# 본선 레이어 포트 바인딩 (참가자 Layers 화면 기준, 라운드마다 재확인). 미설정 detector는 inactive.
#   L1 starlink-gw 8080/9000 = HTTP auth gateway → 웹/SSRF 가드로 커버(방산 바이너리 아님)
# 실측 프로토콜(R9 PCAP 구조 확인):
#   L1 8080 = HTTP gateway, 9000 = gRPC(h2c)
#   L2 8082 = HTTP/GraphQL(mission-c2), MQTT 공존
#   L3 1883 = MQTT(CONNECT/SUBSCRIBE), 8554 = RTSP(DESCRIBE/OPTIONS rtsp://), 9090 = HTTP
# MAVLink는 본선 포트에서 미확인(1883=MQTT·8554=RTSP·9090=HTTP) → 추측 바인딩 금지, inactive로 둔다.
# 구조검증+surgical+포트gating이 안전장치. SLA 하락 시 해당 DEF_<P>_MODE=observe로 즉시 롤백.
ENV DEF_MQTT_PORTS=8082,1883 \
    DEF_URL_GUARD_PORTS=8082,8080,9000 \
    DEF_GRPC_PORTS=9000 \
    DEF_GATEWAY_TRAVERSAL_PORTS=8080,8082,8410,8420 \
    DEF_GRAPHQL_PORTS=8082 \
    DEF_P4_WEB_MODE=enforce

# SLA 안전장치(rule 단위 observe 다운그레이드, signatures.py 미수정·가역).
# UAV-MQTT-001: 패턴이 모든 정상 MQTT CONNECT(\x10..MQTT\x04\x02..)를 매치·DROP → 1883 SLA 붕괴.
# 실측 R9 L3: 정상 CONNECT 375건 오탐 DROP. observe로 내림. MQTT # 공격은 UAV-MQTT-003이 계속 차단.
ENV DEF_OBSERVE_RULE_IDS=UAV-MQTT-001

# MQTT root-global wildcard(#·+/#·+/+/#·$share/<g>/#) enforce 전환. R9·R10 실측: 실제 공격이
# `SUBSCRIBE #`로 flag 탈취. paired-normal(uav/#·uav/telemetry/#·$share/g/uav/#·exact)은 모두 ACCEPT라
# concrete prefix 없는 root-global만 high-confidence read primitive로 즉시 DROP한다. SLA 원인은
# UAV-MQTT-001(CONNECT 오탐, 위에서 observe 강등)이었고 broad-#와 무관하므로 enforce가 안전하다.
ENV DEF_MQTT_BROAD_ENFORCE=1

# P4-R11 실측: L4 8410/8420은 HTTP/1.1 + h2c/gRPC이며 RTPS/MQTT/UDS/Modbus가 아니다.
# 잘못된 바이너리 관찰망은 비활성화하고, 위 HTTP 가드로 직접 flag 경로만 surgical 차단한다.

# 백그라운드 LLM 분석(애매·미탐 트래픽 → 시그니처 후보 로그). 판정경로 밖·SLA 무관·best-effort.
# 사용자 승인으로 키 포함(fallback). 대회 런타임이 LLM_API_KEY 주입 시 그쪽이 우선(override).
# LLM_BASE_URL 기본값 http://litellm.lig.internal:4000 그대로 사용.
ENV DEF_BG_ANALYSIS=1 \
    LLM_API_KEY=sk-GUUVPBV5Edm1Hwk7qHO2tw

USER 65534:65534

ENTRYPOINT ["python", "/app/defender.py"]
