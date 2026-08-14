"""예선 dahAgent에서 확인된 방산 프로토콜 의미 프로파일

본선 포트와 wire schema 확정 전 기본 observe 운용을 전제로 한 초기값
정규식 시그니처 담당 파일과 바이너리 프로토콜 정책의 변경 책임 분리
"""

MAVLINK_PROFILE = {
    "validate_crc": True,
    "param_ranges": {
        "EK3_ACC_P_NSE": (0.001, 1.0),
        "EK3_GYRO_P_NSE": (0.0001, 0.1),
        "ATC_RAT_PIT_P": (0.0, 0.5),
        "ATC_RAT_RLL_P": (0.0, 0.5),
        "RATE_PIT_P": (0.0, 0.5),
        "RATE_RLL_P": (0.0, 0.5),
    },
    # MAV_CMD_DO_SET_MODE=176
    # 명령 자체가 아닌 unsigned 조건과 결합한 판정용 프로파일
    "dangerous_commands": [176],
}

CCSDS_PROFILE = {
    "apids": [0x123],
    "sensitive_commands": ["DISABLE"],
    "require_sdls": True,
    # 예선 모델의 4byte counter + 32byte HMAC-SHA256
    "sdls_trailer_len": 36,
}
