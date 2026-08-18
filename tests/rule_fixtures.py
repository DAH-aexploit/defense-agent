"""엔진 회귀 검사용 고정 룰 fixture"""

TEST_SIGNATURES = [
    {"port": 8084, "pattern": r"union\s+select", "reason": "SQLi UNION", "weight": 1.0},
    {"port": 8084, "pattern": r"sqlite_master", "reason": "SQLi schema", "weight": 1.0},
    {"port": 8082, "pattern": r"127\.0\.0\.1|/registry", "reason": "SSRF loopback", "weight": 1.0},
    {"port": 8083, "pattern": r'"role"\s*:\s*"admin"', "reason": "cookie role tamper", "weight": 1.0},
    {"port": 8082, "pattern": r"\.\./", "reason": "path traversal", "weight": 0.5},
    {"port": 8082, "pattern": r"/etc/passwd", "reason": "sensitive file", "weight": 0.5},
]

TEST_WHITELIST = [
    {"pattern": r"^get /health"},
    {"pattern": r"^get / http"},
]
