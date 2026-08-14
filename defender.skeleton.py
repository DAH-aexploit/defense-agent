"""대회 제공 구조를 보존한 최소 방어 에이전트 비교용 스켈레톤

정규식 시그니처 판정, broker SOCK_SEQPACKET 메시지 계약, heartbeat와 fail-open 최소 구현
보안·성능 보완판 ``defender.py``와의 기능 차이 확인 및 회귀 비교 전용
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import socket
import struct
import sys
import threading
import urllib.request

LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "http://litellm.lig.internal:4000").rstrip("/")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
AGENT_SOCKET = os.environ.get("AGENT_SOCKET", "/run/agent.sock")

LLM_MODEL = "gpt-4.1-mini"

MSG_PACKET = 0x01
MSG_VERDICT = 0x02
MSG_HEARTBEAT = 0x05

VERDICT_ACCEPT = 0x00
VERDICT_DROP = 0x01

MAX_PACKET_MSG_SIZE = 1 + 8 + 2 + 65535
VERDICT_MSG_SIZE = 1 + 8 + 1

PACKET_HEADER_LEN = 11

HEARTBEAT_PERIOD = 1.0

def _build_sig_index(raw) -> dict:
    """룰 목록의 목적지 포트별 컴파일 정규식 색인 변환"""
    index: dict = {}
    for sig in raw or []:
        try:
            port = int(sig["port"])
            rx = re.compile(sig["pattern"])
            reason = str(sig.get("reason", ""))
        except (KeyError, TypeError, ValueError, re.error) as e:
            logging.warning("skip bad signature %r: %s", sig, e)
            continue
        index.setdefault(port, []).append((rx, reason))
    return index

def _load_signatures() -> dict:
    """로컬 ``signatures.py`` 적재와 실패 시 빈 정책 기반 안전 기동"""
    try:
        import signatures
        raw = getattr(signatures, "SIGNATURES", [])
    except Exception as e:
        logging.warning("signatures import failed (%s) — ACCEPT-all", e)
        return {}
    return _build_sig_index(raw)

_SIG_BY_PORT = _load_signatures()

def _d_llm_chat(messages: list, timeout: float = 25.0) -> str:
    """비교용 LLM 호출 함수, verdict 경로 호출 제외"""
    body = json.dumps({"model": LLM_MODEL, "messages": messages,
                       "temperature": 0.3, "max_tokens": 800}).encode()
    req = urllib.request.Request(
        f"{LLM_BASE_URL}/v1/chat/completions", data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {LLM_API_KEY}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)["choices"][0]["message"]["content"]

_TCP_PROTO = 6

def _parse_tcp(pkt: bytes):
    """최소 IPv4/TCP 헤더 파싱과 포트·flow·payload·SYN 여부 반환"""
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0x0f) * 4
    if pkt[9] != _TCP_PROTO or len(pkt) < ihl + 20:
        return None
    sport, dport = struct.unpack_from(">HH", pkt, ihl)
    data_off = (pkt[ihl + 12] >> 4) * 4
    if data_off < 20 or len(pkt) < ihl + data_off:
        return None
    is_syn = bool(pkt[ihl + 13] & 0x02) and not (pkt[ihl + 13] & 0x10)
    payload = pkt[ihl + data_off:]
    key = (pkt[12:16], pkt[16:20], sport, dport)
    return dport, key, payload, is_syn

def _req_summary(text: str) -> str:
    """로그 노출·크기 제한을 위한 요청 첫 줄 120자 절삭"""
    line = text.split("\r\n", 1)[0]
    return line[:120]

def make_verdict(pkt_id: int, pkt_data: bytes) -> int:
    """포트별 정규식 룰 적용과 모든 내부 오류의 ACCEPT 처리"""
    del pkt_id
    try:
        parsed = _parse_tcp(pkt_data)
        if parsed is None:
            return VERDICT_ACCEPT
        dport, _key, payload, _syn = parsed

        sigs = _SIG_BY_PORT.get(dport)
        if not sigs or not payload:
            return VERDICT_ACCEPT

        text = payload.decode("latin-1")
        for rx, reason in sigs:
            if rx.search(text):
                logging.warning(
                    "AGENT-DROP port=%d reason=%s req=%s",
                    dport, reason, _req_summary(text),
                )
                return VERDICT_DROP
        return VERDICT_ACCEPT
    except Exception:
        logging.exception("make_verdict error on pkt; ACCEPT")
        return VERDICT_ACCEPT

_VERDICT_STRUCT = struct.Struct(">BQB")

def dial_seqpacket(path: str) -> socket.socket:
    """broker 제공 Unix SOCK_SEQPACKET 소켓 연결"""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    s.connect(path)
    return s

def _parse_packet(data: bytes):
    """broker PACKET frame의 64-bit ID와 raw IP packet 분리"""
    if data[0] != MSG_PACKET:
        logging.warning("unexpected msg_type=0x%02x len=%d, discarded",
                        data[0], len(data))
        return None
    if len(data) < PACKET_HEADER_LEN:
        logging.warning("short PACKET len=%d, discarded", len(data))
        return None
    pkt_id = struct.unpack_from(">Q", data, 1)[0]
    pkt_len = struct.unpack_from(">H", data, 9)[0]
    pkt_data = data[PACKET_HEADER_LEN:PACKET_HEADER_LEN + pkt_len]
    return pkt_id, pkt_data

def _verdict_for(pkt_id: int, pkt_data: bytes) -> int:
    """정책 예외의 broker loop 종료 방지를 위한 fail-open 경계 제공"""
    try:
        return make_verdict(pkt_id, pkt_data)
    except Exception:
        logging.exception("policy error on pkt_id=%d; ACCEPTing", pkt_id)
        return VERDICT_ACCEPT

def main_loop(
    sock: socket.socket,
    write_lock: threading.Lock,
    stop: threading.Event,
) -> None:
    """PACKET 수신과 VERDICT 송신의 직렬 처리 주 loop"""
    while not stop.is_set():
        try:
            data = sock.recv(MAX_PACKET_MSG_SIZE)
        except InterruptedError:
            continue
        except OSError as e:
            logging.error("recv main: %s", e)
            stop.set()
            return
        if not data:
            logging.info("broker hung up (main socket EOF)")
            stop.set()
            return

        parsed = _parse_packet(data)
        if parsed is None:
            continue
        pkt_id, pkt_data = parsed

        verdict = _verdict_for(pkt_id, pkt_data)

        msg = _VERDICT_STRUCT.pack(MSG_VERDICT, pkt_id, verdict)
        with write_lock:
            try:
                sock.send(msg)
            except BlockingIOError:
                continue
            except (BrokenPipeError, ConnectionResetError):
                stop.set()
                return
            except OSError as e:
                logging.error("send verdict: %s", e)
                stop.set()
                return

def heartbeat_loop(
    sock: socket.socket,
    write_lock: threading.Lock,
    stop: threading.Event,
) -> None:
    """broker timeout 방지를 위한 주기적 heartbeat frame 송신"""
    msg = bytes([MSG_HEARTBEAT])
    while not stop.wait(HEARTBEAT_PERIOD):
        with write_lock:
            try:
                sock.send(msg)
            except (BrokenPipeError, ConnectionResetError):
                stop.set()
                return
            except OSError as e:
                logging.warning("heartbeat send: %s", e)

def _configure_logging() -> None:
    """컨테이너 표준 오류의 일관된 timestamp 형식 로그 설정"""
    logging.basicConfig(
        level="INFO",
        format="%(asctime)s.%(msecs)03d agent %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )

def _close_quietly(sock: socket.socket) -> None:
    """종료 중 발생하는 중복 close 오류 무시"""
    try:
        sock.close()
    except OSError:
        pass

def _build_threads(
    main_sock: socket.socket,
    write_lock: threading.Lock,
    stop: threading.Event,
) -> list[threading.Thread]:
    """스켈레톤용 daemon 보조 thread 구성"""
    return [
        threading.Thread(
            target=heartbeat_loop, args=(main_sock, write_lock, stop),
            name="heartbeat", daemon=True,
        ),
    ]

def main() -> int:
    """설정 적재, broker 연결, signal 처리와 정상 종료 관리"""
    _configure_logging()

    logging.info("connecting (main=%s)", AGENT_SOCKET)

    sig_ports = sorted(_SIG_BY_PORT)
    sig_count = sum(len(v) for v in _SIG_BY_PORT.values())
    logging.info("signatures loaded: %d rule(s) over ports %s",
                 sig_count, sig_ports or "[] (blind — ACCEPT-all)")

    try:
        main_sock = dial_seqpacket(AGENT_SOCKET)
    except OSError as e:
        logging.error("dial main socket %s: %s", AGENT_SOCKET, e)
        return 1

    stop = threading.Event()
    write_lock = threading.Lock()

    def _handle_signal(signum, _frame):
        logging.info("signal %d received, shutting down", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    threads = _build_threads(main_sock, write_lock, stop)
    for t in threads:
        t.start()

    logging.info("ready: signature policy (fast ACCEPT + regex DROP)")
    try:
        main_loop(main_sock, write_lock, stop)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=2.0)
        _close_quietly(main_sock)
        logging.info("shutdown complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())
