"""Application-layer events (docs/event_types.md §5): HTTP/1.x, TLS handshakes,
and failed logins on clear-text FTP/SMTP.

Both are recognised by content, on any port, from the first bytes of each
TCP segment (Packet.payload_head): an HTTP request line or status line, or a
TLS record header. Retransmitted segments are counted once.

Only what travels in clear text is visible:
- HTTP/2 and anything inside TLS is encrypted.
- TLS 1.3 encrypts everything after ServerHello, including most alerts, so
  a certificate rejected under TLS 1.3 shows up only as a connection that
  closes right after the handshake started (see the TCP events). TLS 1.2
  and earlier send handshake alerts in clear text.
"""
from __future__ import annotations

from collections import deque

from ..parser import FIN, RST
from ..streams import C2S, Flow, side_name
from .base import ERROR, INFO, WARNING, Capture, Config, Event, flow_event, sort_events

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ",
                b"CONNECT ", b"TRACE ")

TLS_ALERTS = {
    10: "unexpected_message", 20: "bad_record_mac", 22: "record_overflow",
    40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
    47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied", 50: "decode_error",
    51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
    80: "internal_error", 86: "inappropriate_fallback", 109: "missing_extension",
    112: "unrecognized_name", 116: "certificate_required", 120: "no_application_protocol",
}
_HANDSHAKE, _ALERT, _APP_DATA, _CCS = 0x16, 0x15, 0x17, 0x14


def _http_events(flow: Flow, cfg: Config) -> list[Event]:
    events: list[Event] = []
    pending: deque = deque()  # requests waiting for a response (HTTP/1.1 answers in order)
    seen = (set(), set())  # segment starts already handled, per direction
    for p, d in zip(flow.packets, flow.directions):
        head = p.payload_head
        if not head or p.tcp_seq in seen[d]:
            continue
        if d == C2S and head.startswith(HTTP_METHODS):
            seen[d].add(p.tcp_seq)
            parts = head.split(b" ")
            target = parts[1].decode("latin-1") if len(parts) > 1 else ""
            if len(parts) < 3:
                target += "..."  # request line longer than the bytes kept
            # [first packet, method, target, time the request finished sending]
            pending.append([p, parts[0].decode(), target, p.ts])
        elif d == C2S:
            seen[d].add(p.tcp_seq)
            if pending:
                pending[-1][3] = p.ts  # request body still uploading
        elif head.startswith(b"HTTP/1.") and head[9:12].isdigit():
            seen[d].add(p.tcp_seq)
            status = int(head[9:12])
            if 100 <= status < 200:
                continue  # informational: the real response follows
            request = pending.popleft() if pending else None
            metrics = {"status": status}
            evidence = [p.frame]
            if request is not None:
                req_pkt, method, target, sent_ts = request
                # Server latency counts from the end of the request, so a slow
                # upload (large POST) isn't blamed on the server.
                metrics.update(method=method, target=target,
                               latency_ms=(p.ts - sent_ts) * 1000,
                               request_ms=(sent_ts - req_pkt.ts) * 1000)
                evidence.insert(0, req_pkt.frame)
            start = request[0].ts if request is not None else p.ts
            if status >= 400:
                server_side = status >= 500
                events.append(flow_event(flow, "HTTP_ERROR_RESPONSE",
                                         WARNING if server_side else INFO, start, p.ts,
                                         subtype="server" if server_side else "client",
                                         evidence=evidence, metrics=dict(metrics)))
            if "latency_ms" in metrics and metrics["latency_ms"] > cfg.http_slow_ms:
                events.append(flow_event(flow, "HTTP_SLOW_RESPONSE", WARNING, start, p.ts,
                                         evidence=evidence, metrics=dict(metrics)))
    return events


# Clear-text login protocols that greet with "220" and reject a login with a
# fixed reply code: FTP "530 Login incorrect", SMTP "535 Authentication failed".
_AUTH_FAILURE_REPLIES = {b"530": "ftp", b"535": "smtp"}


def _auth_events(flow: Flow) -> list[Event]:
    server = [p for p, d in zip(flow.packets, flow.directions) if d != C2S and p.payload_head]
    if not server or not server[0].payload_head.startswith(b"220"):
        return []  # not an FTP/SMTP session
    events, seen = [], set()
    for p in server[1:]:
        code = p.payload_head[:3]
        if code in _AUTH_FAILURE_REPLIES and p.payload_head[3:4] in (b" ", b"-") \
                and p.tcp_seq not in seen:
            seen.add(p.tcp_seq)  # a retransmitted reply counts once
            events.append(flow_event(flow, "AUTH_FAILURE", WARNING, p.ts,
                                     subtype=_AUTH_FAILURE_REPLIES[code], evidence=[p.frame],
                                     metrics={"reply": code.decode()}))
    return events


def _tls_record(head: bytes) -> int | None:
    """Content type if `head` starts with a plausible TLS record header."""
    if len(head) >= 6 and head[0] in (_HANDSHAKE, _ALERT, _APP_DATA, _CCS) \
            and head[1] == 3 and head[2] <= 4:
        return head[0]
    return None


def _tls_events(flow: Flow, cfg: Config, capture_end: float) -> list[Event]:
    client_hello = server_hello = alert = None
    app_data = False
    for p, d in zip(flow.packets, flow.directions):
        ctype = _tls_record(p.payload_head)
        if ctype is None:
            continue
        head = p.payload_head
        if ctype == _HANDSHAKE:
            if head[5] == 1 and d == C2S and client_hello is None:
                client_hello = p
            elif head[5] == 2 and d != C2S and server_hello is None:
                server_hello = p
        elif ctype == _APP_DATA:
            app_data = True
        elif (ctype == _ALERT and len(head) >= 7 and head[3:5] == b"\x00\x02"
              and head[5] == 2 and not app_data and alert is None):
            alert = (p, d)  # a clear-text fatal alert before any application data
    if client_hello is None:
        return []

    if alert is not None:
        p, d = alert
        code = p.payload_head[6]
        return [flow_event(flow, "TLS_HANDSHAKE_FAILURE", ERROR, client_hello.ts, p.ts,
                           subtype="alert", evidence=[client_hello.frame, p.frame],
                           metrics={"alert": TLS_ALERTS.get(code, f"alert_{code}"),
                                    "alert_code": code, "sent_by": side_name(d),
                                    "server_hello": server_hello is not None})]
    if server_hello is not None:
        return []

    closes = [(p, d) for p, d in zip(flow.packets, flow.directions)
              if p.ts >= client_hello.ts and p.tcp_flags & (FIN | RST)]
    if closes:
        p, d = closes[0]
        return [flow_event(flow, "TLS_HANDSHAKE_FAILURE", ERROR, client_hello.ts, p.ts,
                           subtype="no_server_hello", evidence=[client_hello.frame, p.frame],
                           metrics={"closed_by": side_name(d),
                                    "waited": p.ts - client_hello.ts,
                                    "reset": bool(p.tcp_flags & RST)})]
    if capture_end - client_hello.ts >= cfg.tls_handshake_timeout:
        return [flow_event(flow, "TLS_HANDSHAKE_FAILURE", ERROR, client_hello.ts,
                           subtype="no_server_hello", evidence=[client_hello.frame],
                           metrics={"closed_by": None, "waited": capture_end - client_hello.ts,
                                    "reset": False})]
    return []


def detect_app_events(capture: Capture, config: Config | None = None) -> list[Event]:
    cfg = config or Config()
    end = capture.end_ts if capture.end_ts is not None else 0.0
    events: list[Event] = []
    for flow in capture.table.flows:
        if flow.tcp is None:
            continue
        events.extend(_http_events(flow, cfg))
        events.extend(_tls_events(flow, cfg, end))
        events.extend(_auth_events(flow))
    return sort_events(events)
