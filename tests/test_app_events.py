from collections import Counter

from builders import ACK, FIN, PSH, RST, SYN, tcp4, write_pcap
from pcap_rca.detectors import Capture, run_detectors
from pcap_rca.detectors.app_events import detect_app_events
from pcap_rca.detectors.base import Config
from pcap_rca.inference import infer

C, S = "10.0.0.1", "10.0.0.2"
DATA = ACK | PSH


def handshake(port=80, cport=40000, t0=0.0):
    return [tcp4(C, cport, S, port, t0, seq=0, flags=SYN),
            tcp4(S, port, C, cport, t0 + 0.001, seq=0, ack=1, flags=SYN | ACK),
            tcp4(C, cport, S, port, t0 + 0.002, seq=1, ack=1)]


def c2s(ts, seq, payload, port=80, cport=40000, **kw):
    return tcp4(C, cport, S, port, ts, seq=seq, ack=1, flags=kw.pop("flags", DATA), payload=payload, **kw)


def s2c(ts, seq, payload, port=80, cport=40000, **kw):
    return tcp4(S, port, C, cport, ts, seq=seq, ack=1, flags=kw.pop("flags", DATA), payload=payload, **kw)


def detect(tmp_path, frames, **cfg):
    capture = Capture.from_file(write_pcap(tmp_path / "t.pcap", frames))
    return detect_app_events(capture, Config(**cfg))


def types(events):
    return Counter((e.event_type, e.subtype) for e in events)


# --- HTTP ---------------------------------------------------------------------

def test_http_errors_by_class(tmp_path):
    frames = handshake() + [
        c2s(0.01, 1, b"GET /missing HTTP/1.1\r\nHost: x\r\n\r\n"),
        s2c(0.02, 1, b"HTTP/1.1 404 Not Found\r\n\r\n"),
        c2s(0.03, 40, b"GET /boom HTTP/1.1\r\nHost: x\r\n\r\n"),
        s2c(0.04, 30, b"HTTP/1.1 503 Service Unavailable\r\n\r\n"),
        c2s(0.05, 80, b"GET / HTTP/1.1\r\n\r\n"),
        s2c(0.06, 70, b"HTTP/1.1 200 OK\r\n\r\n"),
    ]
    events = detect(tmp_path, frames)
    assert types(events) == {("HTTP_ERROR_RESPONSE", "client"): 1, ("HTTP_ERROR_RESPONSE", "server"): 1}
    client, server = events
    assert (client.severity, client.metrics["status"], client.metrics["target"]) == ("info", 404, "/missing")
    assert (server.severity, server.metrics["method"], server.evidence) == ("warning", "GET", [6, 7])


def test_slow_response_counts_from_end_of_upload(tmp_path):
    frames = handshake() + [
        c2s(0.01, 1, b"POST /upload HTTP/1.1\r\nContent-Length: 2000\r\n"),
        c2s(3.00, 100, b"x" * 1000),
        c2s(6.00, 1100, b"x" * 1000),  # upload finishes at 6 s
        s2c(6.20, 1, b"HTTP/1.1 201 Created\r\n\r\n"),
    ]
    assert detect(tmp_path, frames) == []  # 200 ms server time, not 6.2 s
    (e,) = detect(tmp_path, frames, http_slow_ms=100)
    assert e.event_type == "HTTP_SLOW_RESPONSE"
    assert round(e.metrics["latency_ms"]) == 200 and round(e.metrics["request_ms"]) == 5990


def test_continue_and_pipelining(tmp_path):
    frames = handshake() + [
        c2s(0.01, 1, b"GET /a HTTP/1.1\r\n\r\n"),
        c2s(0.02, 20, b"GET /b HTTP/1.1\r\n\r\n"),
        s2c(0.03, 1, b"HTTP/1.1 100 Continue\r\n\r\n"),
        s2c(0.04, 30, b"HTTP/1.1 200 OK\r\n\r\n"),
        s2c(0.05, 60, b"HTTP/1.1 500 Internal Server Error\r\n\r\n"),
    ]
    (e,) = detect(tmp_path, frames)
    assert e.metrics["target"] == "/b"  # responses answer requests in order


def test_retransmitted_response_counted_once(tmp_path):
    resp = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
    frames = handshake() + [c2s(0.01, 1, b"GET / HTTP/1.1\r\n\r\n"),
                            s2c(0.02, 1, resp, ip_id=5), s2c(0.3, 1, resp, ip_id=6)]
    assert len(detect(tmp_path, frames)) == 1


def test_long_request_line_is_marked_truncated(tmp_path):
    frames = handshake() + [c2s(0.01, 1, b"GET /a/very/long/path/that/goes/on/and/on HTTP/1.1\r\n"),
                            s2c(0.02, 1, b"HTTP/1.1 404 Not Found\r\n")]
    (e,) = detect(tmp_path, frames)
    assert e.metrics["target"].endswith("...")


# --- TLS ----------------------------------------------------------------------

CLIENT_HELLO = bytes.fromhex("16030100c8010000c40303") + b"\x00" * 30
SERVER_HELLO = bytes.fromhex("16030300410200003d0303") + b"\x00" * 30


def alert(code):
    return bytes([0x15, 3, 3, 0, 2, 2, code])


def test_fatal_alert(tmp_path):
    frames = handshake(443) + [c2s(0.01, 1, CLIENT_HELLO, port=443),
                               s2c(0.02, 1, SERVER_HELLO, port=443),
                               c2s(0.03, 50, alert(48), port=443)]
    (e,) = detect(tmp_path, frames)
    assert (e.event_type, e.subtype, e.severity) == ("TLS_HANDSHAKE_FAILURE", "alert", "error")
    assert e.metrics == {"alert": "unknown_ca", "alert_code": 48, "sent_by": "client",
                         "server_hello": True}


def test_successful_handshake_and_encrypted_alerts_are_silent(tmp_path):
    app = bytes([0x17, 3, 3, 0, 40]) + b"\x00" * 20
    frames = handshake(443) + [c2s(0.01, 1, CLIENT_HELLO, port=443),
                               s2c(0.02, 1, SERVER_HELLO, port=443),
                               c2s(0.03, 50, app, port=443),
                               s2c(0.04, 50, alert(40), port=443)]  # after app data: not a handshake failure
    assert detect(tmp_path, frames) == []


def test_no_server_hello(tmp_path):
    hello = handshake(443) + [c2s(0.01, 1, CLIENT_HELLO, port=443)]
    closed = hello + [c2s(2.0, 50, b"", port=443, flags=ACK | FIN)]
    (e,) = detect(tmp_path, closed)
    assert (e.subtype, e.metrics["closed_by"], round(e.metrics["waited"], 2)) == \
        ("no_server_hello", "client", 1.99)

    reset = hello + [s2c(0.5, 1, b"", port=443, flags=RST)]
    (e,) = detect(tmp_path, reset)
    assert e.metrics["closed_by"] == "server" and e.metrics["reset"]

    # Still waiting when the capture ends: only judged after tls_handshake_timeout.
    tail = [tcp4(C, 1, "10.9.9.9", 2, 3.0, flags=SYN)]
    assert detect(tmp_path, hello + tail) == []
    tail = [tcp4(C, 1, "10.9.9.9", 2, 9.0, flags=SYN)]
    assert len(detect(tmp_path, hello + tail)) == 1


# --- logins -----------------------------------------------------------------------

def ftp_session(cport, t0, passwords_ok, port=21):
    frames = handshake(port, cport, t0) + [s2c(t0 + 0.01, 1, b"220 FTP ready\r\n", port=port, cport=cport)]
    seq_c, seq_s = 1, 16
    for i, ok in enumerate(passwords_ok):
        t = t0 + 0.02 + i * 0.01
        frames.append(c2s(t, seq_c, b"PASS guess\r\n", port=port, cport=cport))
        reply = b"230 Login successful\r\n" if ok else b"530 Login incorrect\r\n"
        frames.append(s2c(t + 0.005, seq_s, reply, port=port, cport=cport))
        seq_c, seq_s = seq_c + 12, seq_s + len(reply)
    return frames


def test_failed_logins(tmp_path):
    events = detect(tmp_path, ftp_session(40000, 0.0, [False, False, True]))
    assert types(events) == {("AUTH_FAILURE", "ftp"): 2}
    # "530" at the start of a segment of a non-FTP/SMTP session is not a login reply
    frames = handshake() + [s2c(0.01, 1, b"530 is a number in this HTTP body")]
    assert detect(tmp_path, frames) == []


def test_brute_force_rule(tmp_path):
    frames = []
    for i in range(4):
        frames += ftp_session(41000 + i, i * 1.0, [False, False, False] if i < 3 else [False, True])
    capture = Capture.from_file(write_pcap(tmp_path / "t.pcap", frames))
    (d,) = infer(capture, run_detectors(capture))
    assert (d.rule, d.target, d.confidence) == ("BRUTE_FORCE", "10.0.0.2:21", "high")
    assert "10 times over 4 connections" in d.evidence[0]
    assert "1 login" in d.evidence[1] and "SUCCEEDED" in d.evidence[1]
    assert d.next_steps[0].startswith("Treat the targeted account(s) as compromised")


# --- rules ----------------------------------------------------------------------

def test_tls_failure_rule_gives_specific_next_steps(tmp_path):
    frames = []
    for i in range(2):
        cport = 41000 + i
        frames += handshake(443, cport, i) + [
            c2s(i + 0.01, 1, CLIENT_HELLO, port=443, cport=cport),
            s2c(i + 0.02, 1, SERVER_HELLO, port=443, cport=cport),
            c2s(i + 0.03, 50, alert(45), port=443, cport=cport),
            tcp4(C, cport, S, 443, i + 0.031, seq=57, flags=RST)]
    capture = Capture.from_file(write_pcap(tmp_path / "t.pcap", frames))
    (d,) = infer(capture, run_detectors(capture))  # the client RSTs are claimed too
    assert (d.rule, d.target, d.confidence) == ("TLS_FAILURE", "10.0.0.2:443", "high")
    assert "2 x certificate_expired" in d.evidence[0]
    assert d.next_steps[0].startswith("Certificate problem")


def test_app_errors_rule(tmp_path):
    frames = handshake()
    for i, code in enumerate((500, 502, 404)):
        frames += [c2s(0.01 + i, 1 + 20 * i, b"GET / HTTP/1.1\r\n\r\n"),
                   s2c(0.02 + i, 1 + 40 * i, f"HTTP/1.1 {code} X\r\n\r\n".encode())]
    capture = Capture.from_file(write_pcap(tmp_path / "t.pcap", frames))
    (d,) = infer(capture, run_detectors(capture))
    assert (d.rule, d.target) == ("APP_ERRORS", "10.0.0.2:80")
    assert d.evidence == ["10.0.0.2:80 returned 2 5xx responses"]
