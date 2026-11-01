from collections import Counter

import pytest

from builders import ACK, FIN, PSH, RST, SYN, eth, icmp, ipv4, syn_options, tcp, tcp4, write_pcap
from pcap_rca.detectors.base import Capture, Config
from pcap_rca.detectors.tcp_events import detect_tcp_events

C, S = "10.0.0.1", "10.0.0.2"
CISN, SISN = 1000, 5000
MSS = 1000


def detect(tmp_path, frames, **cfg):
    return detect_tcp_events(Capture.from_file(write_pcap(tmp_path / "t.pcap", frames)),
                             Config(**cfg))


def types(events):
    return Counter(e.event_type for e in events)


def handshake(t0=0.0, rtt=0.01):
    # IP IDs: client 198.., server 99.. -- sequential like Linux/Windows senders.
    return [
        tcp4(C, 40000, S, 80, t0, seq=CISN, flags=SYN, options=syn_options(), ip_id=198),
        tcp4(S, 80, C, 40000, t0 + rtt, seq=SISN, ack=CISN + 1, flags=SYN | ACK,
             options=syn_options(), ip_id=99),
        tcp4(C, 40000, S, 80, t0 + rtt + 0.0001, seq=CISN + 1, ack=SISN + 1, ip_id=199),
    ]


def data(n, ts, ip_id, ack=CISN + 1):
    """Server -> client segment number n (0-based) of MSS bytes."""
    return tcp4(S, 80, C, 40000, ts, seq=SISN + 1 + n * MSS, ack=ack, flags=ACK,
                payload=b"d" * MSS, ip_id=ip_id)


def client_ack(n, ts, ip_id, window=65535, sack=False):
    """Client ACK covering the first n server segments."""
    opts = bytes([5, 10]) + b"\x00" * 8 if sack else b""
    return tcp4(C, 40000, S, 80, ts, seq=CISN + 1, ack=SISN + 1 + n * MSS,
                window=window, options=opts, ip_id=ip_id)


# --- handshake ---------------------------------------------------------------

def test_clean_connection_has_no_events(tmp_path):
    frames = handshake() + [data(0, 0.02, 101), data(1, 0.021, 102), client_ack(2, 0.022, 201),
                            tcp4(S, 80, C, 40000, 0.03, seq=SISN + 1 + 2 * MSS, ack=CISN + 1,
                                 flags=ACK | FIN, ip_id=103),
                            tcp4(C, 40000, S, 80, 0.031, seq=CISN + 1, ack=SISN + 2 + 2 * MSS,
                                 flags=ACK | FIN, ip_id=202)]
    assert detect(tmp_path, frames) == []


def test_syn_timeout_needs_enough_capture_after_the_syn(tmp_path):
    syns = [tcp4(C, 40000, S, 80, t, seq=CISN, flags=SYN) for t in (0.0, 1.0, 3.0)]
    later = tcp4(C, 1, S, 2, 3.5, seq=1, flags=SYN)  # unrelated packet extends the capture
    events = detect(tmp_path, syns + [later])
    timeouts = [e for e in events if e.event_type == "TCP_SYN_TIMEOUT" and e.dport == 80]
    assert len(timeouts) == 1
    assert timeouts[0].metrics == {"syn_count": 3, "retry_intervals": [1.0, 2.0]}
    # The SYN to port 2 at 3.5 s is too close to the capture end to judge.
    assert not [e for e in events if e.dport == 2]


def test_conn_refused(tmp_path):
    frames = [tcp4(C, 40000, S, 81, 0.0, seq=CISN, flags=SYN),
              tcp4(S, 81, C, 40000, 0.001, seq=0, ack=CISN + 1, flags=RST | ACK)]
    (e,) = detect(tmp_path, frames)
    assert (e.event_type, e.src, e.dst, e.dport, e.evidence) == ("TCP_CONN_REFUSED", C, S, 81, [1, 2])


def test_icmp_answered_syn_is_left_to_the_icmp_detector(tmp_path):
    syn = ipv4(C, S, 6, tcp(40000, 9003, seq=CISN, flags=SYN))
    frames = [(0.0, eth(syn)), (0.001, eth(ipv4("10.0.0.254", C, 1, icmp(3, 13, body=syn[:28])))),
              tcp4(C, 1, S, 2, 10.0, flags=ACK)]
    assert not [e for e in detect(tmp_path, frames) if e.dport == 9003]


def test_incomplete_handshake_rst_after_synack(tmp_path):
    frames = handshake()[:2] + [tcp4(C, 40000, S, 80, 0.011, seq=CISN + 1, flags=RST)]
    (e,) = detect(tmp_path, frames)
    assert (e.event_type, e.subtype) == ("TCP_INCOMPLETE_HANDSHAKE", "rst_after_synack")


def test_high_rtt_absolute_and_relative(tmp_path):
    frames = handshake(rtt=0.4)
    (e,) = detect(tmp_path, frames)
    assert (e.event_type, e.metrics["rule"]) == ("TCP_HIGH_RTT", "absolute")
    assert e.metrics["irtt_ms"] == pytest.approx(400.1)

    # Five 20 ms handshakes to the same /24 and one at 100 ms: 5x the median.
    frames = []
    for i, rtt in enumerate([0.02, 0.02, 0.02, 0.02, 0.02, 0.1]):
        t0, port = i * 1.0, 41000 + i
        frames += [tcp4(C, port, S, 80, t0, seq=i, flags=SYN),
                   tcp4(S, 80, C, port, t0 + rtt, seq=9, ack=i + 1, flags=SYN | ACK),
                   tcp4(C, port, S, 80, t0 + rtt, seq=i + 1, ack=10)]
    (e,) = detect(tmp_path, frames)
    assert e.metrics["rule"] == "relative" and e.sport == 41005


def test_relative_rule_ignores_fast_lans(tmp_path):
    frames = []
    for i, rtt in enumerate([0.0001] * 5 + [0.001]):  # 0.1 ms baseline, one 1 ms
        port = 41000 + i
        frames += [tcp4(C, port, S, 80, i, seq=i, flags=SYN),
                   tcp4(S, 80, C, port, i + rtt, seq=9, ack=i + 1, flags=SYN | ACK),
                   tcp4(C, port, S, 80, i + rtt, seq=i + 1, ack=10)]
    assert detect(tmp_path, frames) == []


# --- sequence analysis -----------------------------------------------------

def test_loss_upstream_then_fast_retransmission(tmp_path):
    frames = handshake() + [
        data(0, 0.100, 100),
        # segment 1 (IP ID 101) lost before the capture point
        data(2, 0.102, 102),
        client_ack(1, 0.1021, 200),
        data(3, 0.103, 103),
        client_ack(1, 0.1031, 201, sack=True),
        data(4, 0.104, 104),
        client_ack(1, 0.1041, 202, sack=True),
        data(5, 0.105, 105),
        client_ack(1, 0.1051, 203, sack=True),
        data(1, 0.1052, 106),  # resend: higher IP ID, arrives within 1 ms
        client_ack(6, 0.106, 204),
    ]
    events = detect(tmp_path, frames)
    assert types(events) == {"TCP_RETRANSMISSION": 1, "TCP_LOST_SEGMENT": 1, "TCP_DUP_ACK": 1}
    by_type = {e.event_type: e for e in events}
    assert by_type["TCP_RETRANSMISSION"].subtype == "fast"
    assert by_type["TCP_LOST_SEGMENT"].subtype == "upstream"
    assert by_type["TCP_LOST_SEGMENT"].metrics["missing_bytes"] == MSS
    assert by_type["TCP_DUP_ACK"].metrics["run_length"] == 3


def test_reordering_is_not_a_retransmission(tmp_path):
    frames = handshake() + [
        data(0, 0.100, 100),
        data(2, 0.101, 102),
        data(1, 0.120, 101),  # 19 ms late, but sent before segment 2
        client_ack(3, 0.121, 200),
    ]
    events = detect(tmp_path, frames)
    assert types(events) == {"TCP_OUT_OF_ORDER": 1}
    assert events[0].subtype == "gap"


def test_late_original_marks_its_resend_spurious(tmp_path):
    frames = handshake() + [
        data(0, 0.100, 100),
        data(2, 0.101, 102),
        data(1, 0.150, 103),  # resend fills the gap first
        data(1, 0.151, 101),  # then the delayed original turns up
        client_ack(3, 0.152, 200),
    ]
    events = detect(tmp_path, frames)
    assert types(events) == {"TCP_RETRANSMISSION": 1, "TCP_OUT_OF_ORDER": 1, "TCP_LOST_SEGMENT": 1}
    by_type = {e.event_type: e for e in events}
    assert by_type["TCP_RETRANSMISSION"].subtype == "spurious"
    assert by_type["TCP_OUT_OF_ORDER"].subtype == "late_original"


def test_rto_retransmission_of_seen_data(tmp_path):
    frames = handshake() + [data(0, 0.1, 100), data(0, 0.4, 101), client_ack(1, 0.41, 200)]
    events = detect(tmp_path, frames)
    assert types(events) == {"TCP_RETRANSMISSION": 1}
    assert events[0].subtype == "rto" and events[0].metrics["retrans_rate"] == 0.5


def test_acked_but_never_captured_is_capture_loss(tmp_path):
    frames = handshake() + [data(0, 0.1, 100), data(1, 0.101, 101), client_ack(3, 0.102, 200)]
    (e,) = detect(tmp_path, frames)
    assert (e.event_type, e.subtype, e.metrics["missing_bytes"]) == ("TCP_LOST_SEGMENT", "capture_loss", MSS)


def test_fin_consumes_a_sequence_number(tmp_path):
    fin = tcp4(S, 80, C, 40000, 0.1, seq=SISN + 1, ack=CISN + 1, flags=ACK | FIN, ip_id=100)
    ack_fin = tcp4(C, 40000, S, 80, 0.11, seq=CISN + 1, ack=SISN + 2, ip_id=200)
    assert detect(tmp_path, handshake() + [fin, ack_fin]) == []


def test_zero_window_with_probes(tmp_path):
    frames = handshake() + [
        data(0, 0.10, 100),
        client_ack(1, 0.11, 200, window=0),
        tcp4(S, 80, C, 40000, 0.30, seq=SISN + 1 + MSS, ack=CISN + 1, payload=b"p", ip_id=101),
        tcp4(S, 80, C, 40000, 0.70, seq=SISN + 1 + MSS, ack=CISN + 1, payload=b"p", ip_id=102),
        client_ack(1, 0.90, 201, window=8192),
        data(1, 0.91, 103),
    ]
    events = detect(tmp_path, frames)
    assert types(events) == {"TCP_ZERO_WINDOW": 1}
    e = events[0]
    assert e.metrics["advertised_by"] == "client" and e.metrics["probes"] == 2
    assert e.metrics["duration"] == pytest.approx(0.79) and e.metrics["reopened"]


def test_keepalive_is_not_a_retransmission(tmp_path):
    frames = handshake() + [data(0, 0.1, 100), client_ack(1, 0.11, 200),
                            tcp4(S, 80, C, 40000, 60.0, seq=SISN + MSS, ack=CISN + 1,
                                 payload=b"\x00", ip_id=101)]
    assert detect(tmp_path, frames) == []


def test_rst_midstream(tmp_path):
    frames = handshake() + [data(0, 0.1, 100),
                            tcp4(S, 80, C, 40000, 0.2, seq=SISN + 1 + MSS, flags=RST, ip_id=101)]
    (e,) = detect(tmp_path, frames)
    assert e.event_type == "TCP_RST_MIDSTREAM" and e.severity == "warning"
    assert e.metrics["sender"] == "server" and e.metrics["bytes_before_reset"] == MSS


def test_rst_after_graceful_close_is_ignored(tmp_path):
    frames = handshake() + [
        tcp4(S, 80, C, 40000, 0.1, seq=SISN + 1, ack=CISN + 1, flags=ACK | FIN),
        tcp4(C, 40000, S, 80, 0.2, seq=CISN + 1, ack=SISN + 2, flags=ACK | FIN),
        tcp4(C, 40000, S, 80, 0.3, seq=CISN + 2, flags=RST),
    ]
    assert detect(tmp_path, frames) == []


def test_data_captured_after_its_ack_is_capture_skew(tmp_path):
    # Found on CIC-IDS2017: the mirror port records the ACK ~0.06 ms before the
    # data it acknowledges. That is neither loss nor a retransmission.
    frames = handshake() + [
        data(0, 0.100, 100),
        client_ack(2, 0.10005, 200),   # ACK for segments 0 and 1 ...
        data(1, 0.10011, 101),         # ... recorded just before segment 1
    ]
    (e,) = detect(tmp_path, frames)
    assert (e.event_type, e.subtype, e.count) == ("TCP_OUT_OF_ORDER", "capture_skew", 1)
    assert e.metrics["median_lag_ms"] == pytest.approx(0.06, abs=0.01)


def test_bogus_ack_numbers_are_ignored(tmp_path):
    frames = handshake() + [data(0, 0.1, 100),
                            tcp4(C, 40000, S, 80, 0.11, seq=CISN + 1, ack=SISN + 2**30, ip_id=200)]
    assert detect(tmp_path, frames) == []  # not "1 GB ACKed but never captured"


def test_rst_after_peer_fin_and_after_tls_close_are_info(tmp_path):
    fin_then_rst = handshake() + [
        tcp4(C, 40000, S, 80, 0.1, seq=CISN + 1, ack=SISN + 1, flags=ACK | PSH, payload=b"q" * 50),
        data(0, 0.11, 100, ack=CISN + 51),
        tcp4(C, 40000, S, 80, 0.12, seq=CISN + 51, ack=SISN + 1 + MSS, flags=ACK | FIN, ip_id=201),
        tcp4(S, 80, C, 40000, 0.13, seq=SISN + 1 + MSS, flags=RST, ip_id=101)]
    (e,) = detect(tmp_path, fin_then_rst)
    assert (e.subtype, e.severity) == ("after_peer_fin", "info")

    close_notify = bytes([0x15, 3, 3, 0, 26]) + b"\x00" * 26
    tls_then_rst = handshake() + [
        tcp4(S, 80, C, 40000, 0.1, seq=SISN + 1, ack=CISN + 1, flags=ACK | PSH, payload=close_notify),
        tcp4(S, 80, C, 40000, 0.1001, seq=SISN + 32, flags=RST)]
    (e,) = detect(tmp_path, tls_then_rst)
    assert (e.subtype, e.severity) == ("after_tls_close", "info")


def test_retransmitted_handshake_gives_no_rtt_sample(tmp_path):
    # SYN-ACK lost once: the 1 s "RTT" is the retransmission timeout (Karn's rule).
    frames = [tcp4(C, 40000, S, 80, 0.0, seq=CISN, flags=SYN),
              tcp4(C, 40000, S, 80, 1.0, seq=CISN, flags=SYN),
              tcp4(S, 80, C, 40000, 1.001, seq=SISN, ack=CISN + 1, flags=SYN | ACK),
              tcp4(C, 40000, S, 80, 1.002, seq=CISN + 1, ack=SISN + 1)]
    assert detect(tmp_path, frames) == []
