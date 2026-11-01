import struct
from collections import Counter

from builders import ACK, SYN, dns_message, tcp4, udp4, write_pcap
from pcap_rca.detectors.base import Capture, Config
from pcap_rca.detectors.dns_events import detect_dns_events

C, R, R2 = "10.0.0.1", "10.0.0.53", "10.0.0.54"


def detect(tmp_path, frames, **cfg):
    return detect_dns_events(Capture.from_file(write_pcap(tmp_path / "t.pcap", frames)),
                             Config(**cfg))


def query(ts, name, qid=1, sport=40000, server=R, qtype=1):
    return udp4(C, sport, server, 53, ts, dns_message(qid, name, qtype=qtype))


def answer(ts, name, qid=1, sport=40000, server=R, **kw):
    return udp4(server, 53, C, sport, ts, dns_message(qid, name, response=True, **kw))


def tail(ts):
    """An unrelated packet that keeps the capture running until `ts`."""
    return tcp4(C, 1, "10.9.9.9", 2, ts, flags=SYN)


def types(events):
    return Counter(e.event_type for e in events)


def test_answered_lookup_is_silent(tmp_path):
    assert detect(tmp_path, [query(0, "ok.example"), answer(0.02, "ok.example", answers=["192.0.2.1"])]) == []


def test_rcode_events(tmp_path):
    frames = [query(0, "nx.example", qid=1), answer(0.01, "nx.example", qid=1, rcode=3),
              query(1, "sf.example", qid=2, sport=40001),
              answer(1.01, "sf.example", qid=2, sport=40001, rcode=2),
              query(2, "rf.example", qid=3, sport=40002),
              answer(2.01, "rf.example", qid=3, sport=40002, rcode=5)]
    events = detect(tmp_path, frames)
    assert types(events) == {"DNS_NXDOMAIN": 1, "DNS_SERVFAIL": 1, "DNS_REFUSED": 1}
    nx = events[0]
    assert nx.metrics["qname"] == "nx.example" and nx.metrics["qtype"] == "A"
    assert (nx.src, nx.dst, nx.dport, nx.evidence) == (C, R, 53, [1, 2])


def test_retries_then_timeout_is_one_transaction(tmp_path):
    frames = [query(0, "drop.example"), query(1, "drop.example"), query(2, "drop.example", server=R2),
              tail(10)]
    events = detect(tmp_path, frames)
    assert types(events) == {"DNS_TIMEOUT": 1, "DNS_RETRANSMISSION": 2}
    timeout = next(e for e in events if e.event_type == "DNS_TIMEOUT")
    assert timeout.metrics["queries"] == 3 and timeout.metrics["servers"] == [R, R2]


def test_no_timeout_when_capture_ends_too_soon(tmp_path):
    assert detect(tmp_path, [query(0, "x.example"), tail(1.0)]) == []


def test_retry_answered_late_is_slow_and_retransmitted(tmp_path):
    frames = [query(0, "slow.example"), query(1, "slow.example"),
              answer(1.2, "slow.example", answers=["192.0.2.1"])]
    events = detect(tmp_path, frames)
    assert types(events) == {"DNS_RETRANSMISSION": 1, "DNS_SLOW_RESPONSE": 1}
    slow = next(e for e in events if e.event_type == "DNS_SLOW_RESPONSE")
    assert abs(slow.metrics["latency_ms"] - 1200) < 1e-6


def test_same_name_much_later_is_a_new_transaction(tmp_path):
    frames = [query(0, "a.example"), answer(0.01, "a.example", answers=["192.0.2.1"]),
              query(60, "a.example", qid=2), answer(60.01, "a.example", qid=2, answers=["192.0.2.1"])]
    assert detect(tmp_path, frames) == []


def test_nodata_but_not_for_truncated(tmp_path):
    frames = [query(0, "v4only.example", qtype=28), answer(0.01, "v4only.example", qtype=28)]
    (e,) = detect(tmp_path, frames)
    assert e.event_type == "DNS_NODATA" and e.metrics["qtype"] == "AAAA"


def test_tcp_fallback(tmp_path):
    big = [query(0, "big.example"), answer(0.01, "big.example", tc=True)]
    # Client retries over TCP and the connection is established.
    ok = big + [tcp4(C, 41000, R, 53, 0.02, seq=1, flags=SYN),
                tcp4(R, 53, C, 41000, 0.03, seq=9, ack=2, flags=SYN | ACK),
                tcp4(C, 41000, R, 53, 0.04, seq=2, ack=10)]
    (e,) = detect(tmp_path, ok)
    assert (e.event_type, e.severity, e.metrics["tcp_attempted"], e.metrics["tcp_ok"]) == \
        ("DNS_TCP_FALLBACK", "info", True, True)
    # TCP/53 blocked: SYN never answered.
    (e,) = detect(tmp_path, big + [tcp4(C, 41000, R, 53, 0.02, seq=1, flags=SYN)])
    assert (e.severity, e.metrics["tcp_attempted"], e.metrics["tcp_ok"]) == ("error", True, False)
    # No retry at all.
    (e,) = detect(tmp_path, big)
    assert e.metrics["tcp_attempted"] is False


def test_tcp_retry_after_truncation_is_not_a_retransmission(tmp_path):
    msg = dns_message(9, "big.example")
    frames = [query(0, "big.example"), answer(0.01, "big.example", tc=True),
              tcp4(C, 41000, R, 53, 0.03, seq=2, ack=10, flags=ACK,
                   payload=struct.pack("!H", len(msg)) + msg)]
    assert types(detect(tmp_path, frames)) == {"DNS_TCP_FALLBACK": 1}


def test_response_without_captured_query(tmp_path):
    (e,) = detect(tmp_path, [answer(0, "nx.example", rcode=3)])
    assert e.event_type == "DNS_NXDOMAIN" and e.src == C


def test_duplicate_answers_counted_once(tmp_path):
    frames = [query(0, "nx.example"), answer(0.01, "nx.example", rcode=3),
              answer(0.02, "nx.example", rcode=3)]
    assert types(detect(tmp_path, frames)) == {"DNS_NXDOMAIN": 1}


def test_non_query_opcodes_ignored(tmp_path):
    update = bytearray(dns_message(5, "host.example", response=True, rcode=5))
    update[2] |= 5 << 3  # opcode 5 = UPDATE
    assert detect(tmp_path, [udp4(R, 53, C, 40000, 0, bytes(update))]) == []
