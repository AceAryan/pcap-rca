import struct

import pytest

from builders import SYN, eth, icmp, ipv4, ipv6, tcp, udp, write_pcap
from pcap_rca.detectors.base import Capture
from pcap_rca.detectors.icmp_events import detect_icmp_events

C, S, RTR = "10.0.0.1", "10.0.2.2", "10.0.0.254"


def detect(tmp_path, frames):
    return detect_icmp_events(Capture.from_file(write_pcap(tmp_path / "t.pcap", frames)))


def probe(ts, *, ttl=64, ip_id=7, dport=9999, proto="udp"):
    l4 = udp(40000, dport, b"x" * 8) if proto == "udp" else tcp(40000, dport, seq=1, flags=SYN)
    raw = ipv4(C, S, 17 if proto == "udp" else 6, l4, ttl=ttl, ip_id=ip_id)
    return raw, (ts, eth(raw))


def error(ts, itype, code, original, *, reporter=RTR, rest=b"\x00" * 4):
    return ts, eth(ipv4(reporter, C, 1, icmp(itype, code, rest=rest, body=original[:28])))


@pytest.mark.parametrize("itype,code,expected", [
    (3, 0, "ICMP_NET_UNREACHABLE"), (3, 1, "ICMP_HOST_UNREACHABLE"),
    (3, 3, "ICMP_PORT_UNREACHABLE"), (3, 9, "ICMP_ADMIN_PROHIBITED"),
    (3, 13, "ICMP_ADMIN_PROHIBITED"), (3, 2, "ICMP_UNREACHABLE_OTHER"),
    (11, 0, "ICMP_TTL_EXCEEDED"),
])
def test_classification(tmp_path, itype, code, expected):
    raw, sent = probe(0.0)
    (e,) = detect(tmp_path, [sent, error(0.01, itype, code, raw)])
    assert e.event_type == expected


def test_event_sits_on_the_original_flow(tmp_path):
    raw, sent = probe(0.0)
    (e,) = detect(tmp_path, [sent, error(0.01, 3, 1, raw)])
    assert (e.src, e.sport, e.dst, e.dport, e.proto) == (C, 40000, S, 9999, 17)
    assert e.stream_id == 0 and e.related == {"reporter": RTR, "original_frame": 1}
    assert e.evidence == [2, 1] and e.severity == "error"


def test_frag_needed(tmp_path):
    raw, sent = probe(0.0, proto="tcp", dport=443)
    (e,) = detect(tmp_path, [sent, error(0.01, 3, 4, raw, rest=struct.pack("!HH", 0, 1200))])
    assert e.event_type == "ICMP_FRAG_NEEDED"
    assert e.metrics["next_hop_mtu"] == 1200 and e.metrics["original_size"] == len(raw)


def test_icmpv6_packet_too_big(tmp_path):
    raw = ipv6("2001:db8::1", "2001:db8::2", 17, udp(1000, 2000, b"z" * 8))
    err = icmp(2, 0, rest=struct.pack("!I", 1280), body=raw[:48])
    frames = [(0.0, eth(raw, etype=0x86DD)),
              (0.01, eth(ipv6("2001:db8::fe", "2001:db8::1", 58, err), etype=0x86DD))]
    (e,) = detect(tmp_path, frames)
    assert (e.event_type, e.metrics["next_hop_mtu"], e.related["reporter"]) == \
        ("ICMP_FRAG_NEEDED", 1280, "2001:db8::fe")


def test_ttl_exceeded_loop_vs_traceroute(tmp_path):
    raw, sent = probe(0.0, ttl=64)
    (e,) = detect(tmp_path, [sent, error(0.01, 11, 0, raw)])
    assert (e.subtype, e.metrics["original_ttl"], e.severity) == ("loop", 64, "warning")

    raw, sent = probe(0.0, ttl=2, dport=5000)
    (e,) = detect(tmp_path, [sent, error(0.01, 11, 0, raw)])
    assert (e.subtype, e.severity) == ("traceroute", "info")


def test_ttl_exceeded_without_captured_original(tmp_path):
    raw, _ = probe(0.0, dport=33440)
    (e,) = detect(tmp_path, [error(0.01, 11, 0, raw)])
    assert e.subtype == "traceroute" and e.stream_id is None
    raw, _ = probe(0.0, dport=5000)
    (e,) = detect(tmp_path, [error(0.01, 11, 0, raw)])
    assert e.subtype == "unknown"


def test_ip_id_zero_matches_most_recent_packet_of_the_flow(tmp_path):
    old_raw, old = probe(0.0, ttl=3, ip_id=0)
    new_raw, new = probe(10.0, ttl=64, ip_id=0)  # same 5-tuple, much later
    (e,) = detect(tmp_path, [old, new, error(10.05, 11, 0, new_raw)])
    assert e.related["original_frame"] == 2 and e.subtype == "loop"


def test_traceroute_final_hop_is_info(tmp_path):
    raw, sent = probe(0.0, ttl=5, dport=33440)
    (e,) = detect(tmp_path, [sent, error(0.01, 3, 3, raw, reporter=S)])
    assert (e.event_type, e.subtype, e.severity) == ("ICMP_PORT_UNREACHABLE", "traceroute", "info")


def test_redirects_and_echo_are_not_events(tmp_path):
    raw, sent = probe(0.0)
    echo = (0.02, eth(ipv4(C, S, 1, icmp(8, 0, rest=struct.pack("!HH", 1, 1)))))
    redirect = error(0.01, 5, 1, raw, rest=bytes([10, 0, 0, 9]))
    assert detect(tmp_path, [sent, redirect, echo]) == []
