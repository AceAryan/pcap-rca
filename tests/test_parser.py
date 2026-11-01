import struct

import pytest

from builders import (ACK, DATA_DIR, PSH, SYN, dns_message, eth, icmp, ipv4, ipv6,
                      syn_options, tcp, tcp4, udp, udp4, write_pcap, write_pcapng)
from pcap_rca.parser import (ICMPV6, TCP, UDP, UnsupportedCapture, flag_str,
                             load_packets)

A, B = "10.0.0.1", "10.0.0.2"


def load(tmp_path, frames, **kw):
    return load_packets(write_pcap(tmp_path / "t.pcap", frames, **kw))


def test_tcp_syn_header_and_options(tmp_path):
    pkts, stats = load(tmp_path, [tcp4(A, 40000, B, 80, 1.5, seq=1000, flags=SYN,
                                       options=syn_options(mss=1400, wscale=7), ip_id=7, ttl=61)])
    p = pkts[0]
    assert (p.frame, p.ts, p.src, p.sport, p.dst, p.dport) == (1, 1.5, A, 40000, B, 80)
    assert (p.proto, p.ttl, p.ip_id, p.dont_fragment) == (TCP, 61, 7, True)
    assert (p.tcp_seq, p.tcp_flags, flag_str(p.tcp_flags)) == (1000, SYN, "S")
    assert (p.tcp_mss, p.tcp_wscale, p.tcp_sack_permitted, p.tcp_tsval) == (1400, 7, True, 1000)
    assert p.payload_len == 0
    assert stats.ip_packets == 1 and stats.malformed == 0


def test_payload_length_comes_from_ip_header_not_capture(tmp_path):
    # 1000-byte payload, but the capture only kept the first 100 bytes of the frame.
    frame = eth(ipv4(A, B, 6, tcp(80, 40000, flags=ACK | PSH, payload=b"x" * 1000)))
    pkts, _ = load(tmp_path, [(0.0, frame)], snaplen=100)
    assert pkts[0].payload_len == 1000
    assert pkts[0].ip_len == 1040
    assert not pkts[0].truncated


def test_frame_numbers_count_non_ip_frames(tmp_path):
    arp = eth(b"\x00" * 28, etype=0x0806)
    pkts, stats = load(tmp_path, [(0.0, arp), tcp4(A, 1, B, 2, 0.1)])
    assert [p.frame for p in pkts] == [2]
    assert (stats.frames, stats.non_ip, stats.ip_packets) == (2, 1, 1)


def test_vlan_tagged_frame(tmp_path):
    frame = eth(ipv4(A, B, 17, udp(5000, 6000, b"hi")), vlan=100)
    pkts, _ = load(tmp_path, [(0.0, frame)])
    assert (pkts[0].proto, pkts[0].sport, pkts[0].payload_len) == (UDP, 5000, 2)


def test_ipv6_with_extension_header(tmp_path):
    hop_by_hop = bytes([6, 0]) + b"\x00" * 6  # next header TCP, 8 bytes long
    frame = eth(ipv6("2001:db8::1", "2001:db8::2", 6, tcp(1234, 443, flags=SYN, seq=5),
                     ext=hop_by_hop, ext_nh=0), etype=0x86DD)
    p = load(tmp_path, [(0.0, frame)])[0][0]
    assert (p.ip_version, p.proto, p.sport, p.dport, p.tcp_seq) == (6, TCP, 1234, 443, 5)
    assert p.src == "2001:db8::1"


def test_dns_over_udp(tmp_path):
    q = dns_message(0x1234, "nx.example.com")
    r = dns_message(0x1234, "nx.example.com", response=True, rcode=3)
    ok = dns_message(0x99, "ok.example.com", response=True, answers=["192.0.2.7"])
    big = dns_message(0x77, "big.example.com", response=True, tc=True)
    pkts, _ = load(tmp_path, [udp4(A, 5555, B, 53, 0.0, q), udp4(B, 53, A, 5555, 0.1, r),
                              udp4(B, 53, A, 5555, 0.2, ok), udp4(B, 53, A, 5555, 0.3, big)])
    query, nx, answer, trunc = (p.dns for p in pkts)
    assert (query.id, query.is_response, query.qname, query.qtype) == (0x1234, False, "nx.example.com", 1)
    assert (nx.is_response, nx.rcode, nx.answer_count) == (True, 3, 0)
    assert answer.answers == ((1, "192.0.2.7"),)
    assert trunc.truncated and not nx.truncated


def test_dns_over_tcp(tmp_path):
    msg = dns_message(7, "big.example.com", response=True, answers=["192.0.2.1"] * 3)
    frame = tcp4(B, 53, A, 40000, 0.0, flags=ACK | PSH, payload=struct.pack("!H", len(msg)) + msg)
    p = load(tmp_path, [frame])[0][0]
    assert p.dns.over_tcp and p.dns.answer_count == 3


def test_icmp_frag_needed_quotes_original_segment(tmp_path):
    original = ipv4(A, B, 6, tcp(40000, 9100, seq=123456, flags=ACK, payload=b"x" * 1400), ip_id=42)
    err = icmp(3, 4, rest=struct.pack("!HH", 0, 1200), body=original[:28])
    p = load(tmp_path, [(0.0, eth(ipv4("10.0.0.254", A, 1, err)))])[0][0]
    assert (p.icmp_type, p.icmp_code, p.icmp_mtu) == (3, 4, 1200)
    q = p.icmp_quoted
    assert (q.proto, q.src, q.dst, q.sport, q.dport, q.tcp_seq, q.ip_id) == (6, A, B, 40000, 9100, 123456, 42)
    assert p.is_icmp_error


def test_icmpv6_packet_too_big(tmp_path):
    original = ipv6("2001:db8::1", "2001:db8::2", 17, udp(1000, 2000, b"z" * 8))
    err = icmp(2, 0, rest=struct.pack("!I", 1280), body=original[:48])
    frame = eth(ipv6("2001:db8::fe", "2001:db8::1", ICMPV6, err), etype=0x86DD)
    p = load(tmp_path, [(0.0, frame)])[0][0]
    assert (p.icmp_type, p.icmp_mtu) == (2, 1280)
    assert (p.icmp_quoted.sport, p.icmp_quoted.dport) == (1000, 2000)


def test_icmp_echo(tmp_path):
    p = load(tmp_path, [(0.0, eth(ipv4(A, B, 1, icmp(8, 0, rest=struct.pack("!HH", 77, 3)))))])[0][0]
    assert (p.icmp_echo_id, p.icmp_echo_seq, p.icmp_quoted) == (77, 3, None)


def test_capture_duplicate_dropped_but_real_resends_kept(tmp_path):
    seg = dict(seq=1, flags=ACK | PSH, payload=b"data")
    frames = [
        tcp4(A, 1, B, 2, 0.0000, ip_id=10, **seg),
        tcp4(A, 1, B, 2, 0.0001, ip_id=10, **seg),  # same datagram seen twice -> dropped
        tcp4(A, 1, B, 2, 0.0002, ip_id=11, **seg),  # retransmission: new IP ID -> kept
        tcp4(A, 1, B, 2, 1.0000, ip_id=10, **seg),  # same bytes but far apart -> kept
        tcp4(A, 1, B, 2, 1.0001, ip_id=0, **seg),   # ID 0 carries no identity -> kept
        tcp4(A, 1, B, 2, 1.0002, ip_id=0, **seg),
    ]
    pkts, stats = load(tmp_path, frames)
    assert [p.frame for p in pkts] == [1, 3, 4, 5, 6]
    assert stats.duplicates == 1

    pkts, stats = load_packets(tmp_path / "t.pcap", dedup_window=0)
    assert len(pkts) == 6 and stats.duplicates == 0


def test_fragments(tmp_path):
    first = ipv4(A, B, 17, udp(5000, 6000, b"a" * 100)[:56], ip_id=9, mf=True, df=False,
                 total_len=76)
    second = ipv4(A, B, 17, b"b" * 52, ip_id=9, frag_offset=56, df=False)
    pkts, stats = load(tmp_path, [(0.0, eth(first)), (0.001, eth(second))])
    assert pkts[0].sport == 5000 and pkts[0].is_fragment
    assert pkts[0].payload_len == 100  # from the UDP length field
    assert pkts[1].sport is None and pkts[1].frag_offset == 56
    assert stats.fragments == 2


def test_malformed_and_truncated_frames(tmp_path):
    frames = [(0.0, eth(b"\x45\x00\x00")),  # IP header cut short
              (0.1, eth(ipv4(A, B, 6, b"\x00" * 10)))]  # TCP header cut short
    pkts, stats = load(tmp_path, frames)
    assert stats.malformed == 1
    assert pkts[0].truncated and stats.truncated == 1


def test_pcapng_and_raw_ip_linktype(tmp_path):
    raw = ipv4(A, B, 6, tcp(1, 2, flags=SYN))
    pkts, stats = load_packets(write_pcapng(tmp_path / "t.pcapng", [(5.0, eth(raw))]))
    assert pkts[0].tcp_flags == SYN and stats.linktype == 1
    pkts, stats = load_packets(write_pcap(tmp_path / "raw.pcap", [(5.0, raw)], linktype=101))
    assert pkts[0].dport == 2 and stats.linktype == 101


def test_not_a_capture(tmp_path):
    path = tmp_path / "x.pcap"
    path.write_bytes(b"<!doctype html>")
    with pytest.raises(UnsupportedCapture):
        load_packets(path)


# --- real captures (skipped unless downloaded / generated) --------------------

def _need(path):
    if not path.exists():
        pytest.skip(f"{path.name} not present (see data/README.md)")
    return path


def test_wireshark_dns_sample():
    pkts, stats = load_packets(_need(DATA_DIR / "raw/wireshark/dns.cap"))
    responses = [p.dns for p in pkts if p.dns and p.dns.is_response]
    assert stats.malformed == 0
    assert sum(r.rcode == 3 for r in responses) == 6


def test_synthetic_pmtu_capture_reports_next_hop_mtu():
    pkts, _ = load_packets(_need(DATA_DIR / "synthetic/tcp_pmtu_ok.pcap"))
    errors = [p for p in pkts if p.is_icmp_error]
    assert errors and all(p.icmp_mtu == 1200 and p.icmp_quoted.dport == 9100 for p in errors)
