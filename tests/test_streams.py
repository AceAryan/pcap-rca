import struct

import pytest

from builders import (ACK, DATA_DIR, FIN, PSH, RST, SYN, dns_message, eth, icmp, ipv4,
                      syn_options, tcp, tcp4, udp, udp4, write_pcap)
from pcap_rca.parser import load_packets
from pcap_rca.streams import C2S, S2C, build_flows

C, S = "10.0.0.1", "10.0.0.2"


def flows_for(tmp_path, frames, **kw):
    pkts, _ = load_packets(write_pcap(tmp_path / "t.pcap", frames))
    return pkts, build_flows(pkts, **kw)


def handshake(t0=0.0, cport=40000, isn=1000, server_isn=5000, rtt=0.05):
    return [
        tcp4(C, cport, S, 80, t0, seq=isn, flags=SYN, options=syn_options(wscale=7)),
        tcp4(S, 80, C, cport, t0 + rtt, seq=server_isn, ack=isn + 1, flags=SYN | ACK,
             options=syn_options(mss=1400, wscale=9)),
        tcp4(C, cport, S, 80, t0 + rtt + 0.001, seq=isn + 1, ack=server_isn + 1),
    ]


def test_full_connection(tmp_path):
    frames = handshake() + [
        tcp4(C, 40000, S, 80, 0.06, seq=1001, ack=5001, flags=ACK | PSH, payload=b"GET"),
        tcp4(S, 80, C, 40000, 0.07, seq=5001, ack=1004, flags=ACK | FIN),
        tcp4(C, 40000, S, 80, 0.08, seq=1004, ack=5002, flags=ACK | FIN),
    ]
    pkts, table = flows_for(tmp_path, frames)
    assert len(table.flows) == 1
    f = table.flows[0]
    assert (f.client, f.server, f.client_inferred) == ((C, 40000), (S, 80), False)
    assert f.directions == [C2S, S2C, C2S, C2S, S2C, C2S]
    t = f.tcp
    assert t.established and t.irtt == pytest.approx(0.051)
    assert t.client_side_rtt == pytest.approx(0.05)
    assert (t.mss[C2S], t.mss[S2C]) == (1460, 1400)
    assert (t.window_shift(C2S), t.window_shift(S2C)) == (7, 9)
    assert t.close_reason == "fin"
    assert all(p.flow_id == 0 for p in pkts)


def test_window_scale_needs_both_sides():
    from pcap_rca.streams import TcpState
    t = TcpState(syn_count=1, synack_count=1)
    t.wscale = [7, None]
    assert t.window_shift(C2S) == 0
    assert TcpState().window_shift(C2S) is None  # handshake not captured


def test_retransmitted_syn_stays_in_flow_new_isn_starts_new_flow(tmp_path):
    frames = [
        tcp4(C, 40000, S, 80, 0.0, seq=1000, flags=SYN),
        tcp4(C, 40000, S, 80, 1.0, seq=1000, flags=SYN),  # retransmission
        tcp4(S, 80, C, 40000, 1.01, seq=1, ack=1001, flags=RST | ACK),
        tcp4(C, 40000, S, 80, 5.0, seq=777, flags=SYN),  # port reuse, new ISN
    ]
    _, table = flows_for(tmp_path, frames)
    first, second = table.flows
    assert first.tcp.syn_count == 2 and not first.tcp.established
    assert (first.tcp.close_reason, first.tcp.rst_dir) == ("rst", S2C)
    assert second.tcp.client_isn == 777 and len(second.packets) == 1


def test_capture_starting_mid_connection(tmp_path):
    frames = [tcp4(S, 443, C, 50000, 0.0, seq=9, ack=9, flags=ACK, payload=b"x" * 100),
              tcp4(C, 50000, S, 443, 0.1, seq=9, ack=109)]
    _, table = flows_for(tmp_path, frames)
    f = table.flows[0]
    assert (f.client, f.server, f.client_inferred) == ((C, 50000), (S, 443), True)
    assert f.directions == [S2C, C2S]
    assert not f.tcp.handshake_seen and f.tcp.window_shift(C2S) is None


def test_synack_without_syn_identifies_client(tmp_path):
    _, table = flows_for(tmp_path, handshake()[1:])
    assert table.flows[0].client == (C, 40000)
    assert not table.flows[0].client_inferred


def test_udp_flows_split_on_idle_timeout(tmp_path):
    q = dns_message(1, "a.example.com")
    frames = [udp4(C, 5353, S, 53, 0.0, q), udp4(S, 53, C, 5353, 0.01, q),
              udp4(C, 5353, S, 53, 500.0, q)]
    _, table = flows_for(tmp_path, frames, idle_timeout=120)
    assert [len(f.packets) for f in table.flows] == [2, 1]
    assert table.flows[0].client == (C, 5353)


def test_icmp_error_attached_to_the_flow_it_quotes(tmp_path):
    probe = ipv4(C, S, 17, udp(40000, 9999, b"probe"))
    frames = [(0.0, eth(probe)),
              (0.001, eth(ipv4(S, C, 1, icmp(3, 3, body=probe[:28]))))]
    pkts, table = flows_for(tmp_path, frames)
    assert len(table.flows) == 1  # the ICMP error is not a flow of its own
    flow = table.flows[0]
    assert flow.icmp_errors == [pkts[1]] and table.icmp_errors == [pkts[1]]
    assert table.related_flow(pkts[1]) is flow
    assert pkts[1].flow_id is None


def test_icmp_echo_flows_by_identifier(tmp_path):
    def echo(src, dst, itype, ident, ts):
        return ts, eth(ipv4(src, dst, 1, icmp(itype, 0, rest=struct.pack("!HH", ident, 1))))
    frames = [echo(C, S, 8, 1, 0.0), echo(S, C, 0, 1, 0.01), echo(C, S, 8, 2, 0.02)]
    _, table = flows_for(tmp_path, frames)
    assert [len(f.packets) for f in table.flows] == [2, 1]
    assert table.flows[0].client == (C, None) and not table.flows[0].client_inferred


def test_non_first_fragment_follows_its_first_fragment(tmp_path):
    first = ipv4(C, S, 17, udp(5000, 6000, b"a" * 100)[:56], ip_id=9, mf=True, df=False,
                 total_len=76)
    rest = ipv4(C, S, 17, b"b" * 52, ip_id=9, frag_offset=56, df=False)
    _, table = flows_for(tmp_path, [(0.0, eth(first)), (0.001, eth(rest))])
    assert len(table.flows) == 1 and len(table.flows[0].packets) == 2


# --- synthetic ground-truth captures (skipped unless generated) ---------------

def synthetic(name):
    path = DATA_DIR / "synthetic" / f"{name}.pcap"
    if not path.exists():
        pytest.skip(f"{path.name} not generated (see data/README.md)")
    pkts, _ = load_packets(path)
    return build_flows(pkts)


def tcp_flows(table, port):
    return [f for f in table.flows if f.tcp is not None and f.server[1] == port]


def test_synthetic_conn_refused():
    flows = tcp_flows(synthetic("tcp_conn_refused"), 9001)
    assert len(flows) == 3
    assert all(f.tcp.synack_count == 0 and f.tcp.rst_dir == S2C for f in flows)


def test_synthetic_syn_timeout():
    flows = tcp_flows(synthetic("tcp_syn_timeout"), 9000)
    assert len(flows) == 3
    assert all(f.tcp.syn_count >= 2 and f.tcp.synack_count == 0 and f.tcp.close_reason is None
               for f in flows)


def test_synthetic_high_latency_irtt():
    flows = tcp_flows(synthetic("tcp_high_latency"), 8080)
    assert len(flows) == 3 and all(f.tcp.irtt > 0.39 for f in flows)


def test_synthetic_admin_prohibited_links_icmp_to_syn():
    table = synthetic("icmp_admin_prohibited")
    flows = tcp_flows(table, 9003)
    assert len(flows) == 3 and all(len(f.icmp_errors) == 1 for f in flows)
    assert {p.icmp_code for p in table.icmp_errors} == {13}


def test_synthetic_baseline_transfers_are_complete():
    for f in tcp_flows(synthetic("baseline"), 8080):
        t = f.tcp
        sent = max((p.tcp_seq - t.server_isn) % 2**32 + p.payload_len for p in f.in_direction(S2C))
        assert t.close_reason == "fin" and sent - 1 > 2_000_000
