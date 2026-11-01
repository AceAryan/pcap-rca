"""Root-cause rules on small, exact captures."""
from builders import ACK, RST, SYN, dns_message, eth, icmp, ipv4, tcp4, udp, udp4, write_pcap
from pcap_rca.detectors import Capture, Config, run_detectors
from pcap_rca.inference import infer

C, C2, S, RTR = "10.0.0.1", "10.0.0.7", "10.0.2.2", "10.0.0.254"


def diagnose(tmp_path, frames):
    capture = Capture.from_file(write_pcap(tmp_path / "t.pcap", frames))
    return infer(capture, run_detectors(capture))


def rules(diags):
    return sorted(d.rule for d in diags)


def established(port, t0, cport=40000, client=C):
    return [tcp4(client, cport, S, port, t0, seq=1, flags=SYN),
            tcp4(S, port, client, cport, t0 + 0.001, seq=9, ack=2, flags=SYN | ACK),
            tcp4(client, cport, S, port, t0 + 0.002, seq=2, ack=10)]


def refused(port, t0, cport, client=C):
    return [tcp4(client, cport, S, port, t0, seq=1, flags=SYN),
            tcp4(S, port, client, cport, t0 + 0.001, seq=0, ack=2, flags=RST | ACK)]


def test_nothing_wrong(tmp_path):
    assert diagnose(tmp_path, established(80, 0.0)) == []


def test_service_down_confidence_depends_on_host_liveness(tmp_path):
    (d,) = diagnose(tmp_path, refused(81, 0.0, 40001))
    assert (d.rule, d.target, d.confidence) == ("SERVICE_DOWN", "10.0.2.2:81", "medium")

    (d,) = diagnose(tmp_path, established(80, 0.0) + refused(81, 1.0, 40001))
    assert d.confidence == "high"
    assert any("accepts connections on port(s) 80" in line for line in d.evidence)


def test_firewall_drop_vs_unknown_host(tmp_path):
    syns = [tcp4(C, 40001, S, 9000, t, seq=1, flags=SYN) for t in (1.0, 2.0, 4.0)]
    end = [tcp4(C, 1, "10.9.9.9", 2, 10.0, flags=ACK)]
    (d,) = diagnose(tmp_path, established(80, 0.0) + syns + end)
    assert (d.rule, d.confidence) == ("FIREWALL_DROP", "high")
    (d,) = diagnose(tmp_path, syns + end)
    assert (d.rule, d.confidence) == ("FIREWALL_DROP", "low")


def test_silent_host_on_several_ports_is_unreachable(tmp_path):
    frames = [tcp4(C, 40000 + p, S, p, 0.0, seq=1, flags=SYN) for p in (22, 80, 443)]
    frames.append(tcp4(C, 1, "10.9.9.9", 2, 10.0, flags=ACK))
    (d,) = diagnose(tmp_path, frames)
    assert (d.rule, d.target, d.confidence) == ("HOST_UNREACHABLE", S, "medium")


def test_scan_claims_its_failures(tmp_path):
    frames = []
    for i, port in enumerate(range(1000, 1030)):
        frames += refused(port, i * 0.01, 50000 + i)
    (d,) = diagnose(tmp_path, frames)  # no SERVICE_DOWN for the 30 probed ports
    assert d.rule == "SCAN_OR_FLOOD" and "vertical port scan" in d.evidence[0]


def test_admin_block_and_no_route_name_the_reporter(tmp_path):
    syn = ipv4(C, S, 6, tcp4(C, 40000, S, 22, 0)[1][14 + 20:])
    frames = [(0.0, eth(syn)), (0.001, eth(ipv4(RTR, C, 1, icmp(3, 13, body=syn[:28]))))]
    (d,) = diagnose(tmp_path, frames)
    assert (d.rule, d.target) == ("ADMIN_BLOCK", RTR)
    frames = [(0.0, eth(syn)), (0.001, eth(ipv4(RTR, C, 1, icmp(3, 0, body=syn[:28]))))]
    (d,) = diagnose(tmp_path, frames)
    assert (d.rule, d.target) == ("NO_ROUTE", RTR)


def test_resolver_unreachable_absorbs_the_icmp(tmp_path):
    q = udp4(C, 5353, "10.0.0.53", 53, 0.0, dns_message(1, "a.example"))
    raw_q = q[1][14:]
    err = (3.0, eth(ipv4(RTR, C, 1, icmp(3, 1, body=raw_q[:28]))))
    tail = tcp4(C, 1, "10.9.9.9", 2, 10.0, flags=ACK)
    (d,) = diagnose(tmp_path, [q, err, tail])
    assert (d.rule, d.target) == ("RESOLVER_UNREACHABLE", "10.0.0.53")  # no HOST_UNREACHABLE


def test_resolver_failure_confidence(tmp_path):
    def servfail(i):
        return [udp4(C, 5000 + i, "10.0.0.53", 53, i, dns_message(i, f"n{i}.example")),
                udp4("10.0.0.53", 53, C, 5000 + i, i + 0.01,
                     dns_message(i, f"n{i}.example", response=True, rcode=2))]
    (d,) = diagnose(tmp_path, servfail(1))
    assert (d.rule, d.confidence) == ("RESOLVER_FAILURE", "medium")  # one failure is thin
    (d,) = diagnose(tmp_path, servfail(1) + servfail(2))
    assert d.confidence == "high"


def test_traceroute_is_not_a_problem(tmp_path):
    frames = []
    for i, ttl in enumerate((1, 2)):
        probe = ipv4(C, S, 17, udp(40000, 33434 + i, b"x" * 8), ttl=ttl, ip_id=100 + i)
        reply = icmp(11, 0, body=probe[:28]) if ttl == 1 else icmp(3, 3, body=probe[:28])
        reporter = RTR if ttl == 1 else S
        frames += [(i, eth(probe)), (i + 0.01, eth(ipv4(reporter, C, 1, reply)))]
    assert diagnose(tmp_path, frames) == []


def test_name_not_found_grammar_and_confidence(tmp_path):
    def nx(i, name):
        return [udp4(C, 5000 + i, "10.0.0.53", 53, i, dns_message(i, name)),
                udp4("10.0.0.53", 53, C, 5000 + i, i + 0.01,
                     dns_message(i, name, response=True, rcode=3))]
    (d,) = diagnose(tmp_path, nx(1, "typo.example"))
    assert d.confidence == "medium" and "1 name that doesn't exist" in d.evidence[0]
    (d,) = diagnose(tmp_path, nx(1, "typo.example") + nx(2, "typo.example"))
    assert d.confidence == "high" and "typo.example (2x)" in d.evidence[0]


def test_connection_flood_claims_the_victims_symptoms(tmp_path):
    frames = []
    for i in range(8):  # one client hammering one service
        frames += established(80, i * 0.1, cport=41000 + i)
        frames.append(tcp4(S, 80, C, 41000 + i, i * 0.1 + 0.05, seq=10, flags=RST))  # mid-stream resets
    for i in range(3):  # and new connections go unanswered
        frames.append(tcp4(C, 42000 + i, S, 80, 1.0 + i * 0.01, seq=1, flags=SYN))
    frames.append(tcp4(C, 1, "10.9.9.9", 2, 10.0, flags=ACK))
    capture = Capture.from_file(write_pcap(tmp_path / "t.pcap", frames))
    diags = infer(capture, run_detectors(capture), Config(flood_min_connections=5))
    (d,) = diags  # no FIREWALL_DROP / ABRUPT_TERMINATION for the victim
    assert (d.rule, d.target) == ("SCAN_OR_FLOOD", "10.0.2.2:80")
    assert "opened 11 connections" in d.evidence[0] and "connection flood" in d.evidence[0]
    assert d.next_steps[0].startswith("Block or rate-limit 10.0.0.1")


def test_routine_nxdomain_and_late_dns_replies_are_not_problems(tmp_path):
    def nx(i, name):
        return [udp4(C, 5000 + i, "10.0.0.53", 53, i, dns_message(i, name)),
                udp4("10.0.0.53", 53, C, 5000 + i, i + 0.01,
                     dns_message(i, name, response=True, rcode=3))]
    frames = nx(1, "5.2.0.192.in-addr.arpa") + nx(2, "b._dns-sd._udp.0.0.10.in-addr.arpa")
    # A DNS answer arriving after the client closed its port: ICMP port unreachable.
    late = ipv4("10.0.0.53", C, 17, udp(53, 58753, b"x" * 12))
    frames.append((3.0, eth(ipv4(C, "10.0.0.53", 1, icmp(3, 3, body=late[:28])))))
    assert diagnose(tmp_path, frames) == []


def test_resent_bare_fins_dont_crash_pmtu_rule(tmp_path):
    # Found on CIC-IDS2017: a flow whose only retransmissions are of a FIN.
    fin = [tcp4(S, 80, C, 40000, t, seq=10, ack=2, flags=ACK | 0x01) for t in (1.0, 2.0, 4.0)]
    assert diagnose(tmp_path, established(80, 0.0) + fin) == []


def test_capture_loss_lowers_other_confidence(tmp_path):
    frames = established(80, 0.0) + refused(81, 1.0, 40001)
    # Three times the client ACKs server data the capture never saw.
    for i in range(3):
        frames.append(tcp4(C, 40000, S, 80, 2 + i, seq=2, ack=10 + 1000 * (i + 1)))
    diags = diagnose(tmp_path, frames)
    assert rules(diags) == ["CAPTURE_LOSS", "SERVICE_DOWN"]
    service = next(d for d in diags if d.rule == "SERVICE_DOWN")
    assert service.confidence == "medium" and "Confidence lowered" in service.evidence[-1]
