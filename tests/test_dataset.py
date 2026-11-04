import csv
import json
from types import SimpleNamespace

from builders import ACK, PSH, RST, SYN, tcp4, write_pcap
from pcap_rca.cli import main
from pcap_rca.dataset import (IDENTIFIERS, NORMAL, _epoch, build, cic_labeler, fields,
                              synthetic_labeler, pick_test_groups)
from pcap_rca.detectors import Capture, run_detectors
from pcap_rca.features import EVENT_FIELDS, flow_rows

C, S = "10.10.1.2", "10.10.2.2"


def flow(client, server, first_ts=0.0, proto=6):
    return SimpleNamespace(client=client, server=server, first_ts=first_ts, proto=proto)


# --- labellers ------------------------------------------------------------------

def test_synthetic_labeler_rules():
    labeler = synthetic_labeler({
        "flow_labels": [{"match": {"proto": "tcp", "server_port": 9000}, "label": "FIREWALL_DROP"},
                        {"match": {"server_ip": "10.10.2.99"}, "label": "HOST_UNREACHABLE"},
                        {"match": {"server_ports": [33434, 33534]}, "label": "TRACE"}],
        "default_label": NORMAL})
    assert labeler(flow((C, 40000), (S, 9000))) == "FIREWALL_DROP"
    assert labeler(flow((C, 40000), (S, 9000), proto=17)) == NORMAL  # wrong protocol
    assert labeler(flow((C, 40000), ("10.10.2.99", 80))) == "HOST_UNREACHABLE"
    assert labeler(flow((C, 40000), (S, 33440), proto=17)) == "TRACE"
    assert labeler(flow((C, 40000), (S, 8080))) == NORMAL


def test_cic_labeler_attack_windows_and_directions():
    labeler = cic_labeler()
    scan_time = _epoch("2017-07-07", "15:00")
    # inbound attack through the NAT, any port
    assert labeler(flow(("172.16.0.1", 50000), ("192.168.10.50", 22), scan_time)) == "PORTSCAN"
    # same hosts, outside every Friday window
    assert labeler(flow(("172.16.0.1", 50000), ("192.168.10.50", 22),
                        _epoch("2017-07-07", "12:00"))) == NORMAL
    # DDoS only on port 80
    ddos_time = _epoch("2017-07-07", "16:00")
    assert labeler(flow(("172.16.0.1", 50000), ("192.168.10.50", 80), ddos_time)) == "DDOS"
    # outbound bot beacon to the command server (port on the server side), any time on Friday
    assert labeler(flow(("192.168.10.15", 50000), ("205.174.165.73", 8080),
                        _epoch("2017-07-07", "14:00"))) == "BOTNET"
    # a normal host talking to the web server
    assert labeler(flow(("192.168.10.19", 50000), ("192.168.10.50", 80), ddos_time)) == NORMAL


def test_stratified_split_is_deterministic_and_never_empty():
    runs = [f"tcp_loss__r{i:03d}" for i in range(1, 13)]
    test = pick_test_groups(runs, 0.2)
    assert test == pick_test_groups(reversed(runs), 0.2)  # order doesn't matter
    assert len(test) == 2  # round(12 * 0.2)
    assert len(pick_test_groups(runs[:3], 0.2)) == 1  # at least one, even for small strata
    assert pick_test_groups(runs[:1], 0.2) == set()  # a single group can't be split
    assert pick_test_groups(runs, 0.0) == set()


def test_every_scenario_gets_test_runs(tmp_path):
    frames = [tcp4(C, 40000, S, 9001, 0.0, seq=1, flags=SYN),
              tcp4(S, 9001, C, 40000, 0.001, seq=0, ack=2, flags=RST | ACK)]
    rule = [{"match": {"proto": "tcp", "server_port": 9001}, "label": "SERVICE_DOWN"}]
    for scenario in ("a", "b", "c"):
        for run in range(1, 6):
            name = f"{scenario}__r{run:03d}"
            write_pcap(tmp_path / f"{name}.pcap", frames)
            (tmp_path / f"{name}.json").write_text(json.dumps(
                {"scenario": scenario, "pcap": f"{name}.pcap", "flow_labels": rule}))
    rows = list(build([tmp_path], test_fraction=0.2))
    for scenario in ("a", "b", "c"):
        splits = [r["split"] for r in rows if r["group"].startswith(scenario + "__")]
        assert splits.count("test") == 1 and splits.count("train") == 4


# --- features -------------------------------------------------------------------

def test_flow_rows_carry_event_counts(tmp_path):
    frames = [tcp4(C, 40000, S, 81, 0.0, seq=1, flags=SYN),
              tcp4(S, 81, C, 40000, 0.001, seq=0, ack=2, flags=RST | ACK)]
    capture = Capture.from_file(write_pcap(tmp_path / "t.pcap", frames))
    (row,) = flow_rows(capture.table, run_detectors(capture))
    assert set(EVENT_FIELDS) <= set(row)
    assert row["ev_conn_refused"] == 1 and row["ev_syn_timeout"] == 0
    assert row["retrans_rate"] == 0.0


# --- building -------------------------------------------------------------------

def write_scenario(directory, name, frames, flow_labels):
    write_pcap(directory / f"{name}.pcap", frames)
    (directory / f"{name}.json").write_text(json.dumps(
        {"scenario": name, "pcap": f"{name}.pcap", "flow_labels": flow_labels,
         "default_label": NORMAL}))


def test_build_labels_drops_identifiers_and_groups(tmp_path):
    frames = [tcp4(C, 40000, S, 9001, 0.0, seq=1, flags=SYN),
              tcp4(S, 9001, C, 40000, 0.001, seq=0, ack=2, flags=RST | ACK),
              tcp4(C, 40001, S, 8080, 0.1, seq=1, flags=SYN),
              tcp4(S, 8080, C, 40001, 0.101, seq=9, ack=2, flags=SYN | ACK),
              tcp4(C, 40001, S, 8080, 0.102, seq=2, ack=10, flags=ACK | PSH, payload=b"x")]
    write_scenario(tmp_path, "refused__r001", frames,
                   [{"match": {"proto": "tcp", "server_port": 9001}, "label": "SERVICE_DOWN"}])
    rows = list(build([tmp_path], test_fraction=0.0))
    assert sorted(r["label"] for r in rows) == [NORMAL, "SERVICE_DOWN"]
    assert all(r["group"] == "refused__r001" and r["split"] == "train" for r in rows)
    assert not set(IDENTIFIERS) & set(rows[0])
    kept = list(build([tmp_path], keep_identifiers=True))
    assert {r["server_port"] for r in kept} == {9001, 8080}
    assert "server_port" not in fields() and "server_port" in fields(keep_identifiers=True)


def test_test_rig_flows_are_left_out_and_quality_is_recorded(tmp_path):
    from builders import eth, icmp, ipv4
    import struct
    marker = (0.5, eth(ipv4(C, "10.10.1.1", 1, icmp(8, 0, rest=struct.pack("!HH", 1, 1)))))
    frames = [tcp4(C, 40000, S, 9001, 0.0, seq=1, flags=SYN),
              tcp4(S, 9001, C, 40000, 0.001, seq=0, ack=2, flags=RST | ACK), marker]
    write_scenario(tmp_path, "refused", frames,
                   [{"match": {"proto": "tcp", "server_port": 9001}, "label": "SERVICE_DOWN"}])
    (row,) = build([tmp_path], test_fraction=0.0)  # the end-of-capture echo is gone
    assert (row["label"], row["label_quality"]) == ("SERVICE_DOWN", "exact")


def test_cap_per_label_thins_big_classes_only():
    from pcap_rca.dataset import cap_per_label
    rows = ([{"split": "train", "label": "DDOS", "i": i} for i in range(100)]
            + [{"split": "train", "label": "PATH_LOSS", "i": i} for i in range(5)])
    capped = cap_per_label(rows, 10)
    assert sum(r["label"] == "DDOS" for r in capped) == 10
    assert sum(r["label"] == "PATH_LOSS" for r in capped) == 5
    assert capped == cap_per_label(rows, 10)  # reproducible


def test_cic_captures_are_split_in_time_blocks(tmp_path):
    t0 = _epoch("2017-07-07", "15:00")
    frames = []
    for i in range(10):  # one refused scan probe per minute
        ts = t0 + i * 60
        frames += [tcp4("172.16.0.1", 50000 + i, "192.168.10.50", 1000 + i, ts, seq=1, flags=SYN),
                   tcp4("192.168.10.50", 1000 + i, "172.16.0.1", 50000 + i, ts + 0.001,
                        seq=0, ack=2, flags=RST | ACK)]
    path = write_pcap(tmp_path / "friday.pcap", frames)
    rows = list(build(cic_captures=[path], test_fraction=0.5))
    assert {r["label"] for r in rows} == {"PORTSCAN"}
    assert {r["label_quality"] for r in rows} == {"schedule"}
    assert len({r["group"] for r in rows}) == 10  # one group per minute
    assert {r["split"] for r in rows} == {"train", "test"}  # the attack lands on both sides


def test_dataset_cli(tmp_path, capsys):
    frames = [tcp4(C, 40000, S, 9001, 0.0, seq=1, flags=SYN),
              tcp4(S, 9001, C, 40000, 0.001, seq=0, ack=2, flags=RST | ACK)]
    scen = tmp_path / "synth"
    scen.mkdir()
    write_scenario(scen, "refused", frames,
                   [{"match": {"proto": "tcp", "server_port": 9001}, "label": "SERVICE_DOWN"}])
    out = tmp_path / "ds.csv"
    assert main(["dataset", str(out), "--synthetic", str(scen), "--test-fraction", "0"]) == 0
    with open(out, newline="") as f:
        (row,) = list(csv.DictReader(f))
    assert row["label"] == "SERVICE_DOWN" and row["ev_conn_refused"] == "1"
    assert "SERVICE_DOWN" in capsys.readouterr().out
    assert main(["dataset", str(out)]) == 1  # no inputs
