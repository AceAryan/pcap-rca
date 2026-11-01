import csv

from builders import ACK, FIN, PSH, SYN, syn_options, tcp4, write_pcap
from pcap_rca.cli import main
from pcap_rca.features import (FLOW_FIELDS, PACKET_FIELDS, flow_features, packet_rows,
                               write_csv)
from pcap_rca.parser import load_packets
from pcap_rca.streams import build_flows

C, S = "10.0.0.1", "10.0.0.2"

FRAMES = [
    tcp4(C, 40000, S, 80, 10.00, seq=1000, flags=SYN, options=syn_options()),
    tcp4(S, 80, C, 40000, 10.05, seq=5000, ack=1001, flags=SYN | ACK, options=syn_options()),
    tcp4(C, 40000, S, 80, 10.06, seq=1001, ack=5001),
    tcp4(C, 40000, S, 80, 10.07, seq=1001, ack=5001, flags=ACK | PSH, payload=b"x" * 100),
    tcp4(S, 80, C, 40000, 10.10, seq=5001, ack=1101, flags=ACK | FIN),
    tcp4(C, 40000, S, 80, 10.11, seq=1101, ack=5002, flags=ACK | FIN),
]


def build(tmp_path):
    path = write_pcap(tmp_path / "t.pcap", FRAMES)
    pkts, _ = load_packets(path)
    return path, pkts, build_flows(pkts)


def test_flow_features(tmp_path):
    _, _, table = build(tmp_path)
    row = flow_features(table.flows[0])
    assert set(row) == set(FLOW_FIELDS)
    assert (row["pkts_c2s"], row["pkts_s2c"], row["payload_c2s"]) == (4, 2, 100)
    assert (row["syn"], row["fin"], row["tcp_close"], row["tcp_established"]) == (2, 2, "fin", True)
    assert abs(row["duration"] - 0.11) < 1e-9
    assert abs(row["tcp_irtt"] - 0.06) < 1e-9


def test_packet_rows_relative_sequence_and_timing(tmp_path):
    _, pkts, table = build(tmp_path)
    rows = list(packet_rows(pkts, table))
    assert set(rows[0]) == set(PACKET_FIELDS)
    data = rows[3]
    assert (data["direction"], data["tcp_seq_rel"], data["tcp_ack_rel"]) == ("c2s", 1, 1)
    assert data["tcp_flags"] == "AP"
    assert abs(data["flow_iat"] - 0.01) < 1e-9
    assert rows[0]["flow_iat"] is None and rows[0]["rel_time"] == 0


def test_write_csv_and_cli(tmp_path, capsys):
    path, _, table = build(tmp_path)
    flows_csv, packets_csv = tmp_path / "flows.csv", tmp_path / "packets.csv"
    assert main(["features", str(path), "--flows", str(flows_csv),
                 "--packets", str(packets_csv)]) == 0
    with open(flows_csv, newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1 and rows[0]["tcp_close"] == "fin"
    with open(packets_csv, newline="") as f:
        assert len(list(csv.DictReader(f))) == len(FRAMES)
    assert "flows 1" in capsys.readouterr().out


def test_analyze_cli(tmp_path, capsys):
    import json
    frames = [tcp4(C, 40000, S, 81, 0.0, seq=1, flags=SYN),
              tcp4(S, 81, C, 40000, 0.001, seq=0, ack=2, flags=0x14)]  # RST|ACK
    path = write_pcap(tmp_path / "refused.pcap", frames)
    out_json, out_csv = tmp_path / "e.json", tmp_path / "e.csv"
    assert main(["analyze", str(path), "--json", str(out_json), "--csv", str(out_csv)]) == 0
    text = capsys.readouterr().out
    assert "TCP_CONN_REFUSED" in text and "10.0.0.1:40000 -> 10.0.0.2:81" in text
    assert "[medium] SERVICE_DOWN  10.0.0.2:81" in text and "Next steps:" in text
    report = json.loads(out_json.read_text())
    (event,) = report["events"]
    assert event["event_type"] == "TCP_CONN_REFUSED" and event["evidence"] == [1, 2]
    (diag,) = report["diagnoses"]
    assert diag["rule"] == "SERVICE_DOWN" and diag["frames"] == [1, 2]
    assert report["groups"][0]["scope"] == "FLOW"
    with open(out_csv, newline="") as f:
        (row,) = list(csv.DictReader(f))
    assert json.loads(row["metrics"]) == {"syn_count": 1}

    assert main(["analyze", str(path), "--min-severity", "error", "--only", "dns"]) == 0
    assert "no events" in capsys.readouterr().out


def test_write_csv_blank_for_none(tmp_path):
    out = tmp_path / "x.csv"
    write_csv([{"a": None, "b": 1}], out, ["a", "b"])
    assert out.read_text().splitlines() == ["a,b", ",1"]
