from types import SimpleNamespace

import pytest

from pcap_rca.aggregation import aggregate, make_group
from pcap_rca.aggregation.spatial import prefix, scope_of
from pcap_rca.aggregation.temporal import peak_count, temporal_pattern
from pcap_rca.detectors.base import Config, Event

CFG = Config()


def ev(ts=0.0, src="10.0.0.1", dst="10.0.2.2", dport=80, stream=0, event_type="TCP_RETRANSMISSION",
       severity="warning"):
    return Event(event_type=event_type, severity=severity, ts_start=ts, ts_end=ts, src=src,
                 sport=40000, dst=dst, dport=dport, proto=6, stream_id=stream)


def fake_capture(n_tcp_flows):
    flows = [SimpleNamespace(proto=6) for _ in range(n_tcp_flows)]
    return SimpleNamespace(table=SimpleNamespace(flows=flows))


# --- temporal ----------------------------------------------------------------

@pytest.mark.parametrize("times,pattern", [
    ([0.0], "ISOLATED"),
    ([0, 1, 2], "ISOLATED"),
    ([0, 30, 60, 90, 120], "PERIODIC"),                 # a 30 s timer
    ([0, 0.1, 0.2, 0.3, 0.4, 0.5], "BURST"),
    ([i * 20.0 for i in range(6)] + [7, 33, 71, 95], "SUSTAINED"),
    ([0, 30, 50, 60, 66, 70, 72, 74, 76, 77, 78, 79], "ESCALATING"),
])
def test_temporal_patterns(times, pattern):
    assert temporal_pattern(times, CFG)[0] == pattern


def test_periodic_needs_second_scale_gaps():
    # Evenly spaced every millisecond is a fast stream, not a timer.
    assert temporal_pattern([i * 0.001 for i in range(10)], CFG)[0] == "BURST"


def test_periodic_reports_period():
    pattern, info = temporal_pattern([0, 60, 120, 181, 240], CFG)
    assert pattern == "PERIODIC" and info["period"] == pytest.approx(60, abs=1)


def test_peak_count():
    assert peak_count([0, 1, 2, 20, 21], 10) == 3


# --- spatial -----------------------------------------------------------------

def test_prefix():
    assert prefix("10.1.2.3") == "10.1.2.0/24"
    assert prefix("2001:db8:1:2:aaaa::1") == "2001:db8:1:2::/64"


@pytest.mark.parametrize("events,scope", [
    ([ev(stream=1), ev(stream=1)], "FLOW"),
    ([ev(stream=1), ev(src="10.0.0.9", stream=2)], "SERVICE"),
    ([ev(dport=80, stream=1), ev(dport=443, stream=2)], "SERVER"),
    ([ev(dst="10.0.2.2", stream=1), ev(dst="10.0.2.3", stream=2)], "SUBNET"),
    ([ev(dst="10.0.2.2", stream=1), ev(dst="10.9.9.9", stream=2)], "CLIENT"),
])
def test_scope(events, scope):
    assert scope_of(events, fake_capture(100), CFG)[0] == scope


def test_network_wide_vs_scattered():
    events = [ev(src=f"10.0.0.{i}", dst=f"10.{i}.0.1", stream=i) for i in range(1, 5)]
    assert scope_of(events, fake_capture(6), CFG)[0] == "NETWORK_WIDE"   # 4 of 6 flows
    assert scope_of(events, fake_capture(100), CFG)[0] == "SCATTERED"    # 4 of 100


def test_aggregate_groups_by_type_and_subnet():
    events = ([ev(ts=i, src=f"10.0.0.{i}", stream=i) for i in range(3)]
              + [ev(ts=1, src="10.0.0.7", dst="10.5.5.5", stream=9)]
              + [ev(ts=2, event_type="TCP_CONN_REFUSED", severity="error", stream=4)])
    groups = aggregate(events, fake_capture(100))
    assert [g.describe() for g in groups] == [
        "1 x TCP_CONN_REFUSED  FLOW 10.0.0.1:40000 -> 10.0.2.2:80  ISOLATED",
        "3 x TCP_RETRANSMISSION  SERVICE 10.0.2.2:80  ISOLATED",
        "1 x TCP_RETRANSMISSION  FLOW 10.0.0.7:40000 -> 10.5.5.5:80  ISOLATED",
    ]


def test_make_group_properties():
    g = make_group([ev(ts=1, stream=1), ev(ts=3, src="10.0.0.2", stream=2, severity="error")],
                   fake_capture(10))
    assert (g.count, g.flows, g.clients, g.ts_start, g.ts_end, g.severity) == \
        (2, {1, 2}, {"10.0.0.1", "10.0.0.2"}, 1, 3, "error")
