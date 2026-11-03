"""Shared types for detectors: the event record, thresholds, and the capture
being analysed. Event IDs and thresholds are specified in docs/event_types.md.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..parser import Packet, ParseStats, load_packets
from ..streams import C2S, S2C, Flow, FlowTable, build_flows

INFO, WARNING, ERROR = "info", "warning", "error"
SEVERITY_RANK = {INFO: 0, WARNING: 1, ERROR: 2}


@dataclass
class Event:
    event_type: str
    severity: str
    ts_start: float
    ts_end: float
    src: str | None = None  # flow endpoints, client -> server where known
    sport: int | None = None
    dst: str | None = None
    dport: int | None = None
    proto: int | None = None
    stream_id: int | None = None
    subtype: str | None = None
    count: int = 1
    evidence: list[int] = field(default_factory=list)  # frame numbers
    related: dict = field(default_factory=dict)
    metrics: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Config:
    """Detection thresholds (docs/event_types.md §8)."""

    syn_timeout: float = 3.0
    dup_ack_threshold: int = 3
    ooo_min_window: float = 0.003
    high_rtt_ms: float = 300.0
    high_rtt_factor: float = 3.0
    high_rtt_floor_ms: float = 50.0  # the relative rule never fires below this
    rtt_baseline_min: int = 5
    dns_timeout: float = 2.0
    dns_retx_window: float = 10.0
    dns_slow_ms: float = 500.0
    http_slow_ms: float = 1000.0
    tls_handshake_timeout: float = 5.0
    # aggregation (§6)
    burst_min_events: int = 5
    burst_window: float = 10.0
    periodic_max_cv: float = 0.2
    periodic_min_gap: float = 1.0  # timers tick in seconds; ms-spaced events aren't "periodic"
    network_wide_fraction: float = 0.5
    # root-cause rules (§7)
    loss_rate_threshold: float = 0.02
    loss_min_retrans: int = 10  # a rate from a handful of segments says little
    reorder_min_events: int = 10
    zero_window_min_s: float = 0.2
    pmtu_min_segment: int = 1000
    high_latency_min_flows: int = 2
    slow_resolver_min: int = 2
    capture_loss_min: int = 3
    capture_skew_min: int = 20  # data segments recorded after their own ACK
    scan_min_targets: int = 20
    flood_min_sources: int = 20
    flood_min_connections: int = 500  # from one client to one service
    idle_timeout_min_events: int = 3


@dataclass
class Capture:
    """Everything a detector may look at."""

    packets: list[Packet]
    table: FlowTable
    stats: ParseStats

    @property
    def start_ts(self) -> float | None:
        return self.stats.first_ts

    @property
    def end_ts(self) -> float | None:
        return self.stats.last_ts

    @classmethod
    def from_file(cls, path: str | Path, **parse_kwargs) -> "Capture":
        packets, stats = load_packets(path, **parse_kwargs)
        return cls(packets, build_flows(packets), stats)


def flow_event(flow: Flow, event_type: str, severity: str, ts_start: float,
               ts_end: float | None = None, **kwargs) -> Event:
    """An Event located on `flow`, oriented client -> server."""
    return Event(event_type=event_type, severity=severity,
                 ts_start=ts_start, ts_end=ts_start if ts_end is None else ts_end,
                 src=flow.client[0], sport=flow.client[1],
                 dst=flow.server[0], dport=flow.server[1],
                 proto=flow.proto, stream_id=flow.id, **kwargs)


def direction_name(direction: int) -> str:
    return "c2s" if direction == C2S else "s2c"


def direction_index(name: str) -> int:
    """Inverse of direction_name: 'c2s' -> C2S, 's2c' -> S2C."""
    return C2S if name == "c2s" else S2C


def side_name(direction: int) -> str:
    """Which endpoint sent a packet travelling in `direction`."""
    return "client" if direction == C2S else "server"


def sort_events(events: list[Event]) -> list[Event]:
    """Sort in place by start time, then stream; returns the list."""
    events.sort(key=lambda e: (e.ts_start, e.stream_id if e.stream_id is not None else -1))
    return events
