"""Group events by type and by who is affected, and describe their timing.

    groups = aggregate(events, capture)
    for g in groups:
        print(g.describe())   # "318 x TCP_RETRANSMISSION  SERVICE 10.10.2.2:8080  BURST"
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..detectors.base import SEVERITY_RANK, Capture, Config, Event
from .spatial import endpoint, group_events, prefix, scope_of
from .temporal import temporal_pattern


@dataclass
class EventGroup:
    event_type: str
    scope: str
    key: str  # what is affected, e.g. "10.10.2.2:9000" or "10.10.2.0/24"
    pattern: str
    events: list[Event]
    pattern_info: dict = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.events)

    @property
    def flows(self) -> set[int]:
        return {e.stream_id for e in self.events if e.stream_id is not None}

    @property
    def clients(self) -> set[str]:
        return {e.src for e in self.events}

    @property
    def servers(self) -> set[str]:
        return {e.dst for e in self.events}

    @property
    def ts_start(self) -> float:
        return min(e.ts_start for e in self.events)

    @property
    def ts_end(self) -> float:
        return max(e.ts_end for e in self.events)

    @property
    def severity(self) -> str:
        return max((e.severity for e in self.events), key=SEVERITY_RANK.get)

    @property
    def subtypes(self) -> Counter:
        return Counter(e.subtype for e in self.events if e.subtype)

    def describe(self) -> str:
        return f"{self.count} x {self.event_type}  {self.scope} {self.key}  {self.pattern}"

    def to_dict(self) -> dict:
        return {"event_type": self.event_type, "scope": self.scope, "key": self.key,
                "pattern": self.pattern, "pattern_info": self.pattern_info,
                "count": self.count, "flows": len(self.flows), "severity": self.severity,
                "subtypes": dict(self.subtypes), "ts_start": self.ts_start, "ts_end": self.ts_end}


def make_group(events: list[Event], capture: Capture, cfg: Config | None = None) -> EventGroup:
    """Describe an arbitrary set of events (normally all of one type)."""
    cfg = cfg or Config()
    scope, key = scope_of(events, capture, cfg)
    pattern, info = temporal_pattern([e.ts_start for e in events], cfg)
    event_type = "+".join(sorted({e.event_type for e in events}))
    return EventGroup(event_type, scope, key, pattern, list(events), info)


def aggregate(events: list[Event], capture: Capture, cfg: Config | None = None) -> list[EventGroup]:
    """Default grouping of all events, most severe and largest first."""
    cfg = cfg or Config()
    groups = [make_group(evs, capture, cfg) for evs in group_events(events, capture, cfg)]
    groups.sort(key=lambda g: (-SEVERITY_RANK[g.severity], -g.count, g.event_type))
    return groups


__all__ = ["EventGroup", "aggregate", "endpoint", "make_group", "prefix"]
