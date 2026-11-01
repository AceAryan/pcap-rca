"""Event detectors. Each one takes a Capture and returns a list of Events.

    from pcap_rca.detectors import Capture, run_detectors
    events = run_detectors(Capture.from_file("capture.pcap"))
"""
from __future__ import annotations

from .app_events import AppEventDetector
from .base import ERROR, INFO, WARNING, Capture, Config, Event
from .dns_events import DnsEventDetector
from .icmp_events import IcmpEventDetector
from .tcp_events import TcpEventDetector

DETECTORS = [TcpEventDetector(), DnsEventDetector(), IcmpEventDetector(), AppEventDetector()]
SEVERITY_RANK = {INFO: 0, WARNING: 1, ERROR: 2}


def run_detectors(capture: Capture, config: Config | None = None,
                  only: set[str] | None = None) -> list[Event]:
    """Run every detector (or those named in `only`), events sorted by time."""
    cfg = config or Config()
    events: list[Event] = []
    for detector in DETECTORS:
        if only is None or detector.name in only:
            events.extend(detector.detect(capture, cfg))
    events.sort(key=lambda e: (e.ts_start, e.stream_id if e.stream_id is not None else -1))
    return events


__all__ = ["Capture", "Config", "DETECTORS", "ERROR", "Event", "INFO", "SEVERITY_RANK",
           "WARNING", "run_detectors"]
