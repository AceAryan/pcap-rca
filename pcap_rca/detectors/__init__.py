"""Event detectors. Each one takes a Capture and returns a list of Events.

    from pcap_rca.detectors import Capture, run_detectors
    events = run_detectors(Capture.from_file("capture.pcap"))
"""
from __future__ import annotations

from .app_events import detect_app_events
from .base import ERROR, INFO, SEVERITY_RANK, WARNING, Capture, Config, Event, sort_events
from .dns_events import detect_dns_events
from .icmp_events import detect_icmp_events
from .tcp_events import detect_tcp_events

DETECTORS = {"tcp": detect_tcp_events, "dns": detect_dns_events,
             "icmp": detect_icmp_events, "app": detect_app_events}


def run_detectors(capture: Capture, config: Config | None = None,
                  only: set[str] | None = None) -> list[Event]:
    """Run every detector (or those named in `only`), events sorted by time."""
    cfg = config or Config()
    events: list[Event] = []
    for name, detect in DETECTORS.items():
        if only is None or name in only:
            events.extend(detect(capture, cfg))
    return sort_events(events)


__all__ = ["Capture", "Config", "DETECTORS", "ERROR", "Event", "INFO", "SEVERITY_RANK",
           "WARNING", "run_detectors"]
