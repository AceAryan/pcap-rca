"""ICMP / ICMPv6 error detection (docs/event_types.md §4).

Every ICMP error quotes the header of the packet that caused it. Events are
located on that original flow (src/dst/ports of the quoted packet, and its
stream_id when the flow was captured), while `related["reporter"]` is the
device that sent the error: the router without a route, the firewall that
rejected, the hop where TTL ran out.
"""
from __future__ import annotations

from ..parser import ICMP, ICMPV6, Packet
from ..streams import Flow
from .base import ERROR, INFO, WARNING, Capture, Config, Event, sort_events

TRACEROUTE_PORTS = range(33434, 33535)  # classic UDP traceroute destination ports
LOOP_MIN_TTL = 32  # OS default TTLs are 64/128/255; traceroute stops at 30 hops

# (protocol, type) -> {code: event} ; None key = any other code
_UNREACHABLE_V4 = {0: "ICMP_NET_UNREACHABLE", 6: "ICMP_NET_UNREACHABLE", 11: "ICMP_NET_UNREACHABLE",
                   1: "ICMP_HOST_UNREACHABLE", 7: "ICMP_HOST_UNREACHABLE", 12: "ICMP_HOST_UNREACHABLE",
                   3: "ICMP_PORT_UNREACHABLE", 4: "ICMP_FRAG_NEEDED",
                   9: "ICMP_ADMIN_PROHIBITED", 10: "ICMP_ADMIN_PROHIBITED", 13: "ICMP_ADMIN_PROHIBITED"}
_UNREACHABLE_V6 = {0: "ICMP_NET_UNREACHABLE", 1: "ICMP_ADMIN_PROHIBITED", 3: "ICMP_HOST_UNREACHABLE",
                   4: "ICMP_PORT_UNREACHABLE", 5: "ICMP_ADMIN_PROHIBITED", 6: "ICMP_ADMIN_PROHIBITED"}

SEVERITY = {"ICMP_NET_UNREACHABLE": ERROR, "ICMP_HOST_UNREACHABLE": ERROR,
            "ICMP_PORT_UNREACHABLE": WARNING, "ICMP_ADMIN_PROHIBITED": ERROR,
            "ICMP_FRAG_NEEDED": WARNING, "ICMP_TTL_EXCEEDED": WARNING,
            "ICMP_UNREACHABLE_OTHER": WARNING}


def classify(pkt: Packet) -> str | None:
    """Event ID for an ICMP error, or None for types not in the catalog
    (redirects, parameter problems, source quench)."""
    t, c = pkt.icmp_type, pkt.icmp_code
    if pkt.proto == ICMP:
        if t == 3:
            return _UNREACHABLE_V4.get(c, "ICMP_UNREACHABLE_OTHER")
        if t == 11:
            return "ICMP_TTL_EXCEEDED"
    elif pkt.proto == ICMPV6:
        if t == 1:
            return _UNREACHABLE_V6.get(c, "ICMP_UNREACHABLE_OTHER")
        if t == 2:
            return "ICMP_FRAG_NEEDED"
        if t == 3:
            return "ICMP_TTL_EXCEEDED"
    return None


ORIGINAL_WINDOW = 5.0  # seconds to look back when the IP ID can't identify the packet


def _original(err: Packet, flow: Flow | None) -> Packet | None:
    """The captured packet the error quotes, sent before the error.

    With a non-zero IP ID the match is exact; if that packet passed the
    capture point several times (a loop through the capture link), the copy
    with the highest TTL is the one that left the sender. IP ID 0 (and IPv6,
    which has none) identifies nothing, so fall back to the most recent
    packet of the same 5-tuple within ORIGINAL_WINDOW.
    """
    if flow is None:
        return None  # the original wasn't captured
    q = err.icmp_quoted
    same = [p for p in flow.packets
            if p.ts <= err.ts and p.src == q.src and p.dst == q.dst and p.proto == q.proto
            and (q.sport is None or (p.sport, p.dport) == (q.sport, q.dport))]
    if q.ip_id:
        return max((p for p in same if p.ip_id == q.ip_id), key=lambda p: p.ttl, default=None)
    recent = [p for p in same if err.ts - p.ts <= ORIGINAL_WINDOW]
    return recent[-1] if recent else None


def _ttl_subtype(err: Packet, original: Packet | None) -> str:
    q = err.icmp_quoted
    if err.icmp_code == 1:
        return "reassembly"
    if original is not None:
        return "loop" if original.ttl >= LOOP_MIN_TTL else "traceroute"
    if q.dport in TRACEROUTE_PORTS:
        return "traceroute"
    return "unknown"


def detect_icmp_events(capture: Capture, config: Config | None = None) -> list[Event]:
    table = capture.table
    events: list[Event] = []
    for err in table.icmp_errors:
        event_type = classify(err)
        if event_type is None:
            continue
        q = err.icmp_quoted
        flow = table.related_flow(err)
        original = _original(err, flow)
        severity = SEVERITY[event_type]
        subtype = None
        metrics = {"icmp_type": err.icmp_type, "icmp_code": err.icmp_code}

        if event_type == "ICMP_TTL_EXCEEDED":
            subtype = _ttl_subtype(err, original)
            if original is not None:
                metrics["original_ttl"] = original.ttl
            if subtype == "traceroute":
                severity = INFO
        elif event_type == "ICMP_PORT_UNREACHABLE" and q.dport in TRACEROUTE_PORTS:
            subtype, severity = "traceroute", INFO  # a traceroute's final hop
        elif event_type == "ICMP_FRAG_NEEDED":
            metrics["next_hop_mtu"] = err.icmp_mtu
            if original is not None:
                metrics["original_size"] = original.ip_len

        evidence = [err.frame] + ([original.frame] if original is not None else [])
        events.append(Event(
            event_type=event_type, severity=severity, ts_start=err.ts, ts_end=err.ts,
            src=q.src, sport=q.sport, dst=q.dst, dport=q.dport, proto=q.proto,
            stream_id=flow.id if flow is not None else None, subtype=subtype,
            evidence=evidence,
            related={"reporter": err.src,
                     "original_frame": original.frame if original is not None else None},
            metrics=metrics,
        ))
    return sort_events(events)
