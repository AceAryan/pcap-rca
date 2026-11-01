"""Who is affected by a group of events (docs/event_types.md §6).

Events are oriented client -> server (for ICMP errors: the original packet's
source -> destination; for DNS: client -> resolver), so the "server" side of
an event is the thing that might be broken.

Scope of a set of events, narrowest first:
    FLOW          one stream
    SERVICE       one server IP:port, any number of clients
    SERVER        one server IP, several ports
    SUBNET        several servers in one /24 (/64 for IPv6)
    CLIENT        one client, servers in several subnets
    NETWORK_WIDE  several subnets and >= network_wide_fraction of all flows
                  of that protocol
    SCATTERED     several unrelated endpoints, below the network-wide share
"""
from __future__ import annotations

from collections import defaultdict

FLOW, SERVICE, SERVER, SUBNET, CLIENT, NETWORK_WIDE, SCATTERED = (
    "FLOW", "SERVICE", "SERVER", "SUBNET", "CLIENT", "NETWORK_WIDE", "SCATTERED")


def prefix(ip: str | None) -> str:
    if ip is None:
        return "?"
    if ":" in ip:
        return ":".join(ip.split(":")[:4]) + "::/64"
    return ip.rsplit(".", 1)[0] + ".0/24"


def endpoint(ip: str | None, port: int | None) -> str:
    if port is None:
        return str(ip)
    return f"[{ip}]:{port}" if ip and ":" in ip else f"{ip}:{port}"


def _flows_of_protocols(events, capture) -> int:
    protos = {e.proto for e in events}
    return sum(1 for f in capture.table.flows if f.proto in protos)


def scope_of(events, capture, cfg) -> tuple[str, str]:
    """(scope, key) for a set of events; key names what is affected."""
    flows = {e.stream_id for e in events if e.stream_id is not None}
    services = {(e.dst, e.dport) for e in events}
    servers = {e.dst for e in events}
    clients = {e.src for e in events}
    if len(services) == 1:
        (svc,) = services
        if len(flows) == 1 and all(e.stream_id is not None for e in events):
            first = events[0]
            return FLOW, f"{endpoint(first.src, first.sport)} -> {endpoint(*svc)}"
        return SERVICE, endpoint(*svc)
    if len(servers) == 1:
        return SERVER, next(iter(servers))
    prefixes = {prefix(s) for s in servers}
    if len(prefixes) == 1:
        return SUBNET, next(iter(prefixes))
    if len(clients) == 1:
        return CLIENT, next(iter(clients))
    total = _flows_of_protocols(events, capture)
    if total and len(flows) >= cfg.network_wide_fraction * total:
        return NETWORK_WIDE, f"{len(servers)} servers in {len(prefixes)} subnets"
    return SCATTERED, f"{len(servers)} servers in {len(prefixes)} subnets"


def group_events(events, capture, cfg) -> list[list]:
    """Default grouping: per event type, one group per server subnet. Groups
    of one type spanning several subnets are merged when they share a single
    client (a client-side problem) or reach the network-wide share."""
    by_type: dict[str, list] = defaultdict(list)
    for e in events:
        by_type[e.event_type].append(e)

    groups = []
    for evs in by_type.values():
        buckets: dict[str, list] = defaultdict(list)
        for e in evs:
            buckets[prefix(e.dst)].append(e)
        if len(buckets) > 1:
            flows = {e.stream_id for e in evs if e.stream_id is not None}
            total = _flows_of_protocols(evs, capture)
            single_client = len({e.src for e in evs}) == 1
            if single_client or (total and len(flows) >= cfg.network_wide_fraction * total):
                groups.append(evs)
                continue
        groups.extend(buckets.values())
    return groups
