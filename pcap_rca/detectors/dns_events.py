"""DNS event detection (docs/event_types.md §3).

Queries and responses are grouped into transactions: queries from one client
for the same name and type, with no answer in between, belong together
(within `dns_retx_window`), even when the retries go to another resolver.
A query sent after an answer starts a new transaction, so the TCP retry that
follows a truncated UDP answer is not mistaken for a retransmission.

Only standard queries (opcode 0) are analysed; dynamic updates, NOTIFY etc.
are ignored. DNS over TLS/HTTPS is encrypted and not visible here.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..parser import Packet
from ..streams import FlowTable
from .base import ERROR, INFO, WARNING, Capture, Config, Event, flow_event, sort_events

RCODE_EVENTS = {3: ("DNS_NXDOMAIN", WARNING), 2: ("DNS_SERVFAIL", ERROR), 5: ("DNS_REFUSED", ERROR)}
QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
               28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}


@dataclass
class _Transaction:
    client: str
    qname: str | None
    qtype: int | None
    queries: list[Packet] = field(default_factory=list)
    response: Packet | None = None
    extra_responses: int = 0

    @property
    def ids(self) -> set[int]:
        return {q.dns.id for q in self.queries}

    @property
    def first(self) -> Packet:
        return self.queries[0] if self.queries else self.response

    @property
    def servers(self) -> list[str]:
        return sorted({q.dst for q in self.queries})


def _norm(name: str | None) -> str | None:
    return name.rstrip(".").lower() if name else name


def detect_dns_events(capture: Capture, config: Config | None = None) -> list[Event]:
    cfg = config or Config()
    end = capture.end_ts if capture.end_ts is not None else 0.0
    events: list[Event] = []
    for txn in _transactions(capture.packets, cfg):
        events.extend(_events(txn, capture.table, cfg, end))
    return sort_events(events)


# -- grouping ---------------------------------------------------------------

def _transactions(packets: list[Packet], cfg: Config) -> list[_Transaction]:
    done: list[_Transaction] = []
    open_by_key: dict[tuple, _Transaction] = {}

    for p in packets:
        d = p.dns
        if d is None or d.opcode != 0:
            continue
        if not d.is_response:
            key = (p.src, _norm(d.qname), d.qtype)
            txn = open_by_key.get(key)
            if txn is not None and p.ts - txn.queries[0].ts <= cfg.dns_retx_window:
                txn.queries.append(p)
                continue
            if txn is not None:
                done.append(txn)
            open_by_key[key] = _Transaction(p.src, _norm(d.qname), d.qtype, [p])
            continue

        # Response: find the open transaction for this client and query ID.
        key = (p.dst, _norm(d.qname), d.qtype)
        txn = open_by_key.get(key)
        if txn is None or d.id not in txn.ids:
            key, txn = next(((k, t) for k, t in open_by_key.items()
                             if k[0] == p.dst and d.id in t.ids), (None, None))
        if txn is None:
            # Answer to a query that wasn't captured, or a duplicate answer
            # to one that is already finished.
            late = next((t for t in reversed(done[-50:])
                         if t.client == p.dst and t.response is not None and d.id in t.ids), None)
            if late is not None:
                late.extra_responses += 1
            else:
                done.append(_Transaction(p.dst, _norm(d.qname), d.qtype, response=p))
            continue
        txn.response = p
        done.append(txn)
        del open_by_key[key]

    done.extend(open_by_key.values())
    done.sort(key=lambda t: t.first.ts)
    return done


# -- events -----------------------------------------------------------------

def _events(txn: _Transaction, table: FlowTable, cfg: Config, end: float) -> list[Event]:
    first = txn.first
    flow = table.flow_of(first)
    if flow is None:
        return []
    qtype_name = QTYPE_NAMES.get(txn.qtype, str(txn.qtype))
    base_metrics = {"qname": txn.qname, "qtype": qtype_name,
                    "resolver": txn.response.src if txn.response else first.dst}
    query_frames = [q.frame for q in txn.queries]
    events = []

    def add(event_type, severity, ts_start, ts_end=None, evidence=(), subtype=None, **metrics):
        events.append(flow_event(flow, event_type, severity, ts_start, ts_end,
                                 subtype=subtype, evidence=list(evidence),
                                 metrics={**base_metrics, **metrics}))

    for attempt, q in enumerate(txn.queries[1:], start=2):
        add("DNS_RETRANSMISSION", WARNING, q.ts, evidence=[q.frame],
            attempt=attempt, since_first=q.ts - txn.queries[0].ts)

    r = txn.response
    if r is None:
        last = txn.queries[-1]
        if end - last.ts < cfg.dns_timeout:
            return events  # capture ended too soon to call it a timeout
        related, icmp = {}, []
        for q in txn.queries:  # ICMP errors quoting any of the queries
            qflow = table.flow_of(q)
            if qflow is not None:
                icmp.extend(e for e in qflow.icmp_errors if e not in icmp)
        if icmp:
            related = {"icmp_errors": [{"frame": e.frame, "type": e.icmp_type,
                                        "code": e.icmp_code, "reporter": e.src} for e in icmp]}
        events.append(flow_event(flow, "DNS_TIMEOUT", ERROR, txn.queries[0].ts, last.ts,
                                 evidence=query_frames + [e.frame for e in icmp],
                                 related=related,
                                 metrics={**base_metrics, "queries": len(txn.queries),
                                          "servers": txn.servers}))
        return events

    d = r.dns
    evidence = query_frames + [r.frame]
    latency = r.ts - txn.queries[0].ts if txn.queries else None
    if d.rcode in RCODE_EVENTS:
        event_type, severity = RCODE_EVENTS[d.rcode]
        add(event_type, severity, first.ts, r.ts, evidence, rcode=d.rcode)
    elif d.rcode == 0 and d.answer_count == 0 and not d.truncated:
        add("DNS_NODATA", INFO, first.ts, r.ts, evidence)

    if d.truncated and not d.over_tcp:
        # Did the client retry over TCP to the same server, and did that connect?
        tcp_flows = [f for f in table.flows
                     if f.tcp is not None and f.client[0] == txn.client
                     and f.server == (r.src, r.sport)
                     and 0 <= f.first_ts - r.ts <= cfg.dns_retx_window]
        attempted = bool(tcp_flows)
        ok = any(f.tcp.established for f in tcp_flows)
        add("DNS_TCP_FALLBACK", ERROR if attempted and not ok else INFO, first.ts, r.ts,
            evidence + [f.packets[0].frame for f in tcp_flows],
            tcp_attempted=attempted, tcp_ok=ok)

    if latency is not None and latency * 1000 > cfg.dns_slow_ms:
        add("DNS_SLOW_RESPONSE", WARNING, txn.queries[0].ts, r.ts, evidence,
            latency_ms=latency * 1000, queries=len(txn.queries))
    return events
