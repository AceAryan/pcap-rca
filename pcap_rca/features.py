"""Turn parsed packets and flows into feature rows (dicts) for CSV or ML.

Packet rows: one per IP packet, with the fields from the problem statement
(timestamps, addresses, ports, protocol, TCP flags, sizes, inter-packet
timing) plus flow context (flow id, direction, relative sequence numbers).

Flow rows: one per flow, with volume, size, timing and flag statistics and
the TCP handshake/teardown summary from streams.TcpState. Given the
detectors' events, flow rows also carry per-flow event counts (EVENT_FIELDS):
retransmissions, resets, DNS failures... the signals that separate faults,
so a model doesn't have to re-learn them from raw packet counts.
"""
from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path
from statistics import fmean, pstdev
from typing import Iterable, Iterator

from .parser import ACK, CWR, ECE, FIN, PROTO_NAMES, PSH, RST, SYN, URG, Packet, flag_str
from .streams import C2S, S2C, Flow, FlowTable, side_name

PACKET_FIELDS = [
    "frame", "ts", "rel_time", "flow_id", "direction",
    "src", "sport", "dst", "dport", "proto", "ip_len", "payload_len", "ttl",
    "tcp_flags", "tcp_seq_rel", "tcp_ack_rel", "tcp_window", "flow_iat",
    "icmp_type", "icmp_code",
    "dns_id", "dns_is_response", "dns_qname", "dns_qtype", "dns_rcode",
]

FLOW_FIELDS = [
    "flow_id", "proto", "client_ip", "client_port", "server_ip", "server_port",
    "client_inferred", "start_ts", "end_ts", "duration",
    "pkts_c2s", "pkts_s2c", "bytes_c2s", "bytes_s2c", "payload_c2s", "payload_s2c",
    "pkt_len_min", "pkt_len_mean", "pkt_len_max", "pkt_len_std",
    "iat_min", "iat_mean", "iat_max", "iat_std",
    "ttl_min_c2s", "ttl_min_s2c",
    "syn", "fin", "rst", "psh", "ack", "urg", "ece", "cwr",
    "tcp_syn_count", "tcp_synack_count", "tcp_established", "tcp_irtt",
    "tcp_mss_client", "tcp_mss_server", "tcp_wscale_client", "tcp_wscale_server",
    "tcp_close", "tcp_rst_by", "icmp_errors", "dns_rcode", "dns_latency_ms",
]

_UNREACHABLE = {"ICMP_NET_UNREACHABLE", "ICMP_HOST_UNREACHABLE", "ICMP_PORT_UNREACHABLE",
                "ICMP_ADMIN_PROHIBITED", "ICMP_UNREACHABLE_OTHER"}

# Per-flow event features: name -> which events count towards it.
_EVENT_COUNTS = {
    "ev_retrans": lambda e: e.event_type == "TCP_RETRANSMISSION" and e.subtype != "spurious",
    "ev_retrans_spurious": lambda e: e.event_type == "TCP_RETRANSMISSION" and e.subtype == "spurious",
    "ev_dup_ack_runs": lambda e: e.event_type == "TCP_DUP_ACK",
    "ev_out_of_order": lambda e: e.event_type == "TCP_OUT_OF_ORDER" and e.subtype != "capture_skew",
    "ev_lost_segment": lambda e: e.event_type == "TCP_LOST_SEGMENT" and e.subtype != "capture_loss",
    "ev_capture_loss": lambda e: e.event_type == "TCP_LOST_SEGMENT" and e.subtype == "capture_loss",
    "ev_zero_window": lambda e: e.event_type == "TCP_ZERO_WINDOW",
    "ev_rst_abort": lambda e: e.event_type == "TCP_RST_MIDSTREAM" and e.subtype is None,
    "ev_rst_close": lambda e: e.event_type == "TCP_RST_MIDSTREAM" and e.subtype is not None,
    "ev_syn_timeout": lambda e: e.event_type == "TCP_SYN_TIMEOUT",
    "ev_conn_refused": lambda e: e.event_type == "TCP_CONN_REFUSED",
    "ev_incomplete_handshake": lambda e: e.event_type == "TCP_INCOMPLETE_HANDSHAKE",
    "ev_high_rtt": lambda e: e.event_type == "TCP_HIGH_RTT",
    "ev_icmp_unreachable": lambda e: e.event_type in _UNREACHABLE,
    "ev_icmp_frag_needed": lambda e: e.event_type == "ICMP_FRAG_NEEDED",
    "ev_icmp_ttl_exceeded": lambda e: e.event_type == "ICMP_TTL_EXCEEDED",
    "ev_dns_nxdomain": lambda e: e.event_type == "DNS_NXDOMAIN",
    "ev_dns_servfail": lambda e: e.event_type == "DNS_SERVFAIL",
    "ev_dns_refused": lambda e: e.event_type == "DNS_REFUSED",
    "ev_dns_timeout": lambda e: e.event_type == "DNS_TIMEOUT",
    "ev_dns_retrans": lambda e: e.event_type == "DNS_RETRANSMISSION",
    "ev_dns_slow": lambda e: e.event_type == "DNS_SLOW_RESPONSE",
    "ev_dns_nodata": lambda e: e.event_type == "DNS_NODATA",
    "ev_dns_tcp_fallback": lambda e: e.event_type == "DNS_TCP_FALLBACK",
    "ev_http_4xx": lambda e: e.event_type == "HTTP_ERROR_RESPONSE" and e.subtype == "client",
    "ev_http_5xx": lambda e: e.event_type == "HTTP_ERROR_RESPONSE" and e.subtype == "server",
    "ev_http_slow": lambda e: e.event_type == "HTTP_SLOW_RESPONSE",
    "ev_tls_failure": lambda e: e.event_type == "TLS_HANDSHAKE_FAILURE",
    "ev_auth_failure": lambda e: e.event_type == "AUTH_FAILURE",
}
EVENT_FIELDS = list(_EVENT_COUNTS) + ["ev_capture_skew_segments", "zero_window_s", "retrans_rate"]

_FLAG_FIELDS = (("syn", SYN), ("fin", FIN), ("rst", RST), ("psh", PSH),
                ("ack", ACK), ("urg", URG), ("ece", ECE), ("cwr", CWR))


def _proto_name(proto: int) -> str:
    return PROTO_NAMES.get(proto, str(proto))


def packet_rows(packets: Iterable[Packet], table: FlowTable) -> Iterator[dict]:
    """One row per packet, in capture order. Packets must already be in `table`."""
    first_ts = None
    last_in_flow: dict[int, float] = {}
    for p in packets:
        if first_ts is None:
            first_ts = p.ts
        flow = table.flow_of(p)
        direction = seq_rel = ack_rel = flow_iat = None
        if flow is not None:
            d = flow.direction(p)
            direction = "c2s" if d == C2S else "s2c"
            prev = last_in_flow.get(flow.id)
            flow_iat = p.ts - prev if prev is not None else None
            last_in_flow[flow.id] = p.ts
            if flow.tcp is not None and p.tcp_seq is not None:
                isn, peer_isn = flow.tcp.isn(d), flow.tcp.isn(1 - d)
                if isn is not None:
                    seq_rel = (p.tcp_seq - isn) % 2**32
                if peer_isn is not None and p.tcp_flags & ACK:
                    ack_rel = (p.tcp_ack - peer_isn) % 2**32
        dns = p.dns
        yield {
            "frame": p.frame, "ts": p.ts, "rel_time": p.ts - first_ts,
            "flow_id": p.flow_id, "direction": direction,
            "src": p.src, "sport": p.sport, "dst": p.dst, "dport": p.dport,
            "proto": _proto_name(p.proto), "ip_len": p.ip_len,
            "payload_len": p.payload_len, "ttl": p.ttl,
            "tcp_flags": flag_str(p.tcp_flags) if p.tcp_seq is not None else None,
            "tcp_seq_rel": seq_rel, "tcp_ack_rel": ack_rel, "tcp_window": p.tcp_window,
            "flow_iat": flow_iat,
            "icmp_type": p.icmp_type, "icmp_code": p.icmp_code,
            "dns_id": dns.id if dns else None,
            "dns_is_response": dns.is_response if dns else None,
            "dns_qname": dns.qname if dns else None,
            "dns_qtype": dns.qtype if dns else None,
            "dns_rcode": dns.rcode if dns else None,
        }


def _stats(values: list[float]) -> tuple:
    if not values:
        return None, None, None, None
    return min(values), fmean(values), max(values), pstdev(values)


def flow_features(flow: Flow) -> dict:
    pkts = flow.packets
    sizes = [p.ip_len for p in pkts]
    iats = [b.ts - a.ts for a, b in zip(pkts, pkts[1:])]
    by_dir = ([], [])
    for p, d in zip(pkts, flow.directions):
        by_dir[d].append(p)
    c2s, s2c = by_dir

    row = {
        "flow_id": flow.id, "proto": _proto_name(flow.proto),
        "client_ip": flow.client[0], "client_port": flow.client[1],
        "server_ip": flow.server[0], "server_port": flow.server[1],
        "client_inferred": flow.client_inferred,
        "start_ts": flow.first_ts, "end_ts": flow.last_ts, "duration": flow.duration,
        "pkts_c2s": len(c2s), "pkts_s2c": len(s2c),
        "bytes_c2s": sum(p.ip_len for p in c2s), "bytes_s2c": sum(p.ip_len for p in s2c),
        "payload_c2s": sum(p.payload_len for p in c2s),
        "payload_s2c": sum(p.payload_len for p in s2c),
        "ttl_min_c2s": min((p.ttl for p in c2s), default=None),
        "ttl_min_s2c": min((p.ttl for p in s2c), default=None),
        "icmp_errors": len(flow.icmp_errors),
        "dns_rcode": None, "dns_latency_ms": None,
    }
    (row["pkt_len_min"], row["pkt_len_mean"],
     row["pkt_len_max"], row["pkt_len_std"]) = _stats(sizes)
    row["iat_min"], row["iat_mean"], row["iat_max"], row["iat_std"] = _stats(iats)
    for name, bit in _FLAG_FIELDS:
        row[name] = sum(1 for p in pkts if p.tcp_flags & bit)

    t = flow.tcp
    if t is not None:
        row.update({
            "tcp_syn_count": t.syn_count, "tcp_synack_count": t.synack_count,
            "tcp_established": t.established, "tcp_irtt": t.irtt,
            "tcp_mss_client": t.mss[C2S], "tcp_mss_server": t.mss[S2C],
            "tcp_wscale_client": t.wscale[C2S], "tcp_wscale_server": t.wscale[S2C],
            "tcp_close": t.close_reason or "open",
            "tcp_rst_by": None if t.rst_dir is None else side_name(t.rst_dir),
        })

    queries = [p for p in pkts if p.dns is not None and not p.dns.is_response]
    answer = next((p for p in pkts if p.dns is not None and p.dns.is_response), None)
    if answer is not None:
        row["dns_rcode"] = answer.dns.rcode
        if queries and answer.ts >= queries[0].ts:
            row["dns_latency_ms"] = (answer.ts - queries[0].ts) * 1000
    return row


def event_features(flow: Flow, events: list) -> dict:
    """EVENT_FIELDS for one flow, from the detector events located on it."""
    row = {name: sum(1 for e in events if match(e)) for name, match in _EVENT_COUNTS.items()}
    row["ev_capture_skew_segments"] = sum(
        e.count for e in events if e.event_type == "TCP_OUT_OF_ORDER" and e.subtype == "capture_skew")
    row["zero_window_s"] = sum(e.metrics.get("duration", 0.0) for e in events
                               if e.event_type == "TCP_ZERO_WINDOW")
    data_segments = sum(1 for p in flow.packets if p.payload_len)
    row["retrans_rate"] = row["ev_retrans"] / data_segments if data_segments else 0.0
    return row


def flow_rows(table: FlowTable, events: list | None = None) -> Iterator[dict]:
    """One row per flow. With `events` (from detectors.run_detectors) the rows
    also carry EVENT_FIELDS."""
    by_flow: dict[int, list] = defaultdict(list)
    for e in events or ():
        if e.stream_id is not None:
            by_flow[e.stream_id].append(e)
    for flow in table.flows:
        row = flow_features(flow)
        if events is not None:
            row.update(event_features(flow, by_flow.get(flow.id, [])))
        yield row


def write_csv(rows: Iterable[dict], path: str | Path, fields: list[str]) -> int:
    """Write rows to CSV (missing keys become empty cells). Returns the row count."""
    n = 0
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, restval="", extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: ("" if v is None else v) for k, v in row.items()})
            n += 1
    return n
