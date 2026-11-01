"""Command-line entry point.

    python -m pcap_rca.cli features CAPTURE [--flows flows.csv] [--packets packets.csv]
    python -m pcap_rca.cli analyze CAPTURE [--json events.json] [--csv events.csv]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter

from .aggregation import aggregate
from .detectors import DETECTORS, SEVERITY_RANK, Capture, Event, run_detectors
from .features import FLOW_FIELDS, PACKET_FIELDS, flow_rows, packet_rows, write_csv
from .inference import infer
from .parser import PROTO_NAMES, UnsupportedCapture, load_packets
from .streams import build_flows

EVENT_CSV_FIELDS = ["ts_start", "ts_end", "severity", "event_type", "subtype", "src", "sport",
                    "dst", "dport", "proto", "stream_id", "count", "evidence", "related", "metrics"]


def cmd_features(args) -> int:
    try:
        packets, stats = load_packets(args.capture, dedup_window=args.dedup_window)
    except (OSError, UnsupportedCapture) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    table = build_flows(packets, idle_timeout=args.idle_timeout)

    span = (stats.last_ts - stats.first_ts) if stats.frames else 0.0
    print(f"{args.capture}")
    print(f"  frames {stats.frames:,}  IP packets {stats.ip_packets:,}  non-IP {stats.non_ip:,}  "
          f"malformed {stats.malformed:,}  duplicates dropped {stats.duplicates:,}  "
          f"fragments {stats.fragments:,}  span {span:,.1f} s")
    by_proto = Counter(PROTO_NAMES.get(f.proto, str(f.proto)) for f in table.flows)
    tcp = [f.tcp for f in table.flows if f.tcp is not None]
    print(f"  flows {len(table.flows):,}  " + "  ".join(f"{k} {v:,}" for k, v in by_proto.most_common()))
    if tcp:
        print(f"  TCP: established {sum(t.established for t in tcp):,}  "
              f"closed by FIN {sum(t.close_reason == 'fin' for t in tcp):,}  "
              f"by RST {sum(t.close_reason == 'rst' for t in tcp):,}  "
              f"no handshake seen {sum(not t.handshake_seen for t in tcp):,}")
    print(f"  ICMP errors {len(table.icmp_errors):,}  "
          f"DNS messages {sum(1 for p in packets if p.dns is not None):,}")

    if args.flows:
        n = write_csv(flow_rows(table), args.flows, FLOW_FIELDS)
        print(f"  wrote {n:,} flow rows to {args.flows}")
    if args.packets:
        n = write_csv(packet_rows(packets, table), args.packets, PACKET_FIELDS)
        print(f"  wrote {n:,} packet rows to {args.packets}")
    return 0


def _endpoint(ip, port) -> str:
    if ip is None:
        return "?"
    if port is None:
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _short_metrics(e: Event, limit: int = 4) -> str:
    parts = []
    for k, v in e.metrics.items():
        if isinstance(v, (list, dict)) or v is None:
            continue
        parts.append(f"{k}={v:.4g}" if isinstance(v, float) else f"{k}={v}")
        if len(parts) == limit:
            break
    if e.related.get("reporter"):
        parts.append(f"reporter={e.related['reporter']}")
    return " ".join(parts)


def cmd_analyze(args) -> int:
    try:
        capture = Capture.from_file(args.capture, dedup_window=args.dedup_window)
    except (OSError, UnsupportedCapture) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    only = set(args.only.split(",")) if args.only else None
    all_events = run_detectors(capture, only=only)
    diagnoses = infer(capture, all_events)
    min_rank = SEVERITY_RANK[args.min_severity]
    events = [e for e in all_events if SEVERITY_RANK[e.severity] >= min_rank]

    stats = capture.stats
    start = stats.first_ts or 0.0
    span = (stats.last_ts - start) if stats.frames else 0.0
    print(args.capture)
    print(f"  {stats.ip_packets:,} IP packets, {len(capture.table.flows):,} flows, {span:,.1f} s")

    if diagnoses:
        print(f"\n  Diagnoses ({len(diagnoses)}, most confident first):")
        for i, d in enumerate(diagnoses, 1):
            print(f"\n  {i}. [{d.confidence}] {d.rule}  {d.target}")
            print(f"     {d.title}")
            noun = "event" if d.event_count == 1 else "events"
            print(f"     {d.event_count} {noun}, scope {d.scope}, {d.pattern}, "
                  f"from {d.ts_start - start:.3f}s to {d.ts_end - start:.3f}s")
            for line in d.evidence:
                print(f"     - {line}")
            print("     Next steps:")
            for step in d.next_steps:
                print(f"       * {step}")
            if d.frames:
                print(f"     Frames: {', '.join(map(str, d.frames[:10]))}")
    else:
        print("\n  No root cause identified.")

    if not events:
        print("  no events")
    else:
        by_type: dict[str, list[Event]] = {}
        for e in events:
            by_type.setdefault(e.event_type, []).append(e)
        rows = sorted(by_type.items(), key=lambda kv: (
            -max(SEVERITY_RANK[e.severity] for e in kv[1]), -len(kv[1]), kv[0]))
        print(f"\n  {'Event':28} {'Count':>6} {'Flows':>6}  Severity  Subtypes")
        for event_type, evs in rows:
            worst = max(evs, key=lambda e: SEVERITY_RANK[e.severity]).severity
            flows = len({e.stream_id for e in evs if e.stream_id is not None})
            subtypes = Counter(e.subtype for e in evs if e.subtype)
            sub = ", ".join(f"{k} {v}" for k, v in subtypes.most_common())
            print(f"  {event_type:28} {len(evs):>6} {flows:>6}  {worst:8}  {sub}")

        shown = sorted(events, key=lambda e: (-SEVERITY_RANK[e.severity], e.ts_start))[:args.limit]
        if shown:
            print(f"\n  {'Most severe' if len(events) > len(shown) else 'All'} events "
                  f"({len(shown)} of {len(events)}), time relative to capture start:")
            for e in shown:
                name = e.event_type + (f"[{e.subtype}]" if e.subtype else "")
                route = f"{_endpoint(e.src, e.sport)} -> {_endpoint(e.dst, e.dport)}"
                print(f"  {e.ts_start - start:9.3f}s  {e.severity:7}  {name:38} {route:44} {_short_metrics(e)}")

    if args.json:
        report = {
            "capture": str(args.capture),
            "diagnoses": [d.to_dict() for d in diagnoses],
            "groups": [g.to_dict() for g in aggregate(events, capture)],
            "events": [e.to_dict() for e in events],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1)
        print(f"\n  wrote {len(diagnoses)} diagnoses and {len(events):,} events to {args.json}")
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=EVENT_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for e in events:
                row = e.to_dict()
                for k in ("evidence", "related", "metrics"):
                    row[k] = json.dumps(row[k])
                writer.writerow({k: "" if v is None else v for k, v in row.items()})
        print(f"  wrote {len(events):,} events to {args.csv}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pcap-rca", description="PCAP root-cause analysis")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("analyze", help="detect network events and infer root causes")
    sp.add_argument("capture", help="pcap or pcapng file")
    sp.add_argument("--json", metavar="PATH", help="write all events as JSON")
    sp.add_argument("--csv", metavar="PATH", help="write all events as CSV")
    sp.add_argument("--only", metavar="LIST",
                    help="comma-separated detectors to run: " + ",".join(d.name for d in DETECTORS))
    sp.add_argument("--min-severity", choices=list(SEVERITY_RANK), default="info")
    sp.add_argument("--limit", type=int, default=20, help="events to list on screen (default 20)")
    sp.add_argument("--dedup-window", type=float, default=0.005,
                    help="seconds within which an identical IPv4 datagram is a capture "
                         "duplicate (0 disables; default 0.005)")
    sp.set_defaults(func=cmd_analyze)

    sp = sub.add_parser("features", help="extract packet and flow features")
    sp.add_argument("capture", help="pcap or pcapng file")
    sp.add_argument("--flows", metavar="CSV", help="write one row per flow")
    sp.add_argument("--packets", metavar="CSV", help="write one row per packet")
    sp.add_argument("--idle-timeout", type=float, default=120.0,
                    help="seconds of silence that end a UDP/other flow (default 120)")
    sp.add_argument("--dedup-window", type=float, default=0.005,
                    help="seconds within which an identical IPv4 datagram is a capture "
                         "duplicate (0 disables; default 0.005)")
    sp.set_defaults(func=cmd_features)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
