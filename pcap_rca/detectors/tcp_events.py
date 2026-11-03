"""TCP event detection (docs/event_types.md §2).

Per flow, two things are examined:

1. The handshake, from streams.TcpState: TCP_SYN_TIMEOUT, TCP_CONN_REFUSED,
   TCP_INCOMPLETE_HANDSHAKE, and (across flows) TCP_HIGH_RTT.
2. A walk through every packet that tracks each direction's sequence space,
   the ACKs flowing back and the advertised window: TCP_RETRANSMISSION,
   TCP_OUT_OF_ORDER, TCP_LOST_SEGMENT, TCP_DUP_ACK, TCP_ZERO_WINDOW and
   TCP_RST_MIDSTREAM.

Sequence numbers are made relative to each side's ISN (or the first sequence
number seen when the handshake wasn't captured) and unwrapped past 2**32.
SYN and FIN each occupy one sequence number.

Out-of-order vs retransmission: when a segment fills a gap, the question is
whether it was sent *before* the segment that revealed the gap (reordering)
or *after* it (a resend). Timing alone can't tell on a fast LAN, where a fast
retransmission can arrive within a millisecond. So the sender's IPv4 ID is
compared first (when that sender numbers packets sequentially), then the TCP
timestamp, and only then the time since the gap appeared.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from statistics import median

from ..parser import ACK, FIN, RST, SYN, Packet
from ..streams import C2S, S2C, Flow
from ..aggregation.spatial import prefix
from .base import (ERROR, INFO, WARNING, Capture, Config, Event, direction_name, flow_event,
                   side_name, sort_events)

MOD = 2**32
HALF = 2**31
# An ACK this far beyond the highest data seen can't be data the capture
# missed (that much would never be in flight unseen); it's a bogus ACK number.
MAX_ACK_JUMP = 2**24


def _nearest(value32: int, ref: int | None) -> int:
    """Unwrap a 32-bit relative sequence number to the value closest to `ref`."""
    if ref is None:
        return value32
    return value32 + ((ref - value32 + HALF) // MOD) * MOD


def _is_tls_alert(p: Packet) -> bool:
    """A single small TLS alert record (e.g. an encrypted close_notify)."""
    h = p.payload_head
    return len(h) >= 5 and h[0] == 0x15 and h[1] == 3 and h[2] <= 4 and p.payload_len <= 64


def _sequential_ids(packets: list[Packet]) -> bool:
    """Does this sender increment its IPv4 ID per packet (Linux, Windows)?

    Random IDs (BSD, macOS) carry no ordering information. Consecutive packets
    count as sequential when their IDs are close in either direction, since
    reordering (the very thing we want to detect) produces small backward steps.
    """
    ids = [p.ip_id for p in packets if p.ip_version == 4 and p.ip_id]
    if len(ids) < 4:
        return False
    close = sum(1 for a, b in zip(ids, ids[1:])
                if 0 < (b - a) % 65536 <= 64 or (a - b) % 65536 <= 64)
    return close / (len(ids) - 1) >= 0.8


@dataclass
class _Gap:
    """Sequence space that appeared to be skipped in one direction."""

    start: int
    end: int
    ts: float
    frame: int
    ip_id: int | None
    tsval: int | None
    kind: str | None = None  # 'upstream' | 'reordered' | 'acked_unseen'
    remaining: list = field(default_factory=list)  # unfilled [start, end) pieces


@dataclass
class _Side:
    """State for one endpoint of a connection."""

    # as a data sender
    base: int | None = None
    next_seq: int | None = None  # highest seq + len seen
    max_acked: int | None = None  # highest ACK the peer sent for this side's data
    gaps: list = field(default_factory=list)
    open_gaps: list = field(default_factory=list)
    data_segments: int = 0
    retransmissions: list = field(default_factory=list)
    sequential_ids: bool = False
    # seq -> (ip_id, tsval, ts, retransmission Event | None) of the first copy seen
    first_copy: dict = field(default_factory=dict)
    # data captured only after the ACK that covers it: (frame, lag after the ACK)
    skewed: list = field(default_factory=list)
    # as an ACK sender
    last_ack: int | None = None
    last_win: int | None = None
    dup_run: int = 0
    dup_frames: list = field(default_factory=list)
    dup_start: float = 0.0
    dup_end: float = 0.0
    dup_sack: bool = False
    # as a receiver advertising its window
    seen_open_window: bool = False
    zw_since: float | None = None
    zw_frames: list = field(default_factory=list)
    zw_probes: int = 0


class _Walk:
    """One pass over a TCP flow's packets."""

    def __init__(self, flow: Flow, cfg: Config):
        self.flow, self.cfg, self.t = flow, cfg, flow.tcp
        self.events: list[Event] = []
        self.sides = [_Side(), _Side()]
        self.sides[C2S].base = self.t.client_isn
        self.sides[S2C].base = self.t.server_isn
        for d in (C2S, S2C):
            self.sides[d].sequential_ids = _sequential_ids(flow.in_direction(d))
        self.ooo_window = max(self.t.irtt or 0.0, cfg.ooo_min_window)
        self.rst_seen = False

    def event(self, event_type, severity, ts, **kw) -> Event:
        e = flow_event(self.flow, event_type, severity, ts, **kw)
        self.events.append(e)
        return e

    # -- main loop -----------------------------------------------------------

    def run(self) -> list[Event]:
        prev_ts = None
        for i, (p, d) in enumerate(zip(self.flow.packets, self.flow.directions)):
            if p.tcp_seq is None:  # header truncated
                continue
            me, peer = self.sides[d], self.sides[1 - d]
            flags = p.tcp_flags
            if flags & RST:
                if not self.rst_seen:
                    self.rst_seen = True
                    self._on_first_rst(p, d, i, prev_ts)
                prev_ts = p.ts
                continue
            if flags & ACK and peer.base is not None:
                ack = _nearest((p.tcp_ack - peer.base) % MOD, peer.next_seq)
                self._on_ack(me, peer, p, d, ack)
            self._on_window(me, p, d)
            self._on_segment(me, peer, p, d)
            prev_ts = p.ts
        self._finish()
        return self.events

    # -- ACKs ----------------------------------------------------------------

    def _on_ack(self, me: _Side, peer: _Side, p: Packet, d: int, ack: int) -> None:
        if peer.next_seq is not None and ack - peer.next_seq > MAX_ACK_JUMP:
            return  # acknowledges data that can't exist: a bogus ACK number (attack tools)
        if peer.max_acked is None or ack > peer.max_acked:
            peer.max_acked = ack
        # The peer's data was ACKed but hasn't appeared in the capture (yet).
        # The gap stays open: if the data shows up later, the capture point
        # timestamps the two directions inconsistently; if it never does,
        # the capture dropped it.
        if peer.next_seq is not None and ack > peer.next_seq:
            gap = _Gap(peer.next_seq, ack, p.ts, p.frame, None, None, kind="acked_unseen",
                       remaining=[[peer.next_seq, ack]])
            peer.gaps.append(gap)
            peer.open_gaps.append(gap)
            peer.next_seq = ack

        pure = p.payload_len == 0 and not p.tcp_flags & (SYN | FIN)
        outstanding = peer.next_seq is not None and peer.next_seq > ack
        if (ack == me.last_ack and p.tcp_window == me.last_win and pure
                and p.tcp_window and outstanding):
            if me.dup_run == 0:
                me.dup_start = p.ts
            me.dup_run += 1
            me.dup_end = p.ts
            me.dup_frames.append(p.frame)
            me.dup_sack = me.dup_sack or p.tcp_sack_blocks > 0
        elif ack != me.last_ack or p.tcp_window != me.last_win:
            self._flush_dup_run(me, d)
            me.last_ack, me.last_win = ack, p.tcp_window

    def _flush_dup_run(self, me: _Side, d: int) -> None:
        if me.dup_run >= self.cfg.dup_ack_threshold:
            self.event("TCP_DUP_ACK", WARNING, me.dup_start, ts_end=me.dup_end,
                       count=me.dup_run, evidence=list(me.dup_frames),
                       metrics={"direction": direction_name(d), "run_length": me.dup_run,
                                "ack": me.last_ack, "sack": me.dup_sack})
        me.dup_run, me.dup_frames, me.dup_sack = 0, [], False

    # -- receive window ------------------------------------------------------

    def _on_window(self, me: _Side, p: Packet, d: int) -> None:
        if p.tcp_flags & SYN or not p.tcp_flags & ACK:
            return
        if p.tcp_window == 0:
            if me.zw_since is None and me.seen_open_window:
                me.zw_since, me.zw_frames, me.zw_probes = p.ts, [p.frame], 0
            elif me.zw_since is not None and len(me.zw_frames) < 50:
                me.zw_frames.append(p.frame)
        else:
            me.seen_open_window = True
            if me.zw_since is not None:
                self._close_zero_window(me, d, p.ts, reopened=True, frame=p.frame)

    def _close_zero_window(self, me: _Side, d: int, ts: float, reopened: bool,
                           frame: int | None = None) -> None:
        self.event("TCP_ZERO_WINDOW", WARNING, me.zw_since, ts_end=ts,
                   count=len(me.zw_frames),
                   evidence=me.zw_frames + ([frame] if frame else []),
                   metrics={"advertised_by": side_name(d),
                            "duration": ts - me.zw_since, "probes": me.zw_probes,
                            "reopened": reopened})
        me.zw_since, me.zw_frames = None, []

    # -- sequence space ------------------------------------------------------

    def _on_segment(self, me: _Side, peer: _Side, p: Packet, d: int) -> None:
        flags = p.tcp_flags
        if me.base is None:
            me.base = p.tcp_seq  # handshake not captured: first seq seen is 0
        rel = _nearest((p.tcp_seq - me.base) % MOD,
                       me.next_seq if me.next_seq is not None else 0)
        if flags & SYN:
            # Handshake events cover SYN (re)transmissions.
            me.next_seq = max(me.next_seq or 0, rel + 1)
            return

        if peer.zw_since is not None and p.payload_len <= 1 and not flags & FIN:
            peer.zw_probes += 1  # zero-window probe, not a retransmission
            return
        seq_len = p.payload_len + (1 if flags & FIN else 0)
        if seq_len == 0:
            return
        if me.next_seq is None:
            me.next_seq = rel + seq_len
            me.data_segments += 1
            me.first_copy[rel] = (p.ip_id, p.tcp_tsval, p.ts, None)
            return
        if p.payload_len <= 1 and not flags & FIN and rel == me.next_seq - 1:
            return  # keep-alive
        me.data_segments += 1
        end = rel + seq_len

        if rel >= me.next_seq:
            if rel > me.next_seq:
                gap = _Gap(me.next_seq, rel, p.ts, p.frame, p.ip_id, p.tcp_tsval,
                           remaining=[[me.next_seq, rel]])
                me.gaps.append(gap)
                me.open_gaps.append(gap)
            me.first_copy[rel] = (p.ip_id, p.tcp_tsval, p.ts, None)
            me.next_seq = end
            return

        gap = self._overlapping_gap(me, rel, end)
        if gap is not None and gap.kind == "acked_unseen":
            # Captured after its own ACK: a capture artifact, not network behaviour.
            me.skewed.append((p.frame, p.ts - gap.ts))
            self._fill(me, gap, rel, end)
            me.first_copy.setdefault(rel, (p.ip_id, p.tcp_tsval, p.ts, None))
        elif gap is not None:
            if self._sent_before(me, p, gap.ip_id, gap.tsval, gap.ts, use_timing=True):
                gap.kind = gap.kind or "reordered"
                self._out_of_order(p, d, rel, "gap", p.ts - gap.ts)
                retrans = None
            else:
                gap.kind = "upstream"
                retrans = self._retransmission(me, peer, p, d, rel, end)
            self._fill(me, gap, rel, end)
            me.first_copy.setdefault(rel, (p.ip_id, p.tcp_tsval, p.ts, retrans))
        else:
            first = me.first_copy.get(rel)
            if first is not None and self._sent_before(me, p, first[0], first[1], first[2],
                                                       use_timing=False):
                # The delayed original, arriving after its resend already filled
                # the gap: reordering, and that resend was unnecessary.
                self._out_of_order(p, d, rel, "late_original", p.ts - first[2])
                if first[3] is not None:
                    first[3].subtype = "spurious"
            else:
                self._retransmission(me, peer, p, d, rel, end)
        me.next_seq = max(me.next_seq, end)

    def _out_of_order(self, p: Packet, d: int, rel: int, subtype: str, delay: float) -> None:
        self.event("TCP_OUT_OF_ORDER", INFO, p.ts, subtype=subtype, evidence=[p.frame],
                   metrics={"direction": direction_name(d), "seq": rel,
                            "len": p.payload_len, "delay": delay})

    @staticmethod
    def _overlapping_gap(me: _Side, start: int, end: int) -> _Gap | None:
        for gap in me.open_gaps:
            if any(s < end and start < e for s, e in gap.remaining):
                return gap
        return None

    @staticmethod
    def _fill(me: _Side, gap: _Gap, start: int, end: int) -> None:
        pieces = []
        for s, e in gap.remaining:
            if e <= start or end <= s:
                pieces.append([s, e])
                continue
            if s < start:
                pieces.append([s, start])
            if end < e:
                pieces.append([end, e])
        gap.remaining = pieces
        if not pieces:
            me.open_gaps.remove(gap)

    def _sent_before(self, me: _Side, p: Packet, ip_id: int | None, tsval: int | None,
                     ts: float, use_timing: bool) -> bool:
        """Was `p` sent before the reference packet (given by its IP ID / TSval / time)?

        Falls back to arrival timing (Wireshark's rule) only if `use_timing`.
        """
        if me.sequential_ids and p.ip_id and ip_id:
            return (p.ip_id - ip_id) % 65536 > 32768
        if p.tcp_tsval is not None and tsval is not None and p.tcp_tsval != tsval:
            return (p.tcp_tsval - tsval) % MOD > HALF
        return use_timing and p.ts - ts <= self.ooo_window

    def _retransmission(self, me: _Side, peer: _Side, p: Packet, d: int,
                        rel: int, end: int) -> Event:
        if me.max_acked is not None and end <= me.max_acked:
            subtype = "spurious"
        elif peer.last_ack == rel and (peer.dup_run >= 2 or (peer.dup_run >= 1 and peer.dup_sack)):
            subtype = "fast"
        else:
            subtype = "rto"
        e = self.event("TCP_RETRANSMISSION", WARNING, p.ts, subtype=subtype,
                       evidence=[p.frame],
                       metrics={"direction": direction_name(d), "seq": rel,
                                "len": p.payload_len})
        me.retransmissions.append(e)
        return e

    # -- RST -----------------------------------------------------------------

    def _on_first_rst(self, p: Packet, d: int, index: int, prev_ts: float | None) -> None:
        t = self.t
        before = self.flow.packets[:index]
        data_before = sum(q.payload_len for q in before)
        if t.handshake_seen and not t.established:
            return  # refused or failed handshake: handshake events cover it
        if not t.handshake_seen and data_before == 0:
            return
        if t.fin_ts[C2S] is not None and t.fin_ts[S2C] is not None:
            return  # both sides had already closed: RST after a graceful close
        recent_data = any(q.payload_len and p.ts - q.ts <= 1.0 for q in before)
        # Unacknowledged *data*: a FIN occupies a sequence number but carries none.
        unacked = any(s.next_seq is not None and s.max_acked is not None
                      and s.next_seq - (1 if t.fin_ts[i] is not None else 0) > s.max_acked
                      for i, s in enumerate(self.sides))
        peer_fin = t.fin_ts[1 - d]
        own_last = next((q for q, qd in zip(reversed(before), reversed(self.flow.directions[:index]))
                         if qd == d and q.payload_len), None)
        if own_last is not None and _is_tls_alert(own_last):
            # The sender ended the TLS session (close_notify) and then dropped
            # the TCP connection: normal HTTPS shutdown, not an abort.
            subtype, severity = "after_tls_close", INFO
        elif peer_fin is not None and peer_fin <= p.ts and not unacked:
            # The peer had already closed and nothing was in flight: an abortive
            # close (Windows servers commonly answer a FIN this way), not an abort.
            subtype, severity = "after_peer_fin", INFO
        else:
            subtype, severity = None, WARNING if recent_data or unacked else INFO
        self.event("TCP_RST_MIDSTREAM", severity, p.ts, subtype=subtype,
                   evidence=[p.frame],
                   metrics={"sender": side_name(d),
                            "bytes_before_reset": data_before,
                            "idle_before_reset": p.ts - prev_ts if prev_ts is not None else None,
                            "unacked_data": unacked})

    # -- end of flow ---------------------------------------------------------

    def _finish(self) -> None:
        last_ts = self.flow.last_ts
        for d, side in enumerate(self.sides):
            self._flush_dup_run(side, d)
            if side.zw_since is not None:
                self._close_zero_window(side, d, last_ts, reopened=False)
            if side.retransmissions:
                rate = len(side.retransmissions) / max(side.data_segments, 1)
                for e in side.retransmissions:
                    e.metrics["retrans_rate"] = rate
            if side.skewed:
                lags = sorted(lag for _, lag in side.skewed)
                self.event("TCP_OUT_OF_ORDER", INFO, self.flow.first_ts, ts_end=last_ts,
                           subtype="capture_skew", count=len(lags),
                           evidence=[frame for frame, _ in side.skewed[:20]],
                           metrics={"direction": direction_name(d), "segments": len(lags),
                                    "median_lag_ms": lags[len(lags) // 2] * 1000})
            for gap in side.gaps:
                if gap.kind == "acked_unseen":
                    if not gap.remaining:
                        continue  # everything turned up later: skew, reported above
                    subtype = "capture_loss"
                elif gap.remaining:
                    acked_past = side.max_acked is not None and side.max_acked > gap.remaining[0][0]
                    subtype = "capture_loss" if acked_past else "unknown"
                elif gap.kind == "upstream":
                    subtype = "upstream"
                else:
                    continue  # filled entirely by reordered segments
                # Bytes never seen; for a gap filled by a retransmission, its full size.
                missing = sum(e - s for s, e in gap.remaining) or gap.end - gap.start
                self.event("TCP_LOST_SEGMENT", WARNING, gap.ts, subtype=subtype,
                           evidence=[gap.frame],
                           metrics={"direction": direction_name(d), "seq": gap.start,
                                    "missing_bytes": missing})


# --------------------------------------------------------------------------
# Handshake events
# --------------------------------------------------------------------------

def _handshake_events(flow: Flow, cfg: Config, capture_end: float) -> list[Event]:
    t = flow.tcp
    c2s, s2c = flow.in_direction(C2S), flow.in_direction(S2C)
    syns = [p for p in c2s if p.tcp_flags & SYN and not p.tcp_flags & ACK]

    if t.syn_count and not t.synack_count:
        if flow.icmp_errors:
            return []  # explained by the ICMP error (icmp_events links it)
        rst = next((p for p in s2c if p.tcp_flags & RST), None)
        if rst is not None:
            return [flow_event(flow, "TCP_CONN_REFUSED", ERROR, t.syn_ts, ts_end=rst.ts,
                               count=t.syn_count,
                               evidence=[p.frame for p in syns] + [rst.frame],
                               metrics={"syn_count": t.syn_count})]
        answered = s2c or any(not p.tcp_flags & (SYN | RST) for p in c2s)
        if not answered and capture_end - t.syn_ts >= cfg.syn_timeout:
            intervals = [round(b.ts - a.ts, 3) for a, b in zip(syns, syns[1:])]
            return [flow_event(flow, "TCP_SYN_TIMEOUT", ERROR, t.syn_ts, ts_end=syns[-1].ts,
                               count=t.syn_count, evidence=[p.frame for p in syns],
                               metrics={"syn_count": t.syn_count, "retry_intervals": intervals})]
        return []

    if t.synack_count and not t.established:
        synacks = [p for p in s2c if p.tcp_flags & SYN and p.tcp_flags & ACK]
        after = [p for p in c2s if p.ts >= t.synack_ts and not p.tcp_flags & SYN]
        if after and after[0].tcp_flags & RST:
            return [flow_event(flow, "TCP_INCOMPLETE_HANDSHAKE", WARNING, t.synack_ts,
                               ts_end=after[0].ts, subtype="rst_after_synack",
                               evidence=[synacks[0].frame, after[0].frame],
                               metrics={"synack_count": t.synack_count})]
        if not after and capture_end - t.synack_ts >= cfg.syn_timeout:
            return [flow_event(flow, "TCP_INCOMPLETE_HANDSHAKE", WARNING, t.synack_ts,
                               ts_end=synacks[-1].ts, subtype="no_ack",
                               count=t.synack_count, evidence=[p.frame for p in synacks],
                               metrics={"synack_count": t.synack_count})]
    return []


def _high_rtt_events(flows: list[Flow], cfg: Config) -> list[Event]:
    # Karn's rule: a handshake whose SYN or SYN-ACK was retransmitted measures
    # the retransmission timeout, not the path, so it gives no RTT sample.
    measured = [(f, f.tcp.irtt) for f in flows
                if f.tcp is not None and f.tcp.irtt is not None
                and f.tcp.syn_count == 1 and f.tcp.synack_count == 1]
    by_prefix: dict[str, list[float]] = {}
    for f, rtt in measured:
        by_prefix.setdefault(prefix(f.server[0]), []).append(rtt)

    baselines = {net: median(samples) * 1000 if len(samples) >= cfg.rtt_baseline_min else None
                 for net, samples in by_prefix.items()}  # once per prefix, not per flow

    events = []
    for f, rtt in measured:
        ms = rtt * 1000
        baseline = baselines[prefix(f.server[0])]
        if ms > cfg.high_rtt_ms:
            rule = "absolute"
        elif (baseline is not None and ms >= cfg.high_rtt_floor_ms
              and ms > cfg.high_rtt_factor * baseline):
            rule = "relative"
        else:
            continue
        evidence = [p.frame for p in f.packets[:3]]
        events.append(flow_event(f, "TCP_HIGH_RTT", WARNING, f.tcp.syn_ts,
                                 ts_end=f.tcp.established_ts, evidence=evidence,
                                 metrics={"irtt_ms": ms, "baseline_ms": baseline, "rule": rule}))
    return events


# --------------------------------------------------------------------------

def detect_tcp_events(capture: Capture, config: Config | None = None) -> list[Event]:
    cfg = config or Config()
    end = capture.end_ts if capture.end_ts is not None else 0.0
    events: list[Event] = []
    for flow in capture.table.flows:
        if flow.tcp is None or not flow.packets:
            continue
        events.extend(_handshake_events(flow, cfg, end))
        events.extend(_Walk(flow, cfg).run())
    events.extend(_high_rtt_events(capture.table.flows, cfg))
    return sort_events(events)
