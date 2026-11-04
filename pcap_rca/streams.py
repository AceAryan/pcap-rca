"""Group packets into bidirectional flows and track TCP connection state.

A flow is one conversation between two endpoints:

- TCP: one connection. A SYN with a new initial sequence number on a 5-tuple
  that is already in use (port reuse) starts a new flow; a retransmitted SYN
  doesn't.
- UDP: packets between the same two endpoints, split after
  `idle_timeout` seconds of silence.
- ICMP echo: one flow per (endpoints, echo identifier).
- Anything else (other IP protocols, fragments that can't be tied to a
  first fragment): one flow per protocol and address pair.

ICMP error messages are not flows of their own. Each one is attached to the
flow whose packet it quotes (`Flow.icmp_errors`) and also listed in
`FlowTable.icmp_errors`, so detectors can connect, say, a host-unreachable
to the SYN that triggered it.

Each flow knows its client (the side that started it) and server. Packet
direction 0 is client -> server and 1 is server -> client.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .parser import ACK, FIN, ICMP, RST, SYN, TCP, UDP, Packet

C2S, S2C = 0, 1


def side_name(direction: int) -> str:
    """Which endpoint sent a packet travelling in `direction`."""
    return "client" if direction == C2S else "server"


Endpoint = tuple[str, int | None]


@dataclass
class TcpState:
    """What the handshake and teardown of one TCP connection looked like."""

    syn_ts: float | None = None  # first SYN
    syn_count: int = 0
    synack_ts: float | None = None  # first SYN-ACK
    synack_count: int = 0
    established_ts: float | None = None  # client's ACK of the SYN-ACK
    client_isn: int | None = None
    server_isn: int | None = None
    mss: list = field(default_factory=lambda: [None, None])  # by direction
    wscale: list = field(default_factory=lambda: [None, None])
    sack_permitted: list = field(default_factory=lambda: [False, False])
    fin_ts: list = field(default_factory=lambda: [None, None])
    rst_ts: float | None = None  # first RST
    rst_dir: int | None = None

    @property
    def handshake_seen(self) -> bool:
        return self.syn_count > 0 or self.synack_count > 0

    @property
    def established(self) -> bool:
        return self.established_ts is not None

    @property
    def irtt(self) -> float | None:
        """Initial RTT: first SYN -> handshake ACK (Wireshark's tcp.analysis.initial_rtt)."""
        if self.syn_ts is None or self.established_ts is None:
            return None
        return self.established_ts - self.syn_ts

    @property
    def client_side_rtt(self) -> float | None:
        """SYN -> SYN-ACK: the capture point to server and back."""
        if self.syn_ts is None or self.synack_ts is None:
            return None
        return self.synack_ts - self.syn_ts

    @property
    def server_side_rtt(self) -> float | None:
        """SYN-ACK -> ACK: the capture point to client and back."""
        if self.synack_ts is None or self.established_ts is None:
            return None
        return self.established_ts - self.synack_ts

    @property
    def close_reason(self) -> str | None:
        """'rst', 'fin' (both sides sent FIN), or None while still open."""
        if self.rst_ts is not None:
            return "rst"
        if self.fin_ts[C2S] is not None and self.fin_ts[S2C] is not None:
            return "fin"
        return None

    def isn(self, direction: int) -> int | None:
        return self.client_isn if direction == C2S else self.server_isn

    def window_shift(self, direction: int) -> int | None:
        """Window-scale shift for segments sent in `direction`.

        None if the handshake wasn't captured (scale unknown); 0 if scaling
        wasn't negotiated by both sides. SYN segments are never scaled.
        """
        if self.syn_count == 0 or self.synack_count == 0:
            return None
        if self.wscale[C2S] is None or self.wscale[S2C] is None:
            return 0
        return self.wscale[direction]


@dataclass(eq=False)
class Flow:
    id: int
    proto: int
    client: Endpoint
    server: Endpoint
    client_inferred: bool  # True when no SYN / echo request said who started it
    packets: list[Packet] = field(default_factory=list)
    directions: list[int] = field(default_factory=list)  # parallel to packets
    icmp_errors: list[Packet] = field(default_factory=list)
    tcp: TcpState | None = None

    @property
    def first_ts(self) -> float:
        return self.packets[0].ts

    @property
    def last_ts(self) -> float:
        return self.packets[-1].ts

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts

    def direction(self, pkt: Packet) -> int:
        if self.client[1] is None:  # no ports: ICMP echo, other protocols
            return C2S if pkt.src == self.client[0] else S2C
        return C2S if (pkt.src, pkt.sport) == self.client else S2C

    def in_direction(self, direction: int) -> list[Packet]:
        return [p for p, d in zip(self.packets, self.directions) if d == direction]

    def add(self, pkt: Packet) -> None:
        d = self.direction(pkt)
        pkt.flow_id = self.id
        self.packets.append(pkt)
        self.directions.append(d)
        if self.tcp is not None:
            _update_tcp(self.tcp, pkt, d)

    def __repr__(self) -> str:
        c = f"{self.client[0]}:{self.client[1]}" if self.client[1] is not None else self.client[0]
        s = f"{self.server[0]}:{self.server[1]}" if self.server[1] is not None else self.server[0]
        return f"<Flow {self.id} proto={self.proto} {c} -> {s} pkts={len(self.packets)}>"


def _update_tcp(t: TcpState, pkt: Packet, d: int) -> None:
    flags = pkt.tcp_flags
    if flags & SYN and not flags & ACK:
        t.syn_count += 1
        if t.syn_ts is None:
            t.syn_ts, t.client_isn = pkt.ts, pkt.tcp_seq
        t.mss[d], t.wscale[d], t.sack_permitted[d] = pkt.tcp_mss, pkt.tcp_wscale, pkt.tcp_sack_permitted
    elif flags & SYN and flags & ACK:
        t.synack_count += 1
        if t.synack_ts is None:
            t.synack_ts, t.server_isn = pkt.ts, pkt.tcp_seq
        t.mss[d], t.wscale[d], t.sack_permitted[d] = pkt.tcp_mss, pkt.tcp_wscale, pkt.tcp_sack_permitted
    elif (flags & ACK and not flags & RST and d == C2S and t.established_ts is None
          and t.server_isn is not None and pkt.tcp_ack == (t.server_isn + 1) & 0xFFFFFFFF):
        t.established_ts = pkt.ts
    if flags & FIN and t.fin_ts[d] is None:
        t.fin_ts[d] = pkt.ts
    if flags & RST and t.rst_ts is None:
        t.rst_ts, t.rst_dir = pkt.ts, d


def _guess_client(pkt: Packet) -> tuple[Endpoint, Endpoint]:
    """Pick (client, server) without a handshake: the well-known port is the server."""
    a, b = (pkt.src, pkt.sport), (pkt.dst, pkt.dport)
    if pkt.sport is not None and pkt.dport is not None:
        if pkt.sport < 1024 <= pkt.dport:
            return b, a
    return a, b


class FlowTable:
    """Assigns packets to flows. Feed packets in capture order with add()."""

    def __init__(self, idle_timeout: float = 120.0):
        self.idle_timeout = idle_timeout  # UDP and other connectionless flows
        self.flows: list[Flow] = []  # index == Flow.id
        self.icmp_errors: list[Packet] = []
        self._active: dict[tuple, Flow] = {}
        self._fragments: dict[tuple, Flow] = {}  # (src, dst, proto, ip_id) -> flow
        self._icmp_related: dict[int, Flow] = {}  # ICMP error frame -> flow

    # -- lookups ------------------------------------------------------------

    def related_flow(self, icmp_error: Packet) -> Flow | None:
        """The flow whose packet this ICMP error quotes, if it was captured."""
        return self._icmp_related.get(icmp_error.frame)

    def flow_of(self, pkt: Packet) -> Flow | None:
        return self.flows[pkt.flow_id] if pkt.flow_id is not None else None

    # -- building -----------------------------------------------------------

    def add(self, pkt: Packet) -> None:
        if pkt.icmp_quoted is not None:
            self._add_icmp_error(pkt)
            return

        if pkt.frag_offset > 0:  # no ports: follow the first fragment
            owner = self._fragments.get((pkt.src, pkt.dst, pkt.proto, pkt.ip_id))
            if owner is not None:
                owner.add(pkt)
                if not pkt.more_fragments:
                    del self._fragments[(pkt.src, pkt.dst, pkt.proto, pkt.ip_id)]
                return

        key = self._key(pkt)
        flow = self._active.get(key)
        if flow is not None and self._starts_new_flow(flow, pkt):
            flow = None
        if flow is None:
            flow = self._new_flow(pkt)
            self._active[key] = flow
        flow.add(pkt)
        if pkt.more_fragments and pkt.frag_offset == 0:
            self._fragments[(pkt.src, pkt.dst, pkt.proto, pkt.ip_id)] = flow

    @staticmethod
    def _key(pkt: Packet) -> tuple:
        if pkt.proto in (TCP, UDP) and pkt.sport is not None:
            a, b = (pkt.src, pkt.sport), (pkt.dst, pkt.dport)
            return (pkt.proto, *sorted((a, b)))
        ips = sorted((pkt.src, pkt.dst))
        if pkt.icmp_echo_id is not None:
            return (pkt.proto, *ips, pkt.icmp_echo_id)
        return (pkt.proto, *ips, None)

    def _starts_new_flow(self, flow: Flow, pkt: Packet) -> bool:
        if flow.tcp is not None:
            if not (pkt.tcp_flags & SYN) or pkt.tcp_flags & ACK:
                return False
            t = flow.tcp
            # A SYN after a mid-stream start, or with a new ISN, is a new connection.
            return t.syn_count == 0 or pkt.tcp_seq != t.client_isn
        return pkt.ts - flow.last_ts > self.idle_timeout

    def _new_flow(self, pkt: Packet) -> Flow:
        inferred = True
        if pkt.proto == TCP and pkt.sport is not None:
            if pkt.tcp_flags & SYN and not pkt.tcp_flags & ACK:
                client, server, inferred = (pkt.src, pkt.sport), (pkt.dst, pkt.dport), False
            elif pkt.tcp_flags & SYN:  # SYN-ACK: the SYN wasn't captured
                client, server, inferred = (pkt.dst, pkt.dport), (pkt.src, pkt.sport), False
            else:
                client, server = _guess_client(pkt)
        elif pkt.proto == UDP and pkt.sport is not None:
            client, server = _guess_client(pkt)
        elif pkt.icmp_echo_id is not None:
            request = 8 if pkt.proto == ICMP else 128
            if pkt.icmp_type == request:
                client, server, inferred = (pkt.src, None), (pkt.dst, None), False
            else:
                client, server = (pkt.dst, None), (pkt.src, None)
        else:
            client, server = (pkt.src, None), (pkt.dst, None)

        flow = Flow(id=len(self.flows), proto=pkt.proto, client=client, server=server,
                    client_inferred=inferred,
                    tcp=TcpState() if pkt.proto == TCP and pkt.sport is not None else None)
        self.flows.append(flow)
        return flow

    def _add_icmp_error(self, pkt: Packet) -> None:
        self.icmp_errors.append(pkt)
        q = pkt.icmp_quoted
        if q.proto in (TCP, UDP) and q.sport is not None:
            key = (q.proto, *sorted(((q.src, q.sport), (q.dst, q.dport))))
        else:
            key = (q.proto, *sorted((q.src, q.dst)), None)
        flow = self._active.get(key)
        if flow is not None:
            flow.icmp_errors.append(pkt)
            self._icmp_related[pkt.frame] = flow


def build_flows(packets: Iterable[Packet], **kwargs) -> FlowTable:
    """Assign packets (in capture order) to flows; kwargs go to FlowTable."""
    table = FlowTable(**kwargs)
    for pkt in packets:
        table.add(pkt)
    return table
