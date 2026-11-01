"""Root-cause rules (docs/event_types.md §7).

Each rule looks at the detected events, groups the ones it cares about
(usually by the affected service, resolver or reporting router), and emits a
Diagnosis: what is probably wrong, how confident we are, the evidence in
plain words, and what to check next.

Rules run in a fixed order and *claim* the events they explain, so a later,
more generic rule doesn't explain them again. For example, a port scan claims
its refused connections (the scanned services aren't broken), and an
unreachable resolver claims the ICMP host-unreachable that proves it.

Scope and timing (aggregation/) set the confidence; they don't decide
whether a rule fires. A capture that only shows one server can't tell
"loss on the path" from "loss at that server", so PATH_LOSS still fires,
just with medium instead of high confidence.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from statistics import fmean, median, pstdev

from ..aggregation import EventGroup, endpoint, make_group, prefix
from ..detectors.base import Capture, Config, Event
from ..parser import TCP

LOW, MEDIUM, HIGH = "low", "medium", "high"
_CONFIDENCE_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}
_SEVERITY_RANK = {"info": 0, "warning": 1, "error": 2}

TITLES = {
    "SCAN_OR_FLOOD": "Scan-like connection pattern (scan, flood or peer-to-peer), not a fault",
    "CAPTURE_LOSS": "The capture itself is unreliable (dropped or misordered packets)",
    "RESOLVER_UNREACHABLE": "DNS resolver is down or unreachable",
    "RESOLVER_REFUSED": "DNS resolver refuses to answer this client",
    "RESOLVER_FAILURE": "DNS resolver is failing",
    "DNS_TCP_BLOCKED": "DNS over TCP is blocked",
    "NAME_NOT_FOUND": "Lookups for names that don't exist",
    "ADMIN_BLOCK": "Traffic explicitly rejected by a firewall",
    "NO_ROUTE": "A router has no route to the destination",
    "ROUTING_LOOP": "Routing loop",
    "HOST_UNREACHABLE": "Host is down or unreachable on its local segment",
    "SERVICE_DOWN": "Service not running or not listening",
    "FIREWALL_DROP": "Connections silently dropped (firewall / ACL)",
    "MTU_MISMATCH": "Smaller-MTU link on the path (handled by PMTU discovery)",
    "PMTU_BLACKHOLE": "PMTU black hole: large packets vanish, ICMP is filtered",
    "RECEIVER_BOTTLENECK": "Receiving application can't keep up (end-host issue)",
    "PACKET_REORDERING": "Packets reordered on the path",
    "PATH_LOSS": "Packet loss on the network path",
    "HIGH_LATENCY_PATH": "High latency on the path",
    "SLOW_RESOLVER": "DNS resolver answers slowly",
    "IDLE_TIMEOUT": "Idle connections reset by a timeout (server or middlebox)",
    "ABRUPT_TERMINATION": "Server aborts connections",
    "APP_ERRORS": "Server-side application errors",
    "TLS_FAILURE": "TLS handshakes fail",
}

# Extra next steps for TLS_FAILURE, by what went wrong.
_TLS_CERT_ALERTS = {"bad_certificate", "unsupported_certificate", "certificate_revoked",
                    "certificate_expired", "certificate_unknown", "unknown_ca",
                    "certificate_required"}
_TLS_NEGOTIATION_ALERTS = {"handshake_failure", "protocol_version", "insufficient_security",
                           "inappropriate_fallback", "no_application_protocol",
                           "unrecognized_name", "missing_extension"}

NEXT_STEPS = {
    "SCAN_OR_FLOOD": ["Identify the process on the source host: scanner, malware, or a "
                      "peer-to-peer application trying many peers",
                      "If it isn't expected, hand off to security",
                      "Don't treat the probed targets as broken"],
    "CAPTURE_LOSS": ["Re-capture with a larger buffer (tcpdump -B) and write to fast local storage",
                     "Check SPAN/mirror port oversubscription; capture closer to the host",
                     "Treat the other findings for this capture with caution"],
    "RESOLVER_UNREACHABLE": ["Ping / ARP the resolver address; is the host up?",
                             "Check the DNS server address handed out by DHCP",
                             "Check firewalls between the client and the resolver on UDP/TCP 53"],
    "RESOLVER_REFUSED": ["Check the resolver's ACL / allow-recursion settings for this client's network",
                         "Check which resolver the client is configured to use (DHCP, resolv.conf)"],
    "RESOLVER_FAILURE": ["Query the same names through another resolver to separate resolver from zone problems",
                         "Check the resolver's logs and its upstream forwarders",
                         "Look for DNSSEC validation failures (SERVFAIL)"],
    "DNS_TCP_BLOCKED": ["Allow TCP/53 between clients and the resolver",
                        "Large answers (DNSSEC, many records) fail without it"],
    "NAME_NOT_FOUND": ["Find the process asking for these names and fix its configuration",
                       "Add the missing record if the name should exist",
                       "Many distinct random-looking names: review the host for malware (DGA)"],
    "ADMIN_BLOCK": ["Inspect the ACL / firewall policy on the reporting device",
                    "Decide whether the blocked traffic should be allowed"],
    "NO_ROUTE": ["Check the routing table and default route on the reporting router",
                 "Look for recent routing changes or a withdrawn route"],
    "ROUTING_LOOP": ["traceroute to the destination: hops will repeat",
                     "Compare the routing tables of the routers involved; look for recent changes"],
    "HOST_UNREACHABLE": ["Check the ARP/neighbour table on the last-hop router",
                         "Check the host's power, NIC, switch port and VLAN"],
    "SERVICE_DOWN": ["On the server: ss -ltnp / netstat to see what is listening",
                     "Check the service's logs, recent deploys and restarts",
                     "Check load-balancer health checks for this service"],
    "FIREWALL_DROP": ["Review host firewall, security groups and ACLs on the path for this port",
                      "Test from both sides of each firewall (tcptraceroute, nmap -Pn -p <port>)"],
    "MTU_MISMATCH": ["Usually harmless; consider MSS clamping on the tunnel/VPN edge"],
    "PMTU_BLACKHOLE": ["Find the path MTU: ping -M do -s <size> towards the server",
                       "Allow ICMP type 3 code 4 (and ICMPv6 type 2) through firewalls",
                       "Clamp the TCP MSS on the tunnel/VPN edge"],
    "RECEIVER_BOTTLENECK": ["Check CPU, disk I/O and memory on the receiving host",
                            "Check the application's read loop and socket buffer sizes",
                            "This is an end-host problem, not a network one"],
    "PACKET_REORDERING": ["Check ECMP / LAG hashing: it should be per flow, not per packet",
                          "Usually low priority unless it triggers spurious retransmissions"],
    "PATH_LOSS": ["Check interface error and discard counters along the path",
                  "Run mtr to find the hop where loss starts",
                  "Check link utilization and duplex/speed settings"],
    "HIGH_LATENCY_PATH": ["Run mtr to see where latency grows",
                          "Check queueing / QoS (bufferbloat) and compare with the expected geographic RTT"],
    "SLOW_RESOLVER": ["Check the resolver's load and cache hit rate",
                      "Check its upstream latency; consider a closer or less loaded resolver"],
    "IDLE_TIMEOUT": ["Find the NAT / firewall / load balancer with that idle timeout",
                     "Enable TCP keep-alive below that timeout, or raise the timeout"],
    "ABRUPT_TERMINATION": ["Check server / proxy logs at the reset times",
                           "Look for crashes, restarts and resource limits (memory, file descriptors)"],
    "APP_ERRORS": ["Check application logs and backend health at those times"],
    "TLS_FAILURE": ["Reproduce with: openssl s_client -connect <server>:<port> -servername <name>"],
}


@dataclass
class Diagnosis:
    rule: str
    title: str
    confidence: str
    target: str  # what is (probably) broken
    scope: str
    pattern: str
    severity: str
    ts_start: float
    ts_end: float
    event_count: int
    evidence: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    frames: list[int] = field(default_factory=list)  # first evidence frames, for Wireshark

    def to_dict(self) -> dict:
        return asdict(self)


def _lower(confidence: str) -> str:
    return {HIGH: MEDIUM, MEDIUM: LOW, LOW: LOW}[confidence]


def _plural(n: int, word: str) -> str:
    if n == 1:
        return f"{n} {word}"
    if word.endswith("y") and word[-2:-1] not in "aeiou":
        return f"{n} {word[:-1]}ies"
    return f"{n} {word}s"


# Lookups that fail all the time on healthy networks: reverse lookups of
# addresses without PTR records, service-discovery probes, resolver self-tests.
_ROUTINE_NXDOMAIN = (".in-addr.arpa", ".ip6.arpa", "._dns-sd._udp.", "dnsbugtest")


def _routine_lookup(name: str | None) -> bool:
    name = (name or "").lower()
    return any(marker in name or name.endswith(marker.rstrip(".")) for marker in _ROUTINE_NXDOMAIN)


class _Context:
    def __init__(self, capture: Capture, events: list[Event], cfg: Config):
        self.capture, self.events, self.cfg = capture, events, cfg
        self.claimed: set[int] = set()
        self.diagnoses: list[Diagnosis] = []
        self.by_frame_icmp = {e.evidence[0]: e for e in events if e.event_type.startswith("ICMP_")}
        self._senders = None

    def get(self, *types: str, subtype: str | None = None, claimed: bool = False) -> list[Event]:
        return [e for e in self.events
                if e.event_type in types and (subtype is None or e.subtype == subtype)
                and (claimed or id(e) not in self.claimed)]

    def on_flows(self, flows: set[int], *types: str) -> list[Event]:
        return [e for e in self.events if e.event_type in types and e.stream_id in flows]

    def claim(self, events) -> None:
        self.claimed.update(id(e) for e in events)

    def senders(self) -> Counter:
        """Packets sent per IP address (who showed any sign of life)."""
        if self._senders is None:
            self._senders = Counter(p.src for p in self.capture.packets)
        return self._senders

    def data_segments(self, flow_dirs: set[tuple[int, str]]) -> int:
        """Data-carrying TCP segments in the given (stream, 'c2s'/'s2c') directions."""
        total = 0
        for stream, direction in flow_dirs:
            flow = self.capture.table.flows[stream]
            d = 0 if direction == "c2s" else 1
            total += sum(1 for p, pd in zip(flow.packets, flow.directions)
                         if pd == d and p.payload_len > 0)
        return total

    def add(self, rule: str, events: list[Event], target: str, confidence: str,
            evidence: list[str], claim: list[Event] | None = None) -> Diagnosis:
        group: EventGroup = make_group(events, self.capture, self.cfg)
        frames = []
        for e in sorted(events, key=lambda e: e.ts_start):
            frames.extend(f for f in e.evidence if f not in frames)
            if len(frames) >= 20:
                break
        diag = Diagnosis(
            rule=rule, title=TITLES[rule], confidence=confidence, target=target,
            scope=group.scope, pattern=group.pattern, severity=group.severity,
            ts_start=group.ts_start, ts_end=group.ts_end, event_count=len(events),
            evidence=evidence, next_steps=list(NEXT_STEPS[rule]), frames=frames[:20])
        self.diagnoses.append(diag)
        self.claim(events if claim is None else claim)
        return diag


def _by(events: list[Event], key) -> dict:
    groups: dict = defaultdict(list)
    for e in events:
        groups[key(e)].append(e)
    return groups


def _service(e: Event) -> tuple:
    return (e.dst, e.dport)


# --------------------------------------------------------------------------
# Rules, in evaluation order
# --------------------------------------------------------------------------

def scan_or_flood(ctx: _Context) -> None:
    failures = ctx.get("TCP_SYN_TIMEOUT", "TCP_CONN_REFUSED", "TCP_INCOMPLETE_HANDSHAKE")
    for src, evs in _by(failures, lambda e: e.src).items():
        targets = {_service(e) for e in evs}
        if len(targets) >= ctx.cfg.scan_min_targets:
            hosts, ports = {e.dst for e in evs}, {e.dport for e in evs}
            if len(hosts) == 1:
                kind = "vertical port scan of one host"
            elif len(ports) == 1:
                kind = f"horizontal scan of port {next(iter(ports))}"
            else:
                kind = "many hosts on many ports: a scan, or a peer-to-peer application trying peers"
            ctx.add("SCAN_OR_FLOOD", evs, src, HIGH if len(targets) >= 50 else MEDIUM, [
                f"{src} made {len(evs)} failed connection attempts to "
                f"{_plural(len(ports), 'port')} on {_plural(len(hosts), 'host')} ({kind})"])
    connection_flood(ctx)
    half_open = ctx.get("TCP_INCOMPLETE_HANDSHAKE")
    for svc, evs in _by(half_open, _service).items():
        sources = {e.src for e in evs}
        if len(sources) >= ctx.cfg.flood_min_sources:
            ctx.add("SCAN_OR_FLOOD", evs, endpoint(*svc), HIGH, [
                f"{len(evs)} half-open handshakes from {len(sources)} sources to "
                f"{endpoint(*svc)} (SYN flood)"])


_FLOOD_SYMPTOMS = ("TCP_SYN_TIMEOUT", "TCP_CONN_REFUSED", "TCP_INCOMPLETE_HANDSHAKE",
                   "TCP_RST_MIDSTREAM", "TCP_RETRANSMISSION", "TCP_DUP_ACK", "TCP_LOST_SEGMENT",
                   "TCP_ZERO_WINDOW", "TCP_HIGH_RTT", "HTTP_SLOW_RESPONSE", "HTTP_ERROR_RESPONSE")


def connection_flood(ctx: _Context) -> None:
    """One client opening a huge number of connections to one service (a
    connection flood: HTTP flood, slowloris, ...). Everything that service
    then suffers is a symptom of the flood, so it is claimed here."""
    pairs: dict = defaultdict(list)
    for f in ctx.capture.table.flows:
        if f.tcp is not None:
            pairs[(f.client[0], f.server)].append(f)
    for (src, svc), flows in pairs.items():
        if len(flows) < ctx.cfg.flood_min_connections:
            continue
        symptoms = [e for e in ctx.get(*_FLOOD_SYMPTOMS) if _service(e) == svc]
        if not symptoms:
            continue
        span = max(f.last_ts for f in flows) - min(f.first_ts for f in flows)
        counts = Counter(e.event_type for e in symptoms)
        listed = ", ".join(f"{n:,} x {t}" for t, n in counts.most_common(4))
        diag = ctx.add("SCAN_OR_FLOOD", symptoms, endpoint(*svc), HIGH, [
            f"{src} opened {len(flows):,} connections to {endpoint(*svc)} in {span:.0f} s "
            f"({len(flows) / max(span, 1):.1f}/s): a connection flood (DoS)",
            f"The service shows the strain: {listed}"])
        diag.next_steps = [f"Block or rate-limit {src} (per-source connection limits)",
                           "Enable SYN cookies and shorter header/body timeouts on the server "
                           "(slow-rate attacks such as slowloris hold connections open)",
                           "Hand off to security: identify the source host"]


def capture_loss(ctx: _Context) -> None:
    lost = ctx.get("TCP_LOST_SEGMENT", subtype="capture_loss")
    skew = ctx.get("TCP_OUT_OF_ORDER", subtype="capture_skew")
    skewed = sum(e.count for e in skew)
    if len(lost) < ctx.cfg.capture_loss_min and skewed < ctx.cfg.capture_skew_min:
        return
    evidence = []
    if lost:
        flows = {e.stream_id for e in lost}
        missing = sum(e.metrics.get("missing_bytes", 0) for e in lost)
        evidence.append(f"{_plural(len(lost), 'time')} the receiver ACKed data the capture never "
                        f"saw ({missing:,} bytes on {_plural(len(flows), 'flow')}): the capture "
                        "tool dropped packets, the network didn't")
    if skewed:
        lags = sorted(e.metrics["median_lag_ms"] for e in skew)
        evidence.append(f"{skewed:,} data segments on {_plural(len(skew), 'flow direction')} were "
                        "recorded after the ACK that covers them (median lag "
                        f"{lags[len(lags) // 2]:.3f} ms): the capture point timestamps the two "
                        "directions inconsistently, e.g. a mirror port merging two links")
    flows = {e.stream_id for e in lost + skew}
    ctx.add("CAPTURE_LOSS", lost + skew, "this capture",
            HIGH if len(flows) >= 2 else MEDIUM, evidence)


def resolver_unreachable(ctx: _Context) -> None:
    for resolver, evs in _by(ctx.get("DNS_TIMEOUT"), lambda e: e.dst).items():
        icmp = []
        for e in evs:
            for ref in e.related.get("icmp_errors", []):
                ic = ctx.by_frame_icmp.get(ref["frame"])
                if ic is not None and ic not in icmp:
                    icmp.append(ic)
        if not icmp:
            continue
        kinds = Counter(f"{ic.event_type} from {ic.related['reporter']}" for ic in icmp)
        ctx.add("RESOLVER_UNREACHABLE", evs + icmp, resolver, HIGH, [
            f"{_plural(len(evs), 'DNS lookup')} to {resolver} got no answer",
            "The network reported why: " + ", ".join(f"{n} x {k}" for k, n in kinds.items())])


def resolver_refused(ctx: _Context) -> None:
    for resolver, evs in _by(ctx.get("DNS_REFUSED"), lambda e: e.dst).items():
        names = {e.metrics.get("qname") for e in evs}
        ctx.add("RESOLVER_REFUSED", evs, resolver, HIGH, [
            f"{resolver} answered REFUSED to {_plural(len(evs), 'query')} "
            f"({_plural(len(names), 'name')}) from {', '.join(sorted({e.src for e in evs}))}"])


def resolver_failure(ctx: _Context) -> None:
    evs_all = ctx.get("DNS_SERVFAIL", "DNS_TIMEOUT")
    for resolver, evs in _by(evs_all, lambda e: e.dst).items():
        servfail = [e for e in evs if e.event_type == "DNS_SERVFAIL"]
        timeouts = [e for e in evs if e.event_type == "DNS_TIMEOUT"]
        evidence = []
        if servfail:
            evidence.append(f"{resolver} answered SERVFAIL to {_plural(len(servfail), 'query')}")
        if timeouts:
            names = {e.metrics.get("qname") for e in timeouts}
            evidence.append(f"{_plural(len(timeouts), 'lookup')} ({_plural(len(names), 'name')}) "
                            f"to {resolver} never got an answer and no ICMP error explains why")
        if len(evs) == 1:
            confidence = MEDIUM  # one failed lookup is thin evidence for a broken resolver
        elif servfail or ctx.senders()[resolver]:
            confidence = HIGH  # the resolver is alive but not resolving
        else:
            confidence = MEDIUM
            evidence.append(f"{resolver} sent nothing at all in this capture, so it may "
                            "also be unreachable without the network reporting it")
        ctx.add("RESOLVER_FAILURE", evs, resolver, confidence, evidence)


def dns_tcp_blocked(ctx: _Context) -> None:
    blocked = [e for e in ctx.get("DNS_TCP_FALLBACK")
               if e.metrics.get("tcp_attempted") and not e.metrics.get("tcp_ok")]
    for resolver, evs in _by(blocked, lambda e: e.dst).items():
        syn_fail = [e for e in ctx.get("TCP_SYN_TIMEOUT", "TCP_CONN_REFUSED")
                    if e.dst == resolver and e.dport == 53]
        ctx.add("DNS_TCP_BLOCKED", evs, f"{resolver}:53/tcp", HIGH, [
            f"{_plural(len(evs), 'answer')} from {resolver} were truncated and the client's "
            "TCP retry failed to connect"], claim=evs + syn_fail)


def name_not_found(ctx: _Context) -> None:
    nxdomain = [e for e in ctx.get("DNS_NXDOMAIN") if not _routine_lookup(e.metrics.get("qname"))]
    for client, evs in _by(nxdomain, lambda e: e.src).items():
        names = Counter(e.metrics.get("qname") for e in evs)
        repeated = [n for n, c in names.items() if c >= 2]
        group = make_group(evs, ctx.capture, ctx.cfg)
        top = ", ".join(f"{n} ({c}x)" if c > 1 else str(n) for n, c in names.most_common(5))
        verb = "doesn't" if len(names) == 1 else "don't"
        evidence = [f"{client} looked up {_plural(len(names), 'name')} that {verb} exist: {top}"]
        if group.pattern == "PERIODIC":
            evidence.append(f"The lookups repeat every {group.pattern_info['period']:.1f} s "
                            "(a misconfigured process retrying)")
        if len(names) >= 20:
            evidence.append(f"{len(names)} distinct non-existent names: if they look random, "
                            "consider DGA malware")
        confidence = HIGH if repeated or group.pattern == "PERIODIC" else MEDIUM
        ctx.add("NAME_NOT_FOUND", evs, client, confidence, evidence)


def _by_reporter(events: list[Event]) -> dict:
    return _by(events, lambda e: e.related.get("reporter"))


def admin_block(ctx: _Context) -> None:
    for reporter, evs in _by_reporter(ctx.get("ICMP_ADMIN_PROHIBITED")).items():
        blocked = sorted({endpoint(*_service(e)) for e in evs})
        ctx.add("ADMIN_BLOCK", evs, reporter, HIGH, [
            f"{reporter} rejected {_plural(len(evs), 'packet')} with ICMP "
            f"'administratively prohibited' (to {', '.join(blocked[:5])})"])


def no_route(ctx: _Context) -> None:
    for reporter, evs in _by_reporter(ctx.get("ICMP_NET_UNREACHABLE")).items():
        dests = sorted({e.dst for e in evs})
        ctx.add("NO_ROUTE", evs, reporter, HIGH, [
            f"{reporter} reported 'network unreachable' for {', '.join(dests[:5])}"])


def routing_loop(ctx: _Context) -> None:
    loops = ctx.get("ICMP_TTL_EXCEEDED", subtype="loop")
    for net, evs in _by(loops, lambda e: prefix(e.dst)).items():
        reporters = sorted({e.related.get("reporter") for e in evs})
        ttls = sorted({e.metrics.get("original_ttl") for e in evs if e.metrics.get("original_ttl")})
        ctx.add("ROUTING_LOOP", evs, net, HIGH if len(evs) >= 2 else MEDIUM, [
            f"{_plural(len(evs), 'packet')} to {net} left with TTL {ttls or '?'} "
            f"and still expired (reported by {', '.join(reporters)})"])


def host_unreachable(ctx: _Context) -> None:
    for host, evs in _by(ctx.get("ICMP_HOST_UNREACHABLE"), lambda e: e.dst).items():
        reporters = sorted({e.related.get("reporter") for e in evs})
        ctx.add("HOST_UNREACHABLE", evs, host, HIGH, [
            f"{', '.join(reporters)} reported 'host unreachable' for {host} "
            f"({_plural(len(evs), 'packet')})"])
    # Silence on several ports of a host that never sent anything at all.
    for host, evs in _by(ctx.get("TCP_SYN_TIMEOUT"), lambda e: e.dst).items():
        ports = {e.dport for e in evs}
        if len(ports) >= 2 and not ctx.senders()[host]:
            ctx.add("HOST_UNREACHABLE", evs, host, MEDIUM, [
                f"Connection attempts to {_plural(len(ports), 'port')} on {host} all timed out "
                "and the host sent nothing at all"])


def _answering_ports(ctx: _Context, host: str) -> set[int]:
    return {f.server[1] for f in ctx.capture.table.flows
            if f.server[0] == host and f.tcp is not None and f.tcp.established}


def _late_reply(e: Event) -> bool:
    """ICMP port unreachable for traffic *from* a service port to an ephemeral
    port: a reply (often DNS) arriving after the client closed its socket."""
    return e.sport is not None and e.sport < 1024 <= e.dport


def service_down(ctx: _Context) -> None:
    evs_all = ctx.get("TCP_CONN_REFUSED") + [
        e for e in ctx.get("ICMP_PORT_UNREACHABLE")
        if e.subtype != "traceroute" and not _late_reply(e)]
    for svc, evs in _by(evs_all, _service).items():
        host, port = svc
        others = _answering_ports(ctx, host) - {port}
        how = Counter("refused (TCP RST)" if e.event_type == "TCP_CONN_REFUSED"
                      else "ICMP port unreachable" for e in evs)
        evidence = [f"{_plural(len(evs), 'attempt')} to {endpoint(host, port)} rejected: "
                    + ", ".join(f"{n} x {k}" for k, n in how.items())]
        if others:
            evidence.append(f"{host} itself is up: it accepts connections on port(s) "
                            f"{', '.join(map(str, sorted(others)[:5]))}")
        ctx.add("SERVICE_DOWN", evs, endpoint(host, port), HIGH if others else MEDIUM, evidence)


def firewall_drop(ctx: _Context) -> None:
    for svc, evs in _by(ctx.get("TCP_SYN_TIMEOUT"), _service).items():
        host, port = svc
        others = _answering_ports(ctx, host) - {port}
        same_ok = [f for f in ctx.capture.table.flows
                   if f.server == svc and f.tcp is not None and f.tcp.established]
        syns = sum(e.metrics.get("syn_count", 1) for e in evs)
        evidence = [f"{_plural(len(evs), 'connection attempt')} to {endpoint(host, port)} got "
                    f"no answer at all ({syns} SYNs, no SYN-ACK, RST or ICMP)"]
        if others:
            evidence.append(f"{host} is up: it accepts connections on port(s) "
                            f"{', '.join(map(str, sorted(others)[:5]))}")
            confidence = HIGH
        elif same_ok:
            evidence.append(f"Other connections to {endpoint(host, port)} succeed")
            confidence = HIGH
        else:
            evidence.append(f"{host} answered nothing else in this capture, so it may also be down")
            confidence = LOW
        ctx.add("FIREWALL_DROP", evs, endpoint(host, port), confidence, evidence)


def mtu_mismatch(ctx: _Context) -> None:
    for reporter, evs in _by_reporter(ctx.get("ICMP_FRAG_NEEDED")).items():
        flows = {e.stream_id for e in evs if e.stream_id is not None}
        mtus = sorted({e.metrics.get("next_hop_mtu") for e in evs if e.metrics.get("next_hop_mtu")})
        continued = True
        for e in evs:
            if e.stream_id is None or not e.metrics.get("next_hop_mtu"):
                continue
            flow = ctx.capture.table.flows[e.stream_id]
            limit = e.metrics["next_hop_mtu"]
            if not any(p.ts > e.ts_start and p.src == e.src and 0 < p.ip_len <= limit
                       and p.payload_len > 0 for p in flow.packets):
                continued = False
        retrans = ctx.on_flows(flows, "TCP_RETRANSMISSION")
        evidence = [f"{reporter} reported a next-hop MTU of {', '.join(map(str, mtus)) or '?'} "
                    f"({_plural(len(evs), 'message')})"]
        if continued:
            evidence.append("The sender switched to smaller packets and the transfer continued")
        else:
            evidence.append("But the flow did not continue with smaller packets afterwards")
        if retrans:
            evidence.append(f"{_plural(len(retrans), 'retransmission')} on those flows are "
                            "the oversized segments being resent smaller")
        ctx.add("MTU_MISMATCH", evs, reporter, HIGH if continued else MEDIUM, evidence,
                claim=evs + retrans)


def pmtu_blackhole(ctx: _Context) -> None:
    frag_flows = {e.stream_id for e in ctx.get("ICMP_FRAG_NEEDED", claimed=True)}
    rto = [e for e in ctx.get("TCP_RETRANSMISSION") if e.subtype == "rto"]
    for stream, evs in _by(rto, lambda e: e.stream_id).items():
        if stream is None or stream in frag_flows or len(evs) < 2:
            continue
        flow = ctx.capture.table.flows[stream]
        if flow.tcp is None or not flow.tcp.established:
            continue
        direction = evs[0].metrics["direction"]
        d = 0 if direction == "c2s" else 1
        sent = [p for p, pd in zip(flow.packets, flow.directions) if pd == d and p.payload_len]
        if not sent:
            continue  # only bare FINs were resent
        biggest = max(p.payload_len for p in sent)
        if not all(e.metrics["len"] >= max(ctx.cfg.pmtu_min_segment, 0.9 * biggest) for e in evs):
            continue
        # Stalled: the peer never ACKs past the first resent segment.
        first_seq = min(e.metrics["seq"] for e in evs)
        isn = flow.tcp.isn(d)
        acks = [(p.tcp_ack - isn) % 2**32 for p, pd in zip(flow.packets, flow.directions)
                if pd != d and p.tcp_flags & 0x10 and p.ts >= evs[0].ts_start]
        if isn is None or any(a > first_seq for a in acks):
            continue
        sizes = sorted({e.metrics["len"] for e in evs})
        ctx.add("PMTU_BLACKHOLE", evs, endpoint(flow.server[0], flow.server[1]), HIGH, [
            "The handshake succeeded, but full-size segments "
            f"({', '.join(map(str, sizes))} bytes of payload) were resent {_plural(len(evs), 'time')} "
            "and never acknowledged",
            "No ICMP 'fragmentation needed' reached the sender: it is probably filtered"])


def receiver_bottleneck(ctx: _Context) -> None:
    def advertiser(e: Event) -> str:
        return e.src if e.metrics.get("advertised_by") == "client" else e.dst

    for host, evs in _by(ctx.get("TCP_ZERO_WINDOW"), advertiser).items():
        total = sum(e.metrics.get("duration", 0.0) for e in evs)
        probes = sum(e.metrics.get("probes", 0) for e in evs)
        if total < ctx.cfg.zero_window_min_s and probes == 0:
            continue  # a few milliseconds of full buffer is normal under load
        flows = {e.stream_id for e in evs}
        side_effects = ctx.on_flows(flows, "TCP_RETRANSMISSION")
        evidence = [f"{host} advertised a zero receive window {_plural(len(evs), 'time')} "
                    f"for {total:.2f} s in total; the sender probed {_plural(probes, 'time')}"]
        if side_effects:
            evidence.append(f"{_plural(len(side_effects), 'retransmission')} on the same flows "
                            "are a side effect of the starved receiver")
        ctx.add("RECEIVER_BOTTLENECK", evs, host,
                HIGH if total >= 1.0 or len(evs) >= 3 else MEDIUM, evidence,
                claim=evs + side_effects)


def packet_reordering(ctx: _Context) -> None:
    ooo = [e for e in ctx.get("TCP_OUT_OF_ORDER") if e.subtype != "capture_skew"]
    for net, evs in _by(ooo, lambda e: prefix(e.dst)).items():
        if len(evs) < ctx.cfg.reorder_min_events:
            continue
        flows = {e.stream_id for e in evs}
        retrans = ctx.on_flows(flows, "TCP_RETRANSMISSION")
        real_loss = [e for e in retrans if e.subtype != "spurious"]
        if len(evs) < len(real_loss):
            continue  # loss dominates: PATH_LOSS explains these flows better
        dirs = {(e.stream_id, e.metrics["direction"]) for e in evs}
        rate = len(evs) / max(ctx.data_segments(dirs), 1)
        spurious = [e for e in retrans if e.subtype == "spurious"]
        dupacks = ctx.on_flows(flows, "TCP_DUP_ACK")
        late = sum(1 for e in evs if e.subtype == "late_original")
        evidence = [f"{len(evs)} segments ({rate:.1%} of data) arrived out of order on "
                    f"{_plural(len(flows), 'flow')} to {net}"]
        if late:
            evidence.append(f"{late} originals arrived after their own retransmission")
        if spurious:
            evidence.append(f"{_plural(len(spurious), 'retransmission')} were unnecessary "
                            "(spurious), triggered by the reordering")
        ctx.add("PACKET_REORDERING", evs, net, HIGH if rate >= 0.05 else MEDIUM, evidence,
                claim=evs + spurious + dupacks)


def path_loss(ctx: _Context) -> None:
    retrans = [e for e in ctx.get("TCP_RETRANSMISSION") if e.subtype != "spurious"]
    groups = _by(retrans, lambda e: prefix(e.dst))
    if len(groups) > 1:
        flows = {e.stream_id for e in retrans}
        tcp_flows = sum(1 for f in ctx.capture.table.flows if f.proto == TCP)
        if tcp_flows and len(flows) >= ctx.cfg.network_wide_fraction * tcp_flows:
            groups = {"many subnets": retrans}
    for net, evs in groups.items():
        flows = {e.stream_id for e in evs}
        dirs = {(e.stream_id, e.metrics["direction"]) for e in evs}
        segments = ctx.data_segments(dirs)
        rate = len(evs) / max(segments, 1)
        signals = [e for e in ctx.on_flows(flows, "TCP_DUP_ACK", "TCP_LOST_SEGMENT")
                   if e.subtype != "capture_loss" and id(e) not in ctx.claimed]
        ooo = [e for e in ctx.on_flows(flows, "TCP_OUT_OF_ORDER") if e.subtype != "capture_skew"]
        if (rate <= ctx.cfg.loss_rate_threshold or len(evs) < ctx.cfg.loss_min_retrans
                or not signals or len(ooo) >= len(evs)):
            continue
        servers = {e.dst for e in evs}
        upstream = sum(1 for e in signals if e.event_type == "TCP_LOST_SEGMENT"
                       and e.subtype == "upstream")
        evidence = [f"Retransmission rate {rate:.1%} ({len(evs)} of {segments:,} data segments) "
                    f"on {_plural(len(flows), 'flow')} to {_plural(len(servers), 'server')} in {net}"]
        if upstream:
            verb = "was" if upstream == 1 else "were"
            evidence.append(f"{_plural(upstream, 'gap')} in the received data {verb} later filled by "
                            "retransmissions: the loss happened before the capture point")
        dup_runs = sum(1 for e in signals if e.event_type == "TCP_DUP_ACK")
        if dup_runs:
            evidence.append(f"{_plural(dup_runs, 'run')} of duplicate ACKs signalled the losses")
        if len(servers) >= 2 or rate >= 0.05:
            confidence = HIGH
        else:
            confidence = MEDIUM
            evidence.append("Only one server is involved, so loss at that server can't be ruled out")
        ctx.add("PATH_LOSS", evs, net, confidence, evidence, claim=evs + signals)


def high_latency_path(ctx: _Context) -> None:
    for net, evs in _by(ctx.get("TCP_HIGH_RTT"), lambda e: prefix(e.dst)).items():
        flows = {e.stream_id for e in evs}
        if len(flows) < ctx.cfg.high_latency_min_flows:
            continue
        rtts = [e.metrics["irtt_ms"] for e in evs]
        clients = sorted({e.src for e in evs})
        shown = ", ".join(clients[:3]) + (f" and {len(clients) - 3} more" if len(clients) > 3 else "")
        ctx.add("HIGH_LATENCY_PATH", evs, net, HIGH if len(flows) >= 3 else MEDIUM, [
            f"Handshake RTT between {shown} and {net} was {median(rtts):.0f} ms (median of "
            f"{_plural(len(flows), 'connection')}, max {max(rtts):.0f} ms)"])


def slow_resolver(ctx: _Context) -> None:
    slow_nets = {d.target for d in ctx.diagnoses if d.rule == "HIGH_LATENCY_PATH"}
    for resolver, evs in _by(ctx.get("DNS_SLOW_RESPONSE"), lambda e: e.dst).items():
        if len(evs) < ctx.cfg.slow_resolver_min or prefix(resolver) in slow_nets:
            continue
        lat = [e.metrics["latency_ms"] for e in evs]
        ctx.add("SLOW_RESOLVER", evs, resolver, HIGH if len(evs) >= 5 else MEDIUM, [
            f"{resolver} took {median(lat):.0f} ms (median, max {max(lat):.0f} ms) to answer "
            f"{_plural(len(evs), 'lookup')}",
            "TCP handshakes to that network were not slow, so the delay is the resolver itself"])


def idle_timeout(ctx: _Context) -> None:
    resets = [e for e in ctx.get("TCP_RST_MIDSTREAM") if e.metrics.get("idle_before_reset")]
    for svc, evs in _by(resets, _service).items():
        idles = [e.metrics["idle_before_reset"] for e in evs]
        if len(evs) < ctx.cfg.idle_timeout_min_events or fmean(idles) < 1.0:
            continue
        if pstdev(idles) / fmean(idles) >= ctx.cfg.periodic_max_cv:
            continue
        ctx.add("IDLE_TIMEOUT", evs, endpoint(*svc), HIGH, [
            f"{_plural(len(evs), 'connection')} to {endpoint(*svc)} were reset after being idle "
            f"for {fmean(idles):.0f} s each: an idle timeout on the server or a middlebox"])


def abrupt_termination(ctx: _Context) -> None:
    resets = [e for e in ctx.get("TCP_RST_MIDSTREAM")
              if e.metrics.get("sender") == "server" and e.severity == "warning"]
    for svc, evs in _by(resets, _service).items():
        clients = {e.src for e in evs}
        group = make_group(evs, ctx.capture, ctx.cfg)
        if len(evs) < 2 and group.pattern != "BURST":
            continue
        ctx.add("ABRUPT_TERMINATION", evs, endpoint(*svc),
                HIGH if len(clients) >= 2 or group.pattern == "BURST" else MEDIUM, [
                    f"{endpoint(*svc)} reset {_plural(len(evs), 'active connection')} "
                    f"from {_plural(len(clients), 'client')} in the middle of data transfer"])


def tls_failure(ctx: _Context) -> None:
    for svc, evs in _by(ctx.get("TLS_HANDSHAKE_FAILURE"), _service).items():
        alerts = [e.metrics["alert"] for e in evs if e.subtype == "alert"]
        silent = [e for e in evs if e.subtype == "no_server_hello"]
        evidence, steps = [], []
        if alerts:
            senders = sorted({e.metrics["sent_by"] for e in evs if e.subtype == "alert"})
            counts = ", ".join(f"{n} x {a}" for a, n in Counter(alerts).most_common())
            evidence.append(f"The {' and '.join(senders)} aborted the handshake with a fatal "
                            f"alert: {counts}")
        if silent:
            evidence.append(f"{_plural(len(silent), 'ClientHello')} got no ServerHello before "
                            "the connection closed")
        if _TLS_CERT_ALERTS & set(alerts):
            steps += ["Certificate problem: check the server's chain (intermediates), expiry, "
                      "and that the name matches", "Check the client's trusted CA store"]
        if _TLS_NEGOTIATION_ALERTS & set(alerts):
            steps += ["Negotiation problem: compare TLS versions, cipher suites, SNI and ALPN "
                      "supported by both sides"]
        if silent:
            steps += ["Check that the server really speaks TLS on this port",
                      "Look for a middlebox (SNI filter, IPS, proxy) dropping the handshake"]
        flows = {e.stream_id for e in evs}
        resets = ctx.on_flows(flows, "TCP_RST_MIDSTREAM")
        diag = ctx.add("TLS_FAILURE", evs, endpoint(*svc), HIGH if len(evs) >= 2 else MEDIUM,
                       evidence, claim=evs + resets)
        diag.next_steps = steps + diag.next_steps


def app_errors(ctx: _Context) -> None:
    errors = [e for e in ctx.get("HTTP_ERROR_RESPONSE") if e.subtype == "server"]
    for svc, evs in _by(errors, _service).items():
        if len(evs) >= 2:
            ctx.add("APP_ERRORS", evs, endpoint(*svc), MEDIUM,
                    [f"{endpoint(*svc)} returned {_plural(len(evs), '5xx response')}"])


RULES = [scan_or_flood, capture_loss, resolver_unreachable, resolver_refused, resolver_failure,
         dns_tcp_blocked, name_not_found, admin_block, no_route, routing_loop, host_unreachable,
         service_down, firewall_drop, mtu_mismatch, pmtu_blackhole, receiver_bottleneck,
         packet_reordering, path_loss, high_latency_path, slow_resolver, tls_failure,
         idle_timeout, abrupt_termination, app_errors]


def infer(capture: Capture, events: list[Event], config: Config | None = None) -> list[Diagnosis]:
    """Run every rule; most confident and most severe diagnoses first."""
    ctx = _Context(capture, events, config or Config())
    for rule in RULES:
        rule(ctx)
    if any(d.rule == "CAPTURE_LOSS" for d in ctx.diagnoses):
        for d in ctx.diagnoses:
            if d.rule != "CAPTURE_LOSS":
                d.confidence = _lower(d.confidence)
                d.evidence.append("Confidence lowered: the capture itself lost packets")
    ctx.diagnoses.sort(key=lambda d: (-_CONFIDENCE_RANK[d.confidence],
                                      -_SEVERITY_RANK[d.severity], -d.event_count))
    return ctx.diagnoses
