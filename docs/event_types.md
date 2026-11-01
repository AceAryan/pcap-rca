# Network event catalog

This is the specification the detectors are built against. Every event ID
below is the exact string a detector emits, the string the root-cause rules
match on, and the string used in the ground-truth labels under
`data/synthetic/*.json`.

Pipeline position:

```
parser.py -> streams.py -> detectors/*  -> aggregation/*      -> inference/rules.py
 packets      flows        EVENTS (here)   PATTERNS (here, §6)   ROOT CAUSES (here, §7)
```

---

## 1. Conventions

### 1.1 Event record

Every detector returns a list of events with the same shape (`detectors/base.py`):

| Field | Type | Meaning |
|---|---|---|
| `event_type` | str | ID from this catalog, e.g. `TCP_SYN_TIMEOUT` |
| `subtype` | str \| None | Refinement where listed, e.g. `fast` for a fast retransmission |
| `severity` | `info` \| `warning` \| `error` | Default listed per event; rules may raise it |
| `ts_start`, `ts_end` | float (epoch s) | First / last packet that is evidence for the event |
| `src`, `sport`, `dst`, `dport`, `proto` | | Flow the event belongs to, oriented client → server where known |
| `stream_id` | int \| None | Flow index from `streams.py` |
| `count` | int | Occurrences folded into this event (e.g. 3 SYN retransmissions) |
| `evidence` | list[int] | Frame numbers, so every finding can be checked in Wireshark |
| `related` | dict | Cross-layer links, e.g. the TCP flow quoted inside an ICMP error |
| `metrics` | dict | Event-specific numbers (RTT, duration, rcode, next-hop MTU, …) |

### 1.2 Severity
- **info**: normal protocol behavior worth recording (NODATA, TCP fallback, traceroute).
- **warning**: degrades performance but traffic still flows (retransmissions, slow DNS).
- **error**: something failed (connection never established, name not resolved).

### 1.3 Vantage point
What a capture can show depends on where it was taken. Detectors assume a
single capture point and say where it sits relative to the loss:

- A gap in sequence numbers that is later filled means the packet was lost
  **upstream** of the capture point.
- Data the receiver ACKs but that never appeared in the capture means the
  **capture** dropped it, not the network (`TCP_LOST_SEGMENT` subtype
  `capture_loss`).
- A retransmission seen without a preceding gap means the loss happened
  **downstream** (or the original was delayed).

- The same packet captured twice (SPAN of both ingress and egress, or
  several interfaces) is **not** a retransmission. A real resend has a new
  IPv4 ID; an identical IP ID + seq + length within a few milliseconds is a
  capture duplicate. Drop it in `parser.py` before any detector sees it.

The synthetic captures in `data/synthetic/` are all taken at the client.

### 1.4 Ignoring an incomplete capture
An event that depends on *absence* (no SYN-ACK, no DNS answer) is only
emitted if the capture continues for at least the relevant timeout after the
last request. Otherwise the outcome is unknown and nothing is reported. This
avoids false positives at the end of every capture slice.

All thresholds are configurable; defaults are listed in [§8](#8-default-thresholds).

---

## 2. TCP events (`detectors/tcp_events.py`)

| ID | One-line meaning | Default severity |
|---|---|---|
| `TCP_SYN_TIMEOUT` | Connection attempt never answered | error |
| `TCP_CONN_REFUSED` | Connection attempt answered with RST | error |
| `TCP_INCOMPLETE_HANDSHAKE` | SYN-ACK sent but handshake never completed | warning |
| `TCP_RST_MIDSTREAM` | Established connection aborted with RST | warning |
| `TCP_RETRANSMISSION` | Data segment sent again | warning |
| `TCP_DUP_ACK` | Receiver repeatedly ACKs the same point (signals a hole) | warning |
| `TCP_OUT_OF_ORDER` | Segment arrived late but without retransmission | info |
| `TCP_LOST_SEGMENT` | Gap in sequence space at the capture point | warning |
| `TCP_ZERO_WINDOW` | Receiver advertised a zero window (can't accept data) | warning |
| `TCP_HIGH_RTT` | Handshake round-trip time unusually high | warning |

Flow tracking (`streams.py`) keys TCP by the bidirectional 5-tuple. A SYN on
a 5-tuple whose previous connection has closed (FIN/RST) starts a new stream.

### TCP_SYN_TIMEOUT
- **Detect:** client SYN (plus any retransmitted SYNs) with no SYN-ACK, no RST and no related ICMP error within `syn_timeout` of the first SYN.
- **Metrics:** `syn_count`, retry intervals. Don't assume a particular backoff shape: classic stacks double the interval (1, 2, 4 s…), but recent Linux retries the first SYNs at a fixed 1 s (`net.ipv4.tcp_syn_linear_timeouts`, seen in `data/synthetic/tcp_syn_timeout.pcap`).
- **Not counted:** if an ICMP error quoting this flow arrives, the attempt is explained by the ICMP event (`related`), not reported as a timeout. Retransmitted SYNs are folded into this event, **not** reported as `TCP_RETRANSMISSION`.
- **Cross-check:** `tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.analysis.retransmission`
- **Likely causes:** firewall silently dropping, host down, routing black hole, server SYN backlog full.

### TCP_CONN_REFUSED
- **Detect:** SYN answered by RST (normally RST+ACK with `ack = ISN+1`) from the destination, with no SYN-ACK.
- **Cross-check:** `tcp.flags.reset==1 && tcp.flags.ack==1 && tcp.seq==1 && tcp.ack==1`
- **Likely causes:** nothing listening on the port, service crashed, firewall configured to reject with TCP RST.

### TCP_INCOMPLETE_HANDSHAKE
- **Detect:** SYN-ACK observed but the initiator's final ACK never arrives within `syn_timeout`.
- **Subtypes:** `rst_after_synack` (initiator answered SYN-ACK with RST: half-open scan or client abort), `no_ack` (SYN-ACKs retransmitted, no reply: SYN flood, spoofed sources, asymmetric routing).
- **Likely causes:** port scanning, SYN flood, asymmetric routing, client-side firewall.

### TCP_RST_MIDSTREAM
- **Detect:** RST on a stream after the handshake completed and before both FINs were exchanged.
- **Metrics:** `sender` (client/server), `bytes_before_reset`, `idle_before_reset` (seconds since the previous packet).
- **Severity:** `warning` if unacknowledged data (not counting a FIN) was outstanding or data flowed within the last second; `info` otherwise (some clients close idle connections with RST).
- **Subtypes** for the two normal ways of closing with RST seen on CIC-IDS2017, both `info`:
  - `after_tls_close`: the sender's last data was a small TLS alert record (the encrypted close_notify). HTTPS servers and browsers end the TLS session, then drop TCP.
  - `after_peer_fin`: the other side had already sent FIN and no data was in flight. Windows domain controllers answer a client's FIN this way on Kerberos/LDAP.
- **Likely causes:** application crash or abort, load balancer / NAT / firewall idle timeout, proxy rejecting the request.

### TCP_RETRANSMISSION
- **Detect:** a segment with payload (or FIN) whose sequence range is below the highest sequence already seen in that direction, and which was **sent after** the segment it repeats or the segment that revealed the gap it fills (see [ordering](#which-was-sent-first) below). Otherwise it's `TCP_OUT_OF_ORDER`.
- **Subtypes:**
  - `fast`: the receiver had sent ≥ 2 duplicate ACKs (≥ 1 if they carried SACK blocks) for exactly this sequence number, as in Wireshark.
  - `spurious`: the data had already been ACKed, or the original turned up later (`TCP_OUT_OF_ORDER` subtype `late_original`).
  - `rto`: otherwise (timer-driven; repeated with growing gaps = backoff).
- **Not counted:** keep-alives (≤1 byte at `next_seq − 1`), zero-window probes, SYN/SYN-ACK (handshake events cover them).
- **Metrics:** `direction`, relative `seq`, `len`, and `retrans_rate` (retransmissions / data segments in that direction of the flow).
- **Cross-check:** `tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.spurious_retransmission`
- **Likely causes:** packet loss (congestion, bad link, duplex mismatch), MTU black hole (same segment repeatedly), delay spikes (spurious).

### TCP_DUP_ACK
- **Detect:** pure ACK (no payload, no SYN/FIN/RST) with the same ACK number and the same non-zero window as the previous ACK from that side, while the peer has unacknowledged data outstanding (otherwise it is just a repeated ACK). One event per run of at least `dup_ack_threshold` duplicates; shorter runs still feed the `fast` retransmission subtype.
- **Metrics:** `run_length`, the ACK number (= start of the hole).
- **Cross-check:** `tcp.analysis.duplicate_ack`
- **Likely causes:** loss or reordering on the data path towards the ACK sender.

### TCP_OUT_OF_ORDER
- **Detect:** a segment below the highest sequence seen that was **sent before** the segment it is compared with:
  - subtype `gap`: it fills a gap and was sent before the segment that revealed that gap;
  - subtype `late_original`: its data was already seen, but it was sent before that earlier copy. The delayed original arrived after its own retransmission, which is then marked `spurious`.
  - subtype `capture_skew` (one event per flow direction, `count` = segments): data recorded *after* the ACK that covers it. A receiver can't acknowledge data before it arrives, so the capture point timestamps the two directions inconsistently (typical of a mirror port merging two links). Not network behaviour, and not counted as loss or retransmission. On CIC-IDS2017 Monday this explained 2,346 segments (median lag 0.06 ms) that would otherwise have been 2,346 "spurious retransmissions" plus as many "capture losses".
- **Bogus ACKs:** an ACK more than 16 MB beyond the highest data seen is ignored. That much can't be in flight unseen; such ACK numbers come from attack tools (seen in the CIC-IDS2017 DDoS).
- **Cross-check:** `tcp.analysis.out_of_order`. Wireshark uses arrival timing only, so on fast links it reports some fast retransmissions as out-of-order.

#### Which was sent first
Arrival order says nothing about send order once packets are reordered, and
on a LAN a fast retransmission can arrive within a millisecond of the gap,
so timing alone can't separate "late" from "resent". The detector checks, in
order:
1. **IPv4 ID**, when that sender numbers packets sequentially (Linux and
   Windows do; checked per flow direction): a lower ID was sent earlier.
2. **TCP timestamp (TSval)**, when present and different.
3. **Timing**, for gap fills only: within `ooo_window` (the larger of the
   initial RTT and `ooo_min_window`) of the gap counts as out-of-order.
   Without ID or timestamp information, a repeat of already-seen data is
   always a retransmission.
- **Likely causes:** per-packet load balancing across multiple paths or links (ECMP/LAG), queueing differences. Usually harmless unless it triggers spurious fast retransmissions.

### TCP_LOST_SEGMENT
- **Detect:** a segment whose sequence number is above the next expected one (a gap).
- **Subtypes:**
  - `upstream`: the gap is later filled (by a retransmission), so the loss happened before the capture point.
  - `capture_loss`: the receiver ACKs past the gap but the data never appears, so the capture tool dropped it.
  - `unknown`: the capture ends first.
- **Cross-check:** `tcp.analysis.lost_segment`, `tcp.analysis.ack_lost_segment`
- **Why it matters:** `capture_loss` lowers confidence in every other finding for that capture (see the `CAPTURE_LOSS` rule).

### TCP_ZERO_WINDOW
- **Detect:** window field = 0 in a non-SYN, non-RST segment from a side that had advertised a non-zero window. The event lasts until the window reopens (window update > 0) or the stream ends. It doesn't depend on the window-scale factor, so it works even when the handshake wasn't captured.
- **Metrics:** `advertised_by`, `duration`, `probes` (segments of ≤ 1 byte the peer sent meanwhile; these are never reported as retransmissions), `reopened`.
- **Side effect:** a starved receiver may also drop in-window segments, producing a few genuine `TCP_RETRANSMISSION`s (seen in `data/synthetic/tcp_zero_window.pcap`).
- **Cross-check:** `tcp.analysis.zero_window`, `tcp.analysis.zero_window_probe`
- **Likely causes:** the receiving application isn't reading fast enough (CPU, disk I/O, blocked thread), or its receive buffer is too small. This is an end-host problem, not a network one.

### TCP_HIGH_RTT
- **Detect:** initial RTT (time from SYN to the initiator's ACK, as seen at the capture point) above `high_rtt_ms` (rule `absolute`), **or** above both `high_rtt_floor_ms` and `high_rtt_factor` × the median iRTT to the same /24 (/64 for IPv6) when at least `rtt_baseline_min` samples exist (rule `relative`). The floor stops a 0.2 ms LAN handshake from counting as "4× slower". Following Karn's rule, a handshake whose SYN or SYN-ACK was retransmitted gives no sample: its "RTT" would be the retransmission timeout.
- **Metrics:** `irtt_ms`, `baseline_ms`, `rule`.
- **Cross-check:** `tcp.analysis.initial_rtt > 0.3`
- **Likely causes:** long-distance or satellite path, congestion and bufferbloat, an overloaded server answering SYNs slowly.

---

## 3. DNS events (`detectors/dns_events.py`)

| ID | One-line meaning | Default severity |
|---|---|---|
| `DNS_NXDOMAIN` | Name does not exist (rcode 3) | warning |
| `DNS_SERVFAIL` | Resolver failed (rcode 2) | error |
| `DNS_REFUSED` | Resolver refused to answer (rcode 5) | error |
| `DNS_TIMEOUT` | Query never answered | error |
| `DNS_RETRANSMISSION` | Same query sent again | warning |
| `DNS_SLOW_RESPONSE` | Answered, but slowly | warning |
| `DNS_TCP_FALLBACK` | Truncated UDP answer (TC=1) → retry over TCP | info |
| `DNS_NODATA` | Name exists but has no record of that type | info |

**Transactions.** A query is matched to its response by (client IP/port,
server IP/port, DNS ID, qname, qtype) for UDP, or by TCP stream + ID. Queries
from one client for the same qname + qtype within `dns_retx_window`, with no
answer in between, are one **transaction**, even if retries go to a
different resolver. A query sent *after* an answer starts a new transaction,
so the TCP retry that follows a truncated answer isn't a retransmission. A
response whose query wasn't captured still produces its rcode event. Only
standard queries (opcode 0) are analysed; dynamic updates and NOTIFY are
ignored. DNS over TLS/HTTPS (853/443) is encrypted and invisible to these
detectors.

### DNS_NXDOMAIN
- **Detect:** response with rcode 3. One event per transaction.
- **Metrics:** `qname`, `qtype`, `resolver`.
- **Cross-check:** `dns.flags.rcode == 3`
- **Likely causes:** typo or stale hostname in configuration, a missing record, search-domain expansion (`host.corp.example.com.example.com`, which is mostly harmless noise), or many random-looking names (possible DGA malware: flag for security review).

### DNS_SERVFAIL
- **Detect:** rcode 2. **Cross-check:** `dns.flags.rcode == 2`
- **Likely causes:** the resolver can't reach upstream or authoritative servers, DNSSEC validation failure, a broken zone.

### DNS_REFUSED
- **Detect:** rcode 5. **Cross-check:** `dns.flags.rcode == 5`
- **Likely causes:** the client isn't allowed by the resolver's ACL, a non-recursive server is being used as a resolver, rate limiting.

### DNS_TIMEOUT
- **Detect:** transaction with no response within `dns_timeout` of its last query (§1.4 applies). If an ICMP error quotes the query, it is linked in `related`.
- **Cross-check:** `dns.flags.response == 0 && !dns.response_in`
- **Likely causes:** resolver down or unreachable, firewall dropping UDP/53, the resolver itself timing out upstream.

### DNS_RETRANSMISSION
- **Detect:** every query in a transaction after the first. Emitted per retransmitted query.
- **Cross-check:** `dns.retransmission`
- **Likely causes:** lost query or response, slow resolver.

### DNS_SLOW_RESPONSE
- **Detect:** transaction answered, but more than `dns_slow_ms` after its first query.
- **Metrics:** `latency_ms`.
- **Cross-check:** `dns.time > 0.5`
- **Likely causes:** cache miss with slow upstream recursion, overloaded resolver, high path latency (check `TCP_HIGH_RTT` to the same host).

### DNS_TCP_FALLBACK
- **Detect:** UDP response with TC=1. `metrics.tcp_attempted` records whether the client opened a TCP connection to the same server and port within `dns_retx_window`, and `tcp_ok` whether that connection was established. Success is judged at the TCP level because the TCP answer may span several segments.
- **Cross-check:** `dns.flags.truncated == 1`
- **Severity:** `info`, or `error` if the TCP retry fails (see the `DNS_TCP_BLOCKED` rule).

### DNS_NODATA
- **Detect:** rcode 0 with an empty answer section.
- **Note:** very common for AAAA queries on IPv4-only names; only interesting for A queries or in volume.

---

## 4. ICMP events (`detectors/icmp_events.py`)

ICMP errors carry the IP header and first 8 bytes of the packet that caused
them. Detectors parse that quoted header to fill `related` with the original
flow (protocol, addresses, ports), which lets the rules connect, for example,
an `ICMP_HOST_UNREACHABLE` to the DNS query or TCP SYN that triggered it.
The ICMP **source** address identifies the device that reported the problem.

| ID | ICMPv4 type/code | ICMPv6 type/code | Default severity |
|---|---|---|---|
| `ICMP_NET_UNREACHABLE` | 3/0 | 1/0 | error |
| `ICMP_HOST_UNREACHABLE` | 3/1 | 1/3 | error |
| `ICMP_PORT_UNREACHABLE` | 3/3 | 1/4 | warning |
| `ICMP_ADMIN_PROHIBITED` | 3/9, 3/10, 3/13 | 1/1 | error |
| `ICMP_FRAG_NEEDED` | 3/4 (with next-hop MTU) | 2 (Packet Too Big) | warning |
| `ICMP_TTL_EXCEEDED` | 11/0, 11/1 | 3/0, 3/1 | warning |
| `ICMP_UNREACHABLE_OTHER` | other 3/x | other 1/x | warning |

- **`ICMP_NET_UNREACHABLE`**: a router has no route to the destination network.
- **`ICMP_HOST_UNREACHABLE`**: the last-hop router can't reach the host (usually ARP/ND failure: host down, wrong VLAN).
- **`ICMP_PORT_UNREACHABLE`**: the host is up but nothing listens on that UDP port. This is also how traceroute's final hop answers.
- **`ICMP_ADMIN_PROHIBITED`**: a firewall explicitly rejected the packet. The ICMP source is the firewall.
- **`ICMP_FRAG_NEEDED`**: the packet had DF set and didn't fit the next link. `metrics.next_hop_mtu` comes from the message. Expect the sender to resend smaller segments shortly after.
- **`ICMP_TTL_EXCEEDED`** subtypes:
  - `traceroute`: the quoted probe left with a TTL below 32, or (if it wasn't captured) went to a classic traceroute port 33434–33534. Severity `info`.
  - `loop`: the probe left the capture point with a normal TTL (≥ 32: OS defaults are 64/128/255, traceroute stops at 30) yet still expired, so it circled until TTL ran out. `SkypeIRC.cap` has one: a TTL-64 UDP packet expired 78 ms later at an ISP router.
  - `reassembly`: code 1, fragments that never completed.
  - `unknown`: the original wasn't captured and the port says nothing.

  To tell `traceroute` from `loop`, match the quoted header to the captured outgoing packet and read the TTL it left with (`metrics.original_ttl`). The TTL inside the quote is the remaining value (≈1) and is useless here. The match uses the IP ID when it is non-zero; IP ID 0 identifies nothing, so then it uses the most recent packet of the same 5-tuple within 5 s.
- **`ICMP_PORT_UNREACHABLE`** to a traceroute port (33434–33534) gets subtype `traceroute` and severity `info`: it's the final hop answering, not a fault.

Cross-check filters: `icmp.type == 3 && icmp.code == 4`, `icmp.type == 11`, `icmpv6.type == 2`, etc.

---

## 5. Application events (`detectors/app_events.py`)

HTTP/1.x and TLS are recognised **by content, on any port**, from the first
32 bytes of each TCP segment (`Packet.payload_head`): an HTTP request or
status line, or a TLS record header. Retransmitted segments count once.

Only clear text is visible. HTTP/2 and anything inside TLS are encrypted.
TLS 1.3 also encrypts everything after ServerHello, including most alerts,
so a certificate rejected under TLS 1.3 shows up only as a connection
closing right after the handshake started (TCP events). TLS 1.2 and earlier
send handshake alerts in clear text.

| ID | Detect | Default severity |
|---|---|---|
| `HTTP_ERROR_RESPONSE` | HTTP status ≥ 400 (`subtype` `client` for 4xx, `server` for 5xx). Responses are matched to requests in order (HTTP/1.1 pipelining); `1xx` responses are skipped. Metrics: `status`, `method`, `target` (ends in `...` when the request line didn't fit in 32 bytes), `latency_ms` | info (4xx), warning (5xx) |
| `HTTP_SLOW_RESPONSE` | First response byte more than `http_slow_ms` after the **end** of the request (its last client data segment), so a slow upload isn't blamed on the server. `request_ms` records how long sending the request took | warning |
| `TLS_HANDSHAKE_FAILURE` | subtype `alert`: a clear-text fatal alert (record type 21, length 2, level 2) before any application data. Metrics: `alert` name, `alert_code`, `sent_by`, `server_hello`. subtype `no_server_hello`: a ClientHello never answered by a ServerHello before the connection closed, or for `tls_handshake_timeout` until the capture ends. Metrics: `closed_by`, `waited`, `reset` | error |

Cross-check filters: `http.response.code >= 400`, `tls.alert_message.level == 2`,
`tls.handshake.type == 1` without a following `tls.handshake.type == 2`.

---

## 6. Patterns (`aggregation/`)

Events are grouped by type and scope before root-cause inference, so that
"200 retransmissions" becomes "a burst of retransmissions affecting every
flow towards 10.0.5.0/24".

Events are oriented client → server (ICMP errors: the quoted packet's
source → destination; DNS: client → resolver), so the server side of an
event is the thing that may be broken.

**Spatial scope** (`aggregation/spatial.py`): who is affected. The narrowest
scope that covers every event in the group wins.

| Scope | Definition | Points towards |
|---|---|---|
| `FLOW` | One stream | That connection / application |
| `SERVICE` | One server IP:port, any number of clients | That service |
| `SERVER` | One server IP, several ports | That host |
| `SUBNET` | Several servers in one /24 (/64 for IPv6) | The path to that network |
| `CLIENT` | One client, servers in several subnets | The client host or its access link |
| `NETWORK_WIDE` | Several subnets and ≥ `network_wide_fraction` of all flows of that protocol | The local network or the capture point |
| `SCATTERED` | Several unrelated endpoints, below the network-wide share | Independent problems |

Default grouping (`aggregate()`, used for reports): per event type, one
group per server subnet. Groups of one type in several subnets are merged
when they share a single client, or reach the network-wide share.

**Temporal pattern** (`aggregation/temporal.py`): how events are spread over
time. Checked in this order; the first match wins.

| Pattern | Definition | Points towards |
|---|---|---|
| `PERIODIC` | ≥ 4 events, mean gap ≥ `periodic_min_gap`, coefficient of variation of the gaps < `periodic_max_cv` | Timers: retries, cron jobs, idle timeouts. The minimum gap stops a fast stream (events every ms) from looking like a timer |
| `ESCALATING` | ≥ 2 × `burst_min_events`; over 4 equal windows the count never drops and the last window has ≥ 2× the first | Developing congestion or a spreading failure |
| `BURST` | ≥ `burst_min_events` within some `burst_window` | Sudden incident (link flap, outage) |
| `ISOLATED` | Fewer than `burst_min_events` events | Transient glitch |
| `SUSTAINED` | Many events, but never `burst_min_events` within `burst_window` | A steady low-rate problem |

---

## 7. Root-cause rules (`inference/rules.py`)

Each rule combines events, scopes and patterns into a **diagnosis**: the
affected target, a confidence level (`low` / `medium` / `high`), the evidence
in plain words, the frames to look at in Wireshark, and next steps. Rule IDs
are the `root_cause` values in the ground-truth labels. A capture can trigger
several rules. Benign situations (traceroute, TCP fallback that works) should
trigger none.

**How rules interact.** Rules run in the order of the table below and
*claim* the events they explain, so later, more generic rules skip them. A
port scan claims its failed connections, so the probed services aren't
reported as down. An unreachable resolver claims the ICMP host-unreachable
that proves it. A starved receiver claims the retransmissions it caused.
`CAPTURE_LOSS` lowers every other diagnosis by one confidence level.

**Scope and timing set confidence; they don't gate the rule.** A capture that
shows a single server can't tell "loss on the path" from "loss at that
server", so `PATH_LOSS` still fires there, but at `medium`, with that caveat
in its evidence.

| # | Rule | Fires when | Confidence | Diagnosis |
|---|---|---|---|---|
| 1 | `SCAN_OR_FLOOD` | **Connection flood:** one client opens ≥ `flood_min_connections` TCP connections to one service and that service shows symptoms (unanswered SYNs, resets, retransmissions, slow responses...); claims all of them. **Scan:** one source has failed handshakes (`TCP_SYN_TIMEOUT` / `TCP_CONN_REFUSED` / `TCP_INCOMPLETE_HANDSHAKE`) to ≥ `scan_min_targets` host:port targets. **SYN flood:** ≥ `flood_min_sources` sources leave half-open handshakes on one service. Claims those events | high (scan: at ≥ 50 targets) | Connection flood (DoS), vertical scan (one host), horizontal scan (one port), or many hosts on many ports (a scan, or a peer-to-peer application trying peers). Not a fault |
| 2 | `CAPTURE_LOSS` | ≥ `capture_loss_min` `TCP_LOST_SEGMENT` of subtype `capture_loss`, or ≥ `capture_skew_min` segments of `capture_skew` | high on ≥ 2 flows | The capture is unreliable: it dropped packets, or timestamps the two directions inconsistently. Every other diagnosis is lowered one confidence level |
| 3 | `RESOLVER_UNREACHABLE` | `DNS_TIMEOUT` whose queries drew ICMP unreachables. Claims those ICMP events | high | Resolver host down or no path to it |
| 4 | `RESOLVER_REFUSED` | `DNS_REFUSED` from a resolver | high | Client not allowed to use this resolver |
| 5 | `RESOLVER_FAILURE` | `DNS_SERVFAIL`, or `DNS_TIMEOUT` that no ICMP explains | high if ≥ 2 failures and the resolver sent anything; medium for a single failure or a completely silent resolver (could also be unreachable without ICMP) | Resolver broken or failing upstream |
| 6 | `DNS_TCP_BLOCKED` | `DNS_TCP_FALLBACK` with `tcp_attempted` and not `tcp_ok`. Claims the failed TCP/53 handshakes | high | TCP/53 blocked; large answers fail |
| 7 | `NAME_NOT_FOUND` | `DNS_NXDOMAIN`, per client, ignoring lookups that fail routinely on healthy networks: reverse lookups (`*.in-addr.arpa`, `*.ip6.arpa`), DNS-SD service discovery, resolver self-tests (`dnsbugtest`) | high if a name repeats or the lookups are `PERIODIC` | Misconfigured hostname or missing record; ≥ 20 distinct names → consider DGA malware |
| 8 | `ADMIN_BLOCK` | `ICMP_ADMIN_PROHIBITED`, per reporting device | high | Explicit reject by that device |
| 9 | `NO_ROUTE` | `ICMP_NET_UNREACHABLE`, per reporting router | high | Missing route on that router |
| 10 | `ROUTING_LOOP` | `ICMP_TTL_EXCEEDED` subtype `loop`, per destination /24 | high if ≥ 2 packets | Packets circle until TTL expires |
| 11 | `HOST_UNREACHABLE` | `ICMP_HOST_UNREACHABLE` (high), or `TCP_SYN_TIMEOUT` on ≥ 2 ports of a host that sent nothing at all (medium) | see left | Host down, wrong VLAN, ARP/ND failure |
| 12 | `SERVICE_DOWN` | `TCP_CONN_REFUSED` or `ICMP_PORT_UNREACHABLE` (not traceroute, and not for traffic *from* a port below 1024 *to* an ephemeral port: that's a late reply, typically DNS, to a client that already closed its socket), per service | high if the host accepts connections on another port, else medium (the reject could come from a firewall) | Service not running / not listening |
| 13 | `FIREWALL_DROP` | `TCP_SYN_TIMEOUT`, per service | high if the host accepts other ports or other clients reach this service; low if the host showed no sign of life | Silently filtered |
| 14 | `MTU_MISMATCH` | `ICMP_FRAG_NEEDED`, per reporter. Claims the retransmissions on those flows (the oversized segments resent smaller) | high if the sender then used packets that fit | Smaller-MTU link handled by PMTU discovery |
| 15 | `PMTU_BLACKHOLE` | On an established flow without `ICMP_FRAG_NEEDED`: ≥ 2 `rto` retransmissions of full-size segments (≥ `pmtu_min_segment` and ≥ 90 % of the largest sent) that the peer never ACKs past | high | Large packets vanish and the ICMP is filtered |
| 16 | `RECEIVER_BOTTLENECK` | `TCP_ZERO_WINDOW` from one host totalling ≥ `zero_window_min_s`, or probed by the sender. Claims retransmissions on those flows | high if ≥ 1 s or ≥ 3 episodes | Receiving application can't keep up |
| 17 | `PACKET_REORDERING` | ≥ `reorder_min_events` `TCP_OUT_OF_ORDER` to one /24, at least as many as the non-spurious retransmissions on those flows. Claims the spurious retransmissions and dup-ACK runs | high if ≥ 5 % of data segments | Per-packet load balancing / multipath |
| 18 | `PATH_LOSS` | ≥ `loss_min_retrans` non-spurious retransmissions at a rate > `loss_rate_threshold` of the data segments in those directions, with dup-ACK runs or lost segments, and fewer out-of-order events (excluding `capture_skew`) than retransmissions | high if ≥ 2 servers or ≥ 5 % loss; otherwise medium (one server: loss at that server isn't ruled out) | Loss on the path |
| 19 | `HIGH_LATENCY_PATH` | `TCP_HIGH_RTT` on ≥ `high_latency_min_flows` flows to one /24 | high on ≥ 3 flows | Long or congested path |
| 20 | `SLOW_RESOLVER` | ≥ `slow_resolver_min` `DNS_SLOW_RESPONSE` from one resolver, unless `HIGH_LATENCY_PATH` already explains its network | high on ≥ 5 | Resolver overloaded or slow upstream |
| 21 | `TLS_FAILURE` | `TLS_HANDSHAKE_FAILURE`, per service. Claims the client RSTs that typically follow a rejected handshake. Next steps depend on the cause: certificate alerts → chain/expiry/name/trust store; negotiation alerts → versions/ciphers/SNI/ALPN; no ServerHello → is TLS really served there, or is a middlebox dropping it | high on ≥ 2 failures | TLS handshakes fail |
| 22 | `IDLE_TIMEOUT` | ≥ `idle_timeout_min_events` `TCP_RST_MIDSTREAM` to one service, each after ≥ 1 s idle, with idle times clustered (CV < `periodic_max_cv`) | high | A middlebox drops idle connections |
| 23 | `ABRUPT_TERMINATION` | Server-sent `TCP_RST_MIDSTREAM` of severity warning (data in flight), ≥ 2 per service or a `BURST` | high across ≥ 2 clients or in a burst | Application crash/abort or proxy rejecting |
| 24 | `APP_ERRORS` | ≥ 2 `HTTP_ERROR_RESPONSE` 5xx per service | medium | Server-side application failure |

Each diagnosis carries the next steps from `NEXT_STEPS` in `inference/rules.py`
(for example `PMTU_BLACKHOLE`: find the path MTU with `ping -M do -s <size>`,
allow ICMP 3/4 and ICMPv6 type 2, clamp the MSS).

---

## 8. Default thresholds

| Name | Default | Used by |
|---|---|---|
| `syn_timeout` | 3 s | `TCP_SYN_TIMEOUT`, `TCP_INCOMPLETE_HANDSHAKE` |
| `dup_ack_threshold` | 3 | `TCP_DUP_ACK` |
| `ooo_min_window` | 3 ms | `ooo_window` = max(initial RTT, this); timing fallback only |
| `high_rtt_ms` | 300 ms | `TCP_HIGH_RTT` (`absolute`) |
| `high_rtt_factor` | 3 × baseline median | `TCP_HIGH_RTT` (`relative`) |
| `high_rtt_floor_ms` | 50 ms | `TCP_HIGH_RTT` (`relative` never fires below this) |
| `rtt_baseline_min` | 5 samples | `TCP_HIGH_RTT` |
| `dns_timeout` | 2 s | `DNS_TIMEOUT` |
| `dns_retx_window` | 10 s | DNS transaction grouping |
| `dns_slow_ms` | 500 ms | `DNS_SLOW_RESPONSE` |
| `http_slow_ms` | 1000 ms | `HTTP_SLOW_RESPONSE` (measured from the end of the request) |
| `tls_handshake_timeout` | 5 s | `TLS_HANDSHAKE_FAILURE` (`no_server_hello` when the capture ends first) |
| `burst_min_events` / `burst_window` | 5 events / 10 s | `BURST`, `ISOLATED`, `ESCALATING` |
| `periodic_max_cv` | 0.2 | `PERIODIC`, `IDLE_TIMEOUT` |
| `periodic_min_gap` | 1 s | `PERIODIC` |
| `network_wide_fraction` | 0.5 | `NETWORK_WIDE`, `PATH_LOSS` grouping |
| `loss_rate_threshold` | 2 % of data segments | `PATH_LOSS` |
| `loss_min_retrans` | 10 | `PATH_LOSS` (a rate from a handful of segments says little) |
| `reorder_min_events` | 10 | `PACKET_REORDERING` |
| `zero_window_min_s` | 0.2 s | `RECEIVER_BOTTLENECK` (a few ms of full buffer under load is normal) |
| `pmtu_min_segment` | 1000 bytes | `PMTU_BLACKHOLE` |
| `high_latency_min_flows` | 2 | `HIGH_LATENCY_PATH` |
| `slow_resolver_min` | 2 | `SLOW_RESOLVER` |
| `capture_loss_min` / `capture_skew_min` | 3 / 20 | `CAPTURE_LOSS` |
| `scan_min_targets` / `flood_min_sources` | 20 / 20 | `SCAN_OR_FLOOD` |
| `flood_min_connections` | 500 | `SCAN_OR_FLOOD` (connection flood). On CIC-IDS2017 the busiest normal client→service pair had 94 connections; the floods had 1,987 to 45,626 |
| `idle_timeout_min_events` | 3 | `IDLE_TIMEOUT` |

All thresholds live in `detectors/base.py` (`Config`).

---

## 9. Validation matrix

Where each event can be checked against known ground truth. Synthetic
scenarios come from `data/scripts/capture_faults.sh` (exact expected counts
are in each scenario's `.json`). Public samples are described in
`data/README.md`.

| Event | Synthetic scenario(s) | Public data |
|---|---|---|
| `TCP_SYN_TIMEOUT` | `tcp_syn_timeout` | `SkypeIRC.cap` (15); `NMap-Captures/nmap_standard_scan` (1700 of 2000 unanswered SYNs; the rest are too close to the capture end to judge. Should become `SCAN_OR_FLOOD`, not `FIREWALL_DROP`) |
| `TCP_CONN_REFUSED` | `tcp_conn_refused` | `SkypeIRC.cap` (19); CIC-IDS2017 Friday port scan |
| `TCP_INCOMPLETE_HANDSHAKE` | (none; hard to produce with a real stack) | `NMap-Captures/nmap_zombie_scan` (14), `nmap_OS_scan_succesful` (10), `SkypeIRC.cap` (5), all `rst_after_synack`; CIC-IDS2017 Friday port scan |
| `TCP_RST_MIDSTREAM` | `tcp_rst_midstream` | `SkypeIRC.cap` (30) |
| `TCP_RETRANSMISSION` | `tcp_loss`, `tcp_pmtu_blackhole`, `tcp_pmtu_ok` | `SkypeIRC.cap` (10); CIC-IDS2017 Monday |
| `TCP_DUP_ACK` | `tcp_loss`, `tcp_reorder` | CIC-IDS2017 Monday |
| `TCP_LOST_SEGMENT` | `tcp_loss` (`upstream`) | `nfs_bad_stalls.cap` (31, `capture_loss`) |
| `TCP_OUT_OF_ORDER` | `tcp_reorder` (`gap` and `late_original`) | |
| `TCP_ZERO_WINDOW` | `tcp_zero_window` | Possibly CIC-IDS2017 Wednesday Slowhttptest (slow-read mode only) |
| `TCP_HIGH_RTT` | `tcp_high_latency` | `SkypeIRC.cap` (3), `tcp-ecn-sample.pcap` (1) |
| `DNS_NXDOMAIN` | `dns_nxdomain` | `dns.cap` (6) |
| `DNS_SERVFAIL` | `dns_servfail` | `SkypeIRC.cap` (1) |
| `DNS_REFUSED` | `dns_refused` | |
| `DNS_TIMEOUT`, `DNS_RETRANSMISSION` | `dns_timeout`, `dns_resolver_down` | |
| `DNS_SLOW_RESPONSE` | `dns_slow` | |
| `DNS_TCP_FALLBACK` | `dns_tcp_fallback` | |
| `DNS_NODATA` | `dns_nodata` | |
| `ICMP_PORT_UNREACHABLE` | `icmp_port_unreachable`, `icmp_traceroute` | `SkypeIRC.cap` (5) |
| `ICMP_HOST_UNREACHABLE` | `icmp_host_unreachable`, `dns_resolver_down` | `SkypeIRC.cap` (1) |
| `ICMP_NET_UNREACHABLE` | `icmp_net_unreachable` | |
| `ICMP_ADMIN_PROHIBITED` | `icmp_admin_prohibited` | |
| `ICMP_FRAG_NEEDED` | `tcp_pmtu_ok` | |
| `ICMP_TTL_EXCEEDED` | `icmp_routing_loop` (`loop`), `icmp_traceroute` (`traceroute`) | `SkypeIRC.cap` (17) |
| `HTTP_ERROR_RESPONSE` | `http_errors` (404 `client`, 500 + 503 `server`) | |
| `HTTP_SLOW_RESPONSE` | | `tcp-ethereal-file1.trace` is the counter-example: a 6.6 s POST upload answered 243 ms after it finished is *not* slow |
| `TLS_HANDSHAKE_FAILURE` | `tls_bad_cert` (`alert`: `unknown_ca` from the client), `tls_no_server_hello` | |
| *No TCP fault events expected* | `baseline` | `tcp-ethereal-file1.trace`; `tcp-ecn-sample.pcap` (only a `TCP_HIGH_RTT` of 452 ms) |

TCP counts for public samples come from `detectors/tcp_events.py`, and each
kind was spot-checked by hand at packet level. The DNS/ICMP counts are
from a quick scapy pass and are approximate until those detectors exist.
