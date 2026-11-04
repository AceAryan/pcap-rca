# Architecture

pcap-rca turns a packet capture into a short list of explained problems:
*what* is probably wrong, *how sure* we are, *which packets* show it, and
*what to check next*. Every step is a plain, inspectable rule, with no trained
model involved, so each conclusion can be traced back to frames you can open
in Wireshark.

This document explains how the pieces fit together and why they are built
the way they are. The exact event definitions, rules and thresholds are in
[event_types.md](event_types.md); the datasets are described in
[../data/README.md](../data/README.md).

---

## 1. The pipeline

```
 capture.pcap / .pcapng
        │
        ▼
 ┌──────────────┐   Packet records: addresses, ports, TCP flags/options,
 │  parser.py   │   sizes, ICMP quoted headers, DNS fields, first 32 payload
 └──────┬───────┘   bytes. Capture duplicates removed.
        ▼
 ┌──────────────┐   Flows (one per TCP connection / UDP conversation / ICMP
 │  streams.py  │   echo), client vs server, TCP handshake & teardown state.
 └──────┬───────┘   ICMP errors attached to the flow they quote.
        │
        ├──────────────────────────────► features.py ──► packet / flow CSVs
        │                                                (input for ML)
        ▼
 ┌──────────────┐   Events: TCP_SYN_TIMEOUT, TCP_RETRANSMISSION, DNS_NXDOMAIN,
 │  detectors/  │   ICMP_FRAG_NEEDED, TLS_HANDSHAKE_FAILURE, ... (one record
 └──────┬───────┘   per occurrence, with evidence frame numbers)
        ▼
 ┌──────────────┐   Groups: events of one type, with a scope (who is
 │ aggregation/ │   affected: FLOW, SERVICE, SUBNET, ...) and a temporal
 └──────┬───────┘   pattern (BURST, PERIODIC, ESCALATING, ...)
        ▼
 ┌──────────────┐   Diagnoses: root cause, target, confidence, evidence in
 │  inference/  │   words, next steps, frames to inspect
 └──────┬───────┘
        ▼
     cli.py  ──►  terminal report, JSON (diagnoses + groups + events), CSV
```

Each stage only reads the output of the stages before it, so each can be
tested on its own: the detectors on hand-built captures, the rules on known
events.

---

## 2. Modules

### `parser.py`: bytes → `Packet`

- Reads pcap and pcapng with `dpkt`, but decodes the link layer (Ethernet
  with VLAN tags, Linux SLL/SLL2, raw IP, BSD loopback), IPv4/IPv6 (with
  extension headers and fragments), TCP, UDP and ICMP itself with `struct`.
  This keeps direct access to raw bytes for TCP options, ICMP-quoted headers
  and fragment handling. `dpkt` is used only for DNS messages.
- **Sizes come from the IP header, not the captured length**, so captures cut
  short by a snap length still report true payload sizes.
- Frame numbers count every frame (ARP included), so they match Wireshark.
- Keeps only the first 32 bytes of each TCP payload (`payload_head`): enough
  for an HTTP request/status line or a TLS record header, without holding
  whole payloads in memory.
- **Drops capture duplicates**: the same IPv4 datagram seen twice within 5 ms
  with the same non-zero IP ID (a mirror port seeing both directions). A real
  resend gets a new IP ID, so retransmissions are never dropped. On
  CIC-IDS2017 this removed 17 % of the frames.

Output: a list of `Packet` dataclasses (slotted, 35 fields) plus
`ParseStats` (frames, duplicates, malformed, fragments, ...).

### `streams.py`: packets → `Flow`

- Groups packets into bidirectional flows. TCP: one flow per connection, and
  a SYN with a new initial sequence number starts a new one (port reuse).
  UDP: split after 120 s of silence. ICMP echo: one flow per identifier.
- Decides **client and server**: the SYN sender, else the SYN-ACK receiver,
  else the side using the high port.
- Tracks the TCP handshake and teardown in `TcpState`: SYN/SYN-ACK counts,
  initial RTT, MSS, window scale, FIN/RST times, how the connection ended.
- Attaches each **ICMP error to the flow whose packet it quotes**, so later
  stages can say "this SYN got host-unreachable from router X".

### `features.py`: flows → CSV rows

The feature-extraction deliverable of the project: one row per packet
(timing, addresses, flags, relative sequence numbers, inter-arrival time
within the flow, DNS fields) and one row per flow (volume, size and timing
statistics, flag counts, handshake RTT, MSS, close reason, ICMP errors, DNS
response code and latency).

Given the detectors' events, flow rows also carry **per-flow event counts**
(`EVENT_FIELDS`: `ev_retrans`, `ev_syn_timeout`, `ev_dns_nxdomain`,
`ev_auth_failure`, ... plus `retrans_rate` and `zero_window_s`). These are
the signals that separate faults, so a model doesn't have to re-learn
"retransmission" from raw packet counts. This is where the rule engine feeds
the ML phase.

### `dataset.py`: captures → labelled training table

Builds one table from many captures: flow features + event counts, a
`label` per flow, the capture it came from (`group`) and a `train`/`test`
split assigned **per capture**. Labels come from the synthetic scenarios'
`flow_labels` (which flows carry the injected fault) or, for CIC-IDS2017,
from the published attack schedule (`CIC_SCHEDULE`). Identifying columns
(addresses, ports, timestamps) are dropped by default so a model can't
memorise the lab setup; test-rig traffic (the end-of-capture marker, IPv6
neighbour discovery) is left out; each row records how trustworthy its
label is (`label_quality`: `exact`, `schedule`, `assumed`); and
`--max-per-label` thins the huge flood classes.

### `detectors/`: flows → `Event`

| Module | Finds |
|---|---|
| `tcp_events.py` | Failed/incomplete handshakes, resets, retransmissions, out-of-order, lost segments, dup-ACKs, zero window, high RTT |
| `dns_events.py` | NXDOMAIN, SERVFAIL, REFUSED, timeouts, retries, slow answers, TCP fallback, empty answers |
| `icmp_events.py` | Unreachables (net/host/port/admin), fragmentation needed, TTL exceeded (traceroute vs loop) |
| `app_events.py` | HTTP 4xx/5xx and slow responses, TLS handshake failures (fatal alert or no ServerHello), failed FTP/SMTP logins |

Each detector is a plain function, `detect_<x>_events(capture, config)`,
returning its events sorted with `sort_events`. They all share `base.py`:

- `Event`: one record shape for everything (type, subtype, severity, time
  range, client→server endpoints, flow id, evidence frames, metrics).
- `Config`: every threshold in one place.
- `Capture`: packets, flows and parse statistics together
  (`Capture.from_file(path)`).
- `SEVERITY_RANK`, `sort_events`, and the direction helpers `direction_name`
  / `direction_index` (`c2s` ↔ `C2S`). `side_name` (`client` / `server`)
  lives in `streams.py` next to `C2S`/`S2C`, so `features.py` can use it
  without depending on the detectors.

`DETECTORS` in `detectors/__init__.py` maps a name (`tcp`, `dns`, `icmp`,
`app`) to its function; `run_detectors(capture, only={...})` runs them all
or a subset.

### `aggregation/`: events → `EventGroup`

- `spatial.py`: who is affected. The narrowest scope covering a set of
  events: `FLOW`, `SERVICE`, `SERVER`, `SUBNET`, `CLIENT`, `NETWORK_WIDE`,
  `SCATTERED`.
- `temporal.py`: how events are spread in time: `PERIODIC`, `ESCALATING`,
  `BURST`, `ISOLATED`, `SUSTAINED`.

The rules use these to set confidence ("one server" vs "a whole subnet"), and
the JSON report includes the default grouping.

### `inference/rules.py`: events → `Diagnosis`

25 rules, from `SCAN_OR_FLOOD`, `BRUTE_FORCE` and `CAPTURE_LOSS` down to
`PATH_LOSS`, `RESOLVER_FAILURE`, `PMTU_BLACKHOLE`, `TLS_FAILURE`... Each rule groups the
events it cares about (by service, resolver, reporting router or subnet) and
produces a `Diagnosis` with target, confidence, evidence sentences, next
steps and up to 20 evidence frames. `infer(capture, events)` runs them all.

### `cli.py`

```
python -m pcap_rca.cli features CAPTURE [--flows F.csv] [--packets P.csv] [--no-events]
python -m pcap_rca.cli analyze  CAPTURE [--json R.json] [--csv E.csv]
                                        [--only tcp,dns,icmp,app] [--min-severity ...]
python -m pcap_rca.cli dataset  OUT.csv [--synthetic DIR] [--cic SLICES...]
                                        [--test-fraction 0.2] [--keep-identifiers]
```

---

## 3. Design decisions

**Rules, not a model, for the core.** The problem is troubleshooting: every
conclusion has to be explainable and checkable. A rule can say *"full-size
segments were resent 5 times and never ACKed, and no ICMP fragmentation-needed
arrived"* and point at the frames; a classifier can't. ML is planned as a
second phase on top of the extracted features.

**Rules claim the events they explain.** Rules run in a fixed order, and each
one marks the events it used. Later, more generic rules then skip them, so a
symptom isn't explained twice:

- a port scan claims its 9,000 refused connections, so the victim isn't
  reported as "service down" 9,000 times;
- a dead DNS resolver claims the ICMP host-unreachable that proves it;
- a connection flood claims the victim server's resets, retransmissions and
  slow responses.

**Scope and timing set confidence, they don't gate a rule.** A capture with
one server can't tell "loss on the path" from "loss at that server", so
`PATH_LOSS` still fires, at medium confidence, and says why.

**Decide from evidence, not from timing alone.** Wireshark separates
out-of-order from retransmission by arrival time, which fails on fast links
where a resend arrives within a millisecond. pcap-rca checks which packet was
*sent* first, using the sender's IPv4 ID, then TCP timestamps, and only then
timing.

**Don't blame the network for the capture.** Real captures drop packets,
duplicate them, and on mirror ports record an ACK before the data it
acknowledges (capture skew). Each case is detected and reported as
`CAPTURE_LOSS`, which also lowers the confidence of every other diagnosis.

**Unknown is not failure.** "No SYN-ACK" or "no DNS answer" is only reported
if the capture continues long enough after the request. Otherwise the outcome
is unknown and nothing is reported, so the end of every capture slice isn't
full of false alarms.

---

## 4. How it is tested

| Layer | How |
|---|---|
| Unit tests (`tests/`, ~180) | Packets built byte by byte in `tests/builders.py`, so every case is exact and needs no downloads |
| Ground truth (`tests/test_ground_truth.py`) | 28 fault scenarios generated on real Linux network stacks (`data/scripts/capture_faults.sh`: namespaces, `tc netem`, `iptables`), each labelled with the events that must appear and the one root cause that must fire. Any other event or rule is a failure |
| Real captures | Wireshark samples and CIC-IDS2017 slices, checked by hand at packet level. Results are recorded in `data/README.md` |

The synthetic tests prove the pieces agree with each other; the real
captures are what showed where the assumptions were wrong. Capture skew,
normal RST-based closes, connection floods and bogus attack ACKs were all
found that way.

---

## 5. Limits

- **Everything is in memory.** Comfortable up to about a million packets;
  larger captures should be cut into time slices first
  (`data/scripts/slice_pcap.py`).
- **Only clear text is visible to the app layer.** HTTP/1.x, TLS handshakes
  (≤ 1.2 alerts) and FTP/SMTP login replies. TLS 1.3 alerts, HTTP/2, and
  logins over SSH, POP3 or IMAP are invisible, so brute force against SSH
  isn't detected.
- **DNS over TCP** split across several segments isn't reassembled.
- **Thresholds** were tuned on the synthetic scenarios and a few CIC-IDS2017
  windows, not on a large labelled set of real faults.

---

## 6. Extending it

**A new event:** extend a detector, or write a new function
`detect_<x>_events(capture, config) -> list[Event]` that builds events with
`detectors.base.flow_event` and returns `sort_events(events)`; add it to the
`DETECTORS` dict in `detectors/__init__.py`; document the ID in
`event_types.md`.

**A new root-cause rule:** write a function `my_rule(ctx)` in
`inference/rules.py` that picks events with `ctx.get(...)` and calls
`ctx.add(...)`; add it to `RULES` at the right position (rules earlier in
the list win when two could explain the same events); add a `TITLES` and
`NEXT_STEPS` entry.

**A new ground-truth scenario:** add an `sc_<name>` function to
`data/scripts/capture_faults.sh` that picks its parameters with `pick`,
injects the fault, captures it, declares the faulty flows with `flows` and
writes the label; add it to `SCENARIOS`. `tests/test_ground_truth.py` picks
it up automatically, and `--runs` generates randomised training copies.
