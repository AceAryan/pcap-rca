# Data

Captures are never committed. Everything under `raw/`, `synthetic/` and
`processed/` is git-ignored and recreated with the scripts in `scripts/`.

```
data/
├── scripts/                     # committed
│   ├── download_wireshark_samples.py
│   ├── slice_pcap.py            # pcap/pcapng time slices, also from a stream
│   └── capture_faults.sh        # + fault_helpers.py
├── raw/                         # downloads, untouched
│   └── wireshark/
├── synthetic/                   # canonical fault captures + ground-truth labels (tests)
├── synthetic_runs/              # randomised fault captures (ML training data)
└── processed/                   # slices (cic/ = CIC-IDS2017 windows), datasets
```

The three sources serve different purposes:

| Source | Size | Ground truth | Used for |
|---|---|---|---|
| Wireshark samples | ~1.5 MB | Known content | Parser development, unit tests |
| Synthetic fault captures | a few MB | **Exact** (`*.json` per capture) | Detector precision/recall, rule testing |
| CIC-IDS2017 | ~50 GB total | Attack schedule + flow labels | Realistic scale, baseline vs. anomalies, later ML |

Event IDs used in the labels are defined in [docs/event_types.md](../docs/event_types.md).

---

## 1. Wireshark sample captures

```bash
python data/scripts/download_wireshark_samples.py
```

Downloads nine files from the Wireshark wiki into `raw/wireshark/`,
decompresses `.gz`, extracts `.zip`, and writes `SHA256SUMS`.

| File | Why it's useful |
|---|---|
| `dns.cap` | 19 queries, 6 NXDOMAIN answers |
| `dns-icmp.pcapng` | pcapng format + ICMP echo |
| `SkypeIRC.cap` | Real desktop traffic: 19 refused connections, TTL-exceeded, port/host-unreachable, a SERVFAIL |
| `NMap-Captures/` | Port scans: 2000 unanswered SYNs in `nmap_standard_scan`. Should be classified as a scan, not as a firewall fault |
| `ipv4frags.pcap` | IPv4 fragments (parser test) |
| `tcp-ecn-sample.pcap` | Clean HTTP transfer with an ECN mark and a 452 ms handshake: false-positive check |
| `tcp-ethereal-file1.trace` | Clean large POST: seq/ack tracking, false-positive check |
| `200722_win_scale_examples_anon.pcapng` | Window scaling present / absent / unknown |
| `nfs_bad_stalls.cap` | NFS transfer with ~38 ms stalls; the capture itself dropped data the receiver ACKed (31 `capture_loss` gaps) |

Counting retransmissions with scapy's `len(tcp.payload)` is misleading:
it includes Ethernet padding, so padded pure ACKs look like repeated data
(that's how `tcp-ecn-sample.pcap` once seemed to have ~300 retransmissions).
`pcap_rca.parser` takes lengths from the IP header instead.

## 2. Synthetic fault captures (ground truth)

Real Linux TCP/IP stacks in three network namespaces
(`client → router → server`), with one fault injected per scenario using
`tc netem`, `iptables`, MTU changes and routing changes. Each scenario
writes:

- `synthetic/<scenario>.pcap`: captured on the client interface
- `synthetic/<scenario>.json`: ground truth:

```json
{
  "scenario": "dns_timeout",
  "root_cause": "RESOLVER_FAILURE",
  "expected": {"DNS_TIMEOUT": 2, "DNS_RETRANSMISSION": 4},
  "may_also": [],
  "params": {"lookups": "2", "tries": "3"},
  "flow_labels": [{"match": {"server_ip": "10.10.2.2", "server_port": 53},
                   "label": "RESOLVER_FAILURE"}],
  "default_label": "NORMAL",
  ...
}
```

`expected` maps an event to an exact count, or to `null` for "at least one".
`may_also` lists events that are legitimate side effects. Any other event
reported for that capture is a false positive. `root_cause` is the rule from
`docs/event_types.md` §7 that should fire (`null` means none should).
`flow_labels` say which flows carry the injected fault (every other flow is
`NORMAL`); `params` are the values the scenario used.

### Running it (Windows → WSL2)

Needs Linux and root. Your WSL Ubuntu works (its kernel has `netem`), but it
needs a few packages first:

```bash
wsl -u root
apt update && apt install -y iptables tcpdump dnsutils openssl
cd /mnt/d/AKASH.O/Documents/Study/CN/pcap-rca
bash data/scripts/capture_faults.sh            # all 28 scenarios, ~4 min
bash data/scripts/capture_faults.sh --list
bash data/scripts/capture_faults.sh tcp_loss dns_timeout   # just some

# Training data: N runs of every scenario with random parameters
# (loss 1-8 %, delay 350-700 ms, MTU 1000-1400, 1-8 attempts, ...)
bash data/scripts/capture_faults.sh --runs 12 --seed 2017   # -> data/synthetic_runs/, ~45 min
```

`data/synthetic/` is the canonical set: fixed parameters, used by
`tests/test_ground_truth.py`. `data/synthetic_runs/<scenario>__rNNN.*` is
the randomised set for training; with `--seed` it is reproducible.

Don't edit `capture_faults.sh` while it runs: bash reads a script
incrementally, so a running copy can pick up half-edited lines.

Nothing touches the host's real interfaces; the namespaces are deleted after
each scenario.

| Group | Scenarios |
|---|---|
| Normal | `baseline` |
| TCP | `tcp_loss`, `tcp_reorder`, `tcp_high_latency`, `tcp_syn_timeout`, `tcp_conn_refused`, `tcp_rst_midstream`, `tcp_zero_window`, `tcp_pmtu_ok`, `tcp_pmtu_blackhole` |
| ICMP | `icmp_port_unreachable`, `icmp_admin_prohibited`, `icmp_host_unreachable`, `icmp_net_unreachable`, `icmp_routing_loop`, `icmp_traceroute` |
| DNS | `dns_nxdomain`, `dns_servfail`, `dns_refused`, `dns_timeout`, `dns_slow`, `dns_tcp_fallback`, `dns_nodata`, `dns_resolver_down` |
| App | `http_errors`, `tls_bad_cert`, `tls_no_server_hello`, `auth_bruteforce` |

Scenarios with random loss or reordering (`tcp_loss`, `tcp_reorder`) produce
different packet-level counts on every run, so their labels use `null`
counts.

Things in the captures that aren't part of a fault:

- **IPv6 neighbour discovery / MLD** from the veth interfaces coming up.
- **One ICMP echo to the router at the very end**: an end-of-capture marker.
  A pcap only "ends" at its last packet, so without it a capture finishing
  in silence would look too short to judge "no answer within N seconds"
  for its last request (`docs/event_types.md` §1.4).

The script pins itself to one CPU (`taskset -c 0`). Otherwise the veth
links occasionally reorder bursts when the sender migrates between CPUs,
and the baseline picks up out-of-order events nobody injected. For the
same reason the netem queues are effectively unbounded (`NETEM_LIMIT`):
netem's default 1,000-packet queue overflows under 30 ms of delay at veth
speed, and one reorder run silently lost bursts of up to 156 segments.

## 3. Building the ML dataset

```bash
python -m pcap_rca.cli dataset data/processed/dataset.csv \
    --synthetic data/synthetic_runs \
    --cic data/processed/cic/*.pcapng \
    [--max-per-label 5000]
```

One row per flow: flow statistics, plus per-flow counts of what the
detectors found (`ev_retrans`, `ev_syn_timeout`, `ev_dns_nxdomain`, ...),
plus:

| Column | Meaning |
|---|---|
| `label` | `NORMAL`, the injected fault's root cause (synthetic), or the attack class (CIC-IDS2017) |
| `label_source` | `synthetic` or `cic` |
| `label_quality` | `exact` (synthetic: we injected the fault and know its flows), `schedule` (CIC attack: attacker, victim and time window match), `assumed` (CIC `NORMAL`: merely not part of a scheduled attack) |
| `group` | the capture the flow came from |
| `split` | `train` / `test`, assigned per capture (`--test-fraction`, default 0.2) |

Two precautions are built in:

- **Split by capture, never by row.** Flows of one capture share hosts and
  timing; a random row split would put near-duplicates on both sides and
  inflate the test score. CIC-IDS2017 is the exception that proves the
  rule: each attack exists in only one capture, so a whole-capture split
  would leave it entirely in train or entirely in test. CIC captures are
  therefore split in **1-minute blocks** (`group` = `<capture>@<minute>`).
- **Stratified.** About 20 % of each scenario's runs, and of each CIC
  capture's blocks, go to test, and at least one whenever there are two or
  more. A plain random pick left three classes (`ADMIN_BLOCK`,
  `RESOLVER_UNREACHABLE`, `BRUTE_FORCE`) with no test examples at all. The
  choice is by hash, so the same inputs always give the same split.
- **Identifying columns are dropped** (addresses, ports, timestamps, flow
  id). In the synthetic scenarios the fault is tied to a fixed port (9000 is
  always the filtered one), so a model given ports would learn the lab
  instead of the network behaviour. `--keep-identifiers` keeps them for
  analysis.

Other properties of the data, and what the builder does about them:

- **Test-rig traffic is left out.** Every synthetic capture contains the
  end-of-capture ICMP echo and IPv6 neighbour discovery from the virtual
  interfaces. In the first build these were 1,952 of the 2,152 synthetic
  `NORMAL` rows, and a model would have learned them as "what normal looks
  like". They're excluded (`SYNTHETIC_EXCLUDE` in `pcap_rca/dataset.py`).
- **CIC `NORMAL` is noisy.** 12 % of those flows carry fault events (DNS
  failures, retransmissions...): they are only "not an attack", not
  "healthy". Their `label_quality` is `assumed`; for fault classification,
  consider training without them, or only on `exact` + `schedule`.
- **Heavy imbalance.** The CIC floods contribute tens of thousands of
  near-identical flows against tens to hundreds per fault class.
  `--max-per-label N` keeps at most N rows per label in each split
  (reproducible sample; classes are thinned, never dropped). Use class
  weights and per-class metrics (macro-F1, confusion matrix) either way.
- **Small fault classes.** Each synthetic capture has only 1–5 faulty flows.
  Add runs without touching the existing ones:
  `capture_faults.sh --runs 38 --start-run 13 --seed 2018` (r013–r050).

CIC-IDS2017 flows are labelled from the attack schedule in
`pcap_rca/dataset.py` (`CIC_SCHEDULE`): a flow between an attacker and a
victim of an attack, on the attacked port, starting inside its time window.
Attacks arriving from outside appear as `172.16.0.1` (the firewall's NAT);
infected hosts talk to the attacker `205.174.165.73` directly. CIC's FTP and
SSH brute force get the same `BRUTE_FORCE` label as the synthetic
scenario, so one behaviour has one name. One deliberate deviation from
CIC's schedule: the botnet's beacons are labelled
`BOTNET` all Friday, because the bots kept calling their command server
long after the documented 10:02–11:02 window (seen at 14:00 and 16:00).

## 4. CIC-IDS2017

Canadian Institute for Cybersecurity, 5 days of lab traffic (3–7 July 2017)
with full payloads. Dataset page: <https://www.unb.ca/cic/datasets/ids-2017.html>.
Cite: Sharafaldin, Lashkari, Ghorbani, *"Toward Generating a New Intrusion
Detection Dataset and Intrusion Traffic Characterization"*, ICISSP 2018.

**What the download server is like** (checked November 2026):

- Access needs a one-time registration (name, email, organisation, job title,
  country) at <https://cicresearch.ca/CICDataset/CIC-IDS-2017/>. The file
  browser and downloads then work for that session (cookie).
- Files: `PCAPs/{Monday,Tuesday,Thursday,Friday}-WorkingHours.pcap` and
  `PCAPs/Wednesday-workingHours.pcap`, ~8–13 GB each. Despite the name they
  are **pcapng**.
- The server **ignores range requests**: no resuming, no jumping to an offset.
  Every download streams from byte 0, at roughly 0.1–0.3 MB/s here. That is
  about as fast as the capture itself was recorded (~285 KB per second of
  capture on average), so reaching 14:00 costs about 5 hours of streaming.
- It also **resets every connection after about 12 minutes**, so in practice
  only the first ~10 minutes of each day are reachable from it.

**Fast route: the Hugging Face mirror + `fetch_window.py`.** An unofficial
mirror, [bencorn/CICIDS2017](https://huggingface.co/datasets/bencorn/CICIDS2017),
has the same five PCAPs and supports range requests (1.7–3.3 MB/s here).
Its first 5.7 MB of `Friday-WorkingHours.pcap` were checked byte for byte
against the copy from CIC's own server and are identical; the file sizes
match too. `fetch_window.py` binary-searches the file for the window's start
time (about 15 probes of 512 KB) and downloads only that window:

```bash
H="https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main/pcaps"
python data/scripts/fetch_window.py "$H/Friday-WorkingHours.pcap" \
    data/processed/cic/friday_portscan_nofw_1500-1510.pcapng \
    --start "2017-07-07 15:00" --end "2017-07-07 15:10" --utc-offset -3
```

A 10-minute window takes about a minute. Window sizes vary a lot: most are
50–400 MB, but Tuesday 09:25–09:35 is 3.7 GB (Windows Update downloads), too
big to analyse in memory in one go. Cut such windows to 2 minutes with
`slice_pcap.py`.

**From CIC's own server: slice while streaming.** Don't store whole files;
pipe the download through `slice_pcap.py`, which keeps one time window and
exits (stopping the download) as soon as the window has passed. With a
cookie jar from a registered session (`curl -c cookies.txt -F ... .../insert.php`,
or exported from the browser):

```bash
B="https://cicresearch.ca/CICDataset/CIC-IDS-2017/download.php?file=CIC-IDS-2017%2FPCAPs%2F"
curl -sS -b cookies.txt "${B}Monday-WorkingHours.pcap" \
  | python data/scripts/slice_pcap.py - data/processed/cic/monday_0900-0915.pcapng \
      --start "2017-07-03 09:00" --end "2017-07-03 09:15" --utc-offset -3
```

`slice_pcap.py` also works on a fully downloaded file, and `--info` prints
what a file covers. Schedule times are local lab time: pass `--utc-offset -3`
(Atlantic Daylight Time). The captures start at about 08:59:40 local
(Friday's first packet: 08:59:39.6).

| Day | Window (local) | Traffic | Events it should produce |
|---|---|---|---|
| Mon 3 Jul | all day | Benign only | Baseline rates of retransmission, NXDOMAIN, RST |
| Wed 5 Jul | 09:47–10:10 | DoS slowloris | Many long-lived, nearly idle connections to one web server; `TCP_RST_MIDSTREAM` when the server gives up on them |
| Wed 5 Jul | 10:14–10:35 | DoS Slowhttptest | As above; `TCP_ZERO_WINDOW` only if run in slow-read mode |
| Wed 5 Jul | 10:43–11:00 | DoS Hulk | Bursts of connections, `TCP_RST_MIDSTREAM`, server degradation (`TCP_HIGH_RTT`, `TCP_SYN_TIMEOUT`) |
| Wed 5 Jul | 11:10–11:23 | DoS GoldenEye | As above |
| Fri 7 Jul | 13:55–14:35 | Port scan (firewall on) | `TCP_SYN_TIMEOUT` across many ports → `SCAN_OR_FLOOD` |
| Fri 7 Jul | 14:51–15:29 | Port scan (firewall off) | `TCP_CONN_REFUSED`, `TCP_INCOMPLETE_HANDSHAKE` (`rst_after_synack`) → `SCAN_OR_FLOOD` |
| Fri 7 Jul | 15:56–16:16 | DDoS LOIC | Many sources → one service; connection bursts and server degradation |

The "events it should produce" column is what we expect, not ground truth.
CIC labels attacks, not network faults. Published re-analyses (Engelen et
al., 2021) also found labelling errors in the CIC flow CSVs, which matters
for the ML phase.

### Results on CIC-IDS2017 slices (November 2026)

In CIC-IDS2017 the attacker appears behind NAT as **172.16.0.1**; the main
victim is **192.168.10.50**.

| Slice | Packets | Time | What `analyze` concluded |
|---|---:|---:|---|
| Monday 09:00–09:06 (benign) | 25k | 0.6 s | 16 diagnoses, all real properties of the lab: SERVFAIL for `macpc`, a missing `_kerberos-master` SRV record, ~1 s DNS answers, an SMTPS cipher mismatch, a reordering mirror. No attacks reported |
| Fri 14:00–14:10, port scan, **firewall on** | 88k | 2.5 s | No scan: only 156 attacker packets to 5 ports got past the victim's firewall. That's a correct negative, not a miss |
| Fri 15:00–15:10, port scan, **firewall off** | 118k | 3 s | `SCAN_OR_FLOOD`: "172.16.0.1 made 9007 failed connection attempts to 999 ports on 1 host (vertical port scan)". The victim's 9,007 refusals aren't misreported as `SERVICE_DOWN` |
| Fri 16:00–16:05, DDoS LOIC | 361k | 10 s | `SCAN_OR_FLOOD`: "172.16.0.1 opened 25,224 connections to 192.168.10.50:80 in 300 s (84/s): a connection flood (DoS)", with the server's 23,870 resets and 6,610 retransmissions attributed to it |
| Wed 09:50–10:00, DoS slowloris | 144k | 4.6 s | `SCAN_OR_FLOOD`: 1,987 connections at 3.3/s; the 773 SYNs the exhausted server never answered aren't misreported as a firewall |
| Wed 10:45–10:50, DoS Hulk | 702k | 30 s | `SCAN_OR_FLOOD`: 45,626 connections at 158/s |
| Tue 09:26–09:28, FTP-Patator | 776k | 81 s | `BRUTE_FORCE`: "172.16.0.1 failed to log in to FTP on 192.168.10.50:21 385 times over 133 connections". It was missed (147 connections is below the flood threshold) until the FTP/SMTP login-failure detector existed. Most of the slice's volume is two Windows Update downloads |

Every slice also gets `CAPTURE_LOSS`. CIC's capture both drops packets and
records many data segments *after* the ACK that covers them (capture skew,
median 0.04–0.06 ms). It also contains about 17 % duplicate frames, which the
parser removes. Without handling all three, the benign Monday slice showed
2,400 phantom "spurious retransmissions" and as many phantom losses.
