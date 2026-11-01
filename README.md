# pcap-rca

Rule-based network event detection and root-cause inference engine for PCAP traffic analysis.

## What it does
pcap-rca reads PCAP files, reconstructs TCP/DNS/ICMP/HTTP/TLS activity, and surfaces
explainable network events (retransmissions, zero windows, SYN timeouts, DNS
failures, etc.) with spatial-temporal correlation to infer likely root causes
— no ML required for the core detection layer.

## Why
Most network troubleshooting still means manually scrolling through Wireshark.
pcap-rca automates the pattern recognition a senior network engineer does by
eye, using explicit, auditable detection rules instead of a black-box model.

## Features
- TCP event detection: retransmissions, zero window, SYN timeout, RST, out-of-order
- DNS event detection: NXDOMAIN, timeout, retransmit, TCP fallback
- ICMP event detection: destination unreachable, TTL exceeded, PMTU issues
- Application events: HTTP error / slow responses, TLS handshake failures
- Spatial-temporal aggregation (burst / periodic / escalating patterns)
- Rule-based root-cause correlation with confidence, evidence and next steps
- CLI tool for quick PCAP analysis

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
# Packet + flow feature extraction (summary on screen, optional CSVs)
python -m pcap_rca.cli features path/to/capture.pcap --flows flows.csv --packets packets.csv

# Root-cause diagnoses (with evidence and next steps), then the events behind them;
# --json writes diagnoses + event groups + events, --csv the events
python -m pcap_rca.cli analyze path/to/capture.pcap --json report.json --csv events.csv
python -m pcap_rca.cli analyze capture.pcap --only tcp,dns --min-severity warning
```

Event IDs, detection rules and thresholds: [docs/event_types.md](docs/event_types.md).
Datasets and ground-truth captures: [data/README.md](data/README.md).
Run the tests with `pytest`. With the synthetic captures generated, every
detector is also checked against their labels (`tests/test_ground_truth.py`).

## Architecture
See [docs/architecture.md](docs/architecture.md) for the full pipeline.

## Status
Early development.

- [x] PCAP/PCAPNG parsing, flow reconstruction, packet + flow feature export
- [x] TCP, DNS, ICMP and HTTP/TLS event detectors
- [x] Spatial-temporal aggregation (scope + burst/periodic/escalating patterns)
- [x] Root-cause rules with confidence, evidence and next steps
- All 27 synthetic fault scenarios: expected events and exactly the expected root cause
- [ ] Validation on CIC-IDS2017 (needs the dataset; see data/README.md)
- [ ] ML/DL phase

## License
MIT