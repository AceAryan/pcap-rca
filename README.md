# pcap-rca

Rule-based network event detection and root-cause inference engine for PCAP traffic analysis.

## What it does
pcap-rca reads PCAP files, reconstructs TCP/DNS/ICMP activity, and surfaces
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
- Spatial-temporal aggregation (burst / periodic / escalating patterns)
- Rule-based root-cause correlation
- CLI tool for quick PCAP analysis

## Installation
\`\`\`bash
pip install -r requirements.txt
\`\`\`

## Usage
\`\`\`bash
python -m pcap-rca.cli analyze path/to/capture.pcap
\`\`\`

## Architecture
See [docs/architecture.md](docs/architecture.md) for the full pipeline.

## Status
Early development — detectors implemented: [ ] list as you go

## License
MIT