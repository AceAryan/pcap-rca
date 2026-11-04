"""Build a labelled per-flow dataset for the ML phase.

One row per flow: the flow features and per-flow event counts from
features.py, plus

    label         what is wrong with this flow: NORMAL, a root-cause ID from
                  the synthetic scenarios (PATH_LOSS, FIREWALL_DROP, ...), or a
                  CIC-IDS2017 attack class (PORTSCAN, DOS_HULK, ...)
    label_source  synthetic | cic | none
    label_quality how far the label can be trusted:
                  exact     synthetic: we injected the fault and know its flows
                  schedule  CIC attack: attacker, victim and time window match
                  assumed   CIC NORMAL: merely not part of a scheduled attack;
                            real faults among these flows are unlabelled
    group         the capture the flow came from
    split         train | test, assigned per group, never per row: flows of
                  one capture share timing and hosts, so splitting rows at
                  random would leak test information into training

Identifying columns (addresses, ports, timestamps, flow id) are dropped by
default. In the synthetic scenarios the fault is tied to particular hosts
and ports (port 9000 is always the filtered one), so a model given them would
learn the lab setup instead of network behaviour.

Labels come from:
- synthetic captures: the scenario's <name>.json "flow_labels", written by
  data/scripts/capture_faults.sh, say which flows carry the injected fault;
- CIC-IDS2017 captures: CIC_SCHEDULE below, from the dataset's published
  attacker/victim addresses and attack times.
"""
from __future__ import annotations

import json
import random
import zlib
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator

from .detectors import Capture, run_detectors
from .features import EVENT_FIELDS, FLOW_FIELDS, flow_rows
from .parser import PROTO_NAMES
from .streams import Flow

NORMAL = "NORMAL"
IDENTIFIERS = ["flow_id", "client_ip", "client_port", "server_ip", "server_port",
               "start_ts", "end_ts"]
LABEL_FIELDS = ["label", "label_source", "label_quality", "group", "split"]

Labeler = Callable[[Flow], "str | None"]  # None: leave this flow out of the dataset

# Flows in the synthetic captures that belong to the test rig, not the scenario:
# the end-of-capture ICMP echo to the router, and IPv6 neighbour discovery / MLD
# from the virtual interfaces coming up. They appear in every capture, so a
# model would learn them as "what normal looks like".
SYNTHETIC_EXCLUDE = [{"proto": "icmp", "server_ip": "10.10.1.1"}, {"proto": "icmpv6"}]


# --------------------------------------------------------------------------
# Synthetic captures: labels written by capture_faults.sh
# --------------------------------------------------------------------------

def _matches(flow: Flow, match: dict) -> bool:
    if "proto" in match and PROTO_NAMES.get(flow.proto, "").lower() != match["proto"]:
        return False
    if "server_ip" in match and flow.server[0] != match["server_ip"]:
        return False
    port = flow.server[1]
    if "server_port" in match and port != match["server_port"]:
        return False
    if "server_ports" in match:
        lo, hi = match["server_ports"]
        if port is None or not lo <= port <= hi:
            return False
    return True


def synthetic_labeler(label: dict) -> Labeler:
    """Label flows by the scenario's "flow_labels" rules; first match wins.
    Test-rig flows (`exclude`, default SYNTHETIC_EXCLUDE) get None: left out."""
    rules = label.get("flow_labels", [])
    default = label.get("default_label", NORMAL)
    exclude = label.get("exclude", SYNTHETIC_EXCLUDE)

    def labeler(flow: Flow) -> str | None:
        if any(_matches(flow, match) for match in exclude):
            return None
        for rule in rules:
            if _matches(flow, rule["match"]):
                return rule["label"]
        return default
    return labeler


# --------------------------------------------------------------------------
# CIC-IDS2017
# --------------------------------------------------------------------------

CIC_UTC_OFFSET = -3  # schedule times are local lab time (ADT)
CIC_NAT = "172.16.0.1"  # inbound attacks arrive through the firewall's NAT
CIC_KALI = "205.174.165.73"  # outbound victims talk to the attacker directly
CIC_WEB_SERVER = "192.168.10.50"
CIC_BOTS = {"192.168.10.5", "192.168.10.8", "192.168.10.9", "192.168.10.14", "192.168.10.15"}


@dataclass(frozen=True)
class CicAttack:
    label: str
    day: str  # YYYY-MM-DD
    start: str  # HH:MM local
    end: str
    attackers: frozenset
    victims: frozenset
    ports: frozenset | None = None  # service port of the flow (either side), None = any


def _attack(label, day, start, end, attackers, victims, ports=None):
    return CicAttack(label, day, start, end, frozenset(attackers), frozenset(victims),
                     frozenset(ports) if ports else None)


# From the CIC-IDS2017 description (unb.ca/cic/datasets/ids-2017.html).
# Brute force uses the same label as the synthetic BRUTE_FORCE scenario, so one
# behaviour has one name across both sources.
CIC_SCHEDULE = [
    _attack("BRUTE_FORCE", "2017-07-04", "09:20", "10:20", {CIC_NAT}, {CIC_WEB_SERVER}, {21}),
    _attack("BRUTE_FORCE", "2017-07-04", "14:00", "15:00", {CIC_NAT}, {CIC_WEB_SERVER}, {22}),
    _attack("DOS_SLOWLORIS", "2017-07-05", "09:47", "10:10", {CIC_NAT}, {CIC_WEB_SERVER}, {80}),
    _attack("DOS_SLOWHTTPTEST", "2017-07-05", "10:14", "10:35", {CIC_NAT}, {CIC_WEB_SERVER}, {80}),
    _attack("DOS_HULK", "2017-07-05", "10:43", "11:00", {CIC_NAT}, {CIC_WEB_SERVER}, {80}),
    _attack("DOS_GOLDENEYE", "2017-07-05", "11:10", "11:23", {CIC_NAT}, {CIC_WEB_SERVER}, {80}),
    _attack("HEARTBLEED", "2017-07-05", "15:12", "15:32", {CIC_NAT}, {"192.168.10.51"}, {444}),
    _attack("WEB_ATTACK", "2017-07-06", "09:20", "10:42", {CIC_NAT}, {CIC_WEB_SERVER}, {80}),
    _attack("INFILTRATION", "2017-07-06", "14:19", "15:45", {CIC_KALI},
            {"192.168.10.8", "192.168.10.25"}),
    # The bots keep calling the command server long after the documented
    # 10:02-11:02 window (seen at 14:00-16:05 in our slices), so all day.
    _attack("BOTNET", "2017-07-07", "00:00", "23:59", {CIC_KALI}, CIC_BOTS, {8080}),
    _attack("PORTSCAN", "2017-07-07", "13:55", "15:29", {CIC_NAT}, {CIC_WEB_SERVER}),
    _attack("DDOS", "2017-07-07", "15:56", "16:16", {CIC_NAT}, {CIC_WEB_SERVER}, {80}),
]


def _epoch(day: str, hhmm: str) -> float:
    local = datetime.strptime(f"{day} {hhmm}", "%Y-%m-%d %H:%M")
    return local.replace(tzinfo=timezone(timedelta(hours=CIC_UTC_OFFSET))).timestamp()


def cic_labeler(schedule: list[CicAttack] = CIC_SCHEDULE, margin: float = 60.0) -> Labeler:
    """Label a flow with the attack whose attacker and victim it connects,
    on the victim's attacked port, starting inside the attack window
    (± `margin` seconds)."""
    windows = [(a, _epoch(a.day, a.start) - margin, _epoch(a.day, a.end) + 60 + margin)
               for a in schedule]

    def labeler(flow: Flow) -> str:
        ips = {flow.client[0], flow.server[0]}
        for attack, start, end in windows:
            if not start <= flow.first_ts <= end:
                continue
            if not (ips & attack.attackers and ips & attack.victims):
                continue
            if attack.ports is None or {flow.client[1], flow.server[1]} & attack.ports:
                return attack.label
        return NORMAL
    return labeler


# --------------------------------------------------------------------------
# Building
# --------------------------------------------------------------------------

CIC_BLOCK_SECONDS = 60.0  # CIC captures are split in 1-minute blocks (see capture_rows)


def pick_test_groups(groups: Iterable[str], test_fraction: float) -> set[str]:
    """Stratified, deterministic choice of test groups among `groups` (one
    stratum: the runs of one scenario, or the blocks of one CIC capture).

    About `test_fraction` of them, but at least one whenever there are two or
    more, so no class ends up with zero test examples by chance. Chosen by
    hash, so the same inputs always give the same split."""
    ordered = sorted(set(groups), key=lambda g: (zlib.crc32(g.encode()), g))
    if test_fraction <= 0 or len(ordered) < 2:
        return set()
    n_test = min(max(1, round(len(ordered) * test_fraction)), len(ordered) - 1)
    return set(ordered[:n_test])


def _quality(source: str, label: str) -> str:
    if source == "synthetic":
        return "exact"
    if source == "cic":
        return "assumed" if label == NORMAL else "schedule"
    return ""


def cap_per_label(rows: list[dict], max_rows: int) -> list[dict]:
    """Keep at most `max_rows` rows per (split, label), sampled reproducibly.

    The CIC floods contribute tens of thousands of near-identical flows; a
    cap keeps them from drowning the fault classes without losing variety
    (whole classes are never dropped, only thinned)."""
    by_key: dict[tuple, list[int]] = {}
    for i, row in enumerate(rows):
        by_key.setdefault((row["split"], row["label"]), []).append(i)
    keep: list[int] = []
    for key, indices in by_key.items():
        if len(indices) > max_rows:
            indices = random.Random(f"{key[0]}/{key[1]}").sample(indices, max_rows)
        keep.extend(indices)
    return [rows[i] for i in sorted(keep)]


def fields(keep_identifiers: bool = False) -> list[str]:
    feats = [f for f in FLOW_FIELDS if keep_identifiers or f not in IDENTIFIERS]
    return feats + EVENT_FIELDS + LABEL_FIELDS


def capture_rows(path: Path, labeler: Labeler | None, source: str, test_fraction: float,
                 keep_identifiers: bool = False, block_seconds: float | None = None,
                 split: str | None = None) -> list[dict]:
    """Rows for one capture.

    Normally the whole capture is one group and `split` says which side it
    is on. With `block_seconds`, each time block of the capture is its own
    group and the blocks are split here (stratified within the capture): used
    for CIC-IDS2017, where each attack lives in a single capture and a
    whole-capture split would leave it entirely in train or entirely in test.
    """
    capture = Capture.from_file(path)
    events = run_detectors(capture)
    rows = []
    for flow, row in zip(capture.table.flows, flow_rows(capture.table, events)):
        label = labeler(flow) if labeler else ""
        if label is None:
            continue  # test-rig traffic, not part of the scenario
        if not keep_identifiers:
            for key in IDENTIFIERS:
                row.pop(key, None)
        group = path.stem
        if block_seconds:
            group += f"@{int(flow.first_ts // block_seconds)}"
        row.update(label=label, label_source=source,
                   label_quality=_quality(source, label), group=group)
        rows.append(row)
    test = pick_test_groups((r["group"] for r in rows), test_fraction) if block_seconds else set()
    for row in rows:
        row["split"] = split or ("test" if row["group"] in test else "train")
    return rows


def synthetic_inputs(directory: Path) -> Iterator[tuple[Path, Labeler, str]]:
    """(capture, labeler, scenario) for every <name>.pcap with a <name>.json next to it."""
    for label_path in sorted(directory.glob("*.json")):
        label = json.loads(label_path.read_text())
        pcap = label_path.with_name(label["pcap"])
        if pcap.exists():
            yield pcap, synthetic_labeler(label), label.get("scenario", pcap.stem)


def build(synthetic_dirs: Iterable[Path] = (), cic_captures: Iterable[Path] = (),
          other_captures: Iterable[Path] = (), test_fraction: float = 0.2,
          keep_identifiers: bool = False, progress: Callable[[str], None] | None = None
          ) -> Iterator[dict]:
    """Rows for every input capture. Unlabelled `other_captures` get an empty label.

    Synthetic captures are split stratified by scenario: about `test_fraction`
    of each scenario's runs (at least one) go to test."""
    synthetic = [s for d in synthetic_dirs for s in synthetic_inputs(Path(d))]
    by_scenario: dict[str, list[str]] = {}
    for pcap, _, scenario in synthetic:
        by_scenario.setdefault(scenario, []).append(pcap.stem)
    test = set().union(*(pick_test_groups(stems, test_fraction) for stems in by_scenario.values()))

    inputs: list[tuple[Path, Labeler | None, str, float | None, str | None]] = []
    inputs += [(p, lab, "synthetic", None, "test" if p.stem in test else "train")
               for p, lab, _ in synthetic]
    inputs += [(Path(p), cic_labeler(), "cic", CIC_BLOCK_SECONDS, None) for p in cic_captures]
    inputs += [(Path(p), None, "none", None, "train") for p in other_captures]
    for i, (path, labeler, source, block, split) in enumerate(inputs, 1):
        if progress:
            progress(f"[{i}/{len(inputs)}] {path.name}")
        yield from capture_rows(path, labeler, source, test_fraction, keep_identifiers,
                                block, split)


def summarize(rows: list[dict]) -> str:
    counts = Counter((r["split"], r["label"]) for r in rows)
    labels = sorted({label for _, label in counts}, key=lambda l: (l != NORMAL, l))
    lines = [f"{'label':26} {'train':>8} {'test':>8}"]
    for label in labels:
        lines.append(f"{label or '(unlabelled)':26} {counts['train', label]:>8,} {counts['test', label]:>8,}")
    splits = Counter({r["group"]: r["split"] for r in rows}.values())
    lines.append(f"groups (synthetic captures, 1-minute blocks of CIC captures): "
                 f"{splits['train']} train, {splits['test']} test")
    return "\n".join(lines)
