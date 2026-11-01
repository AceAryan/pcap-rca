"""Every detector against the labelled fault-injection captures.

Each data/synthetic/<scenario>.json lists the events that must be reported
(exact count, or null for "at least one") and the side effects that may be.
Anything else a detector reports for that capture is a false positive.
"""
import json
from collections import Counter

import pytest

from builders import DATA_DIR
from pcap_rca.detectors import Capture, run_detectors
from pcap_rca.inference import infer

CHECKED_PREFIXES = ("TCP_", "DNS_", "ICMP_", "HTTP_", "TLS_")
LABELS = sorted((DATA_DIR / "synthetic").glob("*.json"))


@pytest.mark.skipif(not LABELS, reason="synthetic captures not generated (see data/README.md)")
@pytest.mark.parametrize("label_path", LABELS, ids=[p.stem for p in LABELS])
def test_scenario(label_path):
    label = json.loads(label_path.read_text())
    events = run_detectors(Capture.from_file(label_path.with_name(label["pcap"])))
    got = Counter(e.event_type for e in events)
    expected = {k: v for k, v in label["expected"].items() if k.startswith(CHECKED_PREFIXES)}
    allowed = set(expected) | set(label["may_also"])

    for event_type, count in expected.items():
        if count is None:
            assert got[event_type] > 0, f"missing {event_type}"
        else:
            assert got[event_type] == count, f"{event_type}: got {got[event_type]}, want {count}"
    unexpected = {k: v for k, v in got.items() if k not in allowed}
    assert not unexpected, f"false positives: {unexpected}"


@pytest.mark.skipif(not LABELS, reason="synthetic captures not generated (see data/README.md)")
@pytest.mark.parametrize("label_path", LABELS, ids=[p.stem for p in LABELS])
def test_root_cause(label_path):
    """Exactly the labelled rule fires (none for benign scenarios)."""
    label = json.loads(label_path.read_text())
    if not all(k.startswith(CHECKED_PREFIXES) for k in label["expected"]):
        pytest.skip("depends on a detector that doesn't exist yet")
    capture = Capture.from_file(label_path.with_name(label["pcap"]))
    fired = sorted({d.rule for d in infer(capture, run_detectors(capture))})
    assert fired == ([label["root_cause"]] if label["root_cause"] else [])
