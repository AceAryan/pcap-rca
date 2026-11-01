"""Download the Wireshark sample captures used for parser and detector tests.

Files land in data/raw/wireshark/ (git-ignored). .gz files are decompressed
next to the original and .zip files are extracted into their own folder, so
the parser only ever sees plain capture files. Already-downloaded files are
skipped; SHA256SUMS records exactly what was fetched.

    python data/scripts/download_wireshark_samples.py [--out DIR]
"""
import argparse
import gzip
import hashlib
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

BASE_URL = "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/"

# (file name, why it is in the set)
SAMPLES = [
    ("dns.cap", "DNS queries/responses: DNS parser and transaction matching"),
    ("dns-icmp.pcapng.gz", "DNS mixed with ICMP, pcapng format"),
    ("SkypeIRC.cap", "Real desktop traffic: refused/unanswered SYNs, ICMP errors, SERVFAIL"),
    ("NMap-Captures.zip", "Port scans: thousands of unanswered SYNs (a scan, not a fault)"),
    ("ipv4frags.pcap", "IPv4 fragmentation with MTU 1000 on one side"),
    ("tcp-ecn-sample.pcap", "Clean HTTP transfer with ECN mark: false-positive check"),
    ("tcp-ethereal-file1.trace", "Large POST over many segments: seq/ack tracking"),
    ("200722_win_scale_examples_anon.pcapng", "Window scaling present/absent/unknown"),
    ("nfs_bad_stalls.cap", "NFS with ~38 ms stalls and capture-dropped segments"),
]


def download(url, dest):
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "pcap-rca-dataset-fetch"})
    with urllib.request.urlopen(req, timeout=60) as resp, open(tmp, "wb") as out:
        shutil.copyfileobj(resp, out)
    tmp.replace(dest)


def unpack(path):
    if path.suffix == ".gz":
        target = path.with_suffix("")
        if not target.exists():
            with gzip.open(path, "rb") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
    elif path.suffix == ".zip":
        target = path.with_suffix("")
        if not target.exists():
            # ZipFile.extractall strips absolute paths and ".." components.
            with zipfile.ZipFile(path) as zf:
                zf.extractall(target)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    default_out = Path(__file__).resolve().parent.parent / "raw" / "wireshark"
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", type=Path, default=default_out)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    failed = []
    for name, why in SAMPLES:
        dest = args.out / name
        if dest.exists():
            print(f"[skip] {name}")
        else:
            try:
                download(BASE_URL + name, dest)
                print(f"[ ok ] {name:42} {why}")
            except OSError as exc:
                print(f"[FAIL] {name}: {exc}", file=sys.stderr)
                failed.append(name)
                continue
        unpack(dest)

    sums = [f"{sha256(args.out / n)}  {n}" for n, _ in SAMPLES if (args.out / n).exists()]
    (args.out / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    print(f"\n{len(sums)}/{len(SAMPLES)} samples in {args.out}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
