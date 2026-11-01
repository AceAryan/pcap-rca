"""Download only one time window of a remote pcapng file, using HTTP ranges.

For a server that supports range requests (e.g. the Hugging Face mirror of
CIC-IDS2017, see data/README.md), this finds the byte offset where the
window starts by binary search on packet timestamps, then downloads just
that part. A 10-minute slice of a 9 GB day costs a few hundred MB instead of
the whole file.

    python data/scripts/fetch_window.py URL OUT.pcapng \\
        --start "2017-07-07 14:00" --end "2017-07-07 14:10" --utc-offset -3

The output is a valid pcapng: the file's own header blocks, then the packets
inside the window. Only pcapng with packets in (roughly) time order is
supported, which is how CIC-IDS2017 is stored.
"""
import argparse
import io
import struct
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from slice_pcap import ORDER_SLACK, parse_local, report, write_slice  # noqa: E402

PROBE_BYTES = 512 * 1024
HEADER_BYTES = 256 * 1024
EPB = 6
KNOWN_BLOCKS = {1, 2, 3, 4, 5, 6, 0x0A0D0D0A, 0x0A}  # IDB, PB, SPB, NRB, ISB, EPB, SHB, DSB
UA = {"User-Agent": "pcap-rca-dataset-fetch"}


def http_range(url, start, end=None):
    rng = f"bytes={start}-" + ("" if end is None else str(end))
    req = urllib.request.Request(url, headers={**UA, "Range": rng})
    resp = urllib.request.urlopen(req, timeout=120)
    if resp.status != 206:
        sys.exit(f"server ignored the range request (HTTP {resp.status}); "
                 "use slice_pcap.py on a full download instead")
    return resp


def total_size(url):
    resp = http_range(url, 0, 0)
    size = int(resp.headers["Content-Range"].rsplit("/", 1)[1])
    resp.close()
    return size


def read_header(url):
    """Section header + interface description blocks, byte order, ts resolutions."""
    data = http_range(url, 0, HEADER_BYTES - 1).read()
    if data[:4] != b"\x0a\x0d\x0d\x0a":
        sys.exit("not a pcapng file")
    order = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    i, resolutions = 0, []
    while i + 12 <= len(data):
        btype, length = struct.unpack_from(order + "II", data, i)
        if btype in (EPB, 2, 3):
            return data[:i], order, resolutions
        if btype == 1:  # IDB: options start after linktype, reserved, snaplen
            resolutions.append(_tsresol(data[i + 16:i + length - 4], order))
        i += length
    sys.exit("no packet found in the first block of the file")


def _tsresol(options, order):
    i = 0
    while i + 4 <= len(options):
        code, length = struct.unpack_from(order + "HH", options, i)
        if code == 0:
            break
        if code == 9 and length >= 1:
            v = options[i + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        i += 4 + length + (-length % 4)
    return 1e-6


def _valid_block(data, i, order):
    if i + 12 > len(data):
        return None
    btype, length = struct.unpack_from(order + "II", data, i)
    if btype not in KNOWN_BLOCKS or length < 12 or length % 4 or length > 1 << 20:
        return None
    if i + length > len(data) or struct.unpack_from(order + "I", data, i + length - 4)[0] != length:
        return None
    return btype, length


def probe(url, offset, order, resolutions):
    """(boundary offset, timestamp) of the first packet block at/after `offset`."""
    data = http_range(url, offset, offset + PROBE_BYTES - 1).read()
    # Blocks are 4-byte aligned relative to the start of the file.
    for i in range((-offset) % 4, len(data) - 32, 4):
        first = _valid_block(data, i, order)
        if not first or first[0] != EPB:
            continue
        # Require two more well-formed blocks after it: random payload bytes
        # almost never look like three chained blocks.
        j = i + first[1]
        second = _valid_block(data, j, order)
        if not second or not _valid_block(data, j + second[1], order):
            continue
        iface, hi, lo = struct.unpack_from(order + "III", data, i + 8)
        if iface >= len(resolutions):
            continue
        return offset + i, ((hi << 32) | lo) * resolutions[iface]
    sys.exit(f"no packet boundary found near offset {offset:,}")


def find_offset(url, target_ts, size, header_len, order, resolutions):
    """Largest packet boundary whose timestamp is <= target_ts (binary search)."""
    lo, hi = header_len, size - PROBE_BYTES
    best = header_len
    while hi - lo > PROBE_BYTES:
        mid = (lo + hi) // 2
        boundary, ts = probe(url, mid, order, resolutions)
        if ts <= target_ts:
            best, lo = boundary, mid
        else:
            hi = mid
        print(f"  probe @ {mid / 1e9:6.3f} GB -> {ts:.0f}", file=sys.stderr)
    return best


class _Chain(io.RawIOBase):
    """Header bytes followed by the HTTP body, as one readable stream."""

    def __init__(self, head, body):
        self.parts = [io.BytesIO(head), body]

    def readable(self):
        return True

    def readinto(self, buf):
        while self.parts:
            n = self.parts[0].readinto(buf)
            if n:
                return n
            self.parts.pop(0)
        return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("url")
    p.add_argument("output")
    p.add_argument("--start", required=True, help="local time 'YYYY-MM-DD HH:MM[:SS]'")
    p.add_argument("--end", required=True, help="local time 'YYYY-MM-DD HH:MM[:SS]'")
    p.add_argument("--utc-offset", type=float, default=0, help="hours (CIC-IDS2017: -3)")
    args = p.parse_args()

    start = parse_local(args.start, args.utc_offset)
    end = parse_local(args.end, args.utc_offset)
    size = total_size(args.url)
    header, order, resolutions = read_header(args.url)
    print(f"{size / 1e9:.2f} GB, locating {args.start} .. {args.end}", file=sys.stderr)

    # Begin a little early: capture order is only roughly chronological.
    begin = find_offset(args.url, start - ORDER_SLACK, size, len(header), order, resolutions)
    body = http_range(args.url, begin)
    stream = io.BufferedReader(_Chain(header, body), buffer_size=1 << 20)
    with open(args.output, "wb") as out:
        result = write_slice(stream, out, start, end)
    body.close()
    report(result, args.output, args.utc_offset)


if __name__ == "__main__":
    main()
