"""Cut a manageable slice out of a large pcap or pcapng capture.

Streams the input block by block using only the standard library, so it
works on multi-GB captures such as CIC-IDS2017 without Wireshark installed.
The input may be "-" (stdin), so a download can be sliced while it streams
and stopped as soon as the wanted window has passed:

    curl -sS URL | python data/scripts/slice_pcap.py - out.pcapng --start ... --end ...

The output keeps the input's format (pcap stays pcap, pcapng stays pcapng).

    # what does the file cover?
    python data/scripts/slice_pcap.py IN --info

    # wall-clock window (CIC-IDS2017 times are local, UTC-3)
    python data/scripts/slice_pcap.py IN OUT --start "2017-07-07 13:55" \\
        --end "2017-07-07 14:05" --utc-offset -3

    # relative window / first N packets
    python data/scripts/slice_pcap.py IN OUT --skip-seconds 3600 --duration 600
    python data/scripts/slice_pcap.py IN OUT --max-packets 200000
"""
import argparse
import struct
import sys
from datetime import datetime, timedelta, timezone

# classic pcap: magic -> (byte order, timestamp resolution)
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB, PCAPNG_EPB, PCAPNG_OBSOLETE_PB = 0x00000001, 0x00000006, 0x00000002
MAX_RECORD = 1 << 18  # a bigger pcap record header means corruption
MAX_BLOCK = 1 << 24
# Captures are only roughly time-ordered; keep reading this far past --end.
ORDER_SLACK = 60.0


class Truncated(Exception):
    pass


def read_exact(f, n):
    data = f.read(n)
    if len(data) < n:
        raise Truncated
    return data


# --------------------------------------------------------------------------
# Readers: each yields (timestamp or None, raw bytes to copy to the output)
# --------------------------------------------------------------------------

def pcap_records(f, first4):
    header = first4 + read_exact(f, 20)
    order, res = PCAP_MAGICS[first4]
    rec = struct.Struct(order + "IIII")
    yield None, header  # global header: always copied
    while True:
        rh = f.read(16)
        if not rh:
            return
        if len(rh) < 16:
            raise Truncated
        sec, frac, incl, _ = rec.unpack(rh)
        if incl > MAX_RECORD:
            sys.exit(f"corrupt pcap record header (caplen {incl})")
        yield sec + frac * res, rh + read_exact(f, incl)


def _tsresol(options: bytes, order: str) -> float:
    """if_tsresol (option 9) of an Interface Description Block; default µs."""
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


def pcapng_blocks(f, first4):
    """Section header, interface and other blocks are copied as-is (ts None);
    packet blocks carry their timestamp."""
    order = "<"
    resolutions = []  # timestamp resolution per interface, in IDB order
    head = first4
    while True:
        if head is None:
            head = f.read(4)
            if not head:
                return
            if len(head) < 4:
                raise Truncated
        length_raw = read_exact(f, 4)
        if head == b"\x0a\x0d\x0d\x0a":  # section header (same bytes in either order)
            bom = read_exact(f, 4)  # byte-order magic decides this section's order
            order = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            length = struct.unpack(order + "I", length_raw)[0]
            resolutions = []
            yield None, head + length_raw + bom + read_exact(f, length - 12)
            head = None
            continue
        btype = struct.unpack(order + "I", head)[0]
        length = struct.unpack(order + "I", length_raw)[0]
        if length < 12 or length > MAX_BLOCK:
            sys.exit(f"corrupt pcapng block (type {btype:#x}, length {length})")
        body = read_exact(f, length - 8)  # ends with the repeated block length
        block = head + length_raw + body
        head = None
        if btype == PCAPNG_IDB:
            resolutions.append(_tsresol(body[8:-4], order))
            yield None, block
        elif btype in (PCAPNG_EPB, PCAPNG_OBSOLETE_PB):
            iface, hi, lo = struct.unpack_from(order + "III", body)
            if btype == PCAPNG_OBSOLETE_PB:
                iface &= 0xFFFF
            res = resolutions[iface] if iface < len(resolutions) else 1e-6
            yield ((hi << 32) | lo) * res, block
        else:
            yield None, block  # name resolution, statistics, simple packets...


def open_capture(f):
    first4 = f.read(4)
    if first4 in PCAP_MAGICS:
        return "pcap", pcap_records(f, first4)
    if len(first4) == 4 and struct.unpack("<I", first4)[0] == PCAPNG_SHB:
        return "pcapng", pcapng_blocks(f, first4)
    sys.exit(f"not a pcap/pcapng file (magic {first4.hex()})")


# --------------------------------------------------------------------------

def fmt(ts, offset_hours):
    tz = timezone(timedelta(hours=offset_hours))
    return datetime.fromtimestamp(ts, tz).strftime("%Y-%m-%d %H:%M:%S.%f %z")


def parse_local(text, offset_hours):
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            naive = datetime.strptime(text, pattern)
            break
        except ValueError:
            continue
    else:
        sys.exit(f"can't parse time {text!r}; use 'YYYY-MM-DD HH:MM[:SS]'")
    return naive.replace(tzinfo=timezone(timedelta(hours=offset_hours))).timestamp()


def open_input(path):
    return sys.stdin.buffer if path == "-" else open(path, "rb", buffering=1 << 20)


def info(path, offset_hours):
    count, first, last, size = 0, None, None, 0
    with open_input(path) as f:
        kind, items = open_capture(f)
        try:
            for ts, raw in items:
                size += len(raw)
                if ts is None:
                    continue
                first = ts if first is None else first
                last = ts
                count += 1
        except Truncated:
            print("warning: file ends in a truncated record", file=sys.stderr)
    if not count:
        print("no packets")
        return
    print(f"format  : {kind}")
    print(f"packets : {count:,}")
    print(f"bytes   : {size:,}")
    print(f"first   : {fmt(first, offset_hours)}  (UTC {fmt(first, 0)})")
    print(f"last    : {fmt(last, offset_hours)}  (UTC {fmt(last, 0)})")
    print(f"duration: {last - first:,.1f} s")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", help='capture file, or "-" for stdin')
    p.add_argument("output", nargs="?")
    p.add_argument("--info", action="store_true", help="print packet count and time range, then exit")
    p.add_argument("--utc-offset", type=float, default=0, help="hours; applies to --start/--end and --info")
    p.add_argument("--start", help="absolute local time 'YYYY-MM-DD HH:MM[:SS]'")
    p.add_argument("--end", help="absolute local time 'YYYY-MM-DD HH:MM[:SS]'")
    p.add_argument("--skip-seconds", type=float, help="start this long after the first packet")
    p.add_argument("--duration", type=float, help="seconds to keep from the start point")
    p.add_argument("--max-packets", type=int, help="stop after writing this many packets")
    args = p.parse_args()

    if args.info:
        info(args.input, args.utc_offset)
        return
    if not args.output:
        p.error("output path is required unless --info is given")
    if args.start and args.skip_seconds is not None:
        p.error("use either --start or --skip-seconds, not both")
    if args.end and args.duration is not None:
        p.error("use either --end or --duration, not both")

    start = parse_local(args.start, args.utc_offset) if args.start else None
    end = parse_local(args.end, args.utc_offset) if args.end else None
    with open_input(args.input) as f, open(args.output, "wb") as out:
        result = write_slice(f, out, start, end, args.skip_seconds, args.duration, args.max_packets)
    report(result, args.output, args.utc_offset)


def write_slice(f, out, start=None, end=None, skip_seconds=None, duration=None, max_packets=None):
    """Copy the packets of `f` inside [start, end) to `out`, plus all header
    blocks. Stops reading once past `end` (+ ORDER_SLACK).

    Returns (format, packets read, packets written, first kept ts, last kept ts).
    """
    written = seen = 0
    first_ts = first_kept = last_kept = None
    kind, items = open_capture(f)
    try:
        for ts, raw in items:
            if ts is None:
                out.write(raw)  # headers and interface descriptions
                continue
            seen += 1
            if first_ts is None:
                first_ts = ts
                if skip_seconds is not None:
                    start = first_ts + skip_seconds
                if duration is not None:
                    end = (start if start is not None else first_ts) + duration
            if end is not None and ts >= end + ORDER_SLACK:
                break
            if (start is not None and ts < start) or (end is not None and ts >= end):
                continue
            out.write(raw)
            written += 1
            first_kept = ts if first_kept is None else first_kept
            last_kept = ts
            if max_packets and written >= max_packets:
                break
    except Truncated:
        print("warning: input ends in a truncated record", file=sys.stderr)
    return kind, seen, written, first_kept, last_kept


def report(result, output, utc_offset):
    kind, seen, written, first_kept, last_kept = result
    print(f"read {seen:,} packets, wrote {written:,} to {output} ({kind})")
    if written:
        print(f"  {fmt(first_kept, utc_offset)}  ->  {fmt(last_kept, utc_offset)}")


if __name__ == "__main__":
    main()
