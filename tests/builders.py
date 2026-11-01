"""Build tiny, exact capture files for unit tests (no network needed)."""
from __future__ import annotations

import socket
import struct
from pathlib import Path

import dpkt

SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def eth(payload: bytes, etype: int = 0x0800, vlan: int | None = None) -> bytes:
    head = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"
    if vlan is not None:
        head += struct.pack("!HH", 0x8100, vlan)
    return head + struct.pack("!H", etype) + payload


def ipv4(src, dst, proto, payload, *, ttl=64, ip_id=1, df=True,
         frag_offset=0, mf=False, total_len=None) -> bytes:
    frag = (0x4000 if df else 0) | (0x2000 if mf else 0) | (frag_offset // 8)
    length = total_len if total_len is not None else 20 + len(payload)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, length, ip_id, frag, ttl, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload


def ipv6(src, dst, nh, payload, *, hlim=64, ext: bytes = b"", ext_nh=None) -> bytes:
    """ext: raw extension header bytes; ext_nh: next-header value pointing at it."""
    first = ext_nh if ext else nh
    return (struct.pack("!IHBB", 6 << 28, len(ext) + len(payload), first, hlim)
            + socket.inet_pton(socket.AF_INET6, src)
            + socket.inet_pton(socket.AF_INET6, dst) + ext + payload)


def tcp(sport, dport, *, seq=0, ack=0, flags=ACK, window=65535,
        options: bytes = b"", payload: bytes = b"") -> bytes:
    options += b"\x00" * (-len(options) % 4)
    doff = (20 + len(options)) // 4
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, (doff << 12) | flags,
                       window, 0, 0) + options + payload


def syn_options(mss=1460, wscale=7, sack=True, ts=(1000, 0)) -> bytes:
    opts = struct.pack("!BBH", 2, 4, mss)
    if sack:
        opts += b"\x04\x02"
    if ts:
        opts += struct.pack("!BBII", 8, 10, *ts)
    if wscale is not None:
        opts += b"\x01" + struct.pack("!BBB", 3, 3, wscale)
    return opts


def udp(sport, dport, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(itype, code, rest: bytes = b"\x00" * 4, body: bytes = b"") -> bytes:
    return struct.pack("!BBH", itype, code, 0) + rest + body


def dns_message(qid, qname, *, response=False, rcode=0, qtype=1, tc=False,
                answers: list[str] = ()) -> bytes:
    flags = 0x0100 | (0x8000 | 0x0080 if response else 0) | (0x0200 if tc else 0) | rcode
    q = b"".join(bytes([len(l)]) + l.encode() for l in qname.split(".")) + b"\x00"
    q += struct.pack("!HH", qtype, 1)
    rrs = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(a)
                   for a in answers)
    return struct.pack("!HHHHHH", qid, flags, 1, len(answers), 0, 0) + q + rrs


def write_pcap(path, frames, linktype: int = 1, snaplen: int = 65535) -> Path:
    """frames: list of (timestamp, frame bytes)."""
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f, snaplen=snaplen, linktype=linktype)
        for ts, buf in frames:
            w.writepkt(buf[:snaplen], ts=ts)
    return Path(path)


def write_pcapng(path, frames, linktype: int = 1) -> Path:
    with open(path, "wb") as f:
        w = dpkt.pcapng.Writer(f, linktype=linktype)
        for ts, buf in frames:
            w.writepkt(buf, ts=ts)
    return Path(path)


def tcp4(src, sport, dst, dport, ts, **kw):
    """(ts, Ethernet/IPv4/TCP frame). ip_id and ttl may be passed through kw."""
    ip_kw = {k: kw.pop(k) for k in ("ip_id", "ttl") if k in kw}
    return ts, eth(ipv4(src, dst, 6, tcp(sport, dport, **kw), **ip_kw))


def udp4(src, sport, dst, dport, ts, payload=b"", **ip_kw):
    return ts, eth(ipv4(src, dst, 17, udp(sport, dport, payload), **ip_kw))
