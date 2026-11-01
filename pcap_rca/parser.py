"""Decode PCAP/PCAPNG files into flat per-packet records.

Only headers are decoded: link layer (Ethernet + VLAN, Linux SLL/SLL2, raw
IP, BSD loopback) -> IPv4/IPv6 -> TCP/UDP/ICMP/ICMPv6, plus DNS. Payload
bytes are not kept. Lengths come from the IP header rather than the
captured length, so snaplen-truncated captures still report true sizes.

    from pcap_rca.parser import read_packets
    for pkt in read_packets("capture.pcap"):
        ...

Frame numbers count every frame in the file (including ARP and other
non-IP frames), so they match Wireshark's numbering.
"""
from __future__ import annotations

import socket
import struct
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import dpkt

# IP protocol numbers
ICMP = 1
TCP = 6
UDP = 17
ICMPV6 = 58

PROTO_NAMES = {ICMP: "ICMP", 2: "IGMP", TCP: "TCP", UDP: "UDP", 47: "GRE", 50: "ESP",
               51: "AH", ICMPV6: "ICMPv6", 89: "OSPF", 132: "SCTP"}

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
_FLAG_LETTERS = ((SYN, "S"), (ACK, "A"), (FIN, "F"), (RST, "R"),
                 (PSH, "P"), (URG, "U"), (ECE, "E"), (CWR, "C"))

# ICMP types that quote the packet that caused them
ICMP_ERROR_TYPES = {3, 4, 5, 11, 12}
ICMPV6_ERROR_TYPES = {1, 2, 3, 4}
_ECHO_TYPES = {ICMP: (8, 0), ICMPV6: (128, 129)}

_IPV6_EXT_HEADERS = {0, 43, 44, 51, 60}  # hop-by-hop, routing, fragment, AH, dest opts
PAYLOAD_HEAD_BYTES = 32


def flag_str(flags: int) -> str:
    """TCP flags as letters in Wireshark order, e.g. 0x12 -> 'SA'."""
    return "".join(ch for bit, ch in _FLAG_LETTERS if flags & bit) or "-"


@dataclass(slots=True)
class QuotedHeader:
    """The original packet quoted inside an ICMP error message."""

    proto: int
    src: str
    dst: str
    ttl: int
    ip_id: int | None
    sport: int | None
    dport: int | None
    tcp_seq: int | None


@dataclass(slots=True)
class DnsInfo:
    id: int
    is_response: bool
    opcode: int
    rcode: int
    authoritative: bool
    truncated: bool
    recursion_desired: bool
    recursion_available: bool
    qname: str | None
    qtype: int | None
    answer_count: int
    authority_count: int
    answers: tuple[tuple[int, str], ...]  # (rtype, value) for A/AAAA/CNAME/NS/PTR
    over_tcp: bool


@dataclass(slots=True)
class Packet:
    frame: int
    ts: float
    ip_version: int
    src: str
    dst: str
    proto: int
    ip_len: int  # total IP length from the header (not the captured length)
    ttl: int  # TTL / hop limit
    ip_id: int | None  # IPv4 ID, or IPv6 fragment identification
    dont_fragment: bool
    frag_offset: int = 0
    more_fragments: bool = False
    truncated: bool = False  # capture cut off part of the headers

    # TCP / UDP
    sport: int | None = None
    dport: int | None = None
    payload_len: int = 0  # TCP/UDP payload bytes, from header lengths

    # TCP
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_flags: int = 0
    tcp_window: int | None = None  # raw header value, not scaled
    tcp_mss: int | None = None
    tcp_wscale: int | None = None
    tcp_sack_permitted: bool = False
    tcp_sack_blocks: int = 0
    tcp_tsval: int | None = None
    tcp_tsecr: int | None = None
    # First bytes of the TCP payload: enough for an HTTP request/status line
    # or a TLS record header, without keeping whole payloads in memory.
    payload_head: bytes = b""

    # ICMP / ICMPv6
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_mtu: int | None = None  # next-hop MTU (frag needed / packet too big)
    icmp_echo_id: int | None = None
    icmp_echo_seq: int | None = None
    icmp_quoted: QuotedHeader | None = None

    dns: DnsInfo | None = None

    flow_id: int | None = None  # filled in by streams.FlowTable

    @property
    def is_fragment(self) -> bool:
        return self.frag_offset > 0 or self.more_fragments

    @property
    def is_icmp_error(self) -> bool:
        return self.icmp_quoted is not None


@dataclass
class ParseStats:
    frames: int = 0
    ip_packets: int = 0
    non_ip: int = 0  # ARP, LLDP, STP, ...
    malformed: int = 0
    truncated: int = 0
    duplicates: int = 0  # dropped capture duplicates
    fragments: int = 0
    linktype: int | None = None
    first_ts: float | None = None
    last_ts: float | None = None


class UnsupportedCapture(ValueError):
    pass


class _Malformed(Exception):
    pass


# --------------------------------------------------------------------------
# Link layer
# --------------------------------------------------------------------------

_ETH_IPV4, _ETH_IPV6 = 0x0800, 0x86DD
_VLAN_TYPES = {0x8100, 0x88A8, 0x9100}

LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW = 0, 1, 101
LINKTYPE_LOOP, LINKTYPE_LINUX_SLL, LINKTYPE_IPV4 = 108, 113, 228
LINKTYPE_IPV6, LINKTYPE_LINUX_SLL2 = 229, 276
SUPPORTED_LINKTYPES = {LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, 12, 14,
                       LINKTYPE_LOOP, LINKTYPE_LINUX_SLL, LINKTYPE_IPV4,
                       LINKTYPE_IPV6, LINKTYPE_LINUX_SLL2}


def _l3_payload(linktype: int, buf: bytes) -> bytes | None:
    """Return the IP packet inside a frame, or None for non-IP frames."""
    if linktype == LINKTYPE_ETHERNET:
        if len(buf) < 14:
            raise _Malformed
        etype, off = int.from_bytes(buf[12:14], "big"), 14
        while etype in _VLAN_TYPES:
            if len(buf) < off + 4:
                raise _Malformed
            etype, off = int.from_bytes(buf[off + 2:off + 4], "big"), off + 4
        return buf[off:] if etype in (_ETH_IPV4, _ETH_IPV6) else None
    if linktype in (LINKTYPE_RAW, 12, 14, LINKTYPE_IPV4, LINKTYPE_IPV6):
        return buf
    if linktype == LINKTYPE_LINUX_SLL:
        if len(buf) < 16:
            raise _Malformed
        return buf[16:] if int.from_bytes(buf[14:16], "big") in (_ETH_IPV4, _ETH_IPV6) else None
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(buf) < 20:
            raise _Malformed
        return buf[20:] if int.from_bytes(buf[0:2], "big") in (_ETH_IPV4, _ETH_IPV6) else None
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        # 4-byte address family in host byte order; just check the IP version.
        if len(buf) < 5:
            raise _Malformed
        return buf[4:] if buf[4] >> 4 in (4, 6) else None
    raise UnsupportedCapture(f"link type {linktype}")


# --------------------------------------------------------------------------
# Network layer
# --------------------------------------------------------------------------

def _walk_ipv6_ext(b: bytes, nh: int, off: int):
    """Skip IPv6 extension headers -> (next header, offset, frag_offset, mf, frag_id)."""
    frag_offset, mf, frag_id = 0, False, None
    while nh in _IPV6_EXT_HEADERS:
        if len(b) < off + 8:
            raise _Malformed
        if nh == 44:  # fragment header
            field, frag_id = struct.unpack_from("!HI", b, off + 2)
            frag_offset, mf = (field >> 3) * 8, bool(field & 1)
            nh, off = b[off], off + 8
            if frag_offset:
                break  # no upper-layer header in a non-first fragment
        elif nh == 51:  # AH: length in 4-byte units, minus 2
            nh, off = b[off], off + (b[off + 1] + 2) * 4
        else:
            nh, off = b[off], off + (b[off + 1] + 1) * 8
    return nh, off, frag_offset, mf, frag_id


def _parse_ip(frame: int, ts: float, b: bytes):
    """Return (Packet, transport bytes captured, true transport length)."""
    if not b:
        raise _Malformed
    version = b[0] >> 4
    if version == 4:
        ihl = (b[0] & 0x0F) * 4
        if len(b) < 20 or ihl < 20 or len(b) < ihl:
            raise _Malformed
        total_len, ip_id, frag = struct.unpack_from("!HHH", b, 2)
        if total_len == 0:  # segmentation offload: length not filled in
            total_len = len(b)
        pkt = Packet(
            frame=frame, ts=ts, ip_version=4,
            src=socket.inet_ntoa(b[12:16]), dst=socket.inet_ntoa(b[16:20]),
            proto=b[9], ip_len=total_len, ttl=b[8], ip_id=ip_id,
            dont_fragment=bool(frag & 0x4000),
            frag_offset=(frag & 0x1FFF) * 8, more_fragments=bool(frag & 0x2000),
        )
        return pkt, b[ihl:total_len], total_len - ihl
    if version == 6:
        if len(b) < 40:
            raise _Malformed
        payload_len = int.from_bytes(b[4:6], "big")
        total_len = 40 + payload_len if payload_len else len(b)
        nh, off, frag_offset, mf, frag_id = _walk_ipv6_ext(b, b[6], 40)
        pkt = Packet(
            frame=frame, ts=ts, ip_version=6,
            src=socket.inet_ntop(socket.AF_INET6, b[8:24]),
            dst=socket.inet_ntop(socket.AF_INET6, b[24:40]),
            proto=nh, ip_len=total_len, ttl=b[7], ip_id=frag_id,
            dont_fragment=True,  # IPv6 routers never fragment
            frag_offset=frag_offset, more_fragments=mf,
        )
        return pkt, b[off:total_len], total_len - off
    raise _Malformed


# --------------------------------------------------------------------------
# Transport layer
# --------------------------------------------------------------------------

def _parse_tcp(pkt: Packet, b: bytes, l4_len: int, dns_ports) -> None:
    if len(b) < 20:
        pkt.truncated = True
        return
    sport, dport, seq, ack, off_flags, window = struct.unpack_from("!HHIIHH", b)
    doff = (off_flags >> 12) * 4
    pkt.sport, pkt.dport = sport, dport
    pkt.tcp_seq, pkt.tcp_ack, pkt.tcp_window = seq, ack, window
    pkt.tcp_flags = off_flags & 0xFF
    pkt.payload_len = max(l4_len - doff, 0)

    opts = b[20:min(doff, len(b))]
    if len(b) < doff:
        pkt.truncated = True
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(opts) or opts[i + 1] < 2:
            break  # malformed option list; keep what we have
        length = opts[i + 1]
        body = opts[i + 2:i + length]
        if kind == 2 and len(body) == 2:
            pkt.tcp_mss = int.from_bytes(body, "big")
        elif kind == 3 and len(body) == 1:
            pkt.tcp_wscale = min(body[0], 14)  # RFC 7323 caps the shift at 14
        elif kind == 4:
            pkt.tcp_sack_permitted = True
        elif kind == 5:
            pkt.tcp_sack_blocks = len(body) // 8
        elif kind == 8 and len(body) == 8:
            pkt.tcp_tsval, pkt.tcp_tsecr = struct.unpack("!II", body)
        i += length

    if pkt.payload_len:
        pkt.payload_head = bytes(b[doff:doff + PAYLOAD_HEAD_BYTES])
    if pkt.payload_len >= 14 and (sport in dns_ports or dport in dns_ports):
        payload = b[doff:]
        if len(payload) >= 2:
            msg_len = int.from_bytes(payload[:2], "big")
            # Only messages that start in this segment and fit in it; DNS over
            # TCP split across segments would need stream reassembly.
            if len(payload) >= 2 + msg_len:
                pkt.dns = _parse_dns(payload[2:2 + msg_len], over_tcp=True)


def _parse_udp(pkt: Packet, b: bytes, l4_len: int, dns_ports) -> None:
    if len(b) < 8:
        pkt.truncated = True
        return
    sport, dport, ulen = struct.unpack_from("!HHH", b)
    pkt.sport, pkt.dport = sport, dport
    pkt.payload_len = ulen - 8 if ulen >= 8 else max(l4_len - 8, 0)
    if sport in dns_ports or dport in dns_ports:
        pkt.dns = _parse_dns(b[8:], over_tcp=False)


def _parse_quoted(b: bytes, version: int) -> QuotedHeader | None:
    """Decode the IP header + first 8 bytes quoted in an ICMP error."""
    try:
        if version == 4:
            if len(b) < 20:
                return None
            ihl = (b[0] & 0x0F) * 4
            proto, ttl = b[9], b[8]
            src, dst = socket.inet_ntoa(b[12:16]), socket.inet_ntoa(b[16:20])
            ip_id = int.from_bytes(b[4:6], "big")
            l4 = b[ihl:]
        else:
            if len(b) < 40:
                return None
            proto, off, _, _, ip_id = _walk_ipv6_ext(b, b[6], 40)
            ttl = b[7]
            src = socket.inet_ntop(socket.AF_INET6, b[8:24])
            dst = socket.inet_ntop(socket.AF_INET6, b[24:40])
            l4 = b[off:]
    except (_Malformed, OSError, ValueError):
        return None
    sport = dport = seq = None
    if proto in (TCP, UDP) and len(l4) >= 4:
        sport, dport = struct.unpack_from("!HH", l4)
        if proto == TCP and len(l4) >= 8:
            seq = int.from_bytes(l4[4:8], "big")
    return QuotedHeader(proto, src, dst, ttl, ip_id, sport, dport, seq)


def _parse_icmp(pkt: Packet, b: bytes) -> None:
    if len(b) < 8:
        pkt.truncated = True
        return
    itype, code = b[0], b[1]
    pkt.icmp_type, pkt.icmp_code = itype, code
    echo_request, echo_reply = _ECHO_TYPES[pkt.proto]
    if itype in (echo_request, echo_reply):
        pkt.icmp_echo_id, pkt.icmp_echo_seq = struct.unpack_from("!HH", b, 4)
        return
    if pkt.proto == ICMP and itype in ICMP_ERROR_TYPES:
        if itype == 3 and code == 4:
            pkt.icmp_mtu = int.from_bytes(b[6:8], "big") or None
        pkt.icmp_quoted = _parse_quoted(b[8:], 4)
    elif pkt.proto == ICMPV6 and itype in ICMPV6_ERROR_TYPES:
        if itype == 2:
            pkt.icmp_mtu = int.from_bytes(b[4:8], "big")
        pkt.icmp_quoted = _parse_quoted(b[8:], 6)


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------

def _rr_value(rr) -> str:
    if rr.type == dpkt.dns.DNS_A and len(rr.rdata) == 4:
        return socket.inet_ntoa(rr.rdata)
    if rr.type == dpkt.dns.DNS_AAAA and len(rr.rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rr.rdata)
    for attr in ("cname", "nsname", "ptrname"):
        if hasattr(rr, attr):
            return getattr(rr, attr)
    return ""


def _parse_dns(data: bytes, over_tcp: bool) -> DnsInfo | None:
    if len(data) < 12:
        return None
    try:
        msg = dpkt.dns.DNS(data)
    except (dpkt.UnpackError, dpkt.NeedData, IndexError, ValueError, UnicodeDecodeError):
        return None
    flags = msg.op
    # `is not None`, never truthiness: dpkt's question objects raise on len().
    q = msg.qd[0] if msg.qd else None
    return DnsInfo(
        id=msg.id,
        is_response=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0xF,
        rcode=flags & 0xF,
        authoritative=bool(flags & 0x0400),
        truncated=bool(flags & 0x0200),
        recursion_desired=bool(flags & 0x0100),
        recursion_available=bool(flags & 0x0080),
        qname=q.name if q is not None else None,
        qtype=q.type if q is not None else None,
        answer_count=len(msg.an),
        authority_count=len(msg.ns),
        answers=tuple((rr.type, _rr_value(rr)) for rr in msg.an),
        over_tcp=over_tcp,
    )


# --------------------------------------------------------------------------
# Capture duplicates
# --------------------------------------------------------------------------

class _Deduplicator:
    """Detect the same IPv4 datagram captured twice within `window` seconds.

    A real resend (retransmission, duplicate ACK) gets a new IPv4 ID from the
    sender, so an identical ID + identical transport bytes means the capture
    saw one packet twice (e.g. SPAN of both directions). IPv6 packets and
    IPv4 ID 0 carry no such marker, so they are never treated as duplicates.
    """

    def __init__(self, window: float):
        self.window = window
        self.recent: deque = deque()
        self.seen: dict = {}

    def is_duplicate(self, pkt: Packet, l4: bytes) -> bool:
        if pkt.ip_version != 4 or not pkt.ip_id:
            return False
        while self.recent and pkt.ts - self.recent[0][0] > self.window:
            ts, key = self.recent.popleft()
            if self.seen.get(key) == ts:
                del self.seen[key]
        key = (pkt.src, pkt.dst, pkt.proto, pkt.ip_id, pkt.frag_offset, hash(l4))
        prev = self.seen.get(key)
        if prev is not None and abs(pkt.ts - prev) <= self.window:
            return True
        self.seen[key] = pkt.ts
        self.recent.append((pkt.ts, key))
        return False


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def _open_reader(f):
    magic = f.read(4)
    f.seek(0)
    try:
        if magic == b"\x0a\x0d\x0d\x0a":
            return dpkt.pcapng.Reader(f)
        return dpkt.pcap.Reader(f)
    except (ValueError, dpkt.NeedData, dpkt.UnpackError) as exc:
        raise UnsupportedCapture(f"not a valid pcap/pcapng file (magic {magic.hex()})") from exc


def read_packets(
    path: str | Path,
    *,
    dns_ports: tuple[int, ...] = (53,),
    dedup_window: float = 0.005,
    stats: ParseStats | None = None,
) -> Iterator[Packet]:
    """Yield one Packet per IP frame in the capture.

    dedup_window: seconds within which an identical IPv4 datagram counts as a
        capture duplicate and is dropped (0 disables).
    stats: pass a ParseStats to collect counters while iterating.
    """
    stats = stats if stats is not None else ParseStats()
    dedup = _Deduplicator(dedup_window) if dedup_window > 0 else None
    with open(path, "rb") as f:
        reader = _open_reader(f)
        linktype = reader.datalink()
        if linktype not in SUPPORTED_LINKTYPES:
            raise UnsupportedCapture(f"link type {linktype} is not supported")
        stats.linktype = linktype

        for frame, (ts, buf) in enumerate(reader, start=1):
            ts = float(ts)
            stats.frames += 1
            if stats.first_ts is None:
                stats.first_ts = ts
            stats.last_ts = ts
            try:
                l3 = _l3_payload(linktype, buf)
                if l3 is None:
                    stats.non_ip += 1
                    continue
                pkt, l4, l4_len = _parse_ip(frame, ts, l3)
                if dedup is not None and dedup.is_duplicate(pkt, l4):
                    stats.duplicates += 1
                    continue
                if pkt.is_fragment:
                    stats.fragments += 1
                if pkt.frag_offset == 0:  # only the first fragment has L4 headers
                    if pkt.proto == TCP:
                        _parse_tcp(pkt, l4, l4_len, dns_ports)
                    elif pkt.proto == UDP:
                        _parse_udp(pkt, l4, l4_len, dns_ports)
                    elif pkt.proto in (ICMP, ICMPV6):
                        _parse_icmp(pkt, l4)
            except (_Malformed, struct.error, OSError, ValueError):
                stats.malformed += 1
                continue
            stats.ip_packets += 1
            if pkt.truncated:
                stats.truncated += 1
            yield pkt


def load_packets(path: str | Path, **kwargs) -> tuple[list[Packet], ParseStats]:
    """Read a whole capture into memory."""
    stats = ParseStats()
    packets = list(read_packets(path, stats=stats, **kwargs))
    return packets, stats
