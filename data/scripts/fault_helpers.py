"""Tiny servers and clients used by capture_faults.sh (stdlib only).

Each subcommand runs inside one of the scenario's network namespaces.
Client subcommands print what happened and always exit 0: in these
scenarios the failure is the point, and the capture is the real output.
"""
import argparse
import socket
import socketserver
import struct
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CHUNK = 64 * 1024


# --------------------------------------------------------------------------
# Servers
# --------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    """GET /bytes/N -> N zero bytes, GET /status/CODE -> that status code."""

    protocol_version = "HTTP/1.0"

    def do_GET(self):
        parts = self.path.strip("/").split("/")
        code, size = 404, 0
        if len(parts) == 2 and parts[0] == "bytes" and parts[1].isdigit():
            code, size = 200, int(parts[1])
        elif len(parts) == 2 and parts[0] == "status" and parts[1].isdigit():
            code, size = int(parts[1]), 64
        self.send_response(code)
        self.send_header("Content-Length", str(size))
        self.end_headers()
        while size > 0:
            n = min(size, CHUNK)
            self.wfile.write(bytes(n))
            size -= n

    def log_message(self, *args):
        pass


class _HTTPServer(ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind() reverse-resolves the bind address, which
        # blocks for seconds inside a namespace that has no resolver.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def http_server(args):
    _HTTPServer((args.bind, args.port), _Handler).serve_forever()


def rst_server(args):
    """Answer each request with part of a response, then abort with RST."""
    srv = socket.create_server((args.bind, args.port))
    while True:
        conn, _ = srv.accept()
        conn.recv(4096)
        conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 1000000\r\n\r\n" + bytes(20000))
        time.sleep(0.2)
        # SO_LINGER with a zero timeout turns close() into an abortive RST.
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        conn.close()


def tls_server(args):
    """TLS 1.2 server (handshake alerts stay in clear text) with the given cert."""
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)
    srv = socket.create_server((args.bind, args.port))
    while True:
        conn, _ = srv.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1024)
                tls.sendall(b"hello\n")
        except (ssl.SSLError, OSError):
            pass  # expected: the client rejects our certificate
        finally:
            conn.close()


def login_server(args):
    """Minimal FTP-style login dialogue: 220 greeting, USER -> 331, PASS -> 230
    for the right password, else 530."""
    def serve(conn):
        with conn, conn.makefile("rwb", buffering=0) as f:
            f.write(b"220 pcap-rca FTP ready\r\n")
            for line in f:
                cmd = line.strip().split(b" ", 1)
                if cmd[0].upper() == b"USER":
                    f.write(b"331 Password required\r\n")
                elif cmd[0].upper() == b"PASS":
                    ok = len(cmd) > 1 and cmd[1] == args.password.encode()
                    f.write(b"230 Login successful\r\n" if ok else b"530 Login incorrect\r\n")
                elif cmd[0].upper() == b"QUIT":
                    f.write(b"221 Bye\r\n")
                    return

    srv = socket.create_server((args.bind, args.port))
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


def sink_server(args):
    """Read and discard whatever clients upload."""
    def drain(conn):
        with conn:
            while conn.recv(CHUNK):
                pass

    srv = socket.create_server((args.bind, args.port))
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=drain, args=(conn,), daemon=True).start()


# --- DNS -------------------------------------------------------------------
# Behaviour is chosen by the first label of the query name (zone: .test):
#   ok*       -> A record          nx*      -> NXDOMAIN
#   servfail* -> SERVFAIL          refused* -> REFUSED
#   slow*     -> A record, 1.5 s late
#   drop*     -> never answered    nodata*  -> NOERROR with no answers
#   big*      -> TC=1 over UDP, 40 A records over TCP
#   anything else -> NXDOMAIN

def _dns_answer(query, over_tcp):
    """Return the response bytes for one query, or None to stay silent."""
    if len(query) < 12:
        return None
    qid, flags = struct.unpack("!HH", query[:4])
    i, labels = 12, []
    while i < len(query) and query[i]:
        n = query[i]
        labels.append(query[i + 1:i + 1 + n].decode("ascii", "replace").lower())
        i += 1 + n
    question = query[12:i + 5]  # name + terminating zero + qtype + qclass
    qtype = struct.unpack("!H", query[i + 1:i + 3])[0] if i + 3 <= len(query) else 0
    first = labels[0] if labels else ""

    def build(rcode, answers=(), truncated=False):
        rflags = 0x8000 | 0x0400 | (flags & 0x0100) | 0x0080 | rcode  # QR AA RD RA
        if truncated:
            rflags |= 0x0200
        header = struct.pack("!HHHHHH", qid, rflags, 1, len(answers), 0, 0)
        records = b"".join(
            b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(a)
            for a in answers
        )
        return header + question + records

    wants_a = qtype == 1
    if first.startswith("drop"):
        return None
    if first.startswith("ok"):
        return build(0, ["10.10.2.2"] if wants_a else [])
    if first.startswith("slow"):
        time.sleep(1.5)
        return build(0, ["10.10.2.2"] if wants_a else [])
    if first.startswith("servfail"):
        return build(2)
    if first.startswith("refused"):
        return build(5)
    if first.startswith("nodata"):
        return build(0)
    if first.startswith("big"):
        if not over_tcp:
            return build(0, truncated=True)
        return build(0, [f"10.10.5.{n}" for n in range(1, 41)] if wants_a else [])
    return build(3)


def dns_server(args):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((args.bind, 53))
    tcp = socket.create_server((args.bind, 53))

    def answer_udp(data, addr):
        reply = _dns_answer(data, over_tcp=False)
        if reply is not None:
            udp.sendto(reply, addr)

    def serve_tcp():
        while True:
            conn, _ = tcp.accept()
            with conn:
                head = conn.recv(2)
                if len(head) < 2:
                    continue
                (length,) = struct.unpack("!H", head)
                data = b""
                while len(data) < length:
                    more = conn.recv(length - len(data))
                    if not more:
                        break
                    data += more
                reply = _dns_answer(data, over_tcp=True)
                if reply is not None:
                    conn.sendall(struct.pack("!H", len(reply)) + reply)

    threading.Thread(target=serve_tcp, daemon=True).start()
    while True:
        data, addr = udp.recvfrom(4096)
        # One thread per query so a "slow" answer doesn't hold up the others.
        threading.Thread(target=answer_udp, args=(data, addr), daemon=True).start()


# --------------------------------------------------------------------------
# Clients
# --------------------------------------------------------------------------

def fetch(args):
    for _ in range(args.count):
        try:
            with urllib.request.urlopen(args.url, timeout=args.timeout) as resp:
                size = len(resp.read())
            print(f"fetch {args.url}: {resp.status}, {size} bytes")
        except urllib.error.HTTPError as exc:
            # Read the error body: closing with unread data would send an RST.
            exc.read()
            exc.close()
            print(f"fetch {args.url}: {exc.code}")
        except Exception as exc:  # noqa: BLE001 - every failure is a result here
            print(f"fetch {args.url}: {exc!r}")
        time.sleep(args.gap)


def slow_fetch(args):
    """Download with a tiny receive buffer and a slow reader -> zero window."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.rcvbuf)
    try:
        s.connect((args.host, args.port))
        s.sendall(f"GET {args.path} HTTP/1.0\r\nHost: {args.host}\r\n\r\n".encode())
        total, slow_until = 0, time.monotonic() + args.slow_seconds
        while time.monotonic() < slow_until:
            data = s.recv(args.read)
            if not data:
                break
            total += len(data)
            time.sleep(args.interval)
        # Drain the rest quickly: closing with unread data would send an RST
        # and add an unrelated event to this scenario.
        while data := s.recv(CHUNK):
            total += len(data)
        print(f"slow-fetch: read {total} bytes")
    except OSError as exc:
        print(f"slow-fetch: {exc!r}")
    finally:
        s.close()


def upload(args):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(args.timeout)
    try:
        s.connect((args.host, args.port))
        s.sendall(bytes(args.bytes))
        s.shutdown(socket.SHUT_WR)
        print(f"upload: sent {args.bytes} bytes")
    except OSError as exc:
        print(f"upload: {exc!r}")
    finally:
        s.close()


def tls_connect(args):
    """TLS 1.2 client that verifies the server certificate like a browser."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    for _ in range(args.count):
        try:
            with socket.create_connection((args.host, args.port), timeout=args.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=args.sni) as tls:
                    tls.sendall(b"hi\n")
                    print(f"tls {args.host}:{args.port}: ok, {tls.version()}")
        except (OSError, ssl.SSLError) as exc:
            print(f"tls {args.host}:{args.port}: {exc!r}")
        time.sleep(args.gap)


def guess_logins(args):
    """Password guessing like FTP-Patator: several guesses per connection;
    with --last-correct the very last guess is the right password."""
    total = args.connections * args.per_connection
    n = 0
    for _ in range(args.connections):
        try:
            with socket.create_connection((args.host, args.port), timeout=5) as s, \
                    s.makefile("rwb", buffering=0) as f:
                f.readline()  # greeting
                for _ in range(args.per_connection):
                    n += 1
                    password = args.password if args.last_correct and n == total else f"guess{n}"
                    f.write(b"USER admin\r\n")
                    f.readline()
                    f.write(f"PASS {password}\r\n".encode())
                    f.readline()
                f.write(b"QUIT\r\n")
                f.readline()
        except OSError as exc:
            print(f"guess-logins: {exc!r}")
        time.sleep(args.gap)
    print(f"guess-logins: {n} guesses")


def connect(args):
    for _ in range(args.count):
        try:
            socket.create_connection((args.host, args.port), timeout=args.timeout).close()
            print(f"connect {args.host}:{args.port}: ok")
        except OSError as exc:
            print(f"connect {args.host}:{args.port}: {exc!r}")
        time.sleep(args.gap)


def echo(args):
    """Send one ICMP echo request (raw socket, needs root).

    capture_faults.sh sends this just before stopping tcpdump so the capture's
    last timestamp shows when capturing stopped. Without it, a capture that
    ends in silence looks shorter than it was, and "no answer within N
    seconds" can't be judged for the final request.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    header = struct.pack("!BBHHH", 8, 0, 0, 0xEC40, 1)
    payload = b"pcap-rca end-of-capture marker"
    data = header + payload
    total = sum(struct.unpack(f"!{len(data) // 2}H", data + b"\x00" * (len(data) % 2)))
    total = (total >> 16) + (total & 0xFFFF)
    checksum = ~(total + (total >> 16)) & 0xFFFF
    s.sendto(header[:2] + struct.pack("!H", checksum) + header[4:] + payload, (args.host, 0))
    s.close()


def udp_send(args):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.ttl:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, args.ttl)
    for n in range(args.count):
        try:
            s.sendto(b"pcap-rca probe", (args.host, args.port + n * args.port_step))
        except OSError as exc:  # a previous ICMP error can surface here
            print(f"udp-send: {exc!r}")
        time.sleep(args.gap)
    s.close()


# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, func in [("http-server", http_server), ("rst-server", rst_server),
                       ("sink-server", sink_server)]:
        sp = sub.add_parser(name)
        sp.add_argument("bind")
        sp.add_argument("port", type=int)
        sp.set_defaults(func=func)

    sp = sub.add_parser("login-server")
    sp.add_argument("bind")
    sp.add_argument("port", type=int)
    sp.add_argument("--password", default="letmein")
    sp.set_defaults(func=login_server)

    sp = sub.add_parser("guess-logins")
    sp.add_argument("host")
    sp.add_argument("port", type=int)
    sp.add_argument("--connections", type=int, default=5)
    sp.add_argument("--per-connection", type=int, default=3)
    sp.add_argument("--password", default="letmein")
    sp.add_argument("--last-correct", action="store_true")
    sp.add_argument("--gap", type=float, default=0.1)
    sp.set_defaults(func=guess_logins)

    sp = sub.add_parser("tls-server")
    sp.add_argument("bind")
    sp.add_argument("port", type=int)
    sp.add_argument("cert")
    sp.add_argument("key")
    sp.set_defaults(func=tls_server)

    sp = sub.add_parser("tls-connect")
    sp.add_argument("host")
    sp.add_argument("port", type=int)
    sp.add_argument("--sni", default="pcap-rca.test")
    sp.add_argument("--count", type=int, default=1)
    sp.add_argument("--timeout", type=float, default=3)
    sp.add_argument("--gap", type=float, default=0.5)
    sp.set_defaults(func=tls_connect)

    sp = sub.add_parser("dns-server")
    sp.add_argument("bind")
    sp.set_defaults(func=dns_server)

    sp = sub.add_parser("fetch")
    sp.add_argument("url")
    sp.add_argument("--count", type=int, default=1)
    sp.add_argument("--timeout", type=float, default=30)
    sp.add_argument("--gap", type=float, default=0.5)
    sp.set_defaults(func=fetch)

    sp = sub.add_parser("slow-fetch")
    sp.add_argument("host")
    sp.add_argument("port", type=int)
    sp.add_argument("path")
    sp.add_argument("--rcvbuf", type=int, default=4096)
    sp.add_argument("--read", type=int, default=512)
    sp.add_argument("--interval", type=float, default=0.05)
    sp.add_argument("--slow-seconds", type=float, default=4)
    sp.set_defaults(func=slow_fetch)

    sp = sub.add_parser("upload")
    sp.add_argument("host")
    sp.add_argument("port", type=int)
    sp.add_argument("bytes", type=int)
    sp.add_argument("--timeout", type=float, default=10)
    sp.set_defaults(func=upload)

    sp = sub.add_parser("connect")
    sp.add_argument("host")
    sp.add_argument("port", type=int)
    sp.add_argument("--count", type=int, default=1)
    sp.add_argument("--timeout", type=float, default=4)
    sp.add_argument("--gap", type=float, default=0.5)
    sp.set_defaults(func=connect)

    sp = sub.add_parser("echo")
    sp.add_argument("host")
    sp.set_defaults(func=echo)

    sp = sub.add_parser("udp-send")
    sp.add_argument("host")
    sp.add_argument("port", type=int)
    sp.add_argument("--count", type=int, default=1)
    sp.add_argument("--ttl", type=int, default=0)
    sp.add_argument("--port-step", type=int, default=0)
    sp.add_argument("--gap", type=float, default=0.5)
    sp.set_defaults(func=udp_send)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
