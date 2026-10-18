#!/usr/bin/env python3
"""One hostname's origin, with the IPv4 and IPv6 listening addresses able to behave
DIFFERENTLY. This is what lets the controlled test site seed a specific, deliberate
failure stage (TCP / TLS / HTTP) on the IPv6 path of an otherwise dual-stack host,
without touching DNS at all.

Usage:
  seed_server.py --content-dir DIR --v4-bind ADDR:PORT [--v6-bind ADDR:PORT]
                  --v6-mode {pass,tcp_fail,tls_fail,http_fail}
                  [--scheme {http,https}] [--cert CERT --key KEY]

Modes (what happens on the v6 bind address; the v4 bind always serves normally):
  pass       serve the same content normally (dual-stack, fully working host)
  tcp_fail   do not open a v6 listening socket at all -> connections are refused
  tls_fail   accept the TCP connection, then close it before completing any TLS
             handshake -> the client's TLS handshake fails (reset / no ServerHello)
  http_fail  complete TLS normally, then the HTTP layer returns 500 for every request

In production (the VPS), --v6-bind is the host's real public IPv6 address, and DNS
carries AAAA to it. In local dev (docker-compose / this repo's own tests), the same
code is reused with --v6-bind pointed at a second local address that stands in for
"the IPv6 path", since a real IPv6 address is not always available in a dev sandbox.
"""
from __future__ import annotations
import argparse
import http.server
import socket
import socketserver
import ssl
import sys
import threading


def make_static_handler(content_dir: str):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=content_dir, **kw)

        def log_message(self, fmt, *args):  # keep output quiet
            pass
    return Handler


class AlwaysFailHandler(http.server.BaseHTTPRequestHandler):
    """The HTTP-stage failure: transport (TCP/TLS) works fine, but every response is 500."""
    def _fail(self):
        body = b"seeded HTTP_FAILURE: this host's IPv6 path always returns 500"
        self.send_response(500)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_HEAD = _fail

    def log_message(self, fmt, *args):
        pass


class DualStackServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def __init__(self, addr, handler, family, tls_ctx=None):
        self.address_family = family
        self.tls_ctx = tls_ctx
        super().__init__(addr, handler)

    def get_request(self):
        sock, addr = super().get_request()
        if self.tls_ctx is not None:
            sock = self.tls_ctx.wrap_socket(sock, server_side=True)
        return sock, addr


def family_of(addr: str) -> int:
    return socket.AF_INET6 if ":" in addr else socket.AF_INET


def serve_forever_in_thread(server: DualStackServer, label: str) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, name=label, daemon=True)
    t.start()
    return t


def tls_context(cert: str | None, key: str | None) -> ssl.SSLContext | None:
    if not cert:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


def run_handshake_dropper(bind: str) -> threading.Thread:
    """tls_fail mode: accept the TCP connection, then close before any TLS bytes are sent.
    A real client's TLS handshake will fail with a reset/EOF, not a timeout."""
    host, port = bind.rsplit(":", 1)
    fam = family_of(host)
    srv = socket.socket(fam, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, int(port)))
    srv.listen(50)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                conn.recv(4096)  # read the ClientHello, then just hang up
            except OSError:
                pass
            conn.close()

    t = threading.Thread(target=loop, name="tls-handshake-dropper", daemon=True)
    t.start()
    return t


def build_server(bind: str, handler_cls, scheme: str, cert: str | None, key: str | None) -> DualStackServer:
    host, port = bind.rsplit(":", 1)
    ctx = tls_context(cert, key) if scheme == "https" else None
    return DualStackServer((host, int(port)), handler_cls, family_of(host), ctx)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--content-dir", required=True)
    p.add_argument("--v4-bind", required=True, help="ADDR:PORT")
    p.add_argument("--v6-bind", help="ADDR:PORT (omit for an IPv4-only-by-design host)")
    p.add_argument("--v6-mode", choices=["pass", "tcp_fail", "tls_fail", "http_fail"], default="pass")
    p.add_argument("--scheme", choices=["http", "https"], default="http")
    p.add_argument("--cert")
    p.add_argument("--key")
    args = p.parse_args()

    static_handler = make_static_handler(args.content_dir)
    threads = []

    v4 = build_server(args.v4_bind, static_handler, args.scheme, args.cert, args.key)
    threads.append(serve_forever_in_thread(v4, "v4"))
    print(f"[v4] serving {args.content_dir} on {args.v4_bind} ({args.scheme}) - always PASS", file=sys.stderr)

    if args.v6_bind:
        if args.v6_mode == "tcp_fail":
            print(f"[v6] NOT listening on {args.v6_bind} (mode=tcp_fail): connections will be refused", file=sys.stderr)
        elif args.v6_mode == "tls_fail":
            if args.scheme != "https":
                sys.exit("--v6-mode tls_fail requires --scheme https")
            threads.append(run_handshake_dropper(args.v6_bind))
            print(f"[v6] {args.v6_bind}: accepting TCP, then dropping the TLS handshake (mode=tls_fail)", file=sys.stderr)
        elif args.v6_mode == "http_fail":
            v6 = build_server(args.v6_bind, AlwaysFailHandler, args.scheme, args.cert, args.key)
            threads.append(serve_forever_in_thread(v6, "v6-http-fail"))
            print(f"[v6] serving 500 for every request on {args.v6_bind} (mode=http_fail)", file=sys.stderr)
        else:  # pass
            v6 = build_server(args.v6_bind, static_handler, args.scheme, args.cert, args.key)
            threads.append(serve_forever_in_thread(v6, "v6-pass"))
            print(f"[v6] serving {args.content_dir} on {args.v6_bind} ({args.scheme}) - PASS", file=sys.stderr)
    else:
        print("[v6] no --v6-bind given: this host is IPv4-only by design (no AAAA in DNS)", file=sys.stderr)

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
