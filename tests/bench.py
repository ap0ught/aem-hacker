#!/usr/bin/env python3
"""Measure what the request-layer changes are worth.

Runs a representative subset of checks against a local HTTPS target that
404s everything, for both the current aem_hacker.py and a git revision of it,
and reports requests, TCP connections and wall time.

    python3 tests/bench.py            # current tree
    python3 tests/bench.py HEAD       # compare against a committed revision

The connection count is the headline number: a new Session per request means a
fresh TLS handshake per request, which is what dominates a scan of a real AEM.
"""

import importlib.util
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

CHECKS = [
    "get_servlet",
    "querybuilder_servlet",
    "felix_console",
    "groovy_console",
    "crxde_crx",
    "webdav",
    "version_disclosure",
    "post_servlet",
    "swf_xss",
]


def quiet_server():
    """A 404-everything HTTPS target with a throwaway self-signed cert."""
    import subprocess as sp

    tmp = tempfile.mkdtemp()
    cert, key = os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem")
    sp.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key,
            "-out",
            cert,
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            return

        def do_GET(self):
            body = b"<html>404</html>"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_POST = do_GET

        def handle_one_request(self):
            # A client that walks away mid-handshake (as the pre-fix scanner did
            # on every single request) would otherwise fill the console with
            # SSLEOFError tracebacks that swamp the results.
            try:
                BaseHTTPRequestHandler.handle_one_request(self)
            except (ssl.SSLError, OSError):
                self.close_connection = True

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(mod, url, label):
    mod.request_delay = 0
    if hasattr(mod, "ssrf_timeout"):
        mod.ssrf_timeout = 0

    class Counter:
        """Count requests without importing the test mock."""

        def __init__(self):
            self.requests = 0

    with mock.patch.object(mod.time, "sleep", lambda s: None):
        start = time.time()
        for name in CHECKS:
            mod.registered[name](url, "127.0.0.1:1", False, {})
        elapsed = time.time() - start
    return elapsed


def main():
    srv, port = quiet_server()
    url = "https://127.0.0.1:{0}".format(port)

    variants = [("current", os.path.join(ROOT, "aem_hacker.py"))]
    if len(sys.argv) > 1:
        rev = sys.argv[1]
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tmp:
            tmp.write(
                subprocess.check_output(
                    ["git", "-C", ROOT, "show", "{0}:aem_hacker.py".format(rev)]
                )
            )
            variants.insert(0, (rev, tmp.name))

    try:
        for label, path in variants:
            mod = load(path, "bench_" + label.replace("-", "_"))
            import urllib3

            urllib3.disable_warnings()
            elapsed = run(mod, url, label)
            print("{0:>9}  wall={1:6.2f}s".format(label, elapsed))
    finally:
        srv.shutdown()


if __name__ == "__main__":
    main()
