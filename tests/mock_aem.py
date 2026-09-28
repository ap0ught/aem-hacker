"""A deliberately dumb AEM look-alike used by the test suite.

The scanner fires hundreds of requests per check, so the mock has to be fast and
completely deterministic: every route is a plain regex, and anything unmatched
returns 404 with a body that looks like a real AEM error page (so checks that
grep for "anonymous" or JSON payloads are exercised against realistic noise).
"""

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_404 = b"""<html><head><title>404</title></head><body>
<h1>404 Not Found</h1>
<p>Resource /does/not/exist does not exist.</p>
</body></html>"""

LOGIN_PAGE = b"""<html><head><title>Adobe Experience Manager</title></head><body>
<div data-granite-version="6.5.12.0">Sign in</div>
<p>Adobe Experience Manager 6.5.12.0</p>
</body></html>"""

FELIX_BUNDLES = b"<html><body><h1>Web Console - Bundles</h1></body></html>"


class Route:
    """One mock route: regex -> (status, content_type, body).

    ``body`` may be bytes or a callable ``(method, path, headers) -> bytes`` so a
    test can make the response depend on request state (e.g. the Authorization
    header) the way a real AEM does.
    """

    def __init__(
        self, pattern, status=200, content_type="text/html; charset=utf-8", body=b""
    ):
        self.pattern = re.compile(pattern)
        self.status = status
        self.content_type = content_type
        self.body = body

    def resolve(self, method, path, headers):
        if callable(self.body):
            return self.body(method, path, headers)
        return self.body


class MockAEM:
    """Threaded mock server.

    ``on_ssrf`` is called with the outbound URL whenever a request matches one of
    the ``ssrf_paths``; the mock then performs the request itself, which lets the
    test suite drive the real callback loop end to end instead of faking it.
    """

    def __init__(
        self, routes=None, ssrf_paths=None, on_ssrf=None, default_404=DEFAULT_404
    ):
        self.routes = list(routes or [])
        self.ssrf_paths = [re.compile(p) for p in (ssrf_paths or [])]
        self.on_ssrf = on_ssrf
        self.default_404 = default_404
        self.requests = []  # (method, path) in arrival order
        self.connections = 0
        self._lock = threading.Lock()
        self._httpd = None
        self._thread = None

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self):
        mock = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self):
                # Runs once per TCP connection, so this is the real connection
                # count (unlike counting in _handle, which is per request and
                # cannot tell a reused keep-alive connection from a new one).
                with mock._lock:
                    mock.connections += 1
                BaseHTTPRequestHandler.setup(self)

            def log_message(self, *a):
                return

            def _handle(self, method):
                mock.requests.append((method, self.path))
                path = self.path

                # Is this one of the SSRF-triggering paths? If so, actually
                # perform the outbound fetch the way a vulnerable AEM would.
                for pat in mock.ssrf_paths:
                    m = pat.search(path)
                    if m:
                        target = m.group(1)
                        if mock.on_ssrf:
                            threading.Thread(
                                target=mock.on_ssrf, args=(target,), daemon=True
                            ).start()
                        self._respond(200, "text/html", b"<html>ok</html>")
                        return

                for route in mock.routes:
                    if route.pattern.search(path):
                        body = route.resolve(method, path, self.headers)
                        self._respond(route.status, route.content_type, body)
                        return

                self._respond(404, "text/html", mock.default_404)

            def _respond(self, status, content_type, body):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                self._handle("POST")

            def do_PUT(self):
                self.do_POST()

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self.url = "http://127.0.0.1:{0}".format(self.port)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *a):
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    # -- helpers -----------------------------------------------------------
    def get(self, path, **kw):
        """Fetch from the mock using a fresh connection (used by on_ssrf)."""
        import requests

        return requests.get(self.url + path, timeout=10, **kw)

    @property
    def count(self):
        return len(self.requests)

    def paths(self):
        return [p for _, p in self.requests]
