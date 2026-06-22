"""A FAKE, local "attacker" collector.

Exfiltration and SSRF demos need somewhere for data to go. This is that
somewhere: a tiny HTTP server bound to 127.0.0.1 that logs whatever it receives
and prints it, so you can *see* the leak. It never forwards anything anywhere.
It is the harmless stand-in for a real attacker endpoint.

Run standalone:   python attacks/_lab/attacker_sink.py 8888
Or start in-process from an exploit:   httpd = start(port=8888)
"""

from __future__ import annotations

import datetime
import http.server
import json
import pathlib
import threading

SINK_DIR = pathlib.Path(__file__).resolve().parent / "sink_data"


class _Handler(http.server.BaseHTTPRequestHandler):
    def _capture(self, method: str) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        headers = {k: v for k, v in self.headers.items()}
        SINK_DIR.mkdir(parents=True, exist_ok=True)
        record = {
            "time": datetime.datetime.now().isoformat(timespec="seconds"),
            "method": method,
            "path": self.path,
            "headers": headers,
            "body": body,
        }
        with (SINK_DIR / "received.log").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        print(f"\n  [attacker-sink] captured {method} {self.path}")
        auth = headers.get("Authorization")
        if auth:
            print(f"  [attacker-sink] STOLEN Authorization header: {auth}")
        if body:
            print(f"  [attacker-sink] body: {body[:500]}")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK (captured by fake local sink)")

    def do_POST(self) -> None:  # noqa: N802 (http.server naming)
        self._capture("POST")

    def do_GET(self) -> None:  # noqa: N802
        self._capture("GET")

    def log_message(self, *args) -> None:  # silence default stderr spam
        pass


def start(host: str = "127.0.0.1", port: int = 8888) -> http.server.HTTPServer:
    """Start the sink in a background daemon thread and return the server."""
    httpd = http.server.HTTPServer((host, port), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


if __name__ == "__main__":
    import sys
    import time

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    start(port=port)
    print(f"  [attacker-sink] listening on http://127.0.0.1:{port}  (Ctrl-C to stop)")
    print(f"  [attacker-sink] logging to {SINK_DIR / 'received.log'}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  [attacker-sink] stopped.")
