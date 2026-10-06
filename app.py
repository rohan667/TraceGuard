"""TraceGuard: a local, dependency-free security log detection demo."""

from __future__ import annotations

import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from analyzer import analyze_events, normalize_events

ROOT = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = 8000


def read_json(filename: str):
    return json.loads((ROOT / filename).read_text(encoding="utf-8"))


class TraceGuardHandler(BaseHTTPRequestHandler):
    server_version = "TraceGuard/1.0"

    def send_json(self, payload, status=200):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/events":
            events = read_json("data/sample_events.json")
            return self.send_json({"events": events, "alerts": analyze_events(events)})
        if path == "/api/scenarios":
            return self.send_json(read_json("data/scenarios.json"))
        if path == "/api/health":
            return self.send_json({"ok": True, "name": "TraceGuard"})

        relative = "index.html" if path in ("/", "") else path.lstrip("/")
        target = (ROOT / relative).resolve()
        if ROOT not in target.parents or not target.is_file():
            return self.send_json({"error": "Not found"}, 404)
        content = target.read_bytes()
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in ("application/javascript",):
            content_type += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1_000_000:
                return self.send_json({"error": "Request must be between 1 byte and 1 MB."}, 400)
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if path == "/api/analyze":
                if not isinstance(payload, list):
                    return self.send_json({"error": "Send a JSON array of events."}, 400)
                events = normalize_events(payload)
                return self.send_json({"events": events, "alerts": analyze_events(events)})
            if path == "/api/scenario":
                scenario_id = payload.get("id") if isinstance(payload, dict) else None
                scenarios = read_json("data/scenarios.json")
                scenario = next((item for item in scenarios if item["id"] == scenario_id), None)
                if scenario is None:
                    return self.send_json({"error": "Unknown scenario."}, 404)
                events = normalize_events(scenario["events"])
                return self.send_json({"events": events, "alerts": analyze_events(events), "scenario": scenario["name"]})
            return self.send_json({"error": "Not found"}, 404)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self.send_json({"error": "Request body must be valid UTF-8 JSON."}, 400)
        except ValueError as exc:
            return self.send_json({"error": str(exc)}, 400)

    def log_message(self, format, *args):
        print("[TraceGuard] " + format % args)


def main():
    server = ThreadingHTTPServer((HOST, PORT), TraceGuardHandler)
    print(f"TraceGuard is running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop it.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping TraceGuard…")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
