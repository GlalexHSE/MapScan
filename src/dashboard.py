"""Веб-дашборд на http.server: отдаёт статику и JSON API поверх хранилища."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


def build_handler(storage, run_scan_async):
    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send_body(self, code, body, content_type):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, payload, code=200):
            self.send_body(
                code, json.dumps(payload, ensure_ascii=False),
                "application/json; charset=utf-8",
            )

        def do_GET(self):
            if self.path in STATIC_FILES:
                return self.serve_static(self.path)
            if self.path == "/api/stats":
                return self.send_json(storage.get_stats())
            if self.path == "/api/services":
                return self.send_json(storage.get_services())
            if self.path == "/api/findings":
                return self.send_json(storage.get_findings())
            if self.path == "/api/scans":
                return self.send_json(storage.get_scans())
            self.send_json({"error": "not found"}, code=404)

        def do_POST(self):
            if self.path == "/api/scan":
                started = run_scan_async()
                if started:
                    return self.send_json({"status": "started"})
                return self.send_json({"status": "busy"}, code=409)
            self.send_json({"error": "not found"}, code=404)

        def serve_static(self, path):
            filename, content_type = STATIC_FILES[path]
            file_path = WEB_DIR / filename
            if not file_path.exists():
                return self.send_json({"error": "missing asset"}, code=404)
            self.send_body(200, file_path.read_bytes(), content_type)

    return DashboardHandler


class Dashboard:
    def __init__(self, config, storage, run_scan, scan_lock):
        self.host = config.host
        self.port = config.port
        self.run_scan = run_scan
        self.scan_lock = scan_lock
        handler = build_handler(storage, self.run_scan_async)
        self.server = ThreadingHTTPServer((self.host, self.port), handler)

    def run_scan_async(self):
        if not self.scan_lock.acquire(blocking=False):
            return False

        def worker():
            try:
                self.run_scan()
            except Exception as exc:  # фоновый скан не должен ронять поток
                print(f"[dashboard] Ручной скан завершился ошибкой: {exc}")
            finally:
                self.scan_lock.release()

        threading.Thread(target=worker, name="manual-scan", daemon=True).start()
        return True

    @property
    def url(self):
        return f"http://{self.host}:{self.port}"

    def serve_forever(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()
