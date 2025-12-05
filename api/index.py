#!/usr/bin/env python3
"""WSGI entry point for Vercel deployment."""

import sys
import json
from io import BytesIO
from urllib.parse import urlsplit
from pathlib import Path
from http.server import BaseHTTPRequestHandler

print("[lambda] cold start", flush=True)
print(f"[lambda] python={sys.version}", flush=True)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXTRA_PATHS = [
    PROJECT_ROOT,
    PROJECT_ROOT / "demo_server",
    PROJECT_ROOT / "build_scripts",
    PROJECT_ROOT / "security_agent_service",
]

for path in EXTRA_PATHS:
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

print(f"[lambda] sys.path[0:4]={sys.path[:4]}", flush=True)

fallback_app = None
import_error: Exception | None = None

try:
    from demo_server.server import app as flask_app

    print("[lambda] imported demo_server.server", flush=True)
    wsgi_app = flask_app
except Exception as exc:  # pragma: no cover
    print(f"[lambda] demo_server import failed: {type(exc).__name__}: {exc}", flush=True)
    print("[lambda] falling back to minimal Flask app", flush=True)
    from flask import Flask, jsonify

    fallback_app = Flask(__name__)
    import_error = exc

    @fallback_app.route("/", defaults={"path": ""})
    @fallback_app.route("/<path:path>")
    def _bootstrap_error(path: str):
        return (
            jsonify(
                {
                    "error": "App initialization failed",
                    "message": str(exc),
                    "type": type(exc).__name__,
                }
            ),
            500,
        )

    wsgi_app = fallback_app
else:
    fallback_app = None
    import_error = None


def _error_payload(message: str, error_type: str = "Error"):
    return {
        "error": error_type,
        "message": message,
    }


class handler(BaseHTTPRequestHandler):  # pragma: no cover - executed in production
    server_version = "VercelPythonWSGI/1.0"

    def _read_body(self) -> bytes:
        length = int(self.headers.get("content-length", 0) or 0)
        if length > 0:
            return self.rfile.read(length)
        return b""

    def _build_environ(self, body: bytes) -> dict:
        split_url = urlsplit(self.path)
        environ = {
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "https",
            "wsgi.input": BytesIO(body),
            "wsgi.errors": sys.stderr,
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
            "REQUEST_METHOD": self.command,
            "SCRIPT_NAME": "",
            "PATH_INFO": split_url.path,
            "QUERY_STRING": split_url.query or "",
            "SERVER_NAME": self.headers.get("host", "localhost"),
            "SERVER_PORT": "443",
            "SERVER_PROTOCOL": self.request_version,
            "CONTENT_TYPE": self.headers.get("content-type", ""),
            "CONTENT_LENGTH": str(len(body)),
        }

        for key, value in self.headers.items():
            header_key = f"HTTP_{key.upper().replace('-', '_')}"
            if header_key in ("HTTP_CONTENT_TYPE", "HTTP_CONTENT_LENGTH"):
                continue
            environ[header_key] = value

        # Basic overrides in case X-Forwarded headers exist
        if "HTTP_X_FORWARDED_PROTO" in environ:
            environ["wsgi.url_scheme"] = environ["HTTP_X_FORWARDED_PROTO"]
        if "HTTP_X_FORWARDED_HOST" in environ:
            environ["SERVER_NAME"] = environ["HTTP_X_FORWARDED_HOST"]
        if "HTTP_X_FORWARDED_PORT" in environ:
            environ["SERVER_PORT"] = environ["HTTP_X_FORWARDED_PORT"]

        return environ

    def _send_response(self, status: str, headers: list[tuple[str, str]], body_chunks: list[bytes]) -> None:
        status_code, _, status_text = status.partition(" ")
        status_code_int = int(status_code)

        self.send_response(status_code_int, status_text)
        header_names = {name.lower() for name, _ in headers}
        if "access-control-allow-origin" not in header_names:
            headers.append(("Access-Control-Allow-Origin", "*"))

        body = b"".join(body_chunks)
        if "content-length" not in header_names:
            headers.append(("Content-Length", str(len(body))))

        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _handle_error(self, exc: Exception) -> None:
        print(f"[lambda] request error: {type(exc).__name__}: {exc}", flush=True)
        payload = _error_payload(str(exc), type(exc).__name__)
        body = json.dumps(payload).encode("utf-8")
        self.send_response(500, "Internal Server Error")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
        self.end_headers()

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def do_PUT(self):
        self._dispatch()

    def do_DELETE(self):
        self._dispatch()

    def log_message(self, format, *args):  # pragma: no cover - silence default logging
        print(f"[lambda] {self.address_string()} - {format % args}", flush=True)

    def _dispatch(self):
        try:
            if fallback_app is not None:
                payload = _error_payload(
                    str(import_error) if import_error else "Unknown error",
                    type(import_error).__name__ if import_error else "ImportError",
                )
                body = json.dumps(payload).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)
                return

            body = self._read_body()
            environ = self._build_environ(body)

            status_headers: dict[str, object] = {}
            chunks: list[bytes] = []

            def start_response(status: str, response_headers: list[tuple[str, str]], exc_info=None):
                status_headers["status"] = status
                status_headers["headers"] = response_headers
                return chunks.append

            result = wsgi_app(environ, start_response)
            try:
                for data in result:
                    if isinstance(data, bytes):
                        chunks.append(data)
                    else:
                        chunks.append(data.encode("utf-8"))
            finally:
                if hasattr(result, "close"):
                    result.close()

            status = status_headers.get("status", "500 Internal Server Error")
            headers = status_headers.get("headers", [])
            if not isinstance(headers, list):
                headers = list(headers or [])

            self._send_response(status, headers, chunks)
        except Exception as exc:  # pragma: no cover
            self._handle_error(exc)
