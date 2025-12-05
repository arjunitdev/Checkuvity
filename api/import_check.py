from http.server import BaseHTTPRequestHandler
import json
import traceback


class handler(BaseHTTPRequestHandler):
    def do_GET(self):  # pragma: no cover - diagnostic
        details = {}
        try:
            from demo_server.server import app as flask_app  # noqa: F401
            details["imported"] = True
        except Exception as exc:
            details["imported"] = False
            details["error_type"] = type(exc).__name__
            details["error_message"] = str(exc)
            details["traceback"] = traceback.format_exc()

        body = json.dumps(details, default=str).encode("utf-8")
        self.send_response(200 if details.get("imported") else 500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return

