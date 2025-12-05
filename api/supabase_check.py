from http.server import BaseHTTPRequestHandler
import json
import traceback


import os


class handler(BaseHTTPRequestHandler):
    def do_GET(self):  # pragma: no cover - diagnostic
        details = {}
        try:
            from demo_server.server import _init_supabase, supabase_manager, demo_mode  # noqa: WPS347

            manager = _init_supabase()
            details["demo_mode"] = demo_mode
            details["manager_created"] = manager is not None
            if manager is None:
                details["supabase_manager_present"] = supabase_manager is not None
            details["env"] = {
                "SUPABASE_URL_len": len(os.environ.get("SUPABASE_URL", "")),
                "SUPABASE_SERVICE_ROLE_KEY_len": len(os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")),
                "SUPABASE_ANON_KEY_len": len(os.environ.get("SUPABASE_ANON_KEY", "")),
            }
        except Exception as exc:
            details["error"] = str(exc)
            details["error_type"] = type(exc).__name__
            details["traceback"] = traceback.format_exc()

        body = json.dumps(details, default=str).encode("utf-8")
        self.send_response(200 if details.get("manager_created") else 500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return

