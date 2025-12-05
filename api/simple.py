from http.server import BaseHTTPRequestHandler

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            # Try to import Flask
            from flask import Flask
            test_app = Flask(__name__)
            
            @test_app.route('/')
            def hello():
                return {'status': 'ok', 'message': 'Flask works'}
            
            # Simple test
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "flask_imported": true}')
        except Exception as e:
            import traceback
            error_msg = f"Error: {str(e)}\n{traceback.format_exc()}"
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(error_msg.encode('utf-8'))
    
    def log_message(self, format, *args):
        pass






