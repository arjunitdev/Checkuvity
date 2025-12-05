from http.server import BaseHTTPRequestHandler
from flask import Flask

# Create a minimal Flask app
test_app = Flask(__name__)

@test_app.route('/')
def hello():
    return {'status': 'ok', 'message': 'Flask works'}

@test_app.route('/health')
def health():
    return {'status': 'healthy', 'service': 'flask-test'}

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._handle_request()
    
    def do_POST(self):
        self._handle_request()
    
    def _handle_request(self):
        from io import BytesIO
        import sys
        
        try:
            path = self.path.split('?')[0]
            content_length = int(self.headers.get('Content-Length', 0))
            body_data = self.rfile.read(content_length) if content_length > 0 else b''
            
            host = self.headers.get('Host', 'localhost')
            server_name = host.split(':')[0] if ':' in host else host
            server_port = host.split(':')[1] if ':' in host else '443'
            
            query_string = ''
            if '?' in self.path:
                query_string = self.path.split('?', 1)[1]
            
            environ = {
                'REQUEST_METHOD': self.command,
                'SCRIPT_NAME': '',
                'PATH_INFO': path,
                'QUERY_STRING': query_string,
                'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                'CONTENT_LENGTH': str(len(body_data)),
                'SERVER_NAME': server_name,
                'SERVER_PORT': server_port,
                'wsgi.version': (1, 0),
                'wsgi.url_scheme': 'https',
                'wsgi.input': BytesIO(body_data),
                'wsgi.errors': sys.stderr,
                'wsgi.multithread': False,
                'wsgi.multiprocess': False,
                'wsgi.run_once': False,
            }
            
            for key, value in self.headers.items():
                header_name = key.upper().replace('-', '_')
                if header_name not in ['CONTENT_TYPE', 'CONTENT_LENGTH', 'HOST']:
                    environ[f'HTTP_{header_name}'] = value
            
            response_data = []
            status_code = [200]
            headers = []
            
            def start_response(status, response_headers):
                status_code[0] = int(status.split()[0])
                headers.extend(response_headers)
            
            app_iter = test_app(environ, start_response)
            
            try:
                for data in app_iter:
                    if isinstance(data, bytes):
                        response_data.append(data)
                    else:
                        response_data.append(str(data).encode('utf-8'))
            finally:
                if hasattr(app_iter, 'close'):
                    try:
                        app_iter.close()
                    except:
                        pass
            
            body = b''.join(response_data)
            
            self.send_response(status_code[0])
            for header, value in headers:
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(body)
            
        except Exception as e:
            import traceback
            error_msg = f"Error: {str(e)}\n{traceback.format_exc()}"
            try:
                self.send_response(500)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(error_msg.encode('utf-8'))
            except:
                pass
    
    def log_message(self, format, *args):
        pass
