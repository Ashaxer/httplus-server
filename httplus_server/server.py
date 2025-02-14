import os
import argparse
import base64
import socket
from http.server import SimpleHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

class MultiThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

class AuthPartialContentRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, auth_user=None, auth_pass=None, **kwargs):
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        super().__init__(*args, **kwargs)

    def do_AUTHHEAD(self):
        """Send 401 Unauthorized response for Basic Authentication."""
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Authentication required"')
        self.send_header("Content-Type", "text/html")
        self.end_headers()

    def do_GET(self):
        """Handle GET request with optional authentication and partial content support."""
        # Check authentication if enabled
        if self.auth_user and self.auth_pass:
            auth_header = self.headers.get("Authorization")
            if not auth_header or not self.check_auth(auth_header):
                self.do_AUTHHEAD()
                self.wfile.write(b"Unauthorized")
                return

        if "Range" in self.headers:
            self.send_partial_content()
        else:
            super().do_GET()

    def check_auth(self, auth_header):
        """Verify Basic Authentication credentials."""
        auth_type, encoded = auth_header.split(" ", 1)
        if auth_type.lower() != "basic":
            return False

        decoded = base64.b64decode(encoded).decode("utf-8")
        username, password = decoded.split(":", 1)
        return username == self.auth_user and password == self.auth_pass

    def send_partial_content(self):
        """Send partial content for resume support."""
        file_path = os.path.join(self.directory, self.path.lstrip("/"))  # Ensure correct file path

        if not os.path.exists(file_path):
            self.send_error(404, "File Not Found")
            return

        range_header = self.headers["Range"]
        start, end = range_header.replace("bytes=", "").split("-")
        start = int(start)
        end = int(end) if end else os.path.getsize(file_path) - 1

        with open(file_path, "rb") as f:
            f.seek(start)
            chunk_size = end - start + 1
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{os.path.getsize(file_path)}")
            self.send_header("Content-Length", chunk_size)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(f.read(chunk_size))


def run(bind="0.0.0.0", port=8080, directory=".", auth_user=None, auth_pass=None, threaded=False):
    """Start the HTTP server with optional authentication and multithreading."""
    handler_class = lambda *args, **kwargs: AuthPartialContentRequestHandler(
        *args, directory=directory, auth_user=auth_user, auth_pass=auth_pass, **kwargs
    )

    server_class = MultiThreadedHTTPServer if threaded else HTTPServer
    server_address = (bind, port)

    if ':' in bind:
        HTTPServer.address_family = socket.AF_INET6

    httpd = server_class(server_address, handler_class)
    print(f"Starting {'Threaded ' if threaded else ''}HTTP server at {f'[{bind}]' if ':' in bind else bind}:{port}, serving '{directory}'")
    if auth_user and auth_pass:
        print(f"Authentication enabled. Username: {auth_user}")

    httpd.serve_forever()

def main():
    parser = argparse.ArgumentParser(description="Multithreaded HTTP Server with authentication and partial content support.")

    parser.add_argument("narg_port", nargs="?", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("-b", "--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("-p", "--port",  type=int, help="Port to listen on (overrides positional argument)")
    parser.add_argument("-d", "--dir", default=".", help="Directory to serve (default: current directory)")
    parser.add_argument("-u", "--user", help="Username for basic authentication")
    parser.add_argument("-P", "--pass", dest="password", help="Password for basic authentication")
    parser.add_argument("-t", "--threaded", action="store_true", help="Enable multithreading")

    args = parser.parse_args()
    port = args.port if args.port else args.narg_port


    run(
        bind=args.bind,
        port=port,
        directory=args.dir,
        auth_user=args.user,
        auth_pass=args.password,
        threaded=args.threaded
    )

if __name__ == "__main__":
    main()