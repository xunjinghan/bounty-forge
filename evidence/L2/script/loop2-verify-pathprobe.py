import http.server
import socketserver
import threading
import urllib.parse

LOG = []


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        p = self.path
        u = urllib.parse.urlparse(p)
        LOG.append({"path": p, "urlparse_path": u.path, "netloc": u.netloc})
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


srv = socketserver.ThreadingTCPServer(("127.0.0.1", 18099), H)
srv.daemon_threads = True
t = threading.Thread(target=srv.serve_forever, daemon=True)
t.start()

import socket
for raw in (b"GET //__reset HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
            b"GET /__reset HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
            b"GET //__reset; HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"):
    s = socket.create_connection(("127.0.0.1", 18099), timeout=5)
    s.sendall(raw)
    while s.recv(4096):
        pass
    s.close()

for e in LOG:
    print(repr(e["path"]), "-> urlparse.path=", repr(e["urlparse_path"]),
          "netloc=", repr(e["netloc"]))
srv.shutdown()
