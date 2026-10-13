#!/usr/bin/env python3
# loop3 t7 C1 外带接收端（只绑内网/本地，绝不连公网）
# 监听 0.0.0.0:8099，记录完整原始请求（含 Cookie/UA/路径），写 JSONL
import json, sys, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
LOG = sys.argv[2] if len(sys.argv) > 2 else "/tmp/loop3-t7-oob.jsonl"


class H(BaseHTTPRequestHandler):
    def _rec(self, method):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        e = {"at": datetime.datetime.now().isoformat(), "method": method,
             "path": self.path, "client": self.client_address[0],
             "headers": dict(self.headers), "body": body[:2000]}
        with open(LOG, "a") as f:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print("OOB_HIT " + json.dumps(e, ensure_ascii=False)[:900], flush=True)

    def do_GET(self):
        self._rec("GET")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"loop3-t7-oob-ok")

    def do_POST(self):
        self._rec("POST")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


srv = HTTPServer(("0.0.0.0", PORT), H)
print(f"listening 0.0.0.0:{PORT} log={LOG}", flush=True)
srv.serve_forever()
