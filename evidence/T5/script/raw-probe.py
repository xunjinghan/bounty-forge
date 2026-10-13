# -*- coding: utf-8 -*-
"""minimal raw-socket probe: 只读，看 / 的真实响应头与 body 尾部。"""
import socket
import sys

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8095
PATH = sys.argv[2] if len(sys.argv) > 2 else "/"
COOKIE = sys.argv[3] if len(sys.argv) > 3 else None

req = f"GET {PATH} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUser-Agent: recon-raw/1.0\r\n"
if COOKIE:
    req += f"Cookie: {COOKIE}\r\n"
req += "Connection: close\r\n\r\n"

s = socket.create_connection((HOST, PORT), timeout=10)
s.sendall(req.encode())
chunks = []
while True:
    b = s.recv(65536)
    if not b:
        break
    chunks.append(b)
s.close()
data = b"".join(chunks)
head, _, body = data.partition(b"\r\n\r\n")
print("=== HEAD ===")
print(head.decode("utf-8", "replace"))
print("=== BODY (%d bytes) ===" % len(body))
txt = body.decode("utf-8", "replace")
print(txt[:1200])
print("...")
print(txt[-400:])
