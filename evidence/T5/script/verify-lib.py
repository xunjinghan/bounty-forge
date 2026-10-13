# -*- coding: utf-8 -*-
"""verifier (t5) 独立核验工具库：仅标准库；只打 127.0.0.1。
不复用挖掘员 hunt-lib.py 的任何代码，独立实现。
"""
import http.client
import json
import os
import re
import sqlite3
import sys
import time
import urllib.parse

BASE = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\target-site-lab"
DB_PATH = os.path.join(BASE, "lab.db")
UPLOAD_DIR = os.path.join(BASE, "uploads")
EVID = os.path.join(r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence")

H_8095 = ("127.0.0.1", 8095)
H_8091 = ("127.0.0.1", 8091)


def http(method, path, host=H_8095, headers=None, body=None, timeout=20,
         follow=False):
    """返回原始报文级记录。follow=False，避免掩盖 302 链路。"""
    hdrs = dict(headers or {})
    conn = http.client.HTTPConnection(host[0], host[1], timeout=timeout)
    stamp = time.time()
    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", f"{host[0]}:{host[1]}")
        for k, v in hdrs.items():
            conn.putheader(k, v)
        if body is not None:
            if isinstance(body, str):
                body = body.encode("utf-8")
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        if body is not None:
            conn.send(body)
        resp = conn.getresponse()
        raw = resp.read()
        rec = {
            "method": method,
            "url": f"http://{host[0]}:{host[1]}{path}",
            "req_headers": {"Host": f"{host[0]}:{host[1]}", **hdrs},
            "req_body": (body.decode("utf-8", "replace") if isinstance(body, bytes) else body),
            "status": resp.status,
            "resp_headers": {k: v for k, v in resp.getheaders()},
            "len": len(raw),
            "body_head": raw[:1500].decode("utf-8", "replace"),
            "elapsed_ms": round((time.time() - stamp) * 1000, 1),
        }
        return rec
    except Exception as e:
        return {"method": method, "url": f"http://{host[0]}:{host[1]}{path}",
                "error": f"{type(e).__name__}: {e}",
                "elapsed_ms": round((time.time() - stamp) * 1000, 1)}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def login(username, password, host=H_8095):
    """POST /login，返回 (status, set-cookie token, raw_record)"""
    body = urllib.parse.urlencode({"username": username, "password": password})
    rec = http("POST", "/login", host=host,
               headers={"Content-Type": "application/x-www-form-urlencoded"},
               body=body)
    tok = None
    sc = rec.get("resp_headers", {}).get("Set-Cookie", "")
    m = re.search(r"token=([^;,\s]+)", sc)
    if m and m.group(1):
        tok = m.group(1)
    return tok, rec


def cookie(tok):
    return {"Cookie": f"token={tok}"}


def db_query(sql, args=()):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()


def db_scalar(sql, args=()):
    rows = db_query(sql, args)
    if not rows:
        return None
    return list(rows[0].values())[0]


def db_snapshot(label=""):
    snap = {
        "label": label,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "sha256": sha256_file(DB_PATH),
        "size": os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else None,
        "users": db_query("SELECT id,username,role,balance_cents FROM users ORDER BY id"),
        "orders": db_query("SELECT id,user_id,item,qty,amount_cents,state FROM orders ORDER BY id"),
        "messages": db_query("SELECT id,author,content FROM messages ORDER BY id"),
        "sessions": db_query("SELECT token,user_id,username FROM sessions ORDER BY rowid"),
        "coupon_claims": db_query("SELECT user_id,code FROM coupon_claims"),
        "counts": {
            "users": db_scalar("SELECT COUNT(*) FROM users"),
            "orders": db_scalar("SELECT COUNT(*) FROM orders"),
            "messages": db_scalar("SELECT COUNT(*) FROM messages"),
            "sessions": db_scalar("SELECT COUNT(*) FROM sessions"),
            "coupon_claims": db_scalar("SELECT COUNT(*) FROM coupon_claims"),
        },
        "uploads": sorted(os.listdir(UPLOAD_DIR)) if os.path.isdir(UPLOAD_DIR) else None,
    }
    return snap


def sha256_file(p):
    import hashlib
    if not os.path.exists(p):
        return None
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def role_of(tok):
    r = db_query("SELECT username,role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?", (tok,))
    return r[0] if r else None


def save(name, obj):
    p = os.path.join(EVID, name)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=1)
    print(f"[saved] {p} ({os.path.getsize(p)} bytes)")
    return p
