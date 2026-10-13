#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
t3 补测探针 v2 —— 修正首轮探针的四处盲点（自写，不复用 hunter 脚本）

盲点清单（首轮 probe 的自我复盘）：
  1. db_state() 未覆盖 users.password → B1 的 GET /change-password 变更被漏检
  2. B3 时序错误：先新登录才查旧会话行，导致 sessions_row_still_present=False 是假象
  3. GET //__reset 在原件返回 200 的路径解析需要实证（urlparse("//x") → netloc 语义）
  4. 未测匿名态四入口（队长旁证称 302，需自证）

用法: python loop2-verify-probe2.py
"""
import hashlib
import http.client
import json
import os
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SB = os.path.join(HERE, "loop2-verify-sandbox")
ORIG_DB = os.path.join(SB, "orig", "lab.db")
HARD_DB = os.path.join(SB, "hard", "lab.db")
TS = time.strftime("%Y%m%d-%H%M%S")
REC = []


def req(port, method, path, body=None, cookie=None, headers=None, record=True, tag=""):
    h = {"User-Agent": "lv-probe2/1.0"}
    if headers:
        h.update(headers)
    if cookie:
        h["Cookie"] = "token=%s" % cookie
    if body is not None and "Content-Type" not in h:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        raw = r.read()
        st = r.status
        sc = r.getheader("Set-Cookie") or ""
        c.close()
    except Exception as exc:
        st, raw, sc = -1, ("EXC %r" % (exc,)).encode(), ""
    txt = raw.decode("utf-8", "replace")
    if record:
        REC.append({"tag": tag, "port": port, "method": method, "path": path,
                    "body": body, "cookie": (cookie or "")[:20], "status": st,
                    "resp_len": len(raw), "snippet": txt[:300].replace("\n", " ")})
    return st, txt, sc


def login(port, u, p, tag=""):
    st, _, sc = req(port, "POST", "/login", "username=%s&password=%s" % (u, p), tag=tag)
    tok = ""
    for part in sc.split(";"):
        part = part.strip()
        if part.startswith("token="):
            tok = part[6:]
    return st, tok


def state(dbfile):
    """含 password 列（首轮漏检点 #1）。"""
    c = sqlite3.connect("file:%s?mode=ro" % dbfile.replace("\\", "/"), uri=True)
    try:
        users = {r[0]: {"bal": r[1], "pw": r[2]} for r in
                 c.execute("SELECT username,balance_cents,password FROM users")}
        cols = {r[1] for r in c.execute("PRAGMA table_info(sessions)")}
        q = ("SELECT token,user_id,username,csrf_token FROM sessions" if "csrf_token" in cols
             else "SELECT token,user_id,username FROM sessions")
        sess = [tuple(r) for r in c.execute(q)]
        msgs = c.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        return {"users": users, "orders": c.execute("SELECT COUNT(*) FROM orders").fetchone()[0],
                "sessions": sess, "messages": msgs,
                "orders_states": [tuple(r) for r in c.execute("SELECT id,state FROM orders")]}
    finally:
        c.close()


def fstat(p):
    try:
        st = os.stat(p)
        return {"mtime": st.st_mtime,
                "mtime_str": time.strftime("%H:%M:%S", time.localtime(st.st_mtime)),
                "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest()}
    except FileNotFoundError:
        return {"mtime": None, "mtime_str": None, "sha256": None}


def csrf_of(dbfile, tok):
    c = sqlite3.connect("file:%s?mode=ro" % dbfile.replace("\\", "/"), uri=True)
    try:
        cols = {r[1] for r in c.execute("PRAGMA table_info(sessions)")}
        if "csrf_token" not in cols:
            return None
        r = c.execute("SELECT csrf_token FROM sessions WHERE token=?", (tok,)).fetchone()
        return r[0] if r else None
    finally:
        c.close()


def diff_users(a, b):
    out = {}
    for k in set(a["users"]) | set(b["users"]):
        ua, ub = a["users"].get(k), b["users"].get(k)
        if ua != ub:
            out[k] = {"before": ua, "after": ub}
    return out


def main():
    out = {"meta": {"timestamp": TS, "probe": os.path.basename(__file__),
                    "purpose": "修正首轮探针四处盲点"},
           "checks": {}}

    # ---- 补测 1：B1 重跑，state 含 password ----
    print("[*] fix1: B1 re-run with password column", flush=True)
    port, dbfile = 18096, HARD_DB
    req(port, "POST", "/__reset", "confirm=RESET", tag="f1-reset")
    _, tok = login(port, "alice", "alice123", tag="f1-login")
    csrf = csrf_of(dbfile, tok)
    b1 = []
    for name, path, body in (("wallet_transfer", "/wallet/transfer", "to=bob&amount=7"),
                             ("change_password", "/change-password", "new_password=zzz999"),
                             ("board_post", "/board", "content=f1-canary")):
        s0 = state(dbfile)
        st, txt, _ = req(port, "GET", path + "?" + body + "&csrf_token=" + csrf,
                         cookie=tok, tag="f1-%s" % name)
        s1 = state(dbfile)
        b1.append({"entry": name, "request": "GET %s?%s&csrf_token=<valid>" % (path, body),
                   "status": st, "state_changed": s0 != s1,
                   "user_diff": diff_users(s0, s1),
                   "messages_before": s0["messages"], "messages_after": s1["messages"],
                   "snippet": txt[:140].replace("\n", " ")})
    out["checks"]["fix1_B1_get_state_change"] = b1
    req(port, "POST", "/__reset", "confirm=RESET", tag="f1-restore")

    # ---- 补测 2：B3 时序修正（先查会话有效性，再测口令）----
    print("[*] fix2: B3 ordering fixed", flush=True)
    req(port, "POST", "/__reset", "confirm=RESET", tag="f2-reset")
    _, tok_v = login(port, "bob", "bob123", tag="f2-login-bob")
    csrf_v = csrf_of(dbfile, tok_v)
    s_pre = state(dbfile)
    st_home_pre, _, _ = req(port, "GET", "/home", cookie=tok_v, tag="f2-home-pre")
    st_pw, txt_pw, _ = req(port, "POST", "/change-password",
                           "csrf_token=%s&new_password=bob9999" % csrf_v, cookie=tok_v,
                           tag="f2-change-password")
    s_post = state(dbfile)                       # 新登录之前取样
    st_home_post, _, _ = req(port, "GET", "/home", cookie=tok_v, tag="f2-home-post")
    st_w, _, _ = req(port, "POST", "/wallet/withdraw",
                     "csrf_token=%s&amount=1" % csrf_v, cookie=tok_v, tag="f2-write-post")
    out["checks"]["fix2_B3_session_after_pw_change"] = {
        "home_before": st_home_pre,
        "change_password_status": st_pw,
        "sessions_row_present_after_pwchange": any(r[0] == tok_v for r in s_post["sessions"]),
        "home_after_old_session": st_home_post,
        "write_after_old_session": st_w,
        "pw_changed_in_db": s_post["users"]["bob"]["pw"] == "bob9999",
        "note": "口令已改，但服务端会话行未删除 → 旧 Cookie 仍可用（会话未随凭据变更轮换）",
    }
    st_old, _ = login(port, "bob", "bob123", tag="f2-oldpw")   # 期望 200=失败页
    st_new, _ = login(port, "bob", "bob9999", tag="f2-newpw")  # 期望 302=成功
    out["checks"]["fix2_B3_login_matrix"] = {"old_password_status": st_old,
                                             "new_password_status": st_new,
                                             "legend": "302=成功跳转 /home，200=失败页"}
    req(port, "POST", "/__reset", "confirm=RESET", tag="f2-restore")

    # ---- 补测 3：//__reset 路径解析实证 ----
    print("[*] fix3: path parsing //__reset", flush=True)
    import urllib.parse as up
    parse_probe = {}
    for p in ("//__reset", "/__reset", "/%5f%5freset", "/__reset/", "/./__reset",
              "/__reset?x=1", "/foo/../__reset"):
        pp = up.urlparse(p)
        parse_probe[p] = {"urlparse_path": pp.path, "urlparse_netloc": pp.netloc}
    out["checks"]["fix3_urlparse_table"] = parse_probe
    path_probe = []
    for target, prt, dbf in (("orig", 18095, ORIG_DB), ("hard", 18096, HARD_DB)):
        if target == "orig":
            req(prt, "GET", "/__reset", tag="f3-pre-orig")
        else:
            req(prt, "POST", "/__reset", "confirm=RESET", tag="f3-pre-hard")
        for p in ("//__reset", "/./__reset", "/foo/../__reset", "/__reset/./", "/__RESET",
                  "/__reset%20", "/__reset%00", "/__reset;", "/__reset?"):
            f0 = fstat(dbf)
            st, txt, _ = req(prt, "GET", p, tag="f3-%s-%s" % (target, p))
            time.sleep(0.2)
            f1 = fstat(dbf)
            path_probe.append({"target": target, "path": p, "status": st,
                               "db_changed": f0["sha256"] != f1["sha256"],
                               "mtime_before": f0["mtime_str"], "mtime_after": f1["mtime_str"],
                               "snippet": txt[:100].replace("\n", " ")})
    out["checks"]["fix3_path_variants"] = path_probe

    # ---- 补测 4：匿名态四入口（自证队长旁证）----
    print("[*] fix4: anonymous matrix", flush=True)
    anon = []
    for name, path, body in (("order_create", "/order/create", "product_id=1&qty=1"),
                             ("order_status", "/order/status", "order_id=2&state=paid"),
                             ("coupon_claim", "/coupon/claim", "code=WELCOME10"),
                             ("wallet_withdraw", "/wallet/withdraw", "amount=100")):
        for target, prt, dbf in (("orig", 18095, ORIG_DB), ("hard", 18096, HARD_DB)):
            s0 = state(dbf)
            st_g, _, _ = req(prt, "GET", path + "?" + body, tag="f4-%s-%s-GET" % (target, name))
            st_p, _, _ = req(prt, "POST", path, body, tag="f4-%s-%s-POST" % (target, name))
            s1 = state(dbf)
            anon.append({"target": target, "entry": name, "anon_GET": st_g,
                         "anon_POST": st_p, "db_changed": s0 != s1})
    out["checks"]["fix4_anonymous_matrix"] = anon

    # ---- 补测 5：A6 二次确认串位置 + 跨站提交（绕过相）----
    print("[*] fix5: reset confirm-channel + cross-site", flush=True)
    port, dbfile = 18096, HARD_DB
    req(port, "POST", "/__reset", "confirm=RESET", tag="f5-pre")
    f5 = []
    for label, path, body, headers in (
            ("confirm_in_body", "/__reset", "confirm=RESET", None),
            ("confirm_in_query_empty_body", "/__reset?confirm=RESET", "", None),
            ("confirm_in_query_only_no_body", "/__reset?confirm=RESET", None, None),
            ("confirm_lowercase", "/__reset", "confirm=reset", None),
            ("confirm_extra_ws", "/__reset", "confirm=%20RESET%20", None),
            ("confirm_dup_param_first", "/__reset", "confirm=RESET&confirm=no", None),
            ("confirm_dup_param_last", "/__reset", "confirm=no&confirm=RESET", None),
            ("cross_site_origin", "/__reset", "confirm=RESET",
             {"Origin": "http://evil.example", "Referer": "http://evil.example/x.html"}),
            ("cross_site_sec_fetch", "/__reset", "confirm=RESET",
             {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate",
              "Sec-Fetch-Dest": "document", "Origin": "http://evil.example"}),
            ("cross_site_text_plain", "/__reset", "confirm=RESET",
             {"Content-Type": "text/plain", "Origin": "http://evil.example"}),
    ):
        f0 = fstat(dbfile)
        st, txt, _ = req(port, "POST", path, body, headers=headers, tag="f5-%s" % label)
        time.sleep(0.25)
        f1 = fstat(dbfile)
        f5.append({"case": label, "request": "POST %s body=%r" % (path, body),
                   "headers": headers, "status": st,
                   "reset_triggered": f0["sha256"] != f1["sha256"],
                   "mtime_before": f0["mtime_str"], "mtime_after": f1["mtime_str"],
                   "snippet": txt[:120].replace("\n", " ")})
    out["checks"]["fix5_reset_confirm_channel"] = f5
    req(port, "POST", "/__reset", "confirm=RESET", tag="f5-restore")

    # ---- 证据文件自身哈希 ----
    out["records"] = REC
    p = os.path.join(HERE, "loop2-verify-supplement-%s.json" % TS)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
    out["meta"]["self_sha256"] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)
    print("[+] wrote %s" % p)
    print("self_sha256 =", hashlib.sha256(open(p, "rb").read()).hexdigest())


if __name__ == "__main__":
    main()
