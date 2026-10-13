#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
target-site-lab —— 本地演练靶场（DVWA 风格），经多轮蓝队加固后剩余少量练习面。

仅依赖 Python 3 标准库；仅监听 127.0.0.1。
启动:  python app.py [端口]          # 默认 8095
重置:  python app.py --reset         # 重建数据库/上传目录到初始状态后启动
       GET  http://127.0.0.1:8095/__reset   （HTTP 一键复位，仅回环可达）
"""

import hashlib
import hmac
import html
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #
HOST = "127.0.0.1"
DEFAULT_PORT = 8095
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "lab.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
# 第八轮修复#1：下载白名单目录——只允许下载 downloads/ 内的文件，app.py 等源码不在此目录
DOWNLOAD_DIR = os.path.join(BASE_DIR, "downloads")
BACKUP_PATH = os.path.join(BASE_DIR, "private", "config.bak")
SECRET_KEY = "lab-secret-key-PLEASE-CHANGE-001"
DEBUG = False
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

# 第七轮修复#7：CORS 白名单——只允许同源（127.0.0.1 + 当前端口）
CORS_ALLOWED_ORIGIN = None  # 运行时根据 server port 动态生成

# 第七轮修复#8：SSRF 仅允许回环且非敏感端口
SSRF_ALLOWED_PORTS = {80, 443, 8080, 8081, 8082, 8090, 8091, 8092,
                       8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100}

# 第八轮修复#2：上传后缀白名单收窄为 .jpg/.png/.txt（去掉 .jpeg/.gif/.pdf）
UPLOAD_ALLOWED_EXT = {".jpg", ".png", ".txt"}

# 第七轮修复#13：登录失败限速
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_SECONDS = 900  # 15 分钟
LOGIN_FAILURES = {}  # username -> {"count": int, "locked_until": float}
LOGIN_LOCK = threading.Lock()

# 第七轮修复#4：订单状态机合法流转
ORDER_TRANSITIONS = {
    "unpaid": {"paid"},
    "paid": {"shipped"},
    "shipped": set(),
}


# --------------------------------------------------------------------------- #
# 数据库
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    role TEXT,
    phone TEXT,
    balance_cents INTEGER
);
CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price_cents INTEGER,
    stock INTEGER
);
CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    item TEXT,
    qty INTEGER,
    amount_cents INTEGER,
    state TEXT
);
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT,
    content TEXT
);
CREATE TABLE coupons (
    code TEXT PRIMARY KEY,
    amount_cents INTEGER
);
CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER,
    username TEXT,
    created_at INTEGER
);
-- 第七轮修复#3：优惠券领取记录，(user_id, code) 唯一约束保证幂等
CREATE TABLE coupon_claims (
    user_id INTEGER,
    code TEXT,
    claimed_at INTEGER,
    PRIMARY KEY (user_id, code)
);
"""


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def reset_database():
    """删库重建 + 清空上传目录 + 重写备份文件。"""
    old_bak = os.path.join(BASE_DIR, "config.bak")
    if os.path.exists(old_bak):
        os.remove(old_bak)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    for ext in ("-wal", "-shm"):
        p = DB_PATH + ext
        if os.path.exists(p):
            os.remove(p)
    if os.path.isdir(UPLOAD_DIR):
        shutil.rmtree(UPLOAD_DIR)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    # 第八轮修复#1：创建下载白名单目录并放入示例文件
    if os.path.isdir(DOWNLOAD_DIR):
        shutil.rmtree(DOWNLOAD_DIR)
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    with open(os.path.join(DOWNLOAD_DIR, "readme.txt"), "w", encoding="utf-8") as fh:
        fh.write("这是下载白名单目录内的示例文件。\n只有 downloads/ 目录下的文件可被 /download 接口下载。\n")
    conn = get_db()
    with conn:
        conn.executescript(SCHEMA)
        # 第七轮修复#13：admin 使用强口令（≥12 位混合）
        conn.executemany(
            "INSERT INTO users(username,password,role,phone,balance_cents)"
            " VALUES (?,?,?,?,?)",
            [
                ("admin", "Lab@Admin2024!Secure#9", "admin",
                 "13900000000", 100000),
                ("demo", "demo123", "user", "13800000001", 50000),
                ("alice", "alice123", "user", "13800000002", 88800),
                ("bob", "bob123", "user", "13800000003", 100),
            ],
        )
        conn.executemany(
            "INSERT INTO products(name,price_cents,stock) VALUES (?,?,?)",
            [("机械键盘", 29900, 50), ("无线鼠标", 9900, 100),
             ("USB-C 数据线", 1900, 500)],
        )
        conn.executemany(
            "INSERT INTO orders(user_id,item,qty,amount_cents,state)"
            " VALUES (?,?,?,?,?)",
            [
                (2, "机械键盘", 1, 29900, "paid"),
                (3, "无线鼠标", 1, 9900, "unpaid"),
                (2, "USB-C 数据线", 1, 1900, "shipped"),
            ],
        )
        conn.execute(
            "INSERT INTO messages(author,content) VALUES (?,?)",
            ("admin", "欢迎来到留言板。"),
        )
        conn.execute(
            "INSERT INTO coupons(code,amount_cents) VALUES (?,?)",
            ("WELCOME10", 1000),
        )
    conn.close()
    write_backup_file()
    # 第七轮修复#13：复位时清空登录失败记录
    with LOGIN_LOCK:
        LOGIN_FAILURES.clear()
    print("[reset] 数据库与上传目录已恢复初始状态")


def write_backup_file():
    os.makedirs(os.path.dirname(BACKUP_PATH), exist_ok=True)
    with open(BACKUP_PATH, "w", encoding="utf-8") as fh:
        fh.write(
            "# lab config backup (moved out of web root)\n"
            f"SECRET_KEY={SECRET_KEY}\n"
            f"DB_PATH={DB_PATH}\n"
            "DB_USER=root\nDB_PASSWORD=root123456\n"
            "DEBUG=false\n"
        )


def ensure_initialized():
    if not os.path.exists(DB_PATH):
        reset_database()
    else:
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
        write_backup_file()


# --------------------------------------------------------------------------- #
# 会话 token（第五轮修复：密码学随机 + 防会话固定）
# --------------------------------------------------------------------------- #
def make_token():
    return secrets.token_urlsafe(32)


def create_session(conn, user):
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
    token = make_token()
    conn.execute(
        "INSERT OR REPLACE INTO sessions(token,user_id,username,created_at)"
        " VALUES (?,?,?,?)",
        (token, user["id"], user["username"], int(time.time())))
    conn.commit()
    return token


def yuan(cents):
    try:
        return f"{int(cents) / 100:.2f}"
    except Exception:
        return str(cents)


PAGE = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>{title}</title><style>
body{{font-family:"Segoe UI","Microsoft YaHei",sans-serif;margin:0;background:#f6f7f9}}
nav{{background:#111827;color:#fff;padding:10px 22px}}
nav a{{color:#9ca3af;margin-right:14px;text-decoration:none}}
.wrap{{max-width:900px;margin:24px auto;background:#fff;padding:24px 30px;border-radius:8px}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:6px 10px}}
pre{{background:#0b1020;color:#a7f3d0;padding:12px;border-radius:6px;overflow:auto}}
input,button{{padding:7px 10px;margin:4px 0}}
.warn{{background:#fee2e2;border:1px solid #ef4444;color:#991b1b;padding:8px 12px;border-radius:6px}}
a{{color:#2563eb}}
</style></head><body><nav>
<b>靶场 LAB</b> &nbsp;
<a href="/">首页</a><a href="/search?q=">搜索</a><a href="/board">留言板</a>
<a href="/upload">上传</a><a href="/admin/users">用户管理</a>
<a href="/admin/orders">订单管理</a><a href="/debug">debug</a>
{navright}
</nav><div class="wrap">{body}</div></body></html>"""


def page(title, body, username=None):
    navright = (f'<span style="float:right">{username} | '
                f'<a href="/home">钱包</a> | <a href="/logout">退出</a></span>'
                if username else
                '<span style="float:right"><a href="/">登录</a></span>')
    return PAGE.format(title=title, body=body, navright=navright)


# --------------------------------------------------------------------------- #
# HTTP 处理器
# --------------------------------------------------------------------------- #
class LabHandler(BaseHTTPRequestHandler):
    server_version = "LabHTTP/0.2"

    # -- 基础输出 -- #
    def _send(self, code, content_type, body, extra_headers=None,
              set_cookie=None, clear_cookie=False):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # 安全响应头（第二轮/第三轮修复）
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy",
                         "geolocation=(), microphone=(), camera=()")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; "
                         "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                         "style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; object-src 'none'; "
                         "base-uri 'self'")
        self.send_header("Strict-Transport-Security",
                         "max-age=63072000; includeSubDomains")
        # 第七轮修复#7：CORS 白名单——只反射同源 Origin
        origin = self.headers.get("Origin")
        if origin:
            port = self.server.server_address[1]
            allowed = f"http://127.0.0.1:{port}"
            if origin == allowed:
                self.send_header("Access-Control-Allow-Origin", allowed)
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.send_header("Access-Control-Allow-Methods",
                                 "GET,POST,OPTIONS")
        if set_cookie:
            self.send_header("Set-Cookie",
                             f"token={set_cookie}; Path=/; HttpOnly; SameSite=Lax")
        if clear_cookie:
            self.send_header("Set-Cookie", "token=; Path=/; Max-Age=0")
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def html(self, code, html_str, **kw):
        self._send(code, "text/html; charset=utf-8", html_str, **kw)

    def json(self, code, obj, **kw):
        self._send(code, "application/json; charset=utf-8",
                   json.dumps(obj, ensure_ascii=False), **kw)

    def redirect(self, location, **kw):
        self._send(302, "text/html; charset=utf-8", b"",
                   extra_headers=[("Location", location)], **kw)

    def do_OPTIONS(self):
        self._send(204, "text/plain", b"")

    # -- 工具 -- #
    def parsed(self):
        p = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        return p.path, {k: v[0] for k, v in qs.items()}

    def form(self):
        path, q = self.parsed()
        data = {}
        length = int(self.headers.get("Content-Length") or 0)
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if length and ctype == "application/x-www-form-urlencoded":
            raw = self.rfile.read(length).decode("utf-8", "replace")
            data.update({k: v[0] for k, v in
                         urllib.parse.parse_qs(raw,
                                               keep_blank_values=True).items()})
        data.update(q)
        return path, data

    def _session_token(self):
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            return cookie["token"].value if "token" in cookie else None
        except Exception:
            return None

    # 第七轮修复#5：CSRF token = HMAC-SHA256(SECRET_KEY, session_token)
    def csrf_token(self):
        tok = self._session_token()
        if not tok:
            return ""
        return hmac.new(SECRET_KEY.encode(), tok.encode(),
                        hashlib.sha256).hexdigest()

    def verify_csrf(self, provided):
        expected = self.csrf_token()
        if not expected or not provided:
            return False
        return hmac.compare_digest(expected, provided)

    def current_user(self, conn):
        tok = self._session_token()
        if not tok:
            return None
        row = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id"
            " WHERE s.token=?", (tok,)).fetchone()
        return row

    def require_user(self, conn):
        user = self.current_user(conn)
        if user is None:
            self.redirect("/?err=login")
            return None
        return user

    # -- 入口 -- #
    def do_GET(self):
        try:
            self.route()
        except Exception:
            self._traceback()

    def do_POST(self):
        try:
            self.route()
        except Exception:
            self._traceback()

    def do_HEAD(self):
        try:
            self.route()
        except Exception:
            self._traceback()

    def _traceback(self):
        # 第二轮修复：堆栈只写本地日志，响应只回通用错误页
        tb = traceback.format_exc()
        try:
            with open(os.path.join(BASE_DIR, "lab_errors.log"),
                      "a", encoding="utf-8") as fh:
                fh.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                         f"{self.command} {self.path}\n{tb}\n")
        except Exception:
            pass
        try:
            self.html(500, page("500",
                '<h1>服务器内部错误</h1>'
                '<p>请求处理失败，请稍后重试。</p>'))
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # 路由
    # ------------------------------------------------------------------ #
    def route(self):
        path, q = self.parsed()

        if path == "/":
            return self.index()
        if path == "/login":
            return self.login()
        if path == "/logout":
            return self.logout()
        if path == "/home":
            return self.home()
        if path == "/search":
            return self.search_html(q.get("q", ""))
        if path == "/api/search":
            return self.api_search(q.get("q", ""))
        if path == "/api/order":
            return self.api_order(q.get("id"))
        if path == "/api/profile":
            return self.api_profile(q.get("id"))
        if path == "/greet":
            return self.greet(q.get("name", ""))
        if path == "/ping":
            return self.ping(q.get("host", ""))
        if path == "/download":
            return self.download(q.get("file", ""))
        if path == "/board":
            return self.board()
        if path == "/forgot":
            return self.forgot(q.get("username", ""))
        if path == "/fetch":
            return self.fetch(q.get("url", ""))
        if path == "/upload":
            return self.upload()
        if path.startswith("/uploads/"):
            return self.serve_upload(path[len("/uploads/"):])
        if path == "/order/create":
            return self.order_create()
        if path == "/order/status":
            return self.order_status()
        if path == "/coupon/claim":
            return self.coupon_claim()
        if path == "/wallet/withdraw":
            return self.wallet_withdraw()
        if path == "/wallet/transfer":
            return self.wallet_transfer()
        if path == "/change-password":
            return self.change_password()
        if path == "/admin/users":
            return self.admin_users()
        if path == "/admin/orders":
            return self.admin_orders()
        if path == "/debug":
            return self.debug_page()
        if path == "/__reset":
            return self.reset_endpoint()

        self.html(404, page("404", "<h1>404</h1>"))

    # ------------------------------------------------------------------ #
    # 页面
    # ------------------------------------------------------------------ #
    def index(self):
        path, q = self.parsed()
        err = q.get("err")
        msg = '<div class="warn">请先登录</div>' if err == "login" else ""
        body = f"""
<h1>靶场商城 LAB</h1>{msg}
<form method="post" action="/login">
用户名 <input name="username"> 密码 <input type="password" name="password">
<button>登录</button></form>
<p>测试账号：<code>admin/Lab@Admin2024!Secure#9</code>、
<code>demo/demo123</code>、<code>alice/alice123</code>、<code>bob/bob123</code></p>
<p>（登录有失败限速：连续 5 次失败锁定 15 分钟）</p>
<h3>功能入口</h3>
<ul>
<li><a href="/search?q=">搜索</a> ｜ <a href="/api/search?q=k">JSON 搜索</a></li>
<li><a href="/greet?name=world">/greet</a> ｜ <a href="/ping?host=127.0.0.1">/ping</a></li>
<li><a href="/download?file=README.md">/download</a> ｜ <a href="/board">留言板</a></li>
<li><a href="/fetch?url=http://127.0.0.1:{self.server.server_address[1]}/">/fetch</a>（仅回环非敏感端口）</li>
<li><a href="/upload">文件上传</a>（仅图片/文本/PDF）</li>
<li>后台管理（需 admin）：<a href="/admin/users">用户</a> ｜
<a href="/admin/orders">订单</a></li>
<li>一键复位：<a href="/__reset">/__reset</a></li>
</ul>"""
        conn = get_db()
        try:
            self.html(200, page("靶场", body,
                                (self.current_user(conn) or {})
                                .get("username")))
        finally:
            conn.close()

    # 第七轮修复#13：登录参数化 + 失败限速
    def login(self):
        if self.command != "POST":
            return self.redirect("/")
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = {k: v[0] for k, v in
                urllib.parse.parse_qs(raw, keep_blank_values=True).items()}
        username = form.get("username", "")
        password = form.get("password", "")

        # 限速检查
        now = time.time()
        with LOGIN_LOCK:
            rec = LOGIN_FAILURES.get(username, {})
            if rec.get("locked_until", 0) > now:
                self.html(429, page("账号锁定",
                    '<h1>登录失败次数过多</h1>'
                    '<p>请稍后再试（锁定 15 分钟）。</p>'
                    '<p><a href="/">返回</a></p>'))
                return

        conn = get_db()
        try:
            # 参数化查询，杜绝 SQL 注入
            row = conn.execute(
                "SELECT id,username,password,role,phone,balance_cents"
                " FROM users WHERE username=? AND password=?",
                (username, password)).fetchone()
            if row is None:
                # 记录失败
                with LOGIN_LOCK:
                    rec = LOGIN_FAILURES.setdefault(
                        username, {"count": 0, "locked_until": 0})
                    rec["count"] += 1
                    if rec["count"] >= LOGIN_MAX_FAILURES:
                        rec["locked_until"] = now + LOGIN_LOCK_SECONDS
                        rec["count"] = 0
                self.html(200, page("登录失败",
                    '<h1>登录失败</h1><p>用户名或密码错误。</p>'
                    '<p><a href="/">返回</a></p>'))
                return
            # 登录成功：清空失败记录
            with LOGIN_LOCK:
                LOGIN_FAILURES.pop(username, None)
            token = create_session(conn, row)
            self.redirect("/home", set_cookie=token)
        finally:
            conn.close()

    def logout(self):
        self.redirect("/", clear_cookie=True)

    def home(self):
        conn = get_db()
        try:
            user = self.require_user(conn)
            if not user:
                return
            csrf = self.csrf_token()
            body = f"""
<h1>我的钱包</h1>
<table>
<tr><th>ID</th><td>{user['id']}</td></tr>
<tr><th>用户名</th><td>{user['username']}</td></tr>
<tr><th>角色</th><td>{user['role']}</td></tr>
<tr><th>手机号</th><td>{user['phone']}</td></tr>
<tr><th>余额(分)</th><td id="bal">{user['balance_cents']}</td></tr>
</table>
<h3>业务操作</h3>
<ul>
<li>领券（每券限领一次）：
<a href="/coupon/claim?code=WELCOME10">/coupon/claim?code=WELCOME10</a></li>
<li>下单（价格由服务端按商品定价，数量 1-100）：
<form method="post" action="/order/create">
product_id <input name="product_id" value="1">
qty <input name="qty" value="1">
<button>下单</button></form></li>
<li>提现（原子扣款）：
<form method="post" action="/wallet/withdraw">
amount <input name="amount" value="1000"><button>提现</button></form></li>
<li>转账（需 CSRF token）：
<form method="post" action="/wallet/transfer">
<input type="hidden" name="csrf_token" value="{csrf}">
to(用户名) <input name="to" value="bob">
amount <input name="amount" value="100"><button>转账</button></form></li>
<li>改密（需 CSRF token）：
<form method="post" action="/change-password">
<input type="hidden" name="csrf_token" value="{csrf}">
new_password <input name="new_password"><button>改密</button></form></li>
<li>改订单状态（仅允许 unpaid→paid→shipped）：
<form method="get" action="/order/status">
order_id <input name="order_id" value="2">
state <input name="state" value="paid"><button>更新状态</button></form></li>
</ul>"""
            self.html(200, page("钱包", body, user["username"]))
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 搜索（第二轮修复：SQL 参数化）
    # ------------------------------------------------------------------ #
    def api_search(self, q):
        conn = get_db()
        try:
            sql = "SELECT id,name,price_cents FROM products WHERE name LIKE ?"
            rows = [tuple(r) for r in
                    conn.execute(sql, (f"%{q}%",)).fetchall()]
            self.json(200, {"sql": sql, "results": rows})
        finally:
            conn.close()

    # 第七轮修复#6：搜索页输出 html.escape，杜绝反射型 XSS
    def search_html(self, q):
        conn = get_db()
        try:
            sql = "SELECT id,name,price_cents FROM products WHERE name LIKE ?"
            rows = conn.execute(sql, (f"%{q}%",)).fetchall()
            trs = "".join(
                f"<tr><td>{r['id']}</td><td>{html.escape(r['name'])}</td>"
                f"<td>{yuan(r['price_cents'])}</td></tr>" for r in rows)
            body = (f"<h1>搜索：{html.escape(q)}</h1>"
                    f"<table><tr><th>id</th><th>name</th><th>price</th></tr>"
                    f"{trs}</table>"
                    f'<p><form action="/search">关键词 <input name="q">'
                    f'<button>搜</button></form></p>')
            self.html(200, page("搜索", body))
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 第六轮修复：水平越权已加属主校验
    # ------------------------------------------------------------------ #
    def api_order(self, oid):
        conn = get_db()
        try:
            user = self.require_user(conn)
            if not user:
                return
            row = conn.execute(
                "SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
            if row is None or row["user_id"] != user["id"]:
                self.json(404, {"error": "not found"})
                return
            self.json(200, dict(row))
        finally:
            conn.close()

    def api_profile(self, uid):
        conn = get_db()
        try:
            user = self.require_user(conn)
            if not user:
                return
            row = conn.execute(
                "SELECT id,username,role,phone,balance_cents"
                " FROM users WHERE id=?", (uid,)).fetchone()
            if row is None or row["id"] != user["id"]:
                self.json(404, {"error": "not found"})
                return
            self.json(200, dict(row))
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 第七轮修复#10：SSTI 已禁用 eval，改为固定字符串输出
    # ------------------------------------------------------------------ #
    def greet(self, name):
        body = (f"<h1>Hello, {html.escape(name)}</h1>"
                "<p>（模板引擎 eval 已禁用，{{7*7}} 不会被执行）</p>")
        self.html(200, page("greet", body))

    # ------------------------------------------------------------------ #
    # 第七轮修复#11：命令注入已禁用 shell 拼接，改用参数数组 + 输入校验
    # ------------------------------------------------------------------ #
    def ping(self, host):
        if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', host):
            self.html(400, page("无效主机",
                "<h1>主机名无效</h1><p>只允许字母、数字、点、连字符。</p>"))
            return
        try:
            out = subprocess.run(["ping", "-n", "1", host],
                                 shell=False, capture_output=True,
                                 text=True, timeout=15)
            text = out.stdout + out.stderr
        except Exception:
            text = "ping 执行失败"
        body = f"<h1>ping {html.escape(host)}</h1><pre>{html.escape(text)}</pre>"
        self.html(200, page("ping", body))

    # ------------------------------------------------------------------ #
    # 第七轮修复#12：路径穿越已用 realpath 限制在 BASE_DIR 内
    # ------------------------------------------------------------------ #
    def download(self, filename):
        # 第八轮修复#1：下载白名单目录——只允许 downloads/ 内的文件
        if not filename:
            self.html(404, page("404", "<h1>404</h1>"))
            return
        # urllib.parse.unquote 先解码 %2f 等编码，再 realpath 归一化，防止编码绕过
        decoded = urllib.parse.unquote(filename)
        requested = os.path.realpath(os.path.join(DOWNLOAD_DIR, decoded))
        allowed_real = os.path.realpath(DOWNLOAD_DIR)
        if not (requested == allowed_real or
                requested.startswith(allowed_real + os.sep)):
            self.html(403, page("403",
                "<h1>禁止访问</h1><p>路径越出允许目录。</p>"))
            return
        if not os.path.isfile(requested):
            self.html(404, page("404", "<h1>404</h1>"))
            return
        with open(requested, "rb") as fh:
            data = fh.read()
        self._send(200, "application/octet-stream", data, extra_headers=[
            ("Content-Disposition",
             f'attachment; filename="{os.path.basename(decoded) or "file"}"')])

    # ------------------------------------------------------------------ #
    # 第七轮修复#6：留言板输出 html.escape，杜绝存储型 XSS
    # ------------------------------------------------------------------ #
    def board(self):
        conn = get_db()
        try:
            user = self.current_user(conn)
            if self.command == "POST":
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length).decode("utf-8", "replace")
                form = {k: v[0] for k, v in
                        urllib.parse.parse_qs(raw,
                                             keep_blank_values=True).items()}
                content = form.get("content", "")
                author = user["username"] if user else "anonymous"
                conn.execute("INSERT INTO messages(author,content) VALUES(?,?)",
                             (author, content))
                conn.commit()
                self.redirect("/board")
                return
            rows = conn.execute("SELECT * FROM messages ORDER BY id").fetchall()
            items = "".join(
                f"<tr><td>{r['id']}</td><td>{html.escape(r['author'])}</td>"
                f"<td>{html.escape(r['content'])}</td></tr>" for r in rows)
            body = f"""
<h1>留言板</h1>
<table><tr><th>id</th><th>author</th><th>content</th></tr>{items}</table>
<form method="post" action="/board">
<textarea name="content" rows="4" cols="60"></textarea><br>
<button>发表</button></form>"""
            self.html(200, page("留言板", body,
                                user["username"] if user else None))
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # E2 Host 头注入（保留为练习面，未在本轮清单中）
    # ------------------------------------------------------------------ #
    def forgot(self, username):
        host = (self.headers.get("X-Forwarded-Host")
                or self.headers.get("Host") or "127.0.0.1")
        token = hashlib.md5(username.encode()).hexdigest()
        link = f"http://{host}/reset?user={urllib.parse.quote(username)}&token={token}"
        body = (f"<h1>找回密码</h1><p>已为用户 <b>{html.escape(username)}</b> 生成重置链接：</p>"
                f"<pre>{html.escape(link)}</pre>")
        self.html(200, page("forgot", body))

    # ------------------------------------------------------------------ #
    # 第七轮修复#8：SSRF 限制回环 + 非敏感端口
    # ------------------------------------------------------------------ #
    def fetch(self, url):
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            self.html(400, page("URL 无效", "<h1>URL 格式错误</h1>"))
            return
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
            self.html(403, page("SSRF",
                '<h1>403</h1><p>仅允许 http://127.0.0.1 开头的 URL。</p>'))
            return
        port = parsed.port or 80
        allowed = SSRF_ALLOWED_PORTS | {self.server.server_address[1]}
        if port not in allowed:
            self.html(403, page("SSRF",
                f'<h1>403</h1><p>端口 {port} 不在允许列表中。</p>'))
            return
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = resp.read()
                ctype = resp.headers.get("Content-Type",
                                         "application/octet-stream")
        except Exception:
            self.html(502, page("fetch error",
                                "<h1>拉取失败</h1><p>目标不可达或响应异常。</p>"))
            return
        self._send(200, ctype, data)

    # ------------------------------------------------------------------ #
    # 第七轮修复#9：文件上传后缀白名单 + 文件名清洗 + 禁止执行
    # ------------------------------------------------------------------ #
    def upload(self):
        if self.command != "POST":
            body = """
<h1>文件上传</h1>
<form method="post" action="/upload" enctype="multipart/form-data">
<input type="file" name="file"><button>上传</button></form>
<p>允许类型：jpg / png / txt（后缀白名单 + MIME 魔数双重校验），最大 5MB。</p>
<p>上传后位于 /uploads/&lt;文件名&gt;，以附件方式下载（不会被浏览器执行）。</p>"""
            self.html(200, page("上传", body))
            return

        ctype = self.headers.get("Content-Type", "")
        m = re.search(r"boundary=([^;]+)", ctype)
        if not m:
            self.html(400, page("400", "<h1>不是 multipart 表单</h1>"))
            return
        boundary = m.group(1).strip().strip('"')
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD_BYTES:
            self.html(413, page("413", "<h1>文件过大</h1>"))
            return
        body = self.rfile.read(length)
        saved = []
        rejected = []
        for name, filename, content in self._parse_multipart(body, boundary):
            if name != "file" or not filename:
                continue
            # 文件名清洗：只取 basename，防止路径穿越
            safe_name = os.path.basename(filename)
            ext = os.path.splitext(safe_name)[1].lower()
            # 第八轮修复#2：后缀白名单
            if ext not in UPLOAD_ALLOWED_EXT:
                rejected.append((filename, "后缀不在白名单"))
                continue
            # 第八轮修复#2：MIME 魔数校验——扩展名与实际内容必须匹配
            if not self._check_mime(ext, content):
                rejected.append((filename, "文件内容与扩展名不匹配"))
                continue
            dest = os.path.join(UPLOAD_DIR, safe_name)
            with open(dest, "wb") as fh:
                fh.write(content)
            saved.append(safe_name)
        # 第八轮修复#2：有被拒绝的文件时返回 400（而非 200）
        status = 400 if rejected else 200
        msg = ""
        if saved:
            items = "".join(f'<li><a href="/uploads/{urllib.parse.quote(u)}">{html.escape(u)}</a></li>'
                            for u in saved)
            msg += f"<h1>已上传</h1><ul>{items}</ul>"
        if rejected:
            reasons = "".join(f"<li>{html.escape(f)}：{html.escape(r)}</li>"
                              for f, r in rejected)
            msg += f'<div class="warn"><b>已拒绝：</b><ul>{reasons}</ul></div>'
        if not msg:
            msg = "<h1>未收到文件</h1>"
        self.html(status, page("上传结果", msg))

    @staticmethod
    def _parse_multipart(body, boundary):
        delim = b"--" + boundary.encode()
        for part in body.split(delim):
            if b"Content-Disposition" not in part:
                continue
            head, _, content = part.partition(b"\r\n\r\n")
            if content.endswith(b"\r\n"):
                content = content[:-2]
            head_text = head.decode("utf-8", "replace")
            n = re.search(r'name="([^"]*)"', head_text)
            f = re.search(r'filename="([^"]*)"', head_text)
            yield (n.group(1) if n else "",
                   f.group(1) if f else "", content)

    @staticmethod
    def _check_mime(ext, content):
        """第八轮修复#2：MIME 魔数校验——扩展名与文件实际内容必须匹配。"""
        if ext == ".jpg":
            return len(content) >= 3 and content[:3] == b"\xff\xd8\xff"
        if ext == ".png":
            return len(content) >= 8 and content[:8] == b"\x89PNG\r\n\x1a\n"
        if ext == ".txt":
            # 文本文件：可打印字符（含换行/制表）占比 > 90%，且能被 UTF-8 解码
            if not content:
                return True
            try:
                content.decode("utf-8")
            except UnicodeDecodeError:
                return False
            printable = sum(1 for b in content
                            if 32 <= b <= 126 or b in (9, 10, 13))
            return printable / len(content) > 0.9
        return False

    def serve_upload(self, name):
        # 第七轮修复#9：所有上传文件以 application/octet-stream + attachment 返回，
        # 浏览器不会将其当作 HTML/JS 执行
        safe_name = os.path.basename(urllib.parse.unquote(name))
        path = os.path.join(UPLOAD_DIR, safe_name)
        if not os.path.isfile(path):
            self.html(404, page("404", "<h1>404</h1>"))
            return
        with open(path, "rb") as fh:
            data = fh.read()
        self._send(200, "application/octet-stream", data, extra_headers=[
            ("Content-Disposition", f'attachment; filename="{safe_name}"')])

    # ------------------------------------------------------------------ #
    # 第七轮修复#1：下单——服务端查价、校验数量、校验余额
    # ------------------------------------------------------------------ #
    def order_create(self):
        path, form = self.form()
        conn = get_db()
        try:
            user = self.require_user(conn)
            if not user:
                return
            product_id = form.get("product_id", "")
            try:
                qty = int(form.get("qty", "0"))
            except ValueError:
                qty = 0
            # 数量校验：1-100，拒绝负数/零/超大
            if qty < 1 or qty > 100:
                self.html(400, page("数量无效",
                    "<h1>数量无效</h1><p>数量必须在 1-100 之间。</p>",
                    user["username"]))
                return
            # 服务端按 product_id 查价，不信任客户端 price
            product = conn.execute(
                "SELECT id,name,price_cents FROM products WHERE id=?",
                (product_id,)).fetchone()
            if not product:
                self.html(404, page("商品不存在",
                    "<h1>商品不存在</h1>", user["username"]))
                return
            amount = product["price_cents"] * qty
            # 余额校验
            if user["balance_cents"] < amount:
                self.html(400, page("余额不足",
                    f"<h1>余额不足</h1><p>需要 {amount} 分，当前 {user['balance_cents']} 分。</p>",
                    user["username"]))
                return
            # 扣款 + 建单（同一事务）
            conn.execute("UPDATE users SET balance_cents = balance_cents - ? WHERE id=?",
                         (amount, user["id"]))
            cur = conn.execute(
                "INSERT INTO orders(user_id,item,qty,amount_cents,state)"
                " VALUES (?,?,?,?,?)",
                (user["id"], product["name"], qty, amount, "unpaid"))
            conn.commit()
            new_balance = user["balance_cents"] - amount
            self.html(200, page("下单结果",
                f"<h1>下单成功</h1><p>订单号 {cur.lastrowid}，商品 {product['name']}，"
                f"数量 {qty}，金额 {amount} 分，当前余额 {new_balance} 分</p>"
                '<p><a href="/home">返回钱包</a></p>',
                user["username"]))
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 第七轮修复#4：订单状态机——只允许 unpaid→paid→shipped
    # ------------------------------------------------------------------ #
    def order_status(self):
        path, form = self.form()
        conn = get_db()
        try:
            user = self.require_user(conn)
            if not user:
                return
            oid = form.get("order_id", "")
            new_state = form.get("state", "")
            order = conn.execute(
                "SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
            if order is None:
                self.html(404, page("404", "<h1>订单不存在</h1>",
                                    user["username"]))
                return
            # 属主校验（admin 可操作任意订单）
            if order["user_id"] != user["id"] and user["role"] != "admin":
                self.html(404, page("404", "<h1>订单不存在</h1>",
                                    user["username"]))
                return
            current = order["state"]
            allowed = ORDER_TRANSITIONS.get(current, set())
            if new_state not in allowed:
                self.html(400, page("非法状态流转",
                    f"<h1>非法状态流转</h1><p>当前状态：{current}，"
                    f"不允许直接改为 {new_state}。"
                    f"合法流转：unpaid → paid → shipped。</p>",
                    user["username"]))
                return
            conn.execute("UPDATE orders SET state=? WHERE id=?",
                         (new_state, oid))
            conn.commit()
            self.html(200, page("状态已更新",
                f"<h1>订单 {oid} 状态已从 {current} 改为 {new_state}</h1>"
                '<p><a href="/home">返回</a></p>', user["username"]))
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 第七轮修复#3：优惠券幂等——同一用户同一券只能领一次
    # ------------------------------------------------------------------ #
    def coupon_claim(self):
        path, q = self.form()
        conn = get_db()
        try:
            user = self.require_user(conn)
            if not user:
                return
            code = q.get("code", "")
            coupon = conn.execute(
                "SELECT * FROM coupons WHERE code=?", (code,)).fetchone()
            if not coupon:
                self.html(404, page("券不存在", "<h1>券不存在</h1>",
                                    user["username"]))
                return
            # 幂等：尝试插入领取记录，唯一约束冲突说明已领过
            try:
                conn.execute(
                    "INSERT INTO coupon_claims(user_id,code,claimed_at)"
                    " VALUES (?,?,?)",
                    (user["id"], code, int(time.time())))
            except sqlite3.IntegrityError:
                self.html(200, page("领券失败",
                    "<h1>该券已领取过</h1><p>每张券每人限领一次。</p>"
                    '<p><a href="/home">返回</a></p>', user["username"]))
                return
            conn.execute(
                "UPDATE users SET balance_cents = balance_cents + ? WHERE id=?",
                (coupon["amount_cents"], user["id"]))
            conn.commit()
            new_balance = conn.execute(
                "SELECT balance_cents FROM users WHERE id=?",
                (user["id"],)).fetchone()["balance_cents"]
            self.html(200, page("领券成功",
                f"<h1>领取成功 +{coupon['amount_cents']} 分</h1>"
                f"<p>当前余额 {new_balance} 分（每券限领一次）</p>"
                '<p><a href="/home">返回</a></p>', user["username"]))
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 第七轮修复#2：提现原子化——单条 UPDATE 带余额条件，杜绝竞态
    # ------------------------------------------------------------------ #
    def wallet_withdraw(self):
        path, form = self.form()
        conn = get_db()
        try:
            user = self.require_user(conn)
            if not user:
                return
            try:
                amount = int(form.get("amount", "0"))
            except ValueError:
                amount = 0
            if amount <= 0:
                self.html(400, page("金额无效",
                    "<h1>金额无效</h1><p>提现金额必须大于 0。</p>",
                    user["username"]))
                return
            # 原子扣款：UPDATE 自带 balance_cents >= amount 条件，
            # 数据库行锁保证并发下不会扣成负数
            cur = conn.execute(
                "UPDATE users SET balance_cents = balance_cents - ?"
                " WHERE id=? AND balance_cents >= ?",
                (amount, user["id"], amount))
            conn.commit()
            if cur.rowcount == 0:
                self.html(200, page("提现失败",
                    "<h1>余额不足</h1>"
                    '<p><a href="/home">返回</a></p>', user["username"]))
                return
            left = conn.execute(
                "SELECT balance_cents FROM users WHERE id=?",
                (user["id"],)).fetchone()["balance_cents"]
            self.html(200, page("提现成功",
                f"<h1>提现 {amount} 分成功</h1><p>剩余 {left} 分</p>"
                '<p><a href="/home">返回</a></p>', user["username"]))
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 第七轮修复#5：转账需校验 CSRF token
    # ------------------------------------------------------------------ #
    def wallet_transfer(self):
        path, form = self.form()
        conn = get_db()
        try:
            user = self.require_user(conn)
            if not user:
                return
            if not self.verify_csrf(form.get("csrf_token", "")):
                self.html(403, page("CSRF 校验失败",
                    "<h1>请求被拒绝</h1><p>CSRF token 无效或缺失。</p>",
                    user["username"]))
                return
            to_name = form.get("to", "")
            try:
                amount = int(form.get("amount", "0"))
            except ValueError:
                amount = 0
            if amount <= 0:
                self.html(400, page("金额无效",
                    "<h1>金额无效</h1>", user["username"]))
                return
            target = conn.execute(
                "SELECT * FROM users WHERE username=?", (to_name,)).fetchone()
            if not target:
                self.html(404, page("目标不存在",
                    "<h1>收款人不存在</h1>", user["username"]))
                return
            if target["id"] == user["id"]:
                self.html(400, page("不能给自己转账",
                    "<h1>不能给自己转账</h1>", user["username"]))
                return
            # 原子扣款（带余额条件）
            cur = conn.execute(
                "UPDATE users SET balance_cents = balance_cents - ?"
                " WHERE id=? AND balance_cents >= ?",
                (amount, user["id"], amount))
            if cur.rowcount == 0:
                conn.rollback()
                self.html(400, page("余额不足",
                    "<h1>余额不足</h1>", user["username"]))
                return
            conn.execute(
                "UPDATE users SET balance_cents = balance_cents + ? WHERE id=?",
                (amount, target["id"]))
            conn.commit()
            self.html(200, page("转账成功",
                f"<h1>已向 {html.escape(to_name)} 转账 {amount} 分</h1>",
                user["username"]))
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 第七轮修复#5：改密需校验 CSRF token
    # ------------------------------------------------------------------ #
    def change_password(self):
        path, form = self.form()
        conn = get_db()
        try:
            user = self.require_user(conn)
            if not user:
                return
            if self.command == "GET" and not form.get("new_password"):
                csrf = self.csrf_token()
                body = f"""
<h1>修改密码</h1>
<form method="post" action="/change-password">
<input type="hidden" name="csrf_token" value="{csrf}">
新密码 <input name="new_password"><button>提交</button></form>"""
                self.html(200, page("改密", body, user["username"]))
                return
            if not self.verify_csrf(form.get("csrf_token", "")):
                self.html(403, page("CSRF 校验失败",
                    "<h1>请求被拒绝</h1><p>CSRF token 无效或缺失。</p>",
                    user["username"]))
                return
            new_pw = form.get("new_password", "")
            if len(new_pw) < 6:
                self.html(400, page("密码过短",
                    "<h1>密码至少 6 位</h1>", user["username"]))
                return
            conn.execute("UPDATE users SET password=? WHERE id=?",
                         (new_pw, user["id"]))
            conn.commit()
            self.html(200, page("改密成功",
                "<h1>密码已修改</h1>", user["username"]))
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 第六轮修复：垂直越权已加角色校验，后台不显示明文密码
    # ------------------------------------------------------------------ #
    def admin_users(self):
        conn = get_db()
        try:
            user = self.require_user(conn)
            if not user:
                return
            if user["role"] != "admin":
                self.html(404, page("404", "<h1>404</h1>"))
                return
            rows = conn.execute("SELECT * FROM users").fetchall()
            trs = "".join(
                f"<tr><td>{r['id']}</td><td>{html.escape(r['username'])}</td>"
                f"<td>{html.escape(r['role'])}</td>"
                f"<td>{r['balance_cents']}</td></tr>" for r in rows)
            self.html(200, page("用户管理",
                f"<h1>/admin/users</h1><p>当前角色：{user['role']}</p>"
                f"<table><tr><th>id</th><th>用户名</th>"
                f"<th>角色</th><th>余额</th></tr>{trs}</table>",
                user["username"]))
        finally:
            conn.close()

    def admin_orders(self):
        conn = get_db()
        try:
            user = self.require_user(conn)
            if not user:
                return
            if user["role"] != "admin":
                self.html(404, page("404", "<h1>404</h1>"))
                return
            rows = conn.execute("SELECT * FROM orders").fetchall()
            trs = "".join(
                f"<tr><td>{r['id']}</td><td>{r['user_id']}</td>"
                f"<td>{html.escape(r['item'])}</td><td>{r['qty']}</td>"
                f"<td>{r['amount_cents']}</td>"
                f"<td>{html.escape(r['state'])}</td></tr>"
                for r in rows)
            self.html(200, page("订单管理",
                f"<h1>/admin/orders</h1><p>当前角色：{user['role']}</p>"
                f"<table><tr><th>id</th><th>user_id</th><th>商品</th>"
                f"<th>数量</th><th>金额</th><th>状态</th></tr>{trs}</table>",
                user["username"]))
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # /debug（第四轮修复：仅 admin 可访问）
    # ------------------------------------------------------------------ #
    def debug_page(self):
        conn = get_db()
        try:
            user = self.require_user(conn)
            if not user:
                return
            if user["role"] != "admin":
                self.html(403, page("403",
                    "<h1>403</h1><p>仅管理员可访问。</p>",
                    user["username"]))
                return
            import platform
            info = {
                "DEBUG": DEBUG,
                "SECRET_KEY": SECRET_KEY,
                "DB_PATH": DB_PATH,
                "BASE_DIR": BASE_DIR,
                "UPLOAD_DIR": UPLOAD_DIR,
                "python": sys.version,
                "platform": platform.platform(),
                "server_time": int(time.time()),
                "cwd": os.getcwd(),
            }
            self.html(200, page("debug",
                "<h1>/debug</h1><pre>" +
                json.dumps(info, ensure_ascii=False, indent=2) + "</pre>",
                user["username"]))
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    # 一键复位
    # ------------------------------------------------------------------ #
    def reset_endpoint(self):
        peer = self.client_address[0]
        if peer not in ("127.0.0.1", "::1"):
            self.html(403, "<h1>403</h1>")
            return
        reset_database()
        self.html(200, page("reset",
            "<h1>已重置</h1><p>数据库、上传目录已恢复初始状态。</p>"
            '<p><a href="/">回首页</a></p>'))


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def main():
    args = sys.argv[1:]
    do_reset = "--reset" in args
    args = [a for a in args if a != "--reset"]
    port = DEFAULT_PORT
    if args:
        try:
            port = int(args[0])
            assert 1 <= port <= 65535
        except (ValueError, AssertionError):
            print(f"用法: python {os.path.basename(__file__)} [--reset] [端口]")
            sys.exit(2)

    if HOST != "127.0.0.1":
        raise SystemExit("安全约束：靶场仅允许监听 127.0.0.1")

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    if do_reset:
        reset_database()
    ensure_initialized()

    server = ThreadingHTTPServer((HOST, port), LabHandler)
    server.daemon_threads = True
    print(f"[+] 靶场已启动: http://{HOST}:{port}")
    print(f"[+] 数据库: {DB_PATH}")
    print("[+] 一键复位: GET /__reset 或 python app.py --reset")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[-] 停止")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
