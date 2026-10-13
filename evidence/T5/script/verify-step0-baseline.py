# -*- coding: utf-8 -*-
"""t5 核验 step0：复位到干净基线 + 记录复位前后证据。
用法: python verify-step0-baseline.py
"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_lib_import import *  # noqa

import verify_lib_import as V

out = {"step": "step0-baseline", "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "records": []}

# 1) 复位前状态
pre = V.db_snapshot("reset 前")
out["pre_reset"] = pre

# 2) 匿名 GET /__reset（同时核验 HUNT-06 的无认证特征）
r_reset = V.req("GET", "/__reset")
out["records"].append({"tag": "S0-reset-anon", **r_reset})

# 3) 复位后状态
time.sleep(0.3)
post = V.db_snapshot("reset 后（干净基线）")
out["post_reset"] = post

# 4) 两端点连通性
out["records"].append({"tag": "S0-8095-index", **V.req("GET", "/")})
out["records"].append({"tag": "S0-8091-index", **V.req("GET", "/", host=V.H_8091)})

out["reset_effect"] = {
    "sha_changed": pre["sha256"] != post["sha256"],
    "pre_counts": pre["counts"],
    "post_counts": post["counts"],
    "post_sha": post["sha256"],
}

out["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
V.save("verify-00-baseline-20261012-1855.json", out)
print("pre  counts:", pre["counts"])
print("post counts:", post["counts"])
print("post sha:", post["sha256"])
