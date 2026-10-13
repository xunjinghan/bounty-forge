# -*- coding: utf-8 -*-
"""核验：确认本阶段探测未创建账号 / 未改动数据（只读 DB 查询）。"""
import sqlite3

SITE_DB = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\target-site\target_site.db"
LAB_DB = r"C:\Users\Administrator\Documents\deepseek-harness\default-workspace\target-site-lab\lab.db"

for name, path in (("target-site", SITE_DB), ("target-site-lab", LAB_DB)):
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    print("===", name, path)
    for t in ("users", "sessions", "messages", "orders", "login_attempts", "coupon_claims"):
        try:
            n = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            print(f"  {t}: {n}")
        except Exception as e:
            print(f"  {t}: N/A ({e})")
    try:
        print("  users:", [dict(r) for r in c.execute(
            "SELECT id,username,role,balance_cents FROM users")])
    except Exception as e:
        print("  users err", e)
    try:
        print("  messages:", [dict(r) for r in c.execute(
            "SELECT id,author,substr(content,1,60) c FROM messages")])
    except Exception as e:
        print("  messages err", e)
    try:
        print("  orders:", [dict(r) for r in c.execute(
            "SELECT id,user_id,item,qty,amount_cents,state FROM orders")])
    except Exception as e:
        print("  orders err", e)
    c.close()
