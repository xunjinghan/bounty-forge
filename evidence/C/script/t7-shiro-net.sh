#!/bin/sh
# 只读：shiro 容器 -> 宿主的可达性（用于 C1 OOB 外带）
echo "=== /etc/hosts ==="
cat /etc/hosts
echo "=== routes ==="
cat /proc/net/route
echo "=== ip ==="
ip -4 addr show 2>/dev/null | grep inet
echo "=== reach tests (host candidates:18099) ==="
for t in 172.17.0.1 172.18.0.1 host.docker.internal 10.0.2.2 192.168.31.194; do
  r=$(curl -s -m 4 -o /dev/null -w '%{http_code}' http://$t:18099/ 2>&1)
  rc=$?
  echo "$t -> http=$r rc=$rc"
done
echo "=== DONE ==="
