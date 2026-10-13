#!/bin/bash
# 只读：容器网络 + ysoserial payload 链清单
echo "=== shiro container network ==="
SHIRO=$(docker ps --filter name=vulhub-shiro --format '{{.Names}}')
echo "container=$SHIRO"
docker exec $SHIRO sh -c 'ip addr 2>/dev/null || cat /proc/net/fib_trie | head -30'
echo "--- default gw ---"
docker exec $SHIRO sh -c 'cat /proc/net/route | head -5'
echo "--- resolv/ hosts ---"
docker exec $SHIRO sh -c 'cat /etc/hosts'
echo "=== reachability from container ==="
for tgt in 172.17.0.1 host.docker.internal 192.168.56.101 10.0.2.2; do
  code=$(docker exec $SHIRO curl -s -m 4 -o /dev/null -w '%{http_code}' http://$tgt:1/ 2>/dev/null)
  rc=$?
  echo "$tgt http=$code rc=$rc"
done
echo "=== docker networks ==="
docker network ls
docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} gw={{$v.Gateway}}{{end}}' $SHIRO
echo "=== ysoserial chain availability (msf json) ==="
python3 - <<'PY'
import json
d=json.load(open('/usr/share/metasploit-framework/data/ysoserial_payloads.json'))
print("top-level keys:", list(d.keys()))
none=d.get('none',{})
print("total chains:", len(none))
for k,v in none.items():
    print(" ", k, v.get('status'))
PY
echo "=== DONE ==="
