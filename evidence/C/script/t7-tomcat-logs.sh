#!/bin/sh
# 只读：tomcat 日志（作为可能的 OOB 观察点）+ 容器 IP
echo "=== logs dir ==="
ls -la /usr/local/tomcat/logs/ 2>/dev/null
echo "=== access log config ==="
grep -n -A3 'AccessLogValve' /usr/local/tomcat/conf/server.xml 2>/dev/null | head -20
echo "=== container ip ==="
cat /proc/net/fib_trie 2>/dev/null | grep -A1 '32 host' | head -20
hostname -i 2>/dev/null || echo "no hostname -i"
echo "=== DONE ==="
