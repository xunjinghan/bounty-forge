#!/bin/bash
# 只读：查 PUT 后的文件落点
echo "=== find recently modified in webapps ==="
find /usr/local/tomcat/webapps -newermt '-10 minutes' 2>/dev/null | head -30
echo "=== ls ROOT ==="
ls -la /usr/local/tomcat/webapps/ROOT/
echo "=== ls work ==="
find /usr/local/tomcat/work -name '*t7poc*' 2>/dev/null | head
echo "=== find t7poc anywhere ==="
find / -name '*t7poc*' 2>/dev/null | head -20
echo "=== conf/web.xml readonly context ==="
grep -n -B8 'readonly' /usr/local/tomcat/conf/web.xml | sed -n '1,60p'
echo "=== server.xml Host appBase ==="
grep -n -A3 '<Host' /usr/local/tomcat/conf/server.xml
echo "=== DONE ==="
