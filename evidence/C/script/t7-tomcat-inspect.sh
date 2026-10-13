#!/bin/sh
echo "=== tomcat web.xml readonly ==="
grep -B2 -A6 -i 'readonly' /usr/local/tomcat/conf/web.xml
echo "=== java ==="
java -version 2>&1 | head -3
echo "=== OS ==="
cat /etc/os-release | head -3
echo "=== commands ==="
for t in curl wget bash sh python nc perl; do p=$(command -v $t 2>/dev/null); echo "$t=${p:-MISSING}"; done
echo "=== webapps ==="
ls -la /usr/local/tomcat/webapps/
echo "=== conf/Catalina/localhost ==="
ls -la /usr/local/tomcat/conf/Catalina/localhost/ 2>/dev/null
echo "=== DONE ==="
