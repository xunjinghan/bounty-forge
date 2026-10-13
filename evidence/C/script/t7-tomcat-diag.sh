#!/bin/bash
# 只读：诊断 PUT 后 GET 404
echo "=== tomcat process user ==="
ps aux | grep -i [c]atalina | head -3
id
echo "=== file perms & content head ==="
ls -la /usr/local/tomcat/webapps/ROOT/t7poc230751.jsp
head -c 200 /usr/local/tomcat/webapps/ROOT/t7poc230751.jsp
echo
echo "=== dir perms ==="
ls -ld /usr/local/tomcat/webapps/ROOT
echo "=== local curl from inside container ==="
curl -s -o /dev/null -w "inside GET /t7poc230751.jsp = %{http_code}\n" http://127.0.0.1:8080/t7poc230751.jsp
curl -s -i http://127.0.0.1:8080/t7poc230751.jsp 2>&1 | head -8
echo "=== try existing index.jsp for comparison ==="
curl -s -o /dev/null -w "GET /index.jsp = %{http_code}\n" http://127.0.0.1:8080/index.jsp
echo "=== DONE ==="
