#!/bin/bash
# loop3 t7 开工侦察（只读）：Kali 工具链 + 容器侧线索
echo "=== java ==="
java -version 2>&1 | head -3
which java javac mvn 2>/dev/null
echo "=== ysoserial ==="
find / -maxdepth 5 -iname 'ysoserial*' 2>/dev/null | head -10
ls -la /opt 2>/dev/null | head -20
echo "=== python libs ==="
python3 -c 'import requests;print("requests",requests.__version__)' 2>&1
python3 -c 'import Crypto;print("pycryptodome",Crypto.__version__)' 2>&1
python3 -c 'import Crypto.Cipher.AES;print("AES ok")' 2>&1
echo "=== shiro exploit tools ==="
find / -maxdepth 5 \( -iname '*shiro*exploit*' -o -iname 'shiro_attack*' -o -iname 'ShiroExploit*' \) 2>/dev/null | head -10
echo "=== network from kali ==="
curl -s -m 6 -o /dev/null -w "host.docker.internal=%{http_code}\n" http://host.docker.internal:18081/ 2>&1
curl -s -m 6 -o /dev/null -w "10.0.2.2=%{http_code}\n" http://10.0.2.2:18082/ 2>&1
echo "=== DONE ==="
