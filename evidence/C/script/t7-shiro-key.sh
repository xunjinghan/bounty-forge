#!/bin/sh
# 只读：从 ShiroConfig.class 提取硬编码 AES 密钥 + 查看 MainRealm
cd /tmp && rm -rf jarx && mkdir jarx && cd jarx
unzip -o -q /shirodemo-1.0-SNAPSHOT.jar 'BOOT-INF/classes/org/vulhub/shirodemo/*' 2>/dev/null
ls -la BOOT-INF/classes/org/vulhub/shirodemo/
echo "=== strings: ShiroConfig ==="
strings -a BOOT-INF/classes/org/vulhub/shirodemo/ShiroConfig.class | grep -E '^[A-Za-z0-9+/=]{20,}$|kPH|rememberMe|Cipher|AES|cookie' | head -20
echo "=== javap ShiroConfig ==="
java -version 2>&1 | head -1
echo "(need javap - checking other jdk)"
ls /usr/lib/jvm/
echo "=== strings full ShiroConfig ==="
strings -a BOOT-INF/classes/org/vulhub/shirodemo/ShiroConfig.class | head -60
echo "=== strings MainRealm ==="
strings -a BOOT-INF/classes/org/vulhub/shirodemo/MainRealm.class | head -30
echo "=== DONE ==="
