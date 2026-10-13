#!/bin/bash
# 只读：msf shiro 模块的核心逻辑 + 反序列化 gadget 生成能力
echo "=== module body (60-140) ==="
sed -n '60,150p' /usr/share/metasploit-framework/modules/exploits/multi/http/shiro_rememberme_v124_deserialize.rb
echo "=== java_deserialization.rb ==="
cat /usr/share/metasploit-framework/lib/msf/util/java_deserialization.rb
echo "=== java_deserialization dir ==="
ls -la /usr/share/metasploit-framework/lib/msf/util/ | head -20
find /usr/share/metasploit-framework -path '*java_deserialization*' -o -name '*JavaDeserialization*' 2>/dev/null | head -20
echo "=== DONE ==="
