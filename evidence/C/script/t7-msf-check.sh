#!/bin/bash
# 只读：检查 msf 的 shiro 模块与离线 gadget 生成能力
echo "=== msf version ==="
/usr/bin/msfconsole --version 2>&1 | head -3
echo "=== shiro module head ==="
sed -n '1,60p' /usr/share/metasploit-framework/modules/exploits/multi/http/shiro_rememberme_v124_deserialize.rb
echo "=== module defs (targets/gadgets) ==="
grep -nE "GADGETS|def initialize|'Targets'|DefaultOptions|Key|key" /usr/share/metasploit-framework/modules/exploits/multi/http/shiro_rememberme_v124_deserialize.rb | head -40
echo "=== java deser util present? ==="
ls -la /usr/share/metasploit-framework/lib/msf/util/java_deserialization.rb 2>/dev/null
echo "=== DONE ==="
