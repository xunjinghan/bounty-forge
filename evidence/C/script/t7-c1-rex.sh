#!/bin/bash
# 只读：找出 msf 的 rex gem 路径，用其自身环境生成 ysoserial payload
echo "=== locate rex/text ==="
find / -xdev -path '*rex*' -name 'text.rb' 2>/dev/null | head -5
echo "=== msf gem env ==="
ls -d /usr/lib/ruby/vendor_ruby/rex* /var/lib/gems/*/gems/rex* /usr/share/metasploit-framework/vendor* 2>/dev/null | head
echo "=== try with -I vendor paths ==="
cd /usr/share/metasploit-framework && ruby -Ilib -I/usr/share/metasploit-framework/lib -e 'require "rex/text"; puts "rex OK"' 2>&1 | tail -2
echo "=== try bundler ==="
cd /usr/share/metasploit-framework && (bundle exec ruby -e 'require "rex/text"; puts "bundle rex OK"' 2>&1 | tail -3)
echo "=== gem list rex ==="
gem list 2>/dev/null | grep -i rex | head
gem contents rex-text 2>/dev/null | head -3
echo "=== dpkg rex ==="
dpkg -L metasploit-framework 2>/dev/null | grep -i 'rex/text' | head -3
echo "=== DONE ==="
