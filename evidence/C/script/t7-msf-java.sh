#!/bin/bash
# 只读：msf java 反序列化生成器 + ysoserial json 结构
echo "=== generate_java_deserialization_for_payload ==="
cat /usr/share/metasploit-framework/lib/msf/core/exploit/java_deserialization.rb
echo "=== json structure: bash/CommonsBeanutils1 ==="
python3 - <<'PY'
import json, base64
p='/usr/share/metasploit-framework/data/ysoserial_payloads.json'
d=json.load(open(p))
for typ in ('bash','cmd','none'):
    node=d.get(typ,{})
    if 'CommonsBeanutils1' in node:
        e=node['CommonsBeanutils1']
        b=base64.b64decode(e['bytes'])
        print(f"[{typ}] CommonsBeanutils1 status={e['status']} rawlen={len(b)} bufferOffset={e.get('bufferOffset')} lengthOffset={e.get('lengthOffset')} magic={b[:4].hex()}")
        if e.get('bufferOffset'):
            o=e['bufferOffset'][0]-1
            print(f"   buffer vicinity: {b[max(0,o-40):o+40]!r}")
for ch in ('CommonsCollections2','CommonsCollections5','CommonsCollections6','CommonsBeanutils1','Spring1'):
    e=d.get('bash',{}).get(ch)
    if e: print(ch, e['status'], (e.get('bufferOffset'), e.get('lengthOffset')))
PY
echo "=== java single-file source support ==="
cat > /tmp/t7/X.java <<'EOF'
public class X { public static void main(String[] a){ System.out.println("java-single-file-OK " + System.getProperty("java.version")); } }
EOF
java /tmp/t7/X.java 2>&1 | head -3
echo "=== DONE ==="
