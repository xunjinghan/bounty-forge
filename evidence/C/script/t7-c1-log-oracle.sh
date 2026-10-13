#!/bin/bash
# loop3 t7 C1 补充：提取决定性日志 oracle 证据（带时间戳）
LOG=/tmp/t7-shiro-full.log
docker logs vulhub-shiro-18081 > $LOG 2>&1 || docker logs vulhub-shiro-18081 2> $LOG
echo "=== total lines ==="
wc -l < $LOG
echo
echo "=== [A] BadPaddingException 出现位置（解密失败锚点）==="
grep -n 'BadPadding' $LOG | head -10
echo
echo "=== [B] ClassCastException HashSet->PrincipalCollection（解密+反序列化成功锚点）==="
grep -n 'HashSet cannot be cast' $LOG | head -10
echo
echo "=== [C] ClassResolvingObjectInputStream / DefaultSerializer 调用链 ==="
grep -n 'ClassResolvingObjectInputStream\|DefaultSerializer' $LOG | head -10
echo
echo "=== [D] EOFException（流截断/空流）==="
grep -n 'EOFException' $LOG | head -5
echo
echo "=== [E] 各锚点计数 ==="
for k in BadPadding 'HashSet cannot be cast' ClassResolvingObjectInputStream EOFException CryptoException; do
  printf '%-38s %s\n' "$k" "$(grep -c "$k" $LOG)"
done
echo
echo "=== [F] 带时间戳的行（Shiro 异常头部）==="
grep -nE '^[0-9]{4}-[0-9]{2}-[0-9]{2}.*(BadPadding|HashSet cannot|Exception)' $LOG | tail -12
echo "=== DONE ==="
