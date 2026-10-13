#!/bin/bash
# 收尾：清理 loop3 测试会话文件 + 确认 8099 端口释放 + 靶场最终态
echo "=== sessions now ==="
sudo -n ls /var/lib/php/sessions/ | grep -iE 'loop3|036dd2f5' || echo "(no loop3 test sessions)"
echo "=== remove remaining loop3 test sessions ==="
sudo -n rm -f /var/lib/php/sessions/sess_loop3t4recordingid0000000000001 \
             /var/lib/php/sessions/sess_036dd2f56fcc1ec3e5538e1643d3f510 \
             /var/lib/php/sessions/sess_loop3fixlow0000000000000000000001 \
             /var/lib/php/sessions/sess_loop3t4fixedsessionid000000000001
sudo -n ls /var/lib/php/sessions/ | grep -iE 'loop3|036dd2f5' || echo "CLEAN: no loop3 test sessions left"
echo "=== port 8099 ==="
ss -tln | grep 8099 || echo "8099 closed"
echo "=== 8099 process ==="
pgrep -af "loop3-t4-probe" || echo "no probe processes"
echo "=== teaching dir ==="
ls -d /var/www/html/lo3-teach 2>/dev/null || echo "lo3-teach removed"
echo "=== final bwapp/dvwa state ==="
sudo -n mariadb -N -e "SELECT 'bWAPP.users',id,login,secret FROM bWAPP.users UNION ALL SELECT 'dvwa.users',user_id,user,'' FROM dvwa.users UNION ALL SELECT 'guestbook',comment_id,name,'' FROM dvwa.guestbook;" 2>&1
echo "=== blog rows ==="
sudo -n mariadb -N -e "SELECT COUNT(*) FROM bWAPP.blog;" 2>&1
echo "=== evidence files on kali ==="
ls -la /tmp/loop3-t4-*.json /tmp/loop3-t4-*.jsonl /tmp/loop3-t4-b5-xss.png 2>/dev/null
echo "=== sha256 ==="
sha256sum /tmp/loop3-t4-probe1.json /tmp/loop3-t4-probe2.json /tmp/loop3-t4-probe3.json /tmp/loop3-t4-probe4.json /tmp/loop3-t4-probe5.json /tmp/loop3-t4-probe6.json /tmp/loop3-t4-probe7.json /tmp/loop3-t4-probe8.json /tmp/loop3-t4-probe9.json /tmp/loop3-t4-probe10.json /tmp/loop3-t4-probe11.json /tmp/loop3-t4-probe12.json /tmp/loop3-t4-b5-sink.jsonl /tmp/loop3-t4-probe9-sink.jsonl /tmp/loop3-t4-probe11-sink.jsonl /tmp/loop3-t4-b5-xss.png 2>&1
echo "=== DONE ==="
