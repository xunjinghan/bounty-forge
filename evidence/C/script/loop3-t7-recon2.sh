#!/bin/bash
# loop3 t7 侦察2（只读）：Kali JVM / javac / msf shiro 模块 / jar 搜索
echo "=== JVMs ==="
ls -1 /usr/lib/jvm/ 2>/dev/null
echo "--- javac ---"
command -v javac; javac -version 2>&1 | head -2
echo "=== jars on system ==="
find / -xdev -iname '*.jar' 2>/dev/null | grep -iE 'ysoserial|commons-collections|commons-beanutils|shiro' | head -20
echo "=== msf shiro module ==="
ls /usr/share/metasploit-framework/modules/exploits/multi/http/ 2>/dev/null | grep -i shiro || echo "no shiro msf module"
echo "=== msf ysoserial json ==="
ls -la /usr/share/metasploit-framework/data/ysoserial_payloads.json 2>/dev/null
head -c 400 /usr/share/metasploit-framework/data/ysoserial_payloads.json 2>/dev/null
echo
echo "=== java AES self-test against Shiro default key ==="
mkdir -p /tmp/t7 && cat > /tmp/t7/AesProbe.java <<'EOF'
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
public class AesProbe {
  public static void main(String[] a) throws Exception {
    byte[] k = Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");
    System.out.println("keylen=" + k.length);
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"), new IvParameterSpec(k));
    byte[] out = c.doFinal("PROBE".getBytes("UTF-8"));
    System.out.println("enc_len=" + out.length + " b64=" + Base64.getEncoder().encodeToString(out));
    Cipher d = Cipher.getInstance("AES/CBC/PKCS5Padding");
    d.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"), new IvParameterSpec(k));
    System.out.println("roundtrip=" + new String(d.doFinal(out), "UTF-8"));
  }
}
EOF
cd /tmp/t7 && javac AesProbe.java 2>&1 | head -5 && java AesProbe 2>&1 | head -6
echo "=== DONE ==="
