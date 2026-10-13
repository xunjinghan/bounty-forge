#!/usr/bin/env ruby
# loop3 t7 C1 — 干净判别矩阵：区分「解密失败」与「反序列化失败」
# 全部使用 clean base64（无 kali-run.py JSON 尾部污染）
require 'openssl'
require 'base64'
require 'fileutils'
require 'digest'

outdir = '/tmp/t7-c1-matrix'
FileUtils.mkdir_p(outdir)
KEY = 'kPH+bIxk5D2deZiIxcaaaA=='

def enc(key_b64, plain)
  c = OpenSSL::Cipher.new('aes-128-cbc')
  c.encrypt
  c.key = Base64.decode64(key_b64)
  iv = c.random_iv
  Base64.strict_encode64(iv + c.update(plain.b) + c.final)
end

cases = {
  # 合法 Java 序列化 String "OK"：解密成功 + 反序列化成功 + 类型转换失败
  'P1_valid_serialized_string' => "\xac\xed\x00\x05t\x00\x02OK".b,
  # 合法 padding、明文非序列化流：解密成功 + 反序列化失败
  'P2_garbage_plaintext' => ('X' * 64).b,
  # 合法魔数但截断
  'P3_magic_truncated' => "\xac\xed\x00\x05\x00\x01\x02".b,
  # 长垃圾（排除长度因素）
  'P4_long_garbage' => ('Y' * 2000).b,
}
# P5: 错误密钥加密（解密必然失败）
cases['P5_wrongkey_garbage'] = :wrongkey

cases.each do |name, plain|
  if plain == :wrongkey
    # 用另一个 16 字节 key 加密 -> 服务端用默认 key 解密会 padding 失败
    c = OpenSSL::Cipher.new('aes-128-cbc')
    c.encrypt
    c.key = Base64.decode64('MTIzNDU2Nzg5MGFiY2RlZg==')
    iv = c.random_iv
    b64 = Base64.strict_encode64(iv + c.update(('Z' * 64).b) + c.final)
    File.write("#{outdir}/#{name}.txt", b64)
    puts "#{name} COOKIE_LEN=#{b64.length} PLAIN_SHA256=(wrongkey)"
  else
    b64 = enc(KEY, plain)
    File.write("#{outdir}/#{name}.txt", b64)
    puts "#{name} COOKIE_LEN=#{b64.length} PLAIN_LEN=#{plain.bytesize} PLAIN_SHA256=#{Digest::SHA256.hexdigest(plain)}"
  end
end
puts "WRITTEN_TO=#{outdir}"
