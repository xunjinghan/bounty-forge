# Template selfcheck metrics (loop4 t5 / forge-template)
# NOTE: pure-ASCII source. Windows PowerShell 5.1 reads no-BOM .ps1 as ANSI,
# so non-ASCII literals below are built from code points to stay safe.
param(
  [string]$Dir = 'D:\bounty-forge\reports\submit',
  [string]$Pattern = '*C1-Shiro.md'
)
$ErrorActionPreference = 'Stop'
$targetFile = Get-ChildItem -LiteralPath $Dir -Filter $Pattern -File | Select-Object -First 1
if (-not $targetFile) { Write-Error 'target not found'; exit 1 }
Write-Output ("target       = {0}" -f $targetFile.FullName)
$raw = [System.IO.File]::ReadAllText($targetFile.FullName, [System.Text.Encoding]::UTF8)
$m = [regex]::Match($raw, '(?s)```\r?\n(.*?)\r?\n```')
if (-not $m.Success) { Write-Error 'no code block found'; exit 1 }
$t = $m.Groups[1].Value

function ConvertTo-Str { param([int[]]$codes) -join ($codes | ForEach-Object { [char]$_ }) }

$stop = [char]0x3002   # ideographic full stop
$semi = [char]0xFF1B   # fullwidth semicolon
$s = [regex]::Split($t, "[$stop$semi`r`n]") | Where-Object { $_.Trim().Length -gt 0 }
$L = @($s | ForEach-Object { $_.Trim().Length })
$avg = ($L | Measure-Object -Average).Average
$sum = 0.0
foreach ($x in $L) { $sum += [math]::Pow($x - $avg, 2) }
$std = [math]::Sqrt($sum / $L.Count)

$words = @(
  (ConvertTo-Str 0x7EDF,0x4E0A,0x6240,0x8C13),                                   # zong shang
  (ConvertTo-Str 0x7531,0x6B64,0x53EF,0x89C1),                                   # you ci ke jian
  (ConvertTo-Str 0x8BE5,0x6F0F,0x6D1E,0x672C,0x8D28,0x4E0A),                     # gai lou ben zhi shang
  (ConvertTo-Str 0x5B58,0x5728,0x6781,0x5927,0x5B89,0x5168,0x969C,0x60A3),       # cun zai ji da an quan huan
  (ConvertTo-Str 0x4E00,0x65E6,0x88AB,0x5229,0x7528,0x5C06),                     # yi dan bei li yong jiang
  (ConvertTo-Str 0x503C,0x5F97,0x6CE8,0x610F,0x7684,0x662F)                      # zhi de zhu yi de shi
)
$hit = New-Object System.Collections.Generic.List[string]
foreach ($w in $words) { if ($t.Contains($w)) { $hit.Add($w) } }

$unver = ([regex]::Matches($t, (ConvertTo-Str 0x672A,0x9A8C,0x8BC1))).Count + ([regex]::Matches($t, (ConvertTo-Str 0x672A,0x5B9E,0x6D4B))).Count
$selfc = ([regex]::Matches($t, (ConvertTo-Str 0x4E00,0x5F00,0x59CB))).Count + ([regex]::Matches($t, (ConvertTo-Str 0x6700,0x521D))).Count + ([regex]::Matches($t, (ConvertTo-Str 0x539F,0x5148))).Count
$contra = ([regex]::Matches($t, (ConvertTo-Str 0x4E0D,0x662F))).Count
$spec = ([regex]::Matches($t, '\d{3,}|\d+\.\d+|aced0005|pid=|exit 7|readonly')).Count

Write-Output ("sentences    = {0}" -f $L.Count)
Write-Output ("avg_len      = {0:N1}" -f $avg)
Write-Output ("sigma        = {0:N2}   (threshold >= 8)" -f $std)
Write-Output ("min/max      = {0} / {1}" -f ($L | Measure-Object -Minimum).Minimum, ($L | Measure-Object -Maximum).Maximum)
Write-Output ("chars        = {0}" -f $t.Length)
Write-Output ("specific     = {0}   density = {1:N2} / 100ch  (threshold >= 1)" -f $spec, ($spec * 100.0 / $t.Length))
Write-Output ("ai_words     = {0}   (threshold = 0)  [{1}]" -f $hit.Count, ($hit -join ','))
Write-Output ("unverified   = {0}   (threshold >= 1)" -f $unver)
Write-Output ("self_correct = {0}   (threshold >= 1)" -f $selfc)
Write-Output ("contrast     = {0}   (threshold >= 2)" -f $contra)