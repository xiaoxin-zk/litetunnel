# ============================================================
#  提交前自检：确认源码中没有混入公网 IP、真实域名或密钥。
#
#  用法（在仓库根目录执行）：
#     powershell -ExecutionPolicy Bypass -File scripts/check-secrets.ps1
#
#  建议配合 .git/hooks/pre-commit 使用，防止误提交。
# ============================================================
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

# 需要扫描的源码目录
$targets = @('server', 'web', 'client', 'deploy', 'scripts') |
    ForEach-Object { Join-Path $root $_ } |
    Where-Object { Test-Path $_ }

$extensions = @('.go', '.js', '.vue', '.ts', '.json', '.toml', '.yml', '.yaml', '.ps1', '.sh', '.html', '.css', '.md', '.example')

# 允许出现的私有/回环地址与示例网段
$allowedIps = @(
    '127.0.0.1', '0.0.0.0', '::1', 'localhost',
    '10.0.0.1', '192.168.1.1', '192.168.0.1'
)

$ipPattern = '\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'
$domainPattern = '\b(?:[a-zA-Z0-9-]+\.)+(?:com|cn|net|org|io|top|xyz|vip|cc|me)\b'
$allowedDomains = @('example.com', 'example.org', 'wails.io', 'golang.org', 'github.com', 'goproxy.cn',
    'element-plus.org', 'vuejs.org', 'localhost')

$findings = @()

foreach ($dir in $targets) {
    Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $extensions -contains $_.Extension -and
            $_.FullName -notmatch '\\(node_modules|dist|build|wailsjs)\\' -and
            $_.Name -ne 'package-lock.json'
        } |
        ForEach-Object {
            $file = $_
            $rel = $file.FullName.Substring($root.Length + 1)
            $lineNo = 0
            foreach ($line in Get-Content -LiteralPath $file.FullName -Encoding UTF8) {
                $lineNo++
                # 跳过明显是版本号（v1.2.3.4）或注释中的说明
                foreach ($m in [regex]::Matches($line, $ipPattern)) {
                    $ip = $m.Value
                    if ($allowedIps -contains $ip) { continue }
                    # 跳过版本号形式：前面紧跟 v 或 : 或数字点
                    $before = if ($m.Index -gt 0) { $line.Substring([Math]::Max(0, $m.Index - 1), 1) } else { '' }
                    if ($before -eq 'v' -or $before -eq ':') { continue }
                    $findings += [pscustomobject]@{ 文件 = $rel; 行 = $lineNo; 类型 = 'IP'; 内容 = $line.Trim() }
                }
                foreach ($m in [regex]::Matches($line, $domainPattern)) {
                    $d = $m.Value.ToLower()
                    if ($allowedDomains -contains $d) { continue }
                    if ($d -like '*.local' -or $d -like '*.invalid*') { continue }
                    if ($line -match 'LICENSE|Copyright|@|\.md:') { continue }
                    $findings += [pscustomobject]@{ 文件 = $rel; 行 = $lineNo; 类型 = '域名'; 内容 = $line.Trim() }
                }
            }
        }
}

if ($findings.Count -eq 0) {
    Write-Host '自检通过：源码中未发现硬编码的公网 IP 或真实域名。' -ForegroundColor Green
    exit 0
}

Write-Host "发现 $($findings.Count) 处疑似硬编码，请确认后再提交：" -ForegroundColor Yellow
$findings | Format-Table -AutoSize
exit 1
