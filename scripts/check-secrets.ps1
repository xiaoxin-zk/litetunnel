# ============================================================
#  Pre-commit guard: make sure no public IP / real domain / secret
#  leaked into the source tree.
#
#  NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads
#  BOM-less .ps1 files as ANSI and non-ASCII text breaks parsing.
#
#  Usage (run from the repository root):
#     powershell -ExecutionPolicy Bypass -File scripts/check-secrets.ps1
# ============================================================
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

$targets = @('server', 'web', 'client', 'deploy', 'scripts', '.github') |
    ForEach-Object { Join-Path $root $_ } |
    Where-Object { Test-Path $_ }

$extensions = @('.go', '.js', '.vue', '.ts', '.json', '.toml', '.yml', '.yaml',
                '.ps1', '.sh', '.html', '.css', '.md', '.example')

# Loopback / placeholder addresses that are always fine.
$allowedIps = @(
    '127.0.0.1', '0.0.0.0', '255.255.255.255',
    '10.0.0.1', '192.168.0.1', '192.168.1.1'
)

# Domains that are project dependencies or documentation examples.
$allowedDomains = @(
    'example.com', 'example.org', 'localhost', 'invalid.local',
    'github.com', 'ghcr.io', 'golang.org', 'goproxy.cn',
    'wails.io', 'vuejs.org', 'element-plus.org',
    'actions', 'npmjs.com', 'nodejs.org'
)

$ipPattern = '\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'
$domainPattern = '\b(?:[a-zA-Z0-9][a-zA-Z0-9-]*\.)+(?:com|cn|net|org|io|top|xyz|vip|cc|me|dev|app)\b'

$findings = New-Object System.Collections.ArrayList

foreach ($dir in $targets) {
    Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $extensions -contains $_.Extension -and
            $_.FullName -notmatch '\\(node_modules|dist|build|wailsjs|\.git)\\' -and
            $_.Name -ne 'package-lock.json'
        } |
        ForEach-Object {
            $file = $_
            $rel = $file.FullName.Substring($root.Length + 1)
            $lineNo = 0
            foreach ($line in Get-Content -LiteralPath $file.FullName -Encoding UTF8) {
                $lineNo++

                foreach ($m in [regex]::Matches($line, $ipPattern)) {
                    $ip = $m.Value
                    if ($allowedIps -contains $ip) { continue }
                    # Skip version strings like v1.2.3.4 and port-style prefixes.
                    $before = if ($m.Index -gt 0) { $line.Substring($m.Index - 1, 1) } else { '' }
                    if ($before -eq 'v' -or $before -eq ':') { continue }
                    [void]$findings.Add([pscustomobject]@{
                        File = $rel; Line = $lineNo; Kind = 'IP'; Text = $line.Trim()
                    })
                }

                foreach ($m in [regex]::Matches($line, $domainPattern)) {
                    $d = $m.Value.ToLower()
                    if ($allowedDomains -contains $d) { continue }
                    if ($d -like '*.local') { continue }
                    # Skip email addresses and license headers.
                    if ($line -match '@' -and $line -match 'mailto:|Copyright|LICENSE') { continue }
                    [void]$findings.Add([pscustomobject]@{
                        File = $rel; Line = $lineNo; Kind = 'Domain'; Text = $line.Trim()
                    })
                }
            }
        }
}

if ($findings.Count -eq 0) {
    Write-Host 'PASS: no hard-coded public IP or real domain found in source.' -ForegroundColor Green
    exit 0
}

Write-Host ("WARN: {0} suspicious occurrence(s) found. Review before committing:" -f $findings.Count) -ForegroundColor Yellow
$findings | Format-Table -AutoSize
exit 1
