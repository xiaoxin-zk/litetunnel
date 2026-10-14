# ============================================================
#  从仓库根目录的 .env 渲染 frps.toml 与 Caddyfile。
#
#  用法（在仓库根目录执行）：
#     powershell -ExecutionPolicy Bypass -File deploy/scripts/render.ps1
#
#  说明：源码中不保存任何真实地址，所有部署相关的值都来自 .env（已被 .gitignore 忽略）。
# ============================================================

$ErrorActionPreference = 'Stop'

$root      = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$envFile   = Join-Path $root '.env'
$frpsTpl   = Join-Path $root 'deploy/frps/frps.toml.template'
$frpsOut   = Join-Path $root 'deploy/frps/frps.toml'
$caddyTpl  = Join-Path $root 'deploy/caddy/Caddyfile.template'
$caddyOut  = Join-Path $root 'deploy/caddy/Caddyfile'

if (-not (Test-Path $envFile)) {
    throw "未找到 $envFile，请先复制 .env.example 为 .env 并填写真实值。"
}

# ---- 解析 .env ----
$vars = @{}
foreach ($line in Get-Content -LiteralPath $envFile -Encoding UTF8) {
    $trimmed = $line.Trim()
    if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
    $idx = $trimmed.IndexOf('=')
    if ($idx -lt 1) { continue }
    $key = $trimmed.Substring(0, $idx).Trim()
    $val = $trimmed.Substring($idx + 1).Trim()
    $vars[$key] = $val
}

# ---- 派生变量 ----
function StripScheme([string]$v) {
    if ([string]::IsNullOrWhiteSpace($v)) { return '' }
    return ($v -replace '^https?://', '').TrimEnd('/')
}

$userDomain  = StripScheme $vars['LT_USER_PUBLIC_URL']
$adminDomain = StripScheme $vars['LT_ADMIN_PUBLIC_URL']
$tunnelDomain = if ($vars['LT_TUNNEL_DOMAIN']) { $vars['LT_TUNNEL_DOMAIN'] } else { '' }

if ([string]::IsNullOrWhiteSpace($userDomain)) {
    throw 'LT_USER_PUBLIC_URL 未填写：Caddy 需要一个域名来签发证书。'
}

$derived = @{
    'LT_USER_DOMAIN'      = $userDomain
    'LT_ADMIN_DOMAIN'     = if ($adminDomain) { $adminDomain } else { 'admin.invalid.local' }
    'LT_ADMIN_ALLOW_CIDR' = if ($vars['LT_ADMIN_ALLOW_CIDR']) { $vars['LT_ADMIN_ALLOW_CIDR'] } else { '127.0.0.1/32' }
    'LT_ACME_EMAIL'       = if ($vars['LT_ACME_EMAIL']) { $vars['LT_ACME_EMAIL'] } else { "admin@$userDomain" }
    'LT_TUNNEL_DOMAIN'    = $tunnelDomain
}

foreach ($k in $derived.Keys) { $vars[$k] = $derived[$k] }

# ---- 必填校验 ----
$required = @(
    'LT_GATEWAY_PORT', 'LT_KCP_PORT', 'LT_VHOST_HTTP_PORT', 'LT_VHOST_HTTPS_PORT',
    'LT_FRPS_TOKEN', 'LT_PORT_RANGE_START', 'LT_PORT_RANGE_END', 'LT_MAX_PORTS_PER_USER',
    'LT_FRPS_API_PORT', 'LT_FRPS_API_USER', 'LT_FRPS_API_PASSWORD',
    'LT_USER_PORT', 'LT_ADMIN_PORT'
)
$missing = @()
foreach ($k in $required) {
    if (-not $vars.ContainsKey($k) -or [string]::IsNullOrWhiteSpace($vars[$k])) { $missing += $k }
}
if ($missing.Count -gt 0) {
    throw "以下配置项缺失，请在 .env 中补齐：`n  $($missing -join ', ')"
}

foreach ($k in $vars.Keys) {
    if ($vars[$k] -match '^CHANGE_ME') {
        throw "配置项 $k 仍是占位符，请改为真实值。"
    }
}

# ---- 渲染 ----
function Render([string]$template, [string]$output, [hashtable]$values) {
    $text = Get-Content -LiteralPath $template -Raw -Encoding UTF8
    # 长键优先替换，避免 LT_USER_PORT 误伤 LT_USER_PORT_XXX 这类前缀重叠
    $keys = $values.Keys | Sort-Object { $_.Length } -Descending
    foreach ($k in $keys) {
        $text = $text.Replace('${' + $k + '}', [string]$values[$k])
    }
    if ($text -match '\$\{[A-Z_]+\}') {
        $leftover = [regex]::Matches($text, '\$\{[A-Z_]+\}') | ForEach-Object { $_.Value } | Select-Object -Unique
        throw "模板 $template 中存在未替换的占位符：$($leftover -join ', ')"
    }
    Set-Content -LiteralPath $output -Value $text -Encoding UTF8 -NoNewline
    Write-Host "已生成 $output"
}

Render $frpsTpl $frpsOut $vars
Render $caddyTpl $caddyOut $vars

Write-Host ''
Write-Host '渲染完成。接下来：'
Write-Host '  1) 确保防火墙/安全组只放行 80、443 与隧道端口池（默认 20000-30000），以及网关端口 7000/TCP 与 7001/UDP'
Write-Host '  2) 在仓库根目录执行： docker compose -f deploy/docker-compose.yml up -d --build'
