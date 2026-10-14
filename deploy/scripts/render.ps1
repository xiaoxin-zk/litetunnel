# ============================================================
#  Render frps.toml and Caddyfile from the repository-root .env.
#
#  The repository itself contains no real address: every deployment
#  specific value lives in .env, which is git-ignored.
#
#  NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads
#  BOM-less .ps1 files as ANSI and non-ASCII text breaks parsing.
#
#  Usage (run from the repository root):
#     powershell -ExecutionPolicy Bypass -File deploy/scripts/render.ps1
# ============================================================

$ErrorActionPreference = 'Stop'

$root     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$envFile  = Join-Path $root '.env'
$frpsTpl  = Join-Path $root 'deploy/frps/frps.toml.template'
$frpsOut  = Join-Path $root 'deploy/frps/frps.toml'
$caddyTpl = Join-Path $root 'deploy/caddy/Caddyfile.template'
$caddyOut = Join-Path $root 'deploy/caddy/Caddyfile'

if (-not (Test-Path $envFile)) {
    throw "Missing $envFile. Copy .env.example to .env and fill in real values first."
}

# ---- Parse .env ----
$vars = @{}
foreach ($line in Get-Content -LiteralPath $envFile -Encoding UTF8) {
    $trimmed = $line.Trim()
    if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
    $idx = $trimmed.IndexOf('=')
    if ($idx -lt 1) { continue }
    $vars[$trimmed.Substring(0, $idx).Trim()] = $trimmed.Substring($idx + 1).Trim()
}

function Strip-Scheme([string]$v) {
    if ([string]::IsNullOrWhiteSpace($v)) { return '' }
    return ($v -replace '^https?://', '').TrimEnd('/')
}

$userDomain  = Strip-Scheme $vars['LT_USER_PUBLIC_URL']
$adminDomain = Strip-Scheme $vars['LT_ADMIN_PUBLIC_URL']

if ([string]::IsNullOrWhiteSpace($userDomain)) {
    throw 'LT_USER_PUBLIC_URL is empty: Caddy needs a domain to issue a certificate.'
}

$vars['LT_USER_DOMAIN']      = $userDomain
$vars['LT_ADMIN_DOMAIN']     = if ($adminDomain) { $adminDomain } else { 'admin.invalid.local' }
$vars['LT_ADMIN_ALLOW_CIDR'] = if ($vars['LT_ADMIN_ALLOW_CIDR']) { $vars['LT_ADMIN_ALLOW_CIDR'] } else { '127.0.0.1/32' }
$vars['LT_ACME_EMAIL']       = if ($vars['LT_ACME_EMAIL']) { $vars['LT_ACME_EMAIL'] } else { "admin@$userDomain" }
$vars['LT_TUNNEL_DOMAIN']    = if ($vars['LT_TUNNEL_DOMAIN']) { $vars['LT_TUNNEL_DOMAIN'] } else { '' }

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
    throw "Missing values in .env: $($missing -join ', ')"
}

foreach ($k in $vars.Keys) {
    if ($vars[$k] -match '^CHANGE_ME') {
        throw "$k is still a placeholder. Set a real value."
    }
}

# ---- Render ----
function Render([string]$template, [string]$output, [hashtable]$values) {
    $text = Get-Content -LiteralPath $template -Raw -Encoding UTF8
    # Replace longer keys first so that LT_USER_PORT cannot damage LT_USER_PORT_X.
    foreach ($k in ($values.Keys | Sort-Object { $_.Length } -Descending)) {
        $text = $text.Replace('${' + $k + '}', [string]$values[$k])
    }
    $leftover = [regex]::Matches($text, '\$\{[A-Z_]+\}') | ForEach-Object { $_.Value } | Select-Object -Unique
    if ($leftover) {
        throw "Unresolved placeholders in $template : $($leftover -join ', ')"
    }
    [IO.File]::WriteAllText($output, $text, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Generated $output"
}

Render $frpsTpl  $frpsOut  $vars
Render $caddyTpl $caddyOut $vars

Write-Host ''
Write-Host 'Done. Next steps:'
Write-Host '  1) Open ports 80, 443, the tunnel port pool (default 20000-30000),'
Write-Host '     7000/TCP and 7001/UDP in your firewall / security group only.'
Write-Host '  2) From the repository root run:'
Write-Host '     docker compose -f deploy/docker-compose.yml pull'
Write-Host '     docker compose -f deploy/docker-compose.yml up -d'
