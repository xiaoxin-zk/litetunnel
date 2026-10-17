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
# Values must be decoded with the same semantics the panel helper uses when
# writing them (server/cmd/lt-config/envfile.go, encodeEnvValue), which follows
# Compose dotenv rules:
#   - double-quoted values: escape sequences first (\\" \\\\ \\n \\r \\t),
#     then the $$ interpolation escape;
#   - single-quoted values: taken literally;
#   - bare values: only the $$ escape.
# Without this, a quoted multi-argument DNS configuration (LT_CADDY_DNS_ARGS)
# would reach the Caddyfile template still wrapped in quotes and collapsed into
# a single argument.
function ConvertFrom-DotEnvValue([string]$raw) {
    if ($null -eq $raw -or $raw -eq '') { return '' }
    if ($raw.Length -ge 2 -and $raw[0] -eq '"' -and $raw[$raw.Length - 1] -eq '"') {
        $v = $raw.Substring(1, $raw.Length - 2)
        # Only the escape sequences Compose defines; unknown ones are left as-is
        # (matching the helper's decoder). $1 refers to the character after \.
        $v = [regex]::Replace($v, '\\(["\\nrt])', {
            param($m)
            switch ($m.Groups[1].Value) {
                'n' { "`n" }
                'r' { "`r" }
                't' { "`t" }
                default { $m.Groups[1].Value }
            }
        })
        return $v.Replace('$$', '$')
    }
    if ($raw.Length -ge 2 -and $raw[0] -eq "'" -and $raw[$raw.Length - 1] -eq "'") {
        return $raw.Substring(1, $raw.Length - 2)
    }
    return $raw.Replace('$$', '$')
}

$vars = @{}
foreach ($line in Get-Content -LiteralPath $envFile -Encoding UTF8) {
    $trimmed = $line.Trim()
    if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
    $idx = $trimmed.IndexOf('=')
    if ($idx -lt 1) { continue }
    $vars[$trimmed.Substring(0, $idx).Trim()] = ConvertFrom-DotEnvValue ($trimmed.Substring($idx + 1).Trim())
}

function Strip-Scheme([string]$v) {
    if ([string]::IsNullOrWhiteSpace($v)) { return '' }
    return ($v -replace '^https?://', '').TrimEnd('/')
}

$userDomain = Strip-Scheme $vars['LT_USER_PUBLIC_URL']

if ([string]::IsNullOrWhiteSpace($userDomain)) {
    throw 'LT_USER_PUBLIC_URL is empty: Caddy needs a domain to issue a certificate.'
}

$vars['LT_USER_DOMAIN'] = $userDomain
# Admin console shares the user domain; only the optional IP allowlist placeholder remains.
$vars['LT_ADMIN_ALLOW_CIDR'] = if ($vars['LT_ADMIN_ALLOW_CIDR']) { $vars['LT_ADMIN_ALLOW_CIDR'] } else { '127.0.0.1/32' }
$vars['LT_ACME_EMAIL']       = if ($vars['LT_ACME_EMAIL']) { $vars['LT_ACME_EMAIL'] } else { "admin@$userDomain" }
$vars['LT_TUNNEL_DOMAIN']    = if ($vars['LT_TUNNEL_DOMAIN']) { $vars['LT_TUNNEL_DOMAIN'] } else { '' }

# DNS challenge: the only channel a wildcard certificate can be validated over.
$vars['LT_CADDY_DNS_PROVIDER'] = if ($vars['LT_CADDY_DNS_PROVIDER']) { $vars['LT_CADDY_DNS_PROVIDER'] } else { '' }
if (-not $vars['LT_CADDY_DNS_ARGS']) {
    # Credentials are read from the environment so that they never reach the
    # Caddyfile, the repository, the logs or any backup.
    $vars['LT_CADDY_DNS_ARGS'] = '{env.LT_CADDY_DNS_CREDENTIAL}'
}
if ($vars['LT_TUNNEL_DOMAIN'] -and -not $vars['LT_CADDY_DNS_PROVIDER']) {
    throw @'
LT_TUNNEL_DOMAIN is set but LT_CADDY_DNS_PROVIDER is empty.
A wildcard certificate cannot be validated over HTTP-01/TLS-ALPN-01, it needs
the DNS challenge. Set LT_CADDY_DNS_PROVIDER to the dns directive name (e.g.
cloudflare, matching the module compiled into the Caddy image), or clear
LT_TUNNEL_DOMAIN to disable HTTP/HTTPS tunnels.
'@
}

$required = @(
    'LT_GATEWAY_PORT', 'LT_KCP_PORT', 'LT_VHOST_HTTP_PORT', 'LT_VHOST_HTTPS_PORT',
    'LT_FRPS_TOKEN', 'LT_PORT_RANGE_START', 'LT_PORT_RANGE_END', 'LT_MAX_PORTS_PER_USER',
    'LT_FRPS_API_PORT', 'LT_FRPS_API_USER', 'LT_FRPS_API_PASSWORD',
    'LT_USER_PORT'
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

# ---- HTTPS tunnel mode ----
# edge: the certificate stays in Caddy, which terminates TLS with the wildcard
#       certificate and forwards plain HTTP to vhostHTTPPort.
# e2e : the certificate stays on the local site; frps passes the raw TLS
#       connection through on vhostHTTPSPort, which must be open to the public.
#
# Placed after the required-value check on purpose: in e2e mode the port is
# derived from LT_VHOST_HTTPS_PORT, and a missing value there would silently
# look like "e2e not configured" instead of "you forgot to fill in the port"
# (which is already reported above).
$vars['LT_HTTPS_TUNNEL_MODE'] = if ($vars['LT_HTTPS_TUNNEL_MODE']) { $vars['LT_HTTPS_TUNNEL_MODE'] } else { 'edge' }
$vars['LT_HTTPS_E2E_PORT'] = ''
switch ($vars['LT_HTTPS_TUNNEL_MODE']) {
    'edge' { }
    'e2e'  { $vars['LT_HTTPS_E2E_PORT'] = $vars['LT_VHOST_HTTPS_PORT'] }
    default {
        throw "LT_HTTPS_TUNNEL_MODE must be edge or e2e, got '$($vars['LT_HTTPS_TUNNEL_MODE'])'."
    }
}

# ---- Conditionals ----
# Lines wrapped in "# @if VAR" / "# @endif" are dropped entirely when VAR is
# empty. Substituting an empty value instead would leave a site block whose
# address line is blank, and Caddy refuses to load the whole file over that:
# one optional value left unset would take the entire reverse proxy down.
# Only one expression is supported: "VAR is non-empty". Nesting works.
function Apply-Conditionals([string[]]$lines, [hashtable]$values) {
    $out = New-Object System.Collections.Generic.List[string]
    $states = '1'   # one char per nesting level: 1 = keep, 0 = drop
    foreach ($line in $lines) {
        if ($line -match '^\s*#\s*@if\s+([A-Za-z0-9_]+)\s*$') {
            $v = $values[$Matches[1]]
            if ($states[-1] -eq '1' -and -not [string]::IsNullOrWhiteSpace($v)) {
                $states += '1'
            } else {
                $states += '0'
            }
            continue
        }
        if ($line -match '^\s*#\s*@endif\s*$') {
            if ($states.Length -gt 1) { $states = $states.Substring(0, $states.Length - 1) }
            continue
        }
        if ($states[-1] -eq '1') { $out.Add($line) }
    }
    return $out
}

# ---- Render ----
function Render([string]$template, [string]$output, [hashtable]$values) {
    $raw      = Get-Content -LiteralPath $template -Raw -Encoding UTF8
    $eol      = if ($raw.Contains("`r`n")) { "`r`n" } else { "`n" }
    $trailing = $raw.EndsWith("`n")
    $lines    = [regex]::Split($raw, "`r?`n")
    if ($trailing -and $lines.Count -gt 1) {
        # Drop the empty element produced by the final newline.
        $lines = $lines[0..($lines.Count - 2)]
    }

    $text = ((Apply-Conditionals -lines $lines -values $values) -join $eol)
    if ($trailing) { $text += $eol }

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
Write-Host '     7001/TCP and 7002/UDP in your firewall / security group only.'
Write-Host '  2) From the repository root run:'
Write-Host '     docker compose --env-file .env -f deploy/docker-compose.yml pull'
Write-Host '     docker compose --env-file .env -f deploy/docker-compose.yml up -d'
Write-Host '     (--env-file is required: .env lives in the repository root while the'
Write-Host '      default lookup only looks next to the compose file)'
if ($vars['LT_HTTPS_E2E_PORT']) {
    Write-Host '  3) End-to-end HTTPS is enabled (LT_HTTPS_TUNNEL_MODE=e2e):'
    Write-Host "     - open $($vars['LT_HTTPS_E2E_PORT'])/TCP, the certificate lives on the local site"
    Write-Host "     - reach HTTPS tunnels at <sub>.$($vars['LT_TUNNEL_DOMAIN']):$($vars['LT_HTTPS_E2E_PORT'])"
    Write-Host '       (443 is served by Caddy and returns the platform certificate)'
}
