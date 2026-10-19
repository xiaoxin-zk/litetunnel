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

function Split-PublicUrl([string]$raw) {
    if ([string]::IsNullOrWhiteSpace($raw)) { return @{ Scheme = 'https'; Domain = '' } }
    $scheme = 'https'
    if ($raw.StartsWith('http://', [System.StringComparison]::OrdinalIgnoreCase)) {
        $scheme = 'http'
    } elseif ($raw.StartsWith('https://', [System.StringComparison]::OrdinalIgnoreCase)) {
        $scheme = 'https'
    } elseif ($raw -match '://') {
        throw 'LT_USER_PUBLIC_URL only supports http or https.'
    }
    $domain = ($raw -replace '^https?://', '').TrimEnd('/')
    return @{ Scheme = $scheme; Domain = $domain }
}

$publicUrl = Split-PublicUrl $vars['LT_USER_PUBLIC_URL']
$userDomain = $publicUrl.Domain
$vars['LT_USER_SCHEME'] = $publicUrl.Scheme

if ([string]::IsNullOrWhiteSpace($userDomain)) {
    throw 'LT_USER_PUBLIC_URL is empty: the panel needs a public address.'
}

$vars['LT_USER_DOMAIN'] = $userDomain
if ($vars['LT_USER_SCHEME'] -eq 'https') {
    $vars['LT_HSTS_ON'] = '1'
} else {
    $vars['LT_HSTS_ON'] = ''
    Write-Warning 'LT_USER_PUBLIC_URL uses HTTP: Caddy will not request a certificate and credentials travel in plaintext.'
}
# Admin console shares the user domain; only the optional IP allowlist placeholder remains.
$vars['LT_ADMIN_ALLOW_CIDR'] = if ($vars['LT_ADMIN_ALLOW_CIDR']) { $vars['LT_ADMIN_ALLOW_CIDR'] } else { '127.0.0.1/32' }
$vars['LT_ACME_EMAIL']       = if ($vars['LT_ACME_EMAIL']) { $vars['LT_ACME_EMAIL'] } else { "admin@$userDomain" }
$vars['LT_TUNNEL_DOMAIN']    = if ($vars['LT_TUNNEL_DOMAIN']) { $vars['LT_TUNNEL_DOMAIN'] } else { '' }

# Domain rules must match the panel's checkDomain (server/internal/service/tlsconfig.go):
# bare domain only, at least two labels (IPv4 passes), total <= 253, each label
# 1-63 chars of [a-z0-9-] and not starting/ending with '-'.
function Assert-Domain([string]$name, [string]$d) {
    if ([string]::IsNullOrEmpty($d)) { return }
    if ($d -match '[\s/\\*]') {
        throw "$name=$d contains illegal characters (bare domain only: no scheme, path or *)."
    }
    if ($d.Length -gt 253) {
        throw "$name=$d is longer than 253 characters."
    }
    $labels = $d.Split('.')
    if ($labels.Count -lt 2) {
        throw "$name=$d is not a full domain (needs at least two labels, e.g. panel.example.com)."
    }
    foreach ($l in $labels) {
        if ([string]::IsNullOrEmpty($l)) {
            throw "$name=$d contains an empty label."
        }
        if ($l.Length -gt 63) {
            throw "$name=$d has a label '$l' longer than 63 characters."
        }
        if ($l.StartsWith('-') -or $l.EndsWith('-')) {
            throw "$name=$d has a label '$l' that starts or ends with '-'."
        }
        if ($l -notmatch '^[a-z0-9-]+$') {
            throw "$name=$d has a label '$l' outside [a-z0-9-]."
        }
    }
}

Assert-Domain 'LT_USER_DOMAIN' $userDomain
Assert-Domain 'LT_TUNNEL_DOMAIN' $vars['LT_TUNNEL_DOMAIN']
if ($vars['LT_TUNNEL_DOMAIN'] -and $vars['LT_TUNNEL_DOMAIN'] -eq $userDomain) {
    throw 'LT_TUNNEL_DOMAIN must differ from the panel domain: a wildcard certificate would cover the panel itself.'
}

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

# frps listens on the vhost ports on every interface (proxyBindAddr also binds the
# tunnel port pool, so it cannot be narrowed to loopback). They must therefore never
# collide with a public entry point or with the tunnel pool.
function Assert-VhostPort([string]$name, [string]$value, [string]$other) {
    if ([string]::IsNullOrWhiteSpace($value)) { return }
    $port = 0
    # 与 render.sh 一致：只接受十进制数字文本，+7848 等写法直接拒绝，
    # 避免跨平台对同一份 .env 得出不同的冲突判断。
    if ($value -notmatch '^\d+$' -or -not [int]::TryParse($value, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        throw "$name=$value is not a decimal port between 1 and 65535."
    }
    # Every port this host actually listens on: a collision fails at startup.
    $conflicts = @(
        $vars['LT_GATEWAY_PORT'], $vars['LT_KCP_PORT'], $other,
        $vars['LT_USER_PORT'], $vars['LT_FRPS_API_PORT'], '80', '443'
    ) | Where-Object { $_ }
    foreach ($c in $conflicts) {
        $cp = 0
        if ([int]::TryParse([string]$c, [ref]$cp) -and $cp -eq $port) {
            throw "$name=$value collides with another listening port."
        }
    }
    $start = [int]$vars['LT_PORT_RANGE_START']
    $end = [int]$vars['LT_PORT_RANGE_END']
    if ($port -ge $start -and $port -le $end) {
        throw "$name=$value falls inside the tunnel port pool $start-$end. Choose a port outside it."
    }
}

Assert-VhostPort 'LT_VHOST_HTTP_PORT' $vars['LT_VHOST_HTTP_PORT'] $vars['LT_VHOST_HTTPS_PORT']
Assert-VhostPort 'LT_VHOST_HTTPS_PORT' $vars['LT_VHOST_HTTPS_PORT'] $vars['LT_VHOST_HTTP_PORT']

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

# The generated files carry the frps token and the API password, so they must
# not stay readable by every local account. Inherited NTFS ACLs usually grant
# Users:Read, so pin each file to the current user - the equivalent of
# render.sh's `umask 077` and explicit `chmod 600`.
function Set-OwnerOnly([string]$path) {
    if ($env:OS -ne 'Windows_NT') {
        & chmod 600 $path
        if ($LASTEXITCODE -ne 0) { throw "chmod 600 $path failed" }
        return
    }
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $path /inheritance:r /grant:r "${me}:(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed to restrict $path to $me" }
}

# Render into a hidden temp file next to the target and commit only once every
# template rendered cleanly. Writing straight to the output would leave
# "frps new / Caddy old" behind when the second render throws, and that mixed
# pair looks exactly like a successful run.
$pendingTmp = New-Object System.Collections.Generic.List[string]
$pendingOut = New-Object System.Collections.Generic.List[string]

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

    $tmp = Join-Path (Split-Path -Parent $output) ('.' + (Split-Path -Leaf $output) + '.tmp.' + $PID)
    [IO.File]::WriteAllText($tmp, $text, [System.Text.UTF8Encoding]::new($false))
    Set-OwnerOnly $tmp
    $pendingTmp.Add($tmp)
    $pendingOut.Add($output)
}

# Replacing inside one directory is atomic on NTFS. File.Replace needs an
# existing destination, and the first run has none, so fall back to Move.
function Commit-Rendered([string]$tmp, [string]$output) {
    if (Test-Path -LiteralPath $output) {
        [IO.File]::Replace($tmp, $output, $null)
    } else {
        [IO.File]::Move($tmp, $output)
    }
    Set-OwnerOnly $output
    Write-Host "Generated $output"
}

try {
    Render $frpsTpl  $frpsOut  $vars
    Render $caddyTpl $caddyOut $vars
    for ($i = 0; $i -lt $pendingTmp.Count; $i++) {
        Commit-Rendered $pendingTmp[$i] $pendingOut[$i]
    }
} finally {
    # $ErrorActionPreference = 'Stop' unwinds through here on any failure: no
    # half-written file may survive in the deployment directory.
    foreach ($t in $pendingTmp) {
        if (Test-Path -LiteralPath $t) {
            Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host ''
Write-Host 'Done. Next steps:'
Write-Host '  1) Open port 80 (plus 443 when using HTTPS), the tunnel port pool'
Write-Host '     (default 20000-30000), 7001/TCP and 7002/UDP in your firewall.'
Write-Host '  2) From the repository root run:'
Write-Host '     docker compose --env-file .env -f deploy/docker-compose.yml pull'
Write-Host '     docker compose --env-file .env -f deploy/docker-compose.yml up -d'
Write-Host '     (--env-file is required: .env lives in the repository root while the'
Write-Host '      default lookup only looks next to the compose file)'
if ($vars['LT_USER_SCHEME'] -eq 'https') {
    Write-Host "  3) Console: https://$($vars['LT_USER_DOMAIN'])/"
} else {
    Write-Host "  3) Console: http://$($vars['LT_USER_DOMAIN'])/ (plaintext, no certificate)"
}
if ($vars['LT_HTTPS_E2E_PORT']) {
    Write-Host '  4) End-to-end HTTPS is enabled (LT_HTTPS_TUNNEL_MODE=e2e):'
    Write-Host "     - open $($vars['LT_HTTPS_E2E_PORT'])/TCP, the certificate lives on the local site"
    Write-Host "     - reach HTTPS tunnels at <sub>.$($vars['LT_TUNNEL_DOMAIN']):$($vars['LT_HTTPS_E2E_PORT'])"
    Write-Host '       (443 is served by Caddy and returns the platform certificate)'
}
