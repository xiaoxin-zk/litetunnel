# ============================================================
#  Fixture for deploy/scripts/render.ps1.
#
#  The shell/PowerShell renderers are the only place where the deployment
#  secrets turn into files, and nothing else in CI exercises them. This
#  fixture pins the three properties that are easy to break and expensive to
#  notice:
#    - the generated files are owner-only (token + API password inside);
#    - a template that fails to render leaves the previous files untouched;
#    - no .tmp/.bak leftovers survive in the deployment directory.
#
#  Keep this file ASCII-only: Windows PowerShell 5.1 reads BOM-less .ps1 as
#  ANSI and non-ASCII text breaks parsing.
#
#  Usage: pwsh -File scripts/test-render.ps1
# ============================================================

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$work = Join-Path ([IO.Path]::GetTempPath()) ('lt-render-' + [guid]::NewGuid().ToString('N'))
$failures = 0

function Fail([string]$message) {
    Write-Host "  FAIL: $message" -ForegroundColor Red
    $script:failures++
}

function Ok([string]$message) {
    Write-Host "  ok: $message"
}

function New-Fixture([string]$name) {
    $dir = Join-Path $script:work $name
    New-Item -ItemType Directory -Force -Path (Join-Path $dir 'deploy/scripts') | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $dir 'deploy/frps') | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $dir 'deploy/caddy') | Out-Null
    Copy-Item (Join-Path $repo 'deploy/scripts/render.ps1') (Join-Path $dir 'deploy/scripts/render.ps1')
    Copy-Item (Join-Path $repo 'deploy/frps/frps.toml.template') (Join-Path $dir 'deploy/frps/')
    Copy-Item (Join-Path $repo 'deploy/caddy/Caddyfile.template') (Join-Path $dir 'deploy/caddy/')

    # Derive the fixture .env from the real .env.example so newly required
    # variables are picked up automatically.
    $envText = Get-Content -LiteralPath (Join-Path $repo '.env.example') -Raw
    $envText = [regex]::Replace($envText, 'CHANGE_ME_[A-Za-z0-9_]*', 'fixture_secret_value')
    $envText = [regex]::Replace($envText, '(?m)^LT_USER_PUBLIC_URL=.*$', 'LT_USER_PUBLIC_URL=https://panel.example.com')
    $envText = [regex]::Replace($envText, '(?m)^LT_GATEWAY_HOST=.*$', 'LT_GATEWAY_HOST=gw.example.com')
    $envText = [regex]::Replace($envText, '(?m)^LT_ACME_EMAIL=.*$', 'LT_ACME_EMAIL=ops@example.com')
    Set-Content -LiteralPath (Join-Path $dir '.env') -Value $envText -NoNewline -Encoding UTF8
    return $dir
}

function Invoke-Render([string]$dir) {
    $log = Join-Path $dir 'render.log'
    $renderPath = Join-Path $dir 'deploy/scripts/render.ps1'
    $shell = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
    & $shell -NoProfile -ExecutionPolicy Bypass -File $renderPath *> $log
    return $LASTEXITCODE
}

function Get-FileMode([string]$path) {
    $acl = Get-Acl -LiteralPath $path
    $allowed = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' })
    return $acl.AreAccessRulesProtected, $allowed
}

try {
    Write-Host 'happy path'
    $dir = New-Fixture 'happy'
    $code = Invoke-Render $dir
    if ($code -ne 0) {
        Fail "render failed (exit $code): $((Get-Content -LiteralPath (Join-Path $dir 'render.log') -Raw))"
    } else {
        Ok 'render succeeded'
    }

    $frpsOut = Join-Path $dir 'deploy/frps/frps.toml'
    $caddyOut = Join-Path $dir 'deploy/caddy/Caddyfile'
    if (Test-Path -LiteralPath $frpsOut) { Ok 'frps.toml written' } else { Fail 'frps.toml missing' }
    if (Test-Path -LiteralPath $caddyOut) { Ok 'Caddyfile written' } else { Fail 'Caddyfile missing' }
    if ((Get-Content -LiteralPath $frpsOut -Raw) -match 'fixture_secret_value') {
        Ok 'token rendered'
    } else {
        Fail 'token not rendered into frps.toml'
    }

    # Owner-only: inheritance must be off and exactly one explicit Allow entry
    # (the current user). "icacls /inheritance:r" alone would leave inherited
    # Users:Read entries behind on some systems, which is what this asserts.
    $protected, $allowed = Get-FileMode $frpsOut
    if (-not $protected) { Fail 'ACL inheritance is still enabled on frps.toml' } else { Ok 'ACL inheritance disabled' }
    if ($allowed.Count -ne 1) {
        Fail "frps.toml has $($allowed.Count) explicit Allow entries, expected 1"
    } else {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        if ($allowed[0].IdentityReference.Value -eq $me) {
            Ok "only $me can access frps.toml"
        } else {
            Fail "frps.toml is granted to $($allowed[0].IdentityReference), expected $me"
        }
    }

    $leftovers = @(Get-ChildItem -Path (Join-Path $dir 'deploy') -Recurse -Force -File |
        Where-Object { $_.Name -like '.*.tmp.*' -or $_.Name -like '.*.bak.*' })
    if ($leftovers.Count -eq 0) { Ok 'no temp/backup leftovers' } else { Fail "$($leftovers.Count) temp/backup files left behind" }

    Write-Host 'dotenv quoting and $$ escaping'
    # A quoted multi-argument value must reach the template without quotes and
    # with $$ collapsed to $: otherwise Caddy receives one argument where it
    # expects two and refuses the whole Caddyfile, while the renderer says "ok".
    $dir2 = New-Fixture 'dotenv'
    $envPath = Join-Path $dir2 '.env'
    $text = Get-Content -LiteralPath $envPath -Raw
    $text = [regex]::Replace($text, '(?m)^LT_TUNNEL_DOMAIN=.*$', 'LT_TUNNEL_DOMAIN=tunnel.example.com')
    $text = [regex]::Replace($text, '(?m)^LT_CADDY_DNS_PROVIDER=.*$', 'LT_CADDY_DNS_PROVIDER=cloudflare')
    $text = [regex]::Replace($text, '(?m)^LT_CADDY_DNS_ARGS=.*$', 'LT_CADDY_DNS_ARGS="{env.CF_A} {env.CF_B} prefix$$suffix"')
    Set-Content -LiteralPath $envPath -Value $text -NoNewline -Encoding UTF8
    $code = Invoke-Render $dir2
    if ($code -ne 0) {
        Fail "dotenv fixture failed (exit $code): $((Get-Content -LiteralPath (Join-Path $dir2 'render.log') -Raw))"
    } else {
        $caddy2 = Get-Content -LiteralPath (Join-Path $dir2 'deploy/caddy/Caddyfile') -Raw
        if ($caddy2 -match 'dns cloudflare \{env\.CF_A\} \{env\.CF_B\} prefix\$suffix') {
            Ok 'quoted multi-arg value and $$ unescaped correctly'
        } else {
            Fail "unexpected dns line: $(($caddy2 -split "`n" | Where-Object { $_ -match '^\s*dns ' }) -join '|')"
        }
    }

    Write-Host 'unresolved placeholder keeps the previous files'
    $before = (Get-FileHash -LiteralPath $frpsOut -Algorithm SHA256).Hash
    Add-Content -LiteralPath (Join-Path $dir 'deploy/caddy/Caddyfile.template') -Value '${NOT_DEFINED_ANYWHERE}'
    $code = Invoke-Render $dir
    if ($code -eq 0) {
        Fail 'render should have failed on an unresolved placeholder'
    } else {
        Ok 'failed as expected'
    }
    $after = (Get-FileHash -LiteralPath $frpsOut -Algorithm SHA256).Hash
    if ($before -eq $after) { Ok 'frps.toml unchanged' } else { Fail 'frps.toml was partially updated' }
    $leftovers = @(Get-ChildItem -Path (Join-Path $dir 'deploy') -Recurse -Force -File |
        Where-Object { $_.Name -like '.*.tmp.*' -or $_.Name -like '.*.bak.*' })
    if ($leftovers.Count -eq 0) { Ok 'no temp/backup leftovers after failure' } else { Fail "$($leftovers.Count) temp files left behind after failure" }
} finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($failures -gt 0) {
    Write-Host "render.ps1 fixture failed: $failures check(s)" -ForegroundColor Red
    exit 1
}
Write-Host 'render.ps1 fixture passed'
