# ============================================================
#  Optional LOCAL build helper.
#
#  The canonical build runs in GitHub Actions:
#     - CI       : .github/workflows/ci.yml
#     - Release  : .github/workflows/release.yml  (tag v* -> GHCR + release assets)
#
#  Use this script only when you need a local artifact for debugging.
#
#  NOTE: this file must stay ASCII-only. Windows PowerShell 5.1 reads
#  BOM-less .ps1 files as ANSI, and non-ASCII text would break parsing.
#
#  Usage (run from the repository root):
#     powershell -ExecutionPolicy Bypass -File scripts/build.ps1
#     powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -SkipClient
# ============================================================
param(
    [switch]$SkipClient,
    [switch]$SkipWeb
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $env:GOPROXY) { $env:GOPROXY = 'https://goproxy.cn,direct' }

function Step([string]$name, [scriptblock]$action) {
    Write-Host ''
    Write-Host "==> $name" -ForegroundColor Cyan
    & $action
    if ($LASTEXITCODE -ne 0) { throw "$name failed with exit code $LASTEXITCODE" }
}

Step 'Build server' {
    Push-Location (Join-Path $root 'server')
    try {
        go mod tidy
        go vet ./...
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'bin') | Out-Null
        go build -trimpath -ldflags '-s -w' -o (Join-Path $root 'bin\panel.exe') ./cmd/panel
        Write-Host 'Output: bin/panel.exe'
    } finally {
        Pop-Location
    }
}

if (-not $SkipWeb) {
    foreach ($app in @('user', 'admin')) {
        Step "Build web ($app)" {
            Push-Location (Join-Path $root "web/$app")
            try {
                if (-not (Test-Path 'node_modules')) { npm install --no-audit --no-fund }
                npm run build
            } finally {
                Pop-Location
            }
        }
    }
}

if (-not $SkipClient) {
    Step 'Build Windows client (Wails)' {
        if (-not (Get-Command wails -ErrorAction SilentlyContinue)) {
            Write-Host 'Wails CLI not found, installing...' -ForegroundColor Yellow
            go install github.com/wailsapp/wails/v2/cmd/wails@latest
            $env:PATH = $env:PATH + ';' + (Join-Path $env:USERPROFILE 'go\bin')
        }
        Push-Location (Join-Path $root 'client/windows')
        try {
            go mod tidy
            wails build -clean -platform windows/amd64
            Write-Host 'Output: client/windows/build/bin/LiteTunnel.exe'
            Write-Host 'Hint: put the official frpc.exe next to it.' -ForegroundColor Yellow
        } finally {
            Pop-Location
        }
    }
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
