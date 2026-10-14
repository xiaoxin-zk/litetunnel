# ============================================================
#  一键构建：控制面 + 两个控制台 + Windows 客户端
#
#  用法（在仓库根目录执行）：
#     powershell -ExecutionPolicy Bypass -File scripts/build.ps1
#     powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -SkipClient
# ============================================================
param(
    [switch]$SkipClient,
    [switch]$SkipWeb
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$env:GOPROXY = if ($env:GOPROXY) { $env:GOPROXY } else { 'https://goproxy.cn,direct' }

function Step([string]$name, [scriptblock]$action) {
    Write-Host ''
    Write-Host "==> $name" -ForegroundColor Cyan
    & $action
    if ($LASTEXITCODE -ne 0) { throw "$name 失败（退出码 $LASTEXITCODE）" }
}

# ---- 1. 控制面 ----
Step '构建控制面 (server)' {
    Push-Location (Join-Path $root 'server')
    try {
        go mod tidy
        go vet ./...
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'bin') | Out-Null
        go build -trimpath -ldflags="-s -w" -o (Join-Path $root 'bin/panel.exe') ./cmd/panel
        Write-Host '输出: bin/panel.exe'
    } finally {
        Pop-Location
    }
}

# ---- 2. 前端 ----
if (-not $SkipWeb) {
    foreach ($app in @('user', 'admin')) {
        Step "构建前端 ($app)" {
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

# ---- 3. Windows 客户端 ----
if (-not $SkipClient) {
    Step '构建 Windows 客户端 (Wails)' {
        if (-not (Get-Command wails -ErrorAction SilentlyContinue)) {
            Write-Host '未检测到 wails CLI，正在安装…' -ForegroundColor Yellow
            go install github.com/wailsapp/wails/v2/cmd/wails@latest
            $env:PATH = "$env:PATH;$env:USERPROFILE\go\bin"
        }
        Push-Location (Join-Path $root 'client/windows')
        try {
            wails build -clean -platform windows/amd64
            Write-Host '输出: client/windows/build/bin/LiteTunnel.exe'
            Write-Host '提示：请把官方 frpc.exe 放到该 exe 同目录，客户端会自动识别。' -ForegroundColor Yellow
        } finally {
            Pop-Location
        }
    }
}

Write-Host ''
Write-Host '构建完成。' -ForegroundColor Green
