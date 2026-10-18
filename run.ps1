# ─────────────────────────────────────────────────────────────────────────────
#  KB-Desk  ·  run.ps1   (Windows PowerShell)
#
#  One command to build (first time only) and start KB-Desk.
#
#     .\run.ps1              # relay + host + web viewer  (viewers need only an ID)
#     .\run.ps1 web          # host + web viewer, no relay
#     .\run.ps1 serve        # relay + web viewer (server: control hosts from any browser)
#     .\run.ps1 host         # share this screen (direct)
#     .\run.ps1 relay        # run the relay server only
#     .\run.ps1 viewer       # native desktop viewer
#
#  Any options pass through to the launcher, e.g.
#     .\run.ps1 up --password secret --web-port 8080
#
#  Force a rebuild with:  $env:KB_DESK_REBUILD=1; .\run.ps1
# ─────────────────────────────────────────────────────────────────────────────
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "KB-Desk needs Rust to build. Install it from https://rustup.rs and re-run." -ForegroundColor Red
    exit 1
}

$bin = Join-Path $root "target\release\kbdesk.exe"
if (-not (Test-Path $bin) -or $env:KB_DESK_REBUILD) {
    Write-Host "Building KB-Desk (first run only; this can take a few minutes)..."
    cargo build --release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

& $bin @args
