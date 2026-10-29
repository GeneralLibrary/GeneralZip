# GeneralZip one-shot build script
# Usage:
#   .\build\build.ps1              # native core + managed solution + all tests
#   .\build\build.ps1 -SkipNative  # managed only
#   .\build\build.ps1 -NoTest      # build only

param(
    [switch]$SkipNative,
    [switch]$NoTest
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

Write-Host "=== GeneralZip Build ===" -ForegroundColor Cyan
Write-Host "repo: $repoRoot"

# ---------- 0) prerequisites ----------
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
$rustupToolchainBin = "$env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained"
$dlltoolShim = Join-Path $repoRoot "native\dlltool-shim-rs\target\release\gzdlltool.exe"

if (-not $SkipNative) {
    if (-not $cargo) {
        Write-Warning "cargo not found. Install Rust (GNU toolchain recommended):"
        Write-Host '  $env:RUSTUP_DIST_SERVER="https://rsproxy.cn"; $env:RUSTUP_UPDATE_ROOT="https://rsproxy.cn/rustup"'
        Write-Host '  rustup-init.exe -y --default-toolchain stable-x86_64-pc-windows-gnu --profile minimal'
        Write-Warning "Skipping native core build (managed parts continue)."
        $SkipNative = $true
    }
}

# ---------- 1) Rust native core ----------
if (-not $SkipNative) {
    Write-Host ""
    Write-Host "--- [1/3] Rust native core (generalzip-native) ---" -ForegroundColor Yellow

    # windows-gnu bundled dlltool lacks as.exe: use the Rust shim (native/dlltool-shim-rs)
    if (-not (Test-Path $dlltoolShim)) {
        Write-Host "Building dlltool shim (Rust, one-time)..."
        Push-Location (Join-Path $repoRoot "native\dlltool-shim-rs")
        cargo build --release
        Pop-Location
    }

    $env:PATH = "$env:USERPROFILE\.cargo\bin;$rustupToolchainBin;$env:PATH"
    $env:RUSTFLAGS = "-C dlltool=$dlltoolShim"

    Push-Location (Join-Path $repoRoot "native\generalzip-native")
    try {
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    }
    finally { Pop-Location }

    # drop artifact under runtimes/win-x64/native (for packaging)
    $nativeOut = Join-Path $repoRoot "src\GeneralZip.Native\runtimes\win-x64\native"
    New-Item -ItemType Directory -Force -Path $nativeOut | Out-Null
    Copy-Item (Join-Path $repoRoot "native\generalzip-native\target\release\generalzip_native.dll") $nativeOut -Force
    Write-Host "native core ready: $nativeOut\generalzip_native.dll"
}
else {
    Write-Host ""
    Write-Host "--- [1/3] skipped Rust native core ---" -ForegroundColor DarkGray
}

# ---------- 2) managed solution ----------
Write-Host ""
Write-Host "--- [2/3] dotnet build ---" -ForegroundColor Yellow
dotnet build (Join-Path $repoRoot "GeneralZip.slnx") --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "dotnet build failed" }

# ---------- 3) tests ----------
if (-not $NoTest) {
    Write-Host ""
    Write-Host "--- [3/3] dotnet test ---" -ForegroundColor Yellow
    dotnet test (Join-Path $repoRoot "tests\GeneralZip.Tests\GeneralZip.Tests.csproj") --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "core tests failed" }

    dotnet test (Join-Path $repoRoot "tests\GeneralZip.Native.Tests\GeneralZip.Native.Tests.csproj") --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "native integration tests failed" }
}

Write-Host ""
Write-Host "=== Build OK ===" -ForegroundColor Green
