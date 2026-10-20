<#
.SYNOPSIS
  Configure and build ai_prompt_guard.dll (+ import library), the CLI, the tests and the examples with MSVC (x64, Release).

.DESCRIPTION
  This script NEVER installs anything, never touches PATH or the registry and never writes dependencies anywhere:
  it looks for the tools and libraries you point it to, reports what is missing, and builds into -BuildDir.
  Hyperscan on Windows is the biggest risk of this port (see docs/windows-build.md): if you have no Hyperscan build,
  use -NoHyperscan to build the explicit pcre2_fallback backend (functionally equivalent, slower, reported as
  "pcre2_fallback" in every result).

.PARAMETER BuildDir        Build directory (default: build\windows, or build\windows-fallback with -NoHyperscan)
.PARAMETER Config          Release (default) or Debug
.PARAMETER PrefixPath      Extra CMAKE_PREFIX_PATH entries (directories that contain include\ and lib\)
.PARAMETER HyperscanRoot   Prefix that contains include\hs\hs.h and lib\hs.lib
.PARAMETER Pcre2Root       Prefix that contains include\pcre2.h and lib\pcre2-8.lib
.PARAMETER VcpkgToolchain  Path of vcpkg's scripts\buildsystems\vcpkg.cmake (if you installed the libraries with vcpkg)
.PARAMETER Generator       CMake generator (default: "Visual Studio 17 2022")
.PARAMETER NoHyperscan     Build without Hyperscan (pcre2_fallback backend only)
.PARAMETER StaticRuntime   Link the static MSVC runtime (/MT) instead of the DLL runtime (/MD)
.PARAMETER CheckOnly       Only report which tools / libraries were found

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\windows\build.ps1 -CheckOnly
.EXAMPLE
  powershell -File scripts\windows\build.ps1 -VcpkgToolchain D:\tools\vcpkg\scripts\buildsystems\vcpkg.cmake
.EXAMPLE
  powershell -File scripts\windows\build.ps1 -NoHyperscan -Pcre2Root D:\libs\pcre2
#>
[CmdletBinding()]
param(
  [string]$BuildDir = "",
  [ValidateSet("Release", "Debug")][string]$Config = "Release",
  [string[]]$PrefixPath = @(),
  [string]$HyperscanRoot = "",
  [string]$Pcre2Root = "",
  [string]$VcpkgToolchain = "",
  [string]$Generator = "Visual Studio 17 2022",
  [switch]$NoHyperscan,
  [switch]$StaticRuntime,
  [switch]$CheckOnly
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not $BuildDir) { $BuildDir = if ($NoHyperscan) { "build\windows-fallback" } else { "build\windows" } }
if (-not [System.IO.Path]::IsPathRooted($BuildDir)) { $BuildDir = Join-Path $Root $BuildDir }

function Say($tag, $msg) { Write-Host ("  [{0}] {1}" -f $tag, $msg) }
$missing = @()

Write-Host "== tools"
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if (-not $cmake) {
  foreach ($p in @("$env:ProgramFiles\CMake\bin\cmake.exe")) { if (Test-Path $p) { $cmake = Get-Item $p } }
}
if ($cmake) {
  $cmakePath = if ($cmake.Source) { $cmake.Source } else { $cmake.FullName }
  Say " ok " "cmake: $cmakePath"
} else {
  Say "MISS" "cmake (>= 3.16) not found"; $missing += "cmake"
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = $null
if (Test-Path $vswhere) {
  $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
}
if ($vsPath) { Say " ok " "MSVC (x64 C++ tools): $vsPath" } else { Say "MISS" "Visual Studio / Build Tools with the 'C++ x64/x86 build tools' component"; $missing += "MSVC" }

Write-Host "== libraries (searched in the given roots, CMAKE_PREFIX_PATH and the vcpkg installed tree)"
$roots = @() + $PrefixPath
foreach ($r in @($HyperscanRoot, $Pcre2Root)) { if ($r) { $roots += $r } }
if ($VcpkgToolchain) {
  $vcpkgRoot = Split-Path (Split-Path (Split-Path $VcpkgToolchain))
  $roots += (Join-Path $vcpkgRoot "installed\x64-windows"), (Join-Path $vcpkgRoot "installed\x64-windows-static")
}
function Find-Header($rel) { foreach ($r in $roots) { if (Test-Path (Join-Path $r ("include\" + $rel))) { return $r } } return $null }
$libs = @(@{ Name = "PCRE2 (8-bit)"; Header = "pcre2.h" })
if (-not $NoHyperscan) { $libs = @(@{ Name = "Hyperscan"; Header = "hs\hs.h" }) + $libs }
foreach ($l in $libs) {
  $where = Find-Header $l.Header
  if ($where) { Say " ok " ("{0}: {1}" -f $l.Name, $where) } else { Say "MISS" ("{0} ({1}) not found in the given roots" -f $l.Name, $l.Header); $missing += $l.Name }
}

if ($missing.Count -gt 0) {
  Write-Host ""
  Write-Host "Missing: $($missing -join ', ')" -ForegroundColor Yellow
  Write-Host "Nothing is installed by this script. Options (see docs\windows-build.md):"
  Write-Host "  * vcpkg (installs into the vcpkg directory you choose, not into C:\ unless you cloned vcpkg there):"
  Write-Host "      vcpkg install pcre2:x64-windows hyperscan:x64-windows"
  Write-Host "      then pass  -VcpkgToolchain <vcpkg>\scripts\buildsystems\vcpkg.cmake"
  Write-Host "  * a Hyperscan you built yourself:  -HyperscanRoot <prefix>"
  Write-Host "  * no Hyperscan available:           -NoHyperscan   (explicit pcre2_fallback backend)"
}
if ($CheckOnly) { exit $(if ($missing.Count -gt 0) { 1 } else { 0 }) }
if ($missing.Count -gt 0) { throw "missing prerequisites: $($missing -join ', ')" }

$hs = if ($NoHyperscan) { "OFF" } else { "ON" }
$cfg = @("-S", $Root, "-B", $BuildDir, "-G", $Generator, "-A", "x64", "-DAPG_WITH_HYPERSCAN=$hs")
if ($StaticRuntime) { $cfg += "-DAPG_STATIC_RUNTIME=ON" }
if ($VcpkgToolchain) { $cfg += "-DCMAKE_TOOLCHAIN_FILE=$VcpkgToolchain" }
if ($roots.Count -gt 0) { $cfg += ("-DCMAKE_PREFIX_PATH=" + (($roots | ForEach-Object { $_ -replace "\\", "/" }) -join ";")) }
if ($HyperscanRoot) { $cfg += "-DHYPERSCAN_ROOT=$HyperscanRoot" }
if ($Pcre2Root) { $cfg += "-DPCRE2_ROOT=$Pcre2Root" }
Write-Host "== configure: cmake $($cfg -join ' ')"
& cmake @cfg
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed (exit $LASTEXITCODE)" }
Write-Host "== build ($Config)"
& cmake --build $BuildDir --config $Config --parallel
if ($LASTEXITCODE -ne 0) { throw "build failed (exit $LASTEXITCODE)" }

$out = Join-Path $BuildDir ("bin\" + $Config)
Write-Host ""
Write-Host "Built into $out" -ForegroundColor Green
Get-ChildItem $out -Include "ai_prompt_guard.*", "ai-prompt-guard.exe", "apg_tests.exe" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.Name)" }
Write-Host "Dependent DLLs (Hyperscan, PCRE2, VC runtime) must be next to ai_prompt_guard.dll or on the DLL search path of the process."
Write-Host "Next: scripts\windows\test.ps1"
