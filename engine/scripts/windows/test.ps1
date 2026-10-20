<#
.SYNOPSIS
  The engine's own tests on Windows: the C++ unit tests (apg_tests.exe, incl. the C ABI, hot reload, concurrency, compiler).

.DESCRIPTION
  No benchmark is started. The engine tests need no rule database and no Python; how a real rule set behaves is tested by
  the rules project (rules/tests) with the engine you built.

.EXAMPLE
  powershell -File scripts\windows\test.ps1 -BuildDir build\windows-fallback
#>
[CmdletBinding()]
param(
  [string]$BuildDir = "build\windows",
  [ValidateSet("Release", "Debug")][string]$Config = "Release"
)
$ErrorActionPreference = "Continue"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not [System.IO.Path]::IsPathRooted($BuildDir)) { $BuildDir = Join-Path $Root $BuildDir }
$tests = Join-Path (Join-Path $BuildDir ("bin\" + $Config)) "apg_tests.exe"
if (-not (Test-Path $tests)) { throw "$tests not found: run scripts\windows\build.ps1 first" }
Write-Host "== C++ unit tests (apg_tests.exe)"
Push-Location $Root
& $tests
$rc = $LASTEXITCODE
Pop-Location
if ($rc -eq 0) { Write-Host "ALL TESTS PASSED" -ForegroundColor Green } else { Write-Host "SOME TESTS FAILED" -ForegroundColor Red }
exit $rc
