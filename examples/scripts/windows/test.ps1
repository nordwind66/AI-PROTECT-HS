<#
.SYNOPSIS
  Functional tests on Windows: CTest (C++ unit tests incl. the C ABI), the Python rule-tooling tests, the end-to-end
  tests of the compiled CLI and the DLL (LoadLibrary / C / C++ examples).

.DESCRIPTION
  No benchmark is started. The rule database is copied first; the delivered data\ai_prompt_rules.db is not modified.
  Without Hyperscan on this machine pass -Backend pcre2_fallback (the build must have been made with -NoHyperscan).

.EXAMPLE
  powershell -File scripts\windows\test.ps1 -BuildDir build\windows-fallback -Backend pcre2_fallback
#>
[CmdletBinding()]
param(
  [string]$BuildDir = "build\windows",
  [ValidateSet("Release", "Debug")][string]$Config = "Release",
  [ValidateSet("hyperscan", "pcre2_fallback", "both")][string]$Backend = "hyperscan",
  [string]$Db = "",
  [switch]$NoE2E
)
$ErrorActionPreference = "Continue"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not [System.IO.Path]::IsPathRooted($BuildDir)) { $BuildDir = Join-Path $Root $BuildDir }
if (-not $Db) { $Db = Join-Path $Root "data\ai_prompt_rules.db" }
$out = Join-Path $BuildDir ("bin\" + $Config)
$cli = Join-Path $out "ai-prompt-guard.exe"
$dll = Join-Path $out "ai_prompt_guard.dll"
$tests = Join-Path $out "apg_tests.exe"
foreach ($f in @($cli, $dll, $tests)) { if (-not (Test-Path $f)) { throw "$f not found: run scripts\windows\build.ps1 first" } }
$py = Get-Command python -ErrorAction SilentlyContinue
$failed = $false

Write-Host "== C++ unit tests (apg_tests.exe)"
Push-Location $Root
& $tests
if ($LASTEXITCODE -ne 0) { $failed = $true }
Pop-Location

if ($py) {
  Write-Host "== Python unit tests of the rule tooling"
  Push-Location $Root
  & $py.Source -X utf8 -m unittest discover -s tests/python
  if ($LASTEXITCODE -ne 0) { $failed = $true }
  Pop-Location
} else {
  Write-Host "python not found: Python tests and end-to-end tests are SKIPPED" -ForegroundColor Yellow
}

if ($py -and -not $NoE2E) {
  Write-Host "== end-to-end: compile, load, differential test, tamper, release flow, examples (backend: $Backend)"
  $work = Join-Path $BuildDir "e2e"
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  $dbCopy = Join-Path $work "rules.db"
  Copy-Item -Force $Db $dbCopy
  Push-Location $Root
  & $py.Source -X utf8 tests\e2e\run_e2e.py --cli $cli --workdir (Join-Path $work "work") --db $dbCopy --backend $Backend `
      --lib $dll --examples-dir $out --clean --report (Join-Path $work "report.json")
  if ($LASTEXITCODE -ne 0) { $failed = $true }
  Pop-Location
}

Write-Host ""
if ($failed) { Write-Host "SOME TESTS FAILED (see above)" -ForegroundColor Red; exit 1 }
Write-Host "ALL TESTS PASSED" -ForegroundColor Green
