# Lab-extended soak (default 120s). Not a dedicated-hardware published envelope.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Bin = if ($args.Count -ge 1) { $args[0] } else { ".\target\debug\a3s-gateway.exe" }
if (-not (Test-Path $Bin)) {
  Write-Host "building a3s-gateway..."
  cargo build --bin a3s-gateway
  $Bin = ".\target\debug\a3s-gateway.exe"
}

$Dur = if ($env:A3S_GATEWAY_SOAK_DURATION) { $env:A3S_GATEWAY_SOAK_DURATION } else { "120" }
$C = if ($env:A3S_GATEWAY_SOAK_CONCURRENCY) { $env:A3S_GATEWAY_SOAK_CONCURRENCY } else { "8" }

function Invoke-Python {
  param([string[]]$PythonArgs)
  if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 @PythonArgs
  } elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    & python3 @PythonArgs
  } else {
    & python @PythonArgs
  }
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

foreach ($profile in @("http-json", "sse-finite", "openai-json", "openai-sse")) {
  Invoke-Python @(
    "scripts/soak-gateway.py",
    "--bin", $Bin,
    "--profile", $profile,
    "--duration", $Dur,
    "--concurrency", $C,
    "--envelope-status", "lab-extended"
  )
}
Write-Host "soak-gateway lab-extended: OK"
