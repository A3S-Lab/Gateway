# Cross-platform Managed Runtime Service real OS-process evidence used by
# Enterprise GA smoke. Not Cloud EXIT; not a published capacity envelope.
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Filters = @(
  "real_os_process_upstream_survives_bind_health_traffic_drain_remove",
  "real_os_process_upstream_restart_restores_route_and_replay_preserves_identity",
  "real_os_process_upstream_sse_drain_waits_for_admitted_stream",
  "real_os_process_upstream_websocket_drain_waits_for_admitted_stream",
  "real_os_process_upstream_grpc_drain_waits_for_admitted_stream"
)

Write-Host "managed-runtime: running $($Filters.Count) real OS-process cases"
$failed = $false
foreach ($filter in $Filters) {
  Write-Host "managed-runtime: case $filter"
  $log = Join-Path ([System.IO.Path]::GetTempPath()) ("a3s-mrt-" + [guid]::NewGuid().ToString() + ".log")
  try {
    # Serialize threads: Windows exclusive-bind + free_port TOCTOU under parallel tests.
    cmd /c "cargo test --locked --test managed_runtime_real_process $filter -- --nocapture --test-threads=1 > `"$log`" 2>&1"
    $status = $LASTEXITCODE
    Get-Content -Raw $log | Write-Host
    $text = Get-Content -Raw $log
    if ($status -ne 0) {
      Write-Host "managed-runtime: FAIL $filter (cargo exit $status)" -ForegroundColor Red
      $failed = $true
    } elseif ($text -match "running 0 tests") {
      Write-Host "managed-runtime: FAIL $filter (no tests matched filter)" -ForegroundColor Red
      $failed = $true
    }
  } finally {
    Remove-Item -Force $log -ErrorAction SilentlyContinue
  }
}

if ($failed) {
  Write-Host "managed-runtime: suite failed" -ForegroundColor Red
  exit 1
}
Write-Host "managed-runtime: OK"
exit 0
