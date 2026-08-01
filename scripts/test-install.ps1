[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [string]$Version = "1.0.12"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $repositoryRoot "install.ps1"
$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) "a3s-gateway-installer-test-$([guid]::NewGuid().ToString('N'))"
$server = $null

try {
    $platform = "windows-x86_64"
    $archiveName = "a3s-gateway-$Version-$platform.zip"
    $releaseDir = Join-Path $fixtureRoot "download/v$Version"
    $archiveStage = Join-Path $fixtureRoot "archive"
    $installDir = Join-Path $fixtureRoot "install"
    New-Item -ItemType Directory -Force -Path $releaseDir, $archiveStage | Out-Null
    Copy-Item -LiteralPath $Binary -Destination (Join-Path $archiveStage "a3s-gateway.exe")

    $archivePath = Join-Path $releaseDir $archiveName
    Compress-Archive -Path (Join-Path $archiveStage "a3s-gateway.exe") -DestinationPath $archivePath
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "$archivePath.sha256" -Value "$archiveHash  $archiveName" -Encoding ascii
    Set-Content -LiteralPath (Join-Path $fixtureRoot "latest.json") -Value "{`"tag_name`":`"v$Version`"}" -Encoding ascii

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()
    $server = Start-Process -FilePath python -ArgumentList @(
        "-m", "http.server", "$port", "--bind", "127.0.0.1", "--directory", $fixtureRoot
    ) -PassThru -WindowStyle Hidden

    $ready = $false
    foreach ($attempt in 1..50) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$port/" | Out-Null
            $ready = $true
            break
        } catch {
            Start-Sleep -Milliseconds 100
        }
    }
    if (-not $ready) {
        throw "Test server did not start"
    }

    $env:A3S_GATEWAY_RELEASES_URL = "http://127.0.0.1:$port/download"
    $env:A3S_GATEWAY_PLATFORM = $platform
    $env:A3S_GATEWAY_ALLOW_INSECURE = "1"

    & $installer -Version $Version -InstallDir $installDir -NoModifyPath
    $installedBinary = Join-Path $installDir "a3s-gateway.exe"
    if (-not (Test-Path -LiteralPath $installedBinary -PathType Leaf)) {
        throw "Installer did not create $installedBinary"
    }
    $reportedVersion = (& $installedBinary --version 2>&1 | Out-String).Trim()
    if ($reportedVersion -ne "a3s-gateway $Version") {
        throw "Installed binary reported an unexpected version: $reportedVersion"
    }

    $latestInstallDir = Join-Path $fixtureRoot "install-latest"
    $env:A3S_GATEWAY_LATEST_API_URL = "http://127.0.0.1:$port/latest.json"
    & $installer -InstallDir $latestInstallDir -NoModifyPath
    $latestBinary = Join-Path $latestInstallDir "a3s-gateway.exe"
    $latestReportedVersion = (& $latestBinary --version 2>&1 | Out-String).Trim()
    if ($latestReportedVersion -ne "a3s-gateway $Version") {
        throw "Latest release resolution installed an unexpected version: $latestReportedVersion"
    }

    $installedHashBefore = (Get-FileHash -LiteralPath $installedBinary -Algorithm SHA256).Hash
    Set-Content -LiteralPath "$archivePath.sha256" -Value "$('0' * 64)  $archiveName" -Encoding ascii
    $failedAsExpected = $false
    try {
        & $installer -Version $Version -InstallDir $installDir -NoModifyPath
    } catch {
        $failedAsExpected = $_.Exception.Message -like "*SHA-256 mismatch*"
    }
    if (-not $failedAsExpected) {
        throw "Installer accepted a damaged checksum"
    }
    $installedHashAfter = (Get-FileHash -LiteralPath $installedBinary -Algorithm SHA256).Hash
    if ($installedHashBefore -ne $installedHashAfter) {
        throw "Failed installation replaced the existing binary"
    }

    $env:A3S_GATEWAY_PLATFORM = "plan9-mips"
    $invalidPlatformFailed = $false
    try {
        & $installer -Version $Version -InstallDir $installDir -NoModifyPath
    } catch {
        $invalidPlatformFailed = $_.Exception.Message -like "*Unsupported release platform*"
    }
    if (-not $invalidPlatformFailed) {
        throw "Installer accepted an unsupported platform"
    }

    Write-Host "Windows installer tests passed."
} finally {
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
        $server.WaitForExit()
    }
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}
