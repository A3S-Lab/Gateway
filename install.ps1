[CmdletBinding()]
param(
    [string]$Version = $env:A3S_GATEWAY_VERSION,
    [string]$InstallDir = $env:A3S_GATEWAY_INSTALL_DIR,
    [switch]$NoModifyPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Windows PowerShell 5.1 can otherwise inherit TLS 1.0-only defaults.
[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Program = "a3s-gateway"
$Repository = "A3S-Lab/Gateway"
$ReleasesUrl = if ($env:A3S_GATEWAY_RELEASES_URL) {
    $env:A3S_GATEWAY_RELEASES_URL.TrimEnd("/")
} else {
    "https://github.com/$Repository/releases/download"
}
$LatestApiUrl = if ($env:A3S_GATEWAY_LATEST_API_URL) {
    $env:A3S_GATEWAY_LATEST_API_URL
} else {
    "https://api.github.com/repos/$Repository/releases/latest"
}
$AllowInsecure = $env:A3S_GATEWAY_ALLOW_INSECURE -eq "1"
$SkipPathUpdate = $NoModifyPath -or $env:A3S_GATEWAY_NO_MODIFY_PATH -eq "1"
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "a3s-gateway-install-$([guid]::NewGuid().ToString('N'))"
$PendingBinary = $null

function Write-InstallerLog {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "a3s-gateway installer: $Message"
}

function Assert-SafeUrl {
    param([Parameter(Mandatory = $true)][string]$Url)
    $uri = [uri]$Url
    if ($uri.Scheme -ne "https" -and -not $AllowInsecure) {
        throw "Refusing non-HTTPS download URL: $Url"
    }
}

function Invoke-InstallerDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    Assert-SafeUrl -Url $Url
    foreach ($attempt in 1..3) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Destination -Headers @{
                Accept = "application/vnd.github+json"
                "User-Agent" = "a3s-gateway-installer"
            } -TimeoutSec 300
            return
        } catch {
            if ((Test-NotFoundResponse -ErrorRecord $_) -or $attempt -eq 3) {
                throw
            }
            Start-Sleep -Seconds $attempt
        }
    }
}

function Test-NotFoundResponse {
    param([Parameter(Mandatory = $true)]$ErrorRecord)
    try {
        return [int]$ErrorRecord.Exception.Response.StatusCode -eq 404
    } catch {
        return $false
    }
}

function Resolve-InstallerPlatform {
    if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )) {
        throw "This installer supports Windows only; use install.sh on macOS or Linux"
    }
    if ($env:A3S_GATEWAY_PLATFORM) {
        $platform = $env:A3S_GATEWAY_PLATFORM
    } else {
        $architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        switch ($architecture) {
            "X64" { $platform = "windows-x86_64" }
            "Arm64" { $platform = "windows-arm64" }
            default { throw "Unsupported Windows architecture: $architecture" }
        }
    }
    if ($platform -notin @("windows-x86_64", "windows-arm64")) {
        throw "Unsupported release platform: $platform"
    }
    return $platform
}

function Install-WithCargo {
    param(
        [Parameter(Mandatory = $true)][string]$ExactVersion,
        [Parameter(Mandatory = $true)][string]$Root
    )
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargo) {
        throw "This release has no native Windows archive and Cargo is not installed. Install Rust from https://rustup.rs and retry, or choose a release with Windows assets."
    }
    Write-InstallerLog "native archive unavailable; building version $ExactVersion with Cargo"
    & $cargo.Source install --locked --version $ExactVersion --root $Root $Program
    if ($LASTEXITCODE -ne 0) {
        throw "cargo install failed with exit code $LASTEXITCODE"
    }
    $binary = Join-Path $Root "bin/$Program.exe"
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw "Cargo did not produce $binary"
    }
    return $binary
}

function Add-InstallDirectoryToPath {
    param([Parameter(Mandatory = $true)][string]$Directory)
    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $entries = @($userPath -split ";" | Where-Object { $_ })
    $alreadyPresent = $entries | Where-Object {
        [System.String]::Equals(
            $_.TrimEnd([char]'\'),
            $Directory.TrimEnd([char]'\'),
            $comparison
        )
    }
    if (-not $alreadyPresent) {
        $newUserPath = (@($entries) + $Directory) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        Write-InstallerLog "added $Directory to the user PATH"
    }

    $processEntries = @($env:Path -split ";" | Where-Object { $_ })
    $inProcessPath = $processEntries | Where-Object {
        [System.String]::Equals(
            $_.TrimEnd([char]'\'),
            $Directory.TrimEnd([char]'\'),
            $comparison
        )
    }
    if (-not $inProcessPath) {
        $env:Path = "$Directory;$env:Path"
    }
}

try {
    New-Item -ItemType Directory -Path $TempDir | Out-Null

    if (-not $Version) {
        Write-InstallerLog "resolving the latest stable release"
        $releasePath = Join-Path $TempDir "release.json"
        Invoke-InstallerDownload -Url $LatestApiUrl -Destination $releasePath
        $release = Get-Content -LiteralPath $releasePath -Raw | ConvertFrom-Json
        if (-not $release.tag_name) {
            throw "Latest release response did not contain tag_name"
        }
        $Version = [string]$release.tag_name
    }
    $Version = $Version.TrimStart([char]'v')
    if ($Version -notmatch "^[0-9A-Za-z][0-9A-Za-z.+-]*$") {
        throw "Invalid version: $Version"
    }

    if (-not $InstallDir) {
        $localAppData = [Environment]::GetFolderPath("LocalApplicationData")
        if (-not $localAppData) {
            throw "LocalApplicationData is unavailable; pass -InstallDir explicitly"
        }
        $InstallDir = Join-Path $localAppData "A3S/bin"
    }
    $InstallDir = [System.IO.Path]::GetFullPath($InstallDir)

    $platform = Resolve-InstallerPlatform
    $archiveName = "$Program-$Version-$platform.zip"
    $tag = "v$Version"
    $archiveUrl = "$ReleasesUrl/$tag/$archiveName"
    $checksumUrl = "$archiveUrl.sha256"
    $archivePath = Join-Path $TempDir $archiveName
    $checksumPath = "$archivePath.sha256"
    $stagedBinary = $null

    Write-InstallerLog "downloading $archiveName"
    try {
        Invoke-InstallerDownload -Url $archiveUrl -Destination $archivePath
    } catch {
        if (Test-NotFoundResponse -ErrorRecord $_) {
            $stagedBinary = Install-WithCargo -ExactVersion $Version -Root (Join-Path $TempDir "cargo")
        } else {
            throw
        }
    }

    if (-not $stagedBinary) {
        Invoke-InstallerDownload -Url $checksumUrl -Destination $checksumPath
        $expected = ((Get-Content -LiteralPath $checksumPath -Raw).Trim() -split "\s+")[0].ToLowerInvariant()
        if ($expected -notmatch "^[0-9a-f]{64}$") {
            throw "Release checksum must contain 64 hexadecimal characters"
        }
        $actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "SHA-256 mismatch for $archiveName"
        }
        Write-InstallerLog "verified SHA-256 $actual"

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $stagedBinary = Join-Path $TempDir "$Program.exe"
        $zip = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
        try {
            $matchingEntries = @($zip.Entries | Where-Object {
                $_.FullName -eq "$Program.exe" -and $_.Name -eq "$Program.exe"
            })
            if ($matchingEntries.Count -ne 1) {
                throw "Archive must contain exactly one $Program.exe entry"
            }
            $sourceStream = $matchingEntries[0].Open()
            $destinationStream = [System.IO.File]::Create($stagedBinary)
            try {
                $sourceStream.CopyTo($destinationStream)
            } finally {
                $destinationStream.Dispose()
                $sourceStream.Dispose()
            }
        } finally {
            $zip.Dispose()
        }
    }

    $reportedVersion = (& $stagedBinary --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Downloaded binary did not start"
    }
    if ($reportedVersion -ne "$Program $Version") {
        throw "Downloaded binary reported an unexpected version: $reportedVersion"
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $destination = Join-Path $InstallDir "$Program.exe"
    if (Test-Path -LiteralPath $destination -PathType Container) {
        throw "Installation destination is a directory: $destination"
    }
    $PendingBinary = "$destination.install-$([guid]::NewGuid().ToString('N'))"
    Copy-Item -LiteralPath $stagedBinary -Destination $PendingBinary

    $backup = $null
    if (Test-Path -LiteralPath $destination) {
        $backup = "$destination.backup-$([guid]::NewGuid().ToString('N'))"
        Move-Item -LiteralPath $destination -Destination $backup
    }
    try {
        Move-Item -LiteralPath $PendingBinary -Destination $destination
        $PendingBinary = $null
    } catch {
        $replacementError = $_
        if ($backup -and (Test-Path -LiteralPath $backup)) {
            if (Test-Path -LiteralPath $destination) {
                Remove-Item -LiteralPath $destination -Force
            }
            Move-Item -LiteralPath $backup -Destination $destination
        }
        throw $replacementError
    }
    if ($backup) {
        try {
            Remove-Item -LiteralPath $backup -Force
        } catch {
            Write-Warning "Installed $Program but could not remove backup $backup"
        }
    }

    if ($SkipPathUpdate) {
        if ($env:Path -notlike "*$InstallDir*") {
            Write-InstallerLog "$InstallDir is not on PATH; add it before invoking $Program by name"
        }
    } else {
        Add-InstallDirectoryToPath -Directory $InstallDir
    }
    Write-InstallerLog "installed $reportedVersion at $destination"
} finally {
    if ($PendingBinary -and (Test-Path -LiteralPath $PendingBinary)) {
        Remove-Item -LiteralPath $PendingBinary -Force
    }
    if (Test-Path -LiteralPath $TempDir) {
        Remove-Item -LiteralPath $TempDir -Recurse -Force
    }
}
