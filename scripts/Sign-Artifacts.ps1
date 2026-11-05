<#
.SYNOPSIS
    Enterprise signing driver script for Microsoft Azure Trusted Signing.

.DESCRIPTION
    Dynamically discovers, configures, and executes Microsoft Azure Trusted Signing (formerly
    Azure Code Signing / ACS) across matched file targets. Supports PowerShell scripts,
    PE binaries (.exe, .dll, .sys), MSI installers, Windows catalog/cabinet files (.cat, .cab),
    and AppX/MSIX packages. Operates zero-credential via Azure OIDC federated credentials.

.PARAMETER Endpoint
    Azure Trusted Signing regional endpoint URL (e.g. https://eus.codesigning.azure.net/).

.PARAMETER CodeSigningAccountName
    Azure Trusted Signing account resource name.

.PARAMETER CertificateProfileName
    Certificate profile name within the Trusted Signing account.

.PARAMETER Files
    Glob pattern, single file path, or multiline/comma-separated list of files to sign.

.PARAMETER TimestampRfc3161
    RFC 3161 compliant timestamp server URL. Default is 'http://timestamp.acs.microsoft.com'.

.PARAMETER TimestampDigest
    Hashing algorithm used for timestamp counter-signature. Default is 'SHA256'.

.PARAMETER FileDigest
    Hashing algorithm used for the file digest. Default is 'SHA256'.

.PARAMETER FailOnWarning
    If specified, exits with non-zero exit code if warnings are encountered.

.PARAMETER DryRun
    Simulates signing without invoking remote Azure services. Useful for testing and CI validation.

.PARAMETER CorrelationId
    Optional correlation ID string for Azure request tracking.

.OUTPUTS
    Sets GitHub Actions output variables (signed-files-count, signing-status) and returns:
    0 = Success, 1 = Warning, 2 = Error.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$Endpoint = 'https://eus.codesigning.azure.net/',

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CodeSigningAccountName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateProfileName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Files,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$TimestampRfc3161 = 'http://timestamp.acs.microsoft.com',

    [Parameter(Mandatory = $false)]
    [ValidateSet('SHA256', 'SHA384', 'SHA512')]
    [string]$TimestampDigest = 'SHA256',

    [Parameter(Mandatory = $false)]
    [ValidateSet('SHA256', 'SHA384', 'SHA512')]
    [string]$FileDigest = 'SHA256',

    [Parameter(Mandatory = $false)]
    [switch]$FailOnWarning = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun = $false,

    [Parameter(Mandatory = $false)]
    [string]$CorrelationId = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Supported file extensions for Authenticode / Azure Trusted Signing
$Script:SupportedExtensions = @(
    '.ps1', '.psm1', '.psd1',
    '.exe', '.dll', '.sys', '.ocx',
    '.msi', '.msp', '.msm',
    '.cat', '.cab',
    '.appx', '.appxbundle', '.msix', '.msixbundle'
)

# Logging helper
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'DEBUG')]
        [string]$Level,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $prefix = "[$timestamp] [$Level]"
    switch ($Level) {
        'INFO'    { Write-Host "$prefix $Message" -ForegroundColor Cyan }
        'WARN'    {
            Write-Host "$prefix $Message" -ForegroundColor Yellow
            if ($env:GITHUB_ACTIONS) { Write-Output "::warning::$Message" }
        }
        'ERROR'   {
            Write-Host "$prefix $Message" -ForegroundColor Red
            if ($env:GITHUB_ACTIONS) { Write-Output "::error::$Message" }
        }
        'SUCCESS' { Write-Host "$prefix $Message" -ForegroundColor Green }
        'DEBUG'   { Write-Verbose "$prefix $Message" }
    }
}

# Resolve file globs and multiline paths
function Resolve-TargetFiles {
    param([string]$Patterns)

    $resolved = [System.Collections.Generic.List[string]]::new()
    $lines = $Patterns -split "[\r\n]+" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' -and -not ($_.StartsWith('#')) }

    if (@($lines).Count -eq 0) {
        return @()
    }

    $rawPatterns = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        $cleanLine = $line.Trim().Trim("'").Trim('"').Trim('`')
        if (Test-Path -LiteralPath $cleanLine -PathType Leaf) {
            $rawPatterns.Add($cleanLine)
            continue
        }
        if ($cleanLine -match '[,;]') {
            $parts = $cleanLine -split '[,;]+' | ForEach-Object { $_.Trim().Trim("'").Trim('"').Trim('`') } | Where-Object { $_ -ne '' }
            foreach ($p in $parts) {
                $rawPatterns.Add($p)
            }
        }
        else {
            $rawPatterns.Add($cleanLine)
        }
    }

    foreach ($pat in $rawPatterns) {
        $cleanPat = $pat.Trim().Trim("'").Trim('"').Trim('`')
        
        if (Test-Path -LiteralPath $cleanPat -PathType Leaf) {
            $fullPath = [System.IO.Path]::GetFullPath($cleanPat)
            if (-not $resolved.Contains($fullPath)) {
                $resolved.Add($fullPath)
            }
            continue
        }

        try {
            $matches = Get-ChildItem -Path $cleanPat -File -ErrorAction SilentlyContinue
            if ($matches) {
                foreach ($m in $matches) {
                    $fullPath = [System.IO.Path]::GetFullPath($m.FullName)
                    if (-not $resolved.Contains($fullPath)) {
                        $resolved.Add($fullPath)
                    }
                }
                continue
            }
        }
        catch {
            Write-Log -Level 'DEBUG' -Message "Wildcard expansion failed for pattern: $cleanPat"
        }

        $cwdPat = Join-Path -Path (Get-Location).Path -ChildPath $cleanPat
        if (Test-Path -LiteralPath $cwdPat -PathType Leaf) {
            $fullPath = [System.IO.Path]::GetFullPath($cwdPat)
            if (-not $resolved.Contains($fullPath)) {
                $resolved.Add($fullPath)
            }
            continue
        }
        try {
            $matches = Get-ChildItem -Path $cwdPat -File -ErrorAction SilentlyContinue
            if ($matches) {
                foreach ($m in $matches) {
                    $fullPath = [System.IO.Path]::GetFullPath($m.FullName)
                    if (-not $resolved.Contains($fullPath)) {
                        $resolved.Add($fullPath)
                    }
                }
            }
        }
        catch {
            Write-Log -Level 'DEBUG' -Message "CWD expansion failed for pattern: $cwdPat"
        }
    }

    return $resolved.ToArray()
}

# Compute file SHA-256 hash
function Get-FileSha256 {
    param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return '' }
    $hash = Get-FileHash -LiteralPath $FilePath -Algorithm SHA256
    return $hash.Hash.ToLowerInvariant()
}

# Find SignTool on Windows system
function Find-SignToolPath {
    # Check PATH first
    $cmd = Get-Command -Name 'signtool.exe' -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    # Search standard Windows Kits paths
    $kitsRoots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin"
    )

    foreach ($root in $kitsRoots) {
        if (Test-Path -LiteralPath $root) {
            $candidates = Get-ChildItem -Path $root -Filter 'signtool.exe' -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match 'x64' } |
                Sort-Object -Property LastWriteTime -Descending
            if ($candidates -and @($candidates).Count -gt 0) {
                return $candidates[0].FullName
            }
        }
    }

    return $null
}

# Find or prepare Azure.CodeSigning.Dlib.dll
function Find-DlibPath {
    # Check well-known local installation locations
    $searchLocations = @(
        "$env:USERPROFILE\.azure-trusted-signing\Azure.CodeSigning.Dlib.dll",
        "$env:LOCALAPPDATA\Microsoft\TrustedSigning\Azure.CodeSigning.Dlib.dll",
        "${env:ProgramFiles}\Azure Trusted Signing\Azure.CodeSigning.Dlib.dll",
        "${env:ProgramFiles(x86)}\Azure Trusted Signing\Azure.CodeSigning.Dlib.dll"
    )

    foreach ($loc in $searchLocations) {
        if (Test-Path -LiteralPath $loc -PathType Leaf) {
            return $loc
        }
    }

    # Search in .dotnet tool directory
    $dotnetTools = "$env:USERPROFILE\.dotnet\tools"
    if (Test-Path -LiteralPath $dotnetTools) {
        $found = Get-ChildItem -Path $dotnetTools -Filter 'Azure.CodeSigning.Dlib.dll' -Recurse -File -ErrorAction SilentlyContinue
        if ($found -and @($found).Count -gt 0) {
            return $found[0].FullName
        }
    }

    return $null
}

# Set GitHub Actions output
function Set-GitHubActionOutput {
    param(
        [string]$Name,
        [string]$Value
    )
    if ($env:GITHUB_OUTPUT -and (Test-Path -LiteralPath (Split-Path -Parent $env:GITHUB_OUTPUT) -ErrorAction SilentlyContinue)) {
        "$Name=$Value" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
    }
}

# Main execution logic
function Main {
    Write-Log -Level 'INFO' -Message "================================================================================"
    Write-Log -Level 'INFO' -Message " Koality Assured -- Microsoft Azure Trusted Signing Engine"
    Write-Log -Level 'INFO' -Message " Regional Endpoint : $Endpoint"
    Write-Log -Level 'INFO' -Message " Account Name      : $CodeSigningAccountName"
    Write-Log -Level 'INFO' -Message " Profile Name      : $CertificateProfileName"
    Write-Log -Level 'INFO' -Message " Timestamp RFC3161 : $TimestampRfc3161 ($TimestampDigest)"
    Write-Log -Level 'INFO' -Message " File Digest       : $FileDigest"
    Write-Log -Level 'INFO' -Message " Mode              : $(if ($DryRun) { 'DryRun (Simulation)' } else { 'Live Production' })"
    Write-Log -Level 'INFO' -Message " Strict CI Gating  : FailOnWarning = $FailOnWarning"
    Write-Log -Level 'INFO' -Message "================================================================================"

    # 0. Strict Input Parameter Security Validation
    if (-not ($Endpoint -match '^https://[a-zA-Z0-9.-]+\.codesigning\.azure\.net/?$')) {
        Write-Log -Level 'ERROR' -Message "Security Validation: Endpoint '$Endpoint' is invalid. Must be an HTTPS endpoint on codesigning.azure.net."
        Set-GitHubActionOutput -Name 'signed-files-count' -Value '0'
        Set-GitHubActionOutput -Name 'signing-status' -Value 'error'
        exit 2
    }

    if (-not ($TimestampRfc3161 -match '^https?://[a-zA-Z0-9.-]+')) {
        Write-Log -Level 'ERROR' -Message "Security Validation: Timestamp URL '$TimestampRfc3161' is invalid. Must be an HTTP/HTTPS URL."
        Set-GitHubActionOutput -Name 'signed-files-count' -Value '0'
        Set-GitHubActionOutput -Name 'signing-status' -Value 'error'
        exit 2
    }

    # Resolve target files
    $targetFiles = Resolve-TargetFiles -Patterns $Files
    Write-Log -Level 'INFO' -Message "Discovered $(@($targetFiles).Count) candidate file(s) matching input pattern."

    # Cross-platform environment detection
    $isUnix = $false
    try {
        if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
            $isUnix = $true
        }
    }
    catch {
        if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
            $isUnix = $true
        }
    }

    if ($isUnix -and -not $DryRun) {
        $peTargets = @($targetFiles | Where-Object { $_ -notmatch '\.ps[m1d]1$' })
        if ($peTargets.Count -gt 0) {
            Write-Log -Level 'ERROR' -Message "Cross-platform constraint: Azure Trusted Signing via SignTool and Azure.CodeSigning.Dlib.dll requires a Windows runner (runs-on: windows-latest). Operating System is '$([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)'. Cannot sign PE/MSI binaries on Linux/macOS."
            Set-GitHubActionOutput -Name 'signed-files-count' -Value '0'
            Set-GitHubActionOutput -Name 'signing-status' -Value 'error'
            exit 2
        }
    }

    $warningCount = 0
    $errorCount = 0
    $signedCount = 0
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (@($targetFiles).Count -eq 0) {
        Write-Log -Level 'WARN' -Message "Zero files matched the provided pattern: '$Files'."
        $warningCount++
        if ($FailOnWarning) {
            Write-Log -Level 'ERROR' -Message "Strict CI gating: failing execution due to zero matched files."
            Set-GitHubActionOutput -Name 'signed-files-count' -Value '0'
            Set-GitHubActionOutput -Name 'signing-status' -Value 'warning'
            exit 1
        }
        Set-GitHubActionOutput -Name 'signed-files-count' -Value '0'
        Set-GitHubActionOutput -Name 'signing-status' -Value 'success'
        exit 0
    }

    # Validate file extensions
    $validFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($file in $targetFiles) {
        $ext = [System.IO.Path]::GetExtension($file).ToLowerInvariant()
        if ($Script:SupportedExtensions -contains $ext) {
            $validFiles.Add($file)
        }
        else {
            Write-Log -Level 'WARN' -Message "Unsupported file extension '$ext' on artifact '$file'. Supported extensions: $($Script:SupportedExtensions -join ', ')"
            $warningCount++
        }
    }

    if (@($validFiles).Count -eq 0) {
        Write-Log -Level 'ERROR' -Message "None of the discovered files possess supported Authenticode extensions."
        Set-GitHubActionOutput -Name 'signed-files-count' -Value '0'
        Set-GitHubActionOutput -Name 'signing-status' -Value 'error'
        exit 2
    }

    # Dry-Run mode execution
    if ($DryRun) {
        Write-Log -Level 'INFO' -Message "[DRY-RUN] Simulating signature generation across $(@($validFiles).Count) artifact(s)..."
        foreach ($file in $validFiles) {
            $sha256 = Get-FileSha256 -FilePath $file
            $fileSize = (Get-Item -LiteralPath $file).Length
            Write-Log -Level 'SUCCESS' -Message "[DRY-RUN SIGNED] $file ($fileSize bytes, SHA-256: $sha256)"
            $results.Add([PSCustomObject]@{
                FilePath   = $file
                Status     = 'Simulated'
                Sha256     = $sha256
                SizeBytes  = $fileSize
            })
            $signedCount++
        }

        Set-GitHubActionOutput -Name 'signed-files-count' -Value "$signedCount"
        $statusOutcome = if ($warningCount -gt 0 -and $FailOnWarning) { 'warning' } else { 'success' }
        Set-GitHubActionOutput -Name 'signing-status' -Value $statusOutcome

        if ($warningCount -gt 0 -and $FailOnWarning) {
            Write-Log -Level 'WARN' -Message "Completed dry-run simulation with $warningCount warning(s) under strict gating."
            exit 1
        }
        Write-Log -Level 'SUCCESS' -Message "Completed dry-run simulation successfully: $signedCount artifact(s) processed."
        exit 0
    }

    # Live Signing Mode
    # 1. Prepare Metadata Configuration JSON
    $metadataObj = [ordered]@{
        Endpoint               = $Endpoint
        CodeSigningAccountName = $CodeSigningAccountName
        CertificateProfileName = $CertificateProfileName
    }
    if ($CorrelationId -and $CorrelationId.Trim() -ne '') {
        $metadataObj['CorrelationId'] = $CorrelationId.Trim()
    }
    $metadataJson = $metadataObj | ConvertTo-Json -Compress
    $tempMetadataFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "ts-metadata-$([System.Guid]::NewGuid().ToString('N')).json")
    Set-Content -LiteralPath $tempMetadataFile -Value $metadataJson -Encoding utf8

    try {
        # Discover signing tools
        $signtool = Find-SignToolPath
        $dlib = Find-DlibPath

        # Check if TrustedSigning PowerShell module is available as alternative
        $trustedSigningModule = Get-Module -ListAvailable -Name 'TrustedSigning' -ErrorAction SilentlyContinue

        if (-not $signtool -and -not $trustedSigningModule) {
            Write-Log -Level 'WARN' -Message "Native signtool.exe or TrustedSigning module not found in standard system paths. Attempting dynamic module discovery..."
            try {
                Install-Module -Name 'TrustedSigning' -Scope CurrentUser -Force -SkipPublisherCheck -AllowClobber -ErrorAction Stop
                $trustedSigningModule = Get-Module -ListAvailable -Name 'TrustedSigning'
            }
            catch {
                Write-Log -Level 'WARN' -Message "Could not dynamically install TrustedSigning module: $($_.Exception.Message)"
            }
        }

        # Execute signing
        foreach ($file in $validFiles) {
            $preHash = Get-FileSha256 -FilePath $file
            $fileName = [System.IO.Path]::GetFileName($file)
            Write-Log -Level 'INFO' -Message "Signing artifact: $fileName (Pre-hash: $preHash)"

            $signSuccess = $false

            # Strategy A: Use SignTool with Azure.CodeSigning.Dlib.dll if available
            if ($signtool -and $dlib) {
                Write-Log -Level 'DEBUG' -Message "Invoking signtool.exe: $signtool with dlib: $dlib"
                $signtoolArgs = @(
                    'sign',
                    '/v',
                    '/fd', $FileDigest,
                    '/tr', $TimestampRfc3161,
                    '/td', $TimestampDigest,
                    '/dlib', $dlib,
                    '/dmc', $tempMetadataFile,
                    $file
                )
                $proc = Start-Process -FilePath $signtool -ArgumentList $signtoolArgs -Wait -NoNewWindow -PassThru
                if ($proc.ExitCode -eq 0) {
                    $signSuccess = $true
                }
                else {
                    Write-Log -Level 'ERROR' -Message "signtool.exe exited with non-zero exit code: $($proc.ExitCode) on $fileName"
                }
            }
            # Strategy B: Use TrustedSigning PowerShell module
            elseif ($trustedSigningModule) {
                Write-Log -Level 'DEBUG' -Message "Invoking TrustedSigning module for: $file"
                try {
                    $dir = [System.IO.Path]::GetDirectoryName($file)
                    $splat = @{
                        Endpoint               = $Endpoint
                        CodeSigningAccountName = $CodeSigningAccountName
                        CertificateProfileName = $CertificateProfileName
                        FilesFolder            = $dir
                        FilesFolderFilter      = [System.IO.Path]::GetExtension($file).TrimStart('.')
                        TimestampRfc3161       = $TimestampRfc3161
                        TimestampDigest        = $TimestampDigest
                        FileDigest             = $FileDigest
                    }
                    Invoke-TrustedSigning @splat -ErrorAction Stop
                    $signSuccess = $true
                }
                catch {
                    Write-Log -Level 'ERROR' -Message "Invoke-TrustedSigning failed on $fileName : $($_.Exception.Message)"
                }
            }
            else {
                # Fallback: if in automated mock test environment
                Write-Log -Level 'ERROR' -Message "Neither SignTool with Azure.CodeSigning.Dlib.dll nor TrustedSigning module is configured. Install Microsoft.Trusted.Signing.Client or install the TrustedSigning PowerShell module."
                $errorCount++
                continue
            }

            if ($signSuccess) {
                $postHash = Get-FileSha256 -FilePath $file
                Write-Log -Level 'SUCCESS' -Message "Successfully signed $fileName (Post-hash: $postHash)"
                $results.Add([PSCustomObject]@{
                    FilePath  = $file
                    Status    = 'Signed'
                    Sha256    = $postHash
                    SizeBytes = (Get-Item -LiteralPath $file).Length
                })
                $signedCount++
            }
            else {
                $errorCount++
                $results.Add([PSCustomObject]@{
                    FilePath  = $file
                    Status    = 'Failed'
                    Sha256    = $preHash
                    SizeBytes = (Get-Item -LiteralPath $file).Length
                })
            }
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempMetadataFile) {
            Remove-Item -LiteralPath $tempMetadataFile -Force -ErrorAction SilentlyContinue
        }
    }

    # Write Step Summary to GitHub Actions if available
    if ($env:GITHUB_STEP_SUMMARY) {
        $summary = [System.Text.StringBuilder]::new()
        [void]$summary.AppendLine("### Azure Trusted Signing Summary")
        [void]$summary.AppendLine("| Artifact | Status | Size | SHA-256 Digest |")
        [void]$summary.AppendLine("|:---|:---:|:---:|:---|")
        foreach ($res in $results) {
            $statusBadge = switch ($res.Status) {
                'Signed'    { '[SIGNED]' }
                'Simulated' { '[SIMULATED]' }
                'Failed'    { '[FAILED]' }
                Default     { $res.Status }
            }
            [void]$summary.AppendLine("| ``$([System.IO.Path]::GetFileName($res.FilePath))`` | $statusBadge | $($res.SizeBytes) B | ``$($res.Sha256.Substring(0, 16))...`` |")
        }
        $summary.ToString() | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
    }

    # Set Output Variables
    Set-GitHubActionOutput -Name 'signed-files-count' -Value "$signedCount"

    # Evaluate Overall Status and Exit Code
    if ($errorCount -gt 0) {
        Set-GitHubActionOutput -Name 'signing-status' -Value 'error'
        Write-Log -Level 'ERROR' -Message "Signing completed with $errorCount error(s) and $warningCount warning(s)."
        exit 2
    }
    elseif ($warningCount -gt 0) {
        if ($FailOnWarning) {
            Set-GitHubActionOutput -Name 'signing-status' -Value 'warning'
            Write-Log -Level 'ERROR' -Message "Strict gating triggered: $warningCount warning(s) encountered."
            exit 1
        }
        else {
            Set-GitHubActionOutput -Name 'signing-status' -Value 'warning'
            Write-Log -Level 'WARN' -Message "Signing completed successfully with $warningCount non-fatal warning(s)."
            exit 0
        }
    }
    else {
        Set-GitHubActionOutput -Name 'signing-status' -Value 'success'
        Write-Log -Level 'SUCCESS' -Message "Signing successfully completed for all $signedCount artifact(s)."
        exit 0
    }
}

# Run Main
Main
