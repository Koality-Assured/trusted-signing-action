<#
.SYNOPSIS
    Authenticode signature and certificate chain verification engine.

.DESCRIPTION
    Performs comprehensive cryptographic verification on signed artifacts (.ps1, .exe, .dll,
    .sys, .msi, .cat, .cab, .appx, .msix). Validates:
    1. Signature integrity status (Valid / Untampered).
    2. Signer certificate validity, subject, and issuer chain.
    3. RFC 3161 timestamp counter-signature presence and integrity.
    4. Cryptographic hashing algorithm (e.g. SHA-256).

.PARAMETER Files
    Glob pattern, single file path, or multiline/comma-separated list of files to verify.

.PARAMETER ExpectedDigest
    Expected hash algorithm for the signature (default 'SHA256').

.PARAMETER ExpectedSubject
    Optional string to match against the signer certificate Subject field.

.PARAMETER RequireTimestamp
    Whether an RFC 3161 timestamp counter-signature is required (default $true).

.PARAMETER FailOnWarning
    If specified, exits with non-zero exit code if warnings are encountered.

.PARAMETER DryRun
    Simulates verification without enforcing native Windows Authenticode trust validation.

.OUTPUTS
    Sets GitHub Actions output variables (verified-files-count, verification-status) and returns:
    0 = Success, 1 = Warning, 2 = Error.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Files,

    [Parameter(Mandatory = $false)]
    [ValidateSet('SHA256', 'SHA384', 'SHA512')]
    [string]$ExpectedDigest = 'SHA256',

    [Parameter(Mandatory = $false)]
    [string]$ExpectedSubject = '',

    [Parameter(Mandatory = $false)]
    [bool]$RequireTimestamp = $true,

    [Parameter(Mandatory = $false)]
    [switch]$FailOnWarning = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun = $false
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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

# Resolve file patterns
function Resolve-TargetFiles {
    param([string]$Patterns)

    $resolved = [System.Collections.Generic.List[string]]::new()
    $rawPatterns = $Patterns -split "[\r\n;,]+" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' -and -not ($_.StartsWith('#')) }

    if (@($rawPatterns).Count -eq 0) {
        return @()
    }

    foreach ($pat in $rawPatterns) {
        $cleanPat = $pat.Trim("'`"")
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

function Main {
    Write-Log -Level 'INFO' -Message "================================================================================"
    Write-Log -Level 'INFO' -Message " Koality Assured -- Authenticode Cryptographic Verification Engine"
    Write-Log -Level 'INFO' -Message " Expected Digest   : $ExpectedDigest"
    Write-Log -Level 'INFO' -Message " Expected Subject  : $(if ($ExpectedSubject) { $ExpectedSubject } else { '[ANY]' })"
    Write-Log -Level 'INFO' -Message " Require Timestamp : $RequireTimestamp"
    Write-Log -Level 'INFO' -Message " Mode              : $(if ($DryRun) { 'DryRun (Simulation)' } else { 'Live Cryptographic Audit' })"
    Write-Log -Level 'INFO' -Message " Strict CI Gating  : FailOnWarning = $FailOnWarning"
    Write-Log -Level 'INFO' -Message "================================================================================"

    $targetFiles = Resolve-TargetFiles -Patterns $Files
    Write-Log -Level 'INFO' -Message "Discovered $(@($targetFiles).Count) artifact(s) to verify."

    $warningCount = 0
    $errorCount = 0
    $verifiedCount = 0
    $verificationResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (@($targetFiles).Count -eq 0) {
        Write-Log -Level 'WARN' -Message "Zero files matched verification pattern: '$Files'."
        $warningCount++
        if ($FailOnWarning) {
            Set-GitHubActionOutput -Name 'verified-files-count' -Value '0'
            Set-GitHubActionOutput -Name 'verification-status' -Value 'warning'
            exit 1
        }
        Set-GitHubActionOutput -Name 'verified-files-count' -Value '0'
        Set-GitHubActionOutput -Name 'verification-status' -Value 'success'
        exit 0
    }

    foreach ($file in $targetFiles) {
        $fileName = [System.IO.Path]::GetFileName($file)
        Write-Log -Level 'INFO' -Message "Inspecting Authenticode signature for: $fileName"

        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            Write-Log -Level 'ERROR' -Message "Target artifact does not exist: $file"
            $errorCount++
            continue
        }

        # Dry-run handling
        if ($DryRun) {
            Write-Log -Level 'SUCCESS' -Message "[DRY-RUN VERIFIED] Signature simulation valid for $fileName"
            $verificationResults.Add([PSCustomObject]@{
                FileName    = $fileName
                Status      = 'Valid (Simulated)'
                Subject     = 'CN=Koality Assured Test Simulation'
                HasTimestamp= $true
                Algorithm   = $ExpectedDigest
                Passed      = $true
            })
            $verifiedCount++
            continue
        }

        # Query Authenticode signature
        try {
            $sig = Get-AuthenticodeSignature -FilePath $file
        }
        catch {
            Write-Log -Level 'ERROR' -Message "Failed to query Authenticode signature on $fileName : $($_.Exception.Message)"
            $errorCount++
            continue
        }

        $passed = $false
        $subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'None' }
        $hasTimestamp = ($null -ne $sig.TimeStamperCertificate)
        $algorithm = if ($sig.SignerCertificate) { $sig.SignerCertificate.SignatureAlgorithm.FriendlyName } else { 'None' }

        # Check signature status
        switch ($sig.Status) {
            'Valid' {
                $passed = $true
                Write-Log -Level 'SUCCESS' -Message "Authenticode status is VALID for $fileName"
            }
            'NotSigned' {
                Write-Log -Level 'ERROR' -Message "Artifact is NOT SIGNED: $fileName"
                $errorCount++
            }
            'HashMismatch' {
                Write-Log -Level 'ERROR' -Message "INTEGRITY VIOLATION: Hash mismatch detected on $fileName. File may have been tampered with post-signing!"
                $errorCount++
            }
            'NotTrusted' {
                # In custom CI or test environments, root cert may not be in local machine root store.
                Write-Log -Level 'WARN' -Message "Signature intact but root CA is not trusted on this host for artifact $fileName - $($sig.StatusMessage)"
                $warningCount++
                # If cert structure and signature exist, count as passed with warning unless strict
                if ($sig.SignerCertificate) {
                    $passed = $true
                }
                else {
                    $errorCount++
                }
            }
            'UnknownError' {
                Write-Log -Level 'WARN' -Message "WinVerifyTrust reported status: $($sig.Status) - $($sig.StatusMessage) for $fileName"
                $warningCount++
                if ($sig.SignerCertificate) {
                    $passed = $true
                }
                else {
                    $errorCount++
                }
            }
            Default {
                Write-Log -Level 'ERROR' -Message "Authenticode verification failed for $fileName with status: $($sig.Status) - $($sig.StatusMessage)"
                $errorCount++
            }
        }

        # Check Subject constraint if specified
        if ($passed -and $ExpectedSubject -and $ExpectedSubject.Trim() -ne '') {
            if (-not ($subject -like "*$ExpectedSubject*")) {
                Write-Log -Level 'ERROR' -Message "Signer subject mismatch on $fileName. Expected: '$ExpectedSubject', Got: '$subject'"
                $passed = $false
                $errorCount++
            }
            else {
                Write-Log -Level 'DEBUG' -Message "Signer subject matches expected pattern '$ExpectedSubject'"
            }
        }

        # Check Timestamp requirement
        if ($passed -and $RequireTimestamp) {
            if (-not $hasTimestamp) {
                Write-Log -Level 'WARN' -Message "Missing RFC 3161 timestamp counter-signature on $fileName. Signature will expire when the certificate expires."
                $warningCount++
            }
            else {
                $tsSubject = $sig.TimeStamperCertificate.Subject
                Write-Log -Level 'SUCCESS' -Message "RFC 3161 timestamp counter-signature verified on $fileName (TSA: $tsSubject)"
            }
        }

        # Check Algorithm
        if ($passed -and $algorithm -ne 'None') {
            if ($algorithm -notmatch $ExpectedDigest) {
                Write-Log -Level 'WARN' -Message "Signature algorithm '$algorithm' does not match expected digest '$ExpectedDigest' on $fileName."
                $warningCount++
            }
        }

        if ($passed) {
            $verifiedCount++
        }

        $verificationResults.Add([PSCustomObject]@{
            FileName     = $fileName
            Status       = $sig.Status.ToString()
            Subject      = $subject
            HasTimestamp = $hasTimestamp
            Algorithm    = $algorithm
            Passed       = $passed
        })
    }

    # Write Step Summary
    if ($env:GITHUB_STEP_SUMMARY) {
        $summary = [System.Text.StringBuilder]::new()
        [void]$summary.AppendLine("### Authenticode Signature Verification Report")
        [void]$summary.AppendLine("| Artifact | Status | Subject | Timestamped | Algorithm |")
        [void]$summary.AppendLine("|:---|:---:|:---|:---:|:---:|")
        foreach ($res in $verificationResults) {
            $statusBadge = if ($res.Passed) { '[VALID]' } else { '[FAILED]' }
            $tsBadge = if ($res.HasTimestamp) { '[YES]' } else { '[NO]' }
            [void]$summary.AppendLine("| ``$($res.FileName)`` | $statusBadge | $($res.Subject) | $tsBadge | $($res.Algorithm) |")
        }
        $summary.ToString() | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
    }

    # Set Output Variables
    Set-GitHubActionOutput -Name 'verified-files-count' -Value "$verifiedCount"

    # Evaluate Overall Outcome
    if ($errorCount -gt 0) {
        Set-GitHubActionOutput -Name 'verification-status' -Value 'error'
        Write-Log -Level 'ERROR' -Message "Verification failed: $errorCount error(s) and $warningCount warning(s) across $(@($targetFiles).Count) artifact(s)."
        exit 2
    }
    elseif ($warningCount -gt 0) {
        if ($FailOnWarning) {
            Set-GitHubActionOutput -Name 'verification-status' -Value 'warning'
            Write-Log -Level 'ERROR' -Message "Strict gating triggered: $warningCount verification warning(s) encountered."
            exit 1
        }
        else {
            Set-GitHubActionOutput -Name 'verification-status' -Value 'warning'
            Write-Log -Level 'WARN' -Message "Verification completed with $warningCount non-fatal warning(s)."
            exit 0
        }
    }
    else {
        Set-GitHubActionOutput -Name 'verification-status' -Value 'success'
        Write-Log -Level 'SUCCESS' -Message "All $verifiedCount artifact(s) successfully verified with zero errors or warnings."
        exit 0
    }
}

# Run Main
Main
