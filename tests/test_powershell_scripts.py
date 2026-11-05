"""Tests validating PowerShell scripts syntax, parameter contracts, and dry-run execution."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
SIGN_SCRIPT = SCRIPTS_DIR / "Sign-Artifacts.ps1"
VERIFY_SCRIPT = SCRIPTS_DIR / "Test-AuthenticodeSignature.ps1"


def get_powershell_executable() -> str | None:
    for cmd in ["pwsh", "powershell"]:
        if shutil.which(cmd):
            return cmd
    return None


def test_scripts_exist():
    assert SIGN_SCRIPT.exists(), f"Missing {SIGN_SCRIPT}"
    assert VERIFY_SCRIPT.exists(), f"Missing {VERIFY_SCRIPT}"


def test_powershell_syntax():
    ps = get_powershell_executable()
    if not ps:
        return  # Skip if neither pwsh nor powershell is in PATH

    for script in [SIGN_SCRIPT, VERIFY_SCRIPT]:
        content = script.read_text(encoding="utf-8")
        escaped_content = content.replace("`", "``").replace('"', '`"')
        parse_cmd = [
            ps,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"""
            $errors = $null
            $tokens = $null
            [System.Management.Automation.Language.Parser]::ParseFile('{script.as_posix()}', [ref]$tokens, [ref]$errors) | Out-Null
            if ($errors.Count -gt 0) {{
                $errors | ForEach-Object {{ Write-Error $_.Message }}
                exit 1
            }}
            exit 0
            """
        ]
        result = subprocess.run(parse_cmd, capture_output=True, text=True)
        assert result.returncode == 0, f"PowerShell syntax errors in {script.name}:\n{result.stderr}"


def test_sign_script_parameters():
    content = SIGN_SCRIPT.read_text(encoding="utf-8")
    expected_params = [
        "Endpoint",
        "CodeSigningAccountName",
        "CertificateProfileName",
        "Files",
        "TimestampRfc3161",
        "TimestampDigest",
        "FileDigest",
        "FailOnWarning",
        "DryRun",
    ]
    for param in expected_params:
        assert f"${param}" in content, f"Missing parameter ${param} in Sign-Artifacts.ps1"


def test_verify_script_parameters():
    content = VERIFY_SCRIPT.read_text(encoding="utf-8")
    expected_params = [
        "Files",
        "ExpectedDigest",
        "ExpectedSubject",
        "RequireTimestamp",
        "FailOnWarning",
        "DryRun",
    ]
    for param in expected_params:
        assert f"${param}" in content, f"Missing parameter ${param} in Test-AuthenticodeSignature.ps1"


def test_sign_artifacts_dryrun_execution():
    ps = get_powershell_executable()
    if not ps:
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        test_file = tmp_path / "app.ps1"
        test_file.write_text("Write-Host 'Dry Run Test'", encoding="utf-8")

        gh_output = tmp_path / "github_output.txt"
        env = os.environ.copy()
        env["GITHUB_OUTPUT"] = str(gh_output)

        cmd = [
            ps,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SIGN_SCRIPT),
            "-CodeSigningAccountName", "mock-account",
            "-CertificateProfileName", "mock-profile",
            "-Files", str(test_file),
            "-DryRun"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        assert result.returncode == 0, f"Sign-Artifacts.ps1 failed in DryRun:\n{result.stdout}\n{result.stderr}"
        assert "signed-files-count=1" in gh_output.read_text(encoding="utf-8")


def test_verify_artifacts_dryrun_execution():
    ps = get_powershell_executable()
    if not ps:
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        test_file = tmp_path / "app.ps1"
        test_file.write_text("Write-Host 'Dry Run Test'", encoding="utf-8")

        gh_output = tmp_path / "github_output.txt"
        env = os.environ.copy()
        env["GITHUB_OUTPUT"] = str(gh_output)

        cmd = [
            ps,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(VERIFY_SCRIPT),
            "-Files", str(test_file),
            "-DryRun"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        assert result.returncode == 0, f"Test-AuthenticodeSignature.ps1 failed in DryRun:\n{result.stdout}\n{result.stderr}"
        assert "verified-files-count=1" in gh_output.read_text(encoding="utf-8")


def test_sign_artifacts_fail_on_warning_when_no_files():
    ps = get_powershell_executable()
    if not ps:
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        gh_output = tmp_path / "github_output.txt"
        env = os.environ.copy()
        env["GITHUB_OUTPUT"] = str(gh_output)

        cmd = [
            ps,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SIGN_SCRIPT),
            "-CodeSigningAccountName", "mock-account",
            "-CertificateProfileName", "mock-profile",
            "-Files", str(tmp_path / "nonexistent_*.exe"),
            "-FailOnWarning",
            "-DryRun"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        assert result.returncode == 1, "Expected exit code 1 when no files match and FailOnWarning is set"
