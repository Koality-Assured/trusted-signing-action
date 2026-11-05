"""Pytest suite validating adversarial review checks and zero-leak compliance."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import adversarial_review


def test_adversarial_file_collection():
    files = adversarial_review.collect_target_files()
    assert len(files) > 0, "Adversarial scanner must discover repository files"
    rel_paths = [f.relative_to(REPO_ROOT).as_posix() for f in files]
    assert "action.yml" in rel_paths
    assert "scripts/Sign-Artifacts.ps1" in rel_paths
    assert "scripts/Test-AuthenticodeSignature.ps1" in rel_paths


def test_adversarial_zero_leak_scan():
    files = adversarial_review.collect_target_files()
    violations = adversarial_review.run_pattern_leak_scan(files)
    assert len(violations) == 0, f"Found leak violations:\n" + "\n".join(violations)


def test_adversarial_syntax_validation():
    files = adversarial_review.collect_target_files()
    syntax_errors = adversarial_review.run_syntax_validation(files)
    assert len(syntax_errors) == 0, f"Found syntax violations:\n" + "\n".join(syntax_errors)


def test_adversarial_cryptographic_manifest():
    files = adversarial_review.collect_target_files()
    manifest = adversarial_review.run_cryptographic_audit(files)
    assert len(manifest) == len(files)
    for path, sha256 in manifest.items():
        assert len(sha256) == 64, f"Invalid SHA-256 hash for {path}"
