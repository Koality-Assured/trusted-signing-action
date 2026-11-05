"""Tests for file glob matching, multiline input parsing, and supported extension filtering."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import List, Set

SUPPORTED_EXTENSIONS: Set[str] = {
    ".ps1", ".psm1", ".psd1",
    ".exe", ".dll", ".sys", ".ocx",
    ".msi", ".msp", ".msm",
    ".cat", ".cab",
    ".appx", ".appxbundle", ".msix", ".msixbundle"
}


def parse_and_resolve_patterns(patterns_str: str, base_dir: Path) -> List[Path]:
    """Python reference implementation of the PowerShell Resolve-TargetFiles logic."""
    raw_patterns = [
        line.strip()
        for line in re.split(r"[\r\n;,]+", patterns_str)
        if line.strip() and not line.strip().startswith("#")
    ]

    matched_files: List[Path] = []
    for pat in raw_patterns:
        clean_pat = pat.strip("'\"`")
        
        # Check direct path
        target = Path(clean_pat)
        if not target.is_absolute():
            target = base_dir / target

        if target.is_file():
            if target.resolve() not in matched_files:
                matched_files.append(target.resolve())
            continue

        # Wildcard resolution
        try:
            if "**" in clean_pat:
                # Recursive glob
                rel_pat = clean_pat.replace("\\", "/")
                for found in base_dir.glob(rel_pat):
                    if found.is_file() and found.resolve() not in matched_files:
                        matched_files.append(found.resolve())
            else:
                rel_pat = clean_pat.replace("\\", "/")
                for found in base_dir.glob(rel_pat):
                    if found.is_file() and found.resolve() not in matched_files:
                        matched_files.append(found.resolve())
        except Exception:
            pass

    return matched_files


def test_single_file_matching():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        file1 = tmp_path / "script.ps1"
        file1.write_text("Write-Host 'Hello'", encoding="utf-8")

        resolved = parse_and_resolve_patterns("script.ps1", tmp_path)
        assert len(resolved) == 1
        assert resolved[0] == file1.resolve()


def test_wildcard_glob_matching():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "app.exe").write_bytes(b"MZ\x00\x00")
        (tmp_path / "lib.dll").write_bytes(b"MZ\x00\x00")
        (tmp_path / "notes.txt").write_text("ignore me", encoding="utf-8")

        resolved_exe = parse_and_resolve_patterns("*.exe", tmp_path)
        assert len(resolved_exe) == 1
        assert resolved_exe[0].name == "app.exe"

        resolved_all = parse_and_resolve_patterns("*.*", tmp_path)
        assert len(resolved_all) == 3


def test_multiline_and_comment_parsing():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "mod1.psm1").write_text("function F1 {}", encoding="utf-8")
        (tmp_path / "mod2.psd1").write_text("@{}", encoding="utf-8")
        (tmp_path / "test.msi").write_bytes(b"\xd0\xcf\x11\xe0")

        multiline_input = """
        # Core modules to sign
        mod1.psm1
        
        # Manifests
        mod2.psd1; test.msi
        """

        resolved = parse_and_resolve_patterns(multiline_input, tmp_path)
        names = {f.name for f in resolved}
        assert names == {"mod1.psm1", "mod2.psd1", "test.msi"}


def test_supported_extensions_validation():
    for ext in [".ps1", ".exe", ".dll", ".msi", ".cat", ".cab", ".appx"]:
        assert ext in SUPPORTED_EXTENSIONS, f"Extension {ext} must be supported"

    unsupported = [".txt", ".sh", ".json", ".zip", ".tar.gz"]
    for ext in unsupported:
        assert ext not in SUPPORTED_EXTENSIONS, f"Extension {ext} should not be in Authenticode supported set"


def test_file_with_spaces_and_quotes():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        spaced_file = tmp_path / "My Awesome App.exe"
        spaced_file.write_bytes(b"MZ\x00\x00")

        # Quoted input
        pattern = f'"{spaced_file.name}"'
        resolved = parse_and_resolve_patterns(pattern, tmp_path)
        assert len(resolved) == 1
        assert resolved[0].name == "My Awesome App.exe"


def test_empty_matches_returns_empty_list():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        resolved = parse_and_resolve_patterns("non_existent_*.dll", tmp_path)
        assert resolved == []
