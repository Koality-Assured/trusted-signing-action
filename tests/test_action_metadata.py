"""Tests validating action.yml metadata, schema, and security configuration."""

from __future__ import annotations

from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ACTION_FILE = REPO_ROOT / "action.yml"


def test_action_yml_exists_and_parses():
    assert ACTION_FILE.exists(), "action.yml must exist at repository root"
    content = ACTION_FILE.read_text(encoding="utf-8")
    data = yaml.safe_load(content)
    assert isinstance(data, dict), "action.yml must be a valid YAML dictionary"
    assert data.get("name") == "Azure Trusted Signing"
    assert data.get("author") == "Koality Assured"


def test_action_inputs_schema():
    content = ACTION_FILE.read_text(encoding="utf-8")
    data = yaml.safe_load(content)
    inputs = data.get("inputs", {})

    expected_inputs = [
        "azure-tenant-id",
        "azure-client-id",
        "endpoint",
        "trusted-signing-account-name",
        "certificate-profile-name",
        "files",
        "timestamp-rfc3161",
        "timestamp-digest",
        "verify",
        "fail-on-warning",
    ]

    for expected in expected_inputs:
        assert expected in inputs, f"Missing required input parameter: '{expected}'"

    # Check defaults
    assert inputs["endpoint"]["default"] == "https://eus.codesigning.azure.net/"
    assert inputs["timestamp-rfc3161"]["default"] == "http://timestamp.acs.microsoft.com"
    assert inputs["timestamp-digest"]["default"] == "SHA256"
    assert inputs["verify"]["default"] == "true"
    assert inputs["fail-on-warning"]["default"] == "false"


def test_action_outputs_schema():
    content = ACTION_FILE.read_text(encoding="utf-8")
    data = yaml.safe_load(content)
    outputs = data.get("outputs", {})

    expected_outputs = [
        "signed-files-count",
        "verified-files-count",
        "signing-status",
    ]

    for expected in expected_outputs:
        assert expected in outputs, f"Missing required output parameter: '{expected}'"


def test_action_runs_composite_structure():
    content = ACTION_FILE.read_text(encoding="utf-8")
    data = yaml.safe_load(content)
    runs = data.get("runs", {})

    assert runs.get("using") == "composite", "Action must be a composite GitHub Action"
    steps = runs.get("steps", [])
    assert len(steps) >= 2, "Composite action must define at least execution and verification steps"

    step_names = [s.get("name", "") for s in steps]
    assert any("Sign" in name for name in step_names), "Must include a signing step"
    assert any("Verify" in name for name in step_names), "Must include a verification step"


def test_action_injection_mitigation():
    """Verify that composite run blocks do not interpolate ${{ inputs.* }} directly into shell text."""
    content = ACTION_FILE.read_text(encoding="utf-8")
    data = yaml.safe_load(content)
    steps = data.get("runs", {}).get("steps", [])

    for step in steps:
        run_block = step.get("run", "")
        # Flag dangerous direct interpolation of untrusted file inputs inside shell commands
        assert "${{ inputs.files }}" not in run_block, (
            "Security violation: inputs.files interpolated directly in shell run block. Use $env:INPUT_* instead."
        )
        assert "${{ inputs.endpoint }}" not in run_block, (
            "Security violation: inputs.endpoint interpolated directly in shell run block. Use $env:INPUT_* instead."
        )
