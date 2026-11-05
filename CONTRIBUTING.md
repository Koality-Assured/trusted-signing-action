# Contributing to Trusted Signing Action

Thank you for contributing to the Koality Assured `trusted-signing-action`! We welcome contributions to maintain enterprise-grade security, broad Authenticode artifact compatibility, and robust zero-credential signing pipelines.

---

## Development Workflow

### Prerequisites

- **PowerShell:** PowerShell 7+ (`pwsh`) or Windows PowerShell 5.1+
- **Python:** Python 3.11+
- **Git** with Conventional Commits awareness
- **pytest** & **PyYAML**

### Local Setup

1. Clone repository:
   ```bash
   git clone https://github.com/koality-assured/trusted-signing-action.git
   cd trusted-signing-action
   ```

2. Install test dependencies:
   ```bash
   python -m pip install --upgrade pip
   pip install pytest pyyaml
   ```

3. Run the automated test suite:
   ```bash
   python -m pytest -v
   ```

4. Run the antagonistic security and leak review:
   ```bash
   python adversarial_review.py
   ```

---

## Coding Standards

### GitHub Actions & Shell Scripts
- Use environment variables (`$env:INPUT_*`) rather than inline `${{ inputs.* }}` interpolation inside shell run blocks to prevent command injection.
- Scripts must run with `$ErrorActionPreference = 'Stop'` and `Set-StrictMode -Version Latest`.
- All errors must be logged cleanly and yield well-defined exit codes:
  - `0`: Complete success.
  - `1`: Non-fatal warning (or warning under `FailOnWarning` mode).
  - `2`: Fatal failure / error.

### Python Code & Tests
- Follow PEP 8 and Python 3.11+ typing standards (`from __future__ import annotations`).
- Add comprehensive test cases in `tests/` for any new feature or parameter.

---

## Mandatory Verification Gates

Prior to opening a pull request or merging commits:
1. **100% Test Pass Rate:** `python -m pytest` must report zero failures.
2. **Zero-Leak Antagonistic Review:** `python adversarial_review.py` must pass with status `PASSED`.
3. **Conventional Commits:** Commit messages must follow the Conventional Commits specification (e.g. `feat:`, `fix:`, `docs:`, `refactor:`, `test:`).
