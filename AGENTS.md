# AGENTS.md — Trusted Signing Action Operational Guidelines

Canonical operational rules for autonomous and pair-programming AI coding agents operating on `trusted-signing-action`.

---

## 1. Zero-Leak & Sanitization Invariant (CRITICAL)

- **Strict Proprietary Sanitization:** Agents MUST NOT insert, commit, or reference proprietary company names, legacy studio labels, internal AWS account numbers, real production endpoint URLs, or live API credentials.
- **Sanitized Test Fixtures:** All test fixtures and examples MUST use RFC 2606 reserved domains (`example.com`, `example.org`, `localhost`) and dummy UUIDs or tokens (`00000000-0000-0000-0000-000000000000`, `mock_token`).
- **Adversarial Gate:** Prior to submitting changes, agents MUST execute `python adversarial_review.py` and ensure a 0-violation outcome.

---

## 2. Architecture & Code Style Standards

- **Composite GitHub Action:** `action.yml` must remain a clean composite action relying on environment variables to pass inputs to PowerShell scripts, mitigating shell expansion and command injection vulnerabilities.
- **PowerShell Scripting:**
  - Strict mode enabled (`Set-StrictMode -Version Latest`).
  - Error preference set to Stop (`$ErrorActionPreference = 'Stop'`).
  - Deterministic exit codes: 0 = Success, 1 = Warning, 2 = Error.
  - Multi-engine signing fallback (SignTool with `Azure.CodeSigning.Dlib.dll`, `TrustedSigning` module, and DryRun simulation).
- **Test Automation:**
  - Python tests under `tests/` leveraging pytest and PyYAML.
  - 100% test pass rate required.

---

## 3. Mandatory Verification Gate

Before completing any task or committing changes:
1. Run `python -m pytest -v` (must achieve 100% pass rate).
2. Run `python adversarial_review.py` (must report status `PASSED` with 0 leak violations and 0 syntax errors).
3. Commit using Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
