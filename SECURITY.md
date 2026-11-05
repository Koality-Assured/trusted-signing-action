# Security Policy

## Supported Versions

The following versions of `trusted-signing-action` currently receive active security updates, vulnerability patches, and cryptographic compliance reviews:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## Reporting a Vulnerability

Koality Assured takes the security of code signing pipelines, PKI keys, and CI/CD actions with extreme seriousness. If you discover an authorization bypass, credential leak, command injection risk, or cryptographic vulnerability in this action, please do **NOT** open a public issue.

Instead, submit a responsible disclosure report directly to the Koality Assured Security Team:

- **Security Team Email:** `security@koalityassured.com`
- **PGP Key ID:** `0x4A1E2B3C` (Available upon request)

### What to Include in Your Report

To facilitate swift triage and remediation, please provide:
1. Detailed description of the vulnerability and attack vector.
2. Proof-of-concept (PoC) workflow or invocation demonstrating the flaw (ensure no production secrets or credentials are included).
3. Component impacted (`action.yml`, `Sign-Artifacts.ps1`, `Test-AuthenticodeSignature.ps1`).
4. Suggested remediation or defensive control.

### Response Timelines

- **Initial Acknowledgment:** Within 24 hours of receipt.
- **Triage & Risk Assessment:** Within 72 hours.
- **Remediation & Patch Deployment:** Critical vulnerabilities remediated within 7 business days.

---

## Architectural Security Standards

This GitHub Action enforces zero-trust, enterprise AppSec principles:

1. **Zero-Credential Architecture (OIDC):**
   - No long-lived client secrets, certificates, or private keys are stored in GitHub repository secrets.
   - All authentication routes through Azure Workload Identity Federation using OpenID Connect (OIDC) short-lived JWT tokens.

2. **Anti-Injection Input Sanitization:**
   - Script parameters are bound via shell environment variables rather than direct inline string interpolation in workflow command blocks.
   - Prevents command injection and parameter expansion attacks in CI runner environments.

3. **Cryptographic Authenticode Verification:**
   - Every signed artifact undergoes immediate post-signing validation.
   - Signer certificate chains, RFC 3161 timestamps, and SHA-256 digests are cryptographically asserted before artifacts are accepted into release stages.

4. **Least-Privilege RBAC:**
   - The Azure Service Principal requires only the `Code Signing Certificate Profile Signer` role on the specific certificate profile.
   - No broad subscription or management permissions are required or granted.
