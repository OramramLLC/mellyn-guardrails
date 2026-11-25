# Security Policy

## Supported Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `main` (commit-SHA pinned) | Yes | Current guardrail pack (`.github/workflows/`, `.pre-commit-hooks.yaml`, `scripts/`, `.semgrep/`, `.gitleaks.toml`, `.agent/rules/`) |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for suspected security vulnerabilities.**

Please report security findings privately through **GitHub Security Advisories** (`Security` tab -> `Report a vulnerability`) on the `mellyn-guardrails` repository.

When reporting an issue, please include:
1. Affected component (e.g., `mellyn-reusable-ai-security-gate.yml`, `.pre-commit-hooks.yaml`, `scripts/verify_dependencies.py`, `scripts/sync_agent_rules.py`, `scripts/ci_guardrails.py`, `.semgrep/`, or `.gitleaks.toml`).
2. Clear reproduction steps or a minimal proof-of-concept showing how a fail-closed check, suppression guard, PR base-commit allowlist isolation, or SAST/secret rule can be bypassed.
3. Exact commit SHA and environment (Python version, GitHub Actions runner or local OS).

You can expect an initial acknowledgment within **3 business days** and a coordinated status update as the fix and regression tests are prepared.

---

## Security Commitments & Boundaries

- **Baseline-vs-Candidate Isolation**: The reusable CI gate checks out caller code (`caller/`) and Mellyn Guardrails (`mellyn/` at `job.workflow_repository@job.workflow_sha`) separately so code under review cannot replace or weaken the rules, scripts, or scanner lockfiles that evaluate it. On pull requests, `.mellyn-allowlist.toml` exemptions are read strictly from `HEAD^1` (the PR's base commit).
- **Anti-Suppression Enforcement**: CI scans disable inline `# nosemgrep` and `# gitleaks:allow` comments and ignore caller `.semgrepignore` / `.gitleaksignore` files. Pre-commit scanner wrappers accept only output flags (an allow-list) and fail closed if the target binary or rules file is unavailable. Local hooks still honour inline suppressions and a local `.gitleaksignore`, as the upstream hooks do; they are a convenience, and the CI gate is the boundary.
- **Supply-Chain Integrity**: `scripts/verify_dependencies.py` rejects non-registry sources, unpinned version floors, hash mismatches, newly registered packages (<90 days), and fresh uploads (<14 days) fail-closed. CI verifies Gitleaks against a pinned SHA-256 checksum (`GITLEAKS_LINUX_X64_SHA256`) and installs scanner Python packages with `--require-hashes --no-deps`.
- **No Substitution for Code Review or Runtime Containment**: Static gates and pre-commit hooks do not replace human review or runtime MCP authorization (`OramramLLC/mellyn_security`).
