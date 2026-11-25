# CLAUDE.md — Project Context & OWASP AI Security Guardrails

## Project Overview
This repository houses **Mellyn Guardrails**, the AI-assisted coding and CI/CD security guardrail pack (Planes 1–2 of the Mellyn Security architecture).

- **Included here**: canonical OWASP AI secure-coding rules and hidden-Unicode/sync checker (`scripts/sync_agent_rules.py`), anti-slopsquatting & lockfile supply-chain verifier (`scripts/verify_dependencies.py`, `.mellyn-allowlist.toml`), AI + cloud Gitleaks config (`.gitleaks.toml`), custom OWASP AI Semgrep rules & fixtures (`.semgrep/`), trusted CI runner (`scripts/ci_guardrails.py`), SHA-pinnable reusable GitHub Actions workflow (`.github/workflows/mellyn-reusable-ai-security-gate.yml`), and the 4-hook pre-commit pack (`.pre-commit-hooks.yaml`).
- **Sibling repositories**: `mellyn_security` (core MCP Airlock, runtime authorizer, and forensic flight recorder) and `mellyn-redteam` (adversarial evaluation & conformance harness).

## Essential Commands
On Windows, use `py` instead of `python` if `python` opens the Microsoft Store.

- **Verify dependencies (anti-slopsquatting)**: `python scripts/verify_dependencies.py --online`
- **Run tests**: `python -m unittest discover -s tests -v` (or `pytest`)
- **Check agent rules are in sync**: `python scripts/sync_agent_rules.py --check`
- **Static analysis**: `semgrep scan --config .semgrep/owasp-ai-code-rules.yaml --exclude .semgrep --error`
- **Test the Semgrep rules**: `cd .semgrep && semgrep --test .` (must run inside the directory)
- **Secrets scan**: `gitleaks git --config .gitleaks.toml`
- **All hooks**: `pre-commit run --all-files`

## Mandatory Security Rules
The full ruleset lives in one canonical file shared by every coding assistant in this repo. Edit that file only, then
run `python scripts/sync_agent_rules.py` to regenerate `.cursorrules` and `.github/copilot-instructions.md`.

@.agent/rules/owasp-secure-ai-coding.md
