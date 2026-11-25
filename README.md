# Mellyn Guardrails — OWASP AI-Assisted Coding & CI/CD Security Gate

**Mellyn Guardrails** is a standalone, SHA-pinnable AI-assisted coding and CI/CD security pack (Planes 1–2 of the Mellyn Security architecture). It provides deterministic secret scanning, AI-targeted static analysis, anti-slopsquatting dependency verification, and hidden-Unicode instruction file checks with zero copy-pasted scripts in consuming repositories.

---

## What Is Included

1. **Canonical AI Steering Rules & Hidden-Unicode Sync**
   - Canonical ruleset in [`.agent/rules/owasp-secure-ai-coding.md`](.agent/rules/owasp-secure-ai-coding.md), synchronized to [`CLAUDE.md`](CLAUDE.md), [`.cursorrules`](.cursorrules), and [`.github/copilot-instructions.md`](.github/copilot-instructions.md) via [`scripts/sync_agent_rules.py`](scripts/sync_agent_rules.py).
   - Rejects invisible format, bidi, tag, variation-selector, filler, and lone control characters ("Rules File Backdoor" prompt smuggling) across AI coding instruction files in any repository (`--check --root <repo>`).
   - Starter Claude Code permission boundaries in [`.claude/settings.json`](.claude/settings.json).
2. **AI & Cloud Secret Scanning ([`.gitleaks.toml`](.gitleaks.toml))**
   - Extends Gitleaks defaults with explicit rules for OpenAI (`sk-`, `sk-proj-`, `sk-svcacct-`), Anthropic (`sk-ant-`), Google Gemini (`AIza`), HuggingFace (`hf_`), and LangSmith (`lsv2_`) credentials using value-only placeholder allowlisting (no file-path exemptions).
3. **OWASP AI-Targeted Semgrep SAST ([`.semgrep/owasp-ai-code-rules.yaml`](.semgrep/owasp-ai-code-rules.yaml))**
   - Catches common LLM-generated vulnerabilities (`eval`/`exec`, `shell=True`, unsafe `pickle`/`yaml.load`/`torch.load`, SQL string formatting, `MD5`/`SHA-1`, insecure `random`/`Math.random()`, and unsanitized `dangerouslySetInnerHTML`) with regression fixtures in [`.semgrep/owasp-ai-code-rules.py`](.semgrep/owasp-ai-code-rules.py) and [`.semgrep/owasp-ai-code-rules.tsx`](.semgrep/owasp-ai-code-rules.tsx).
4. **Anti-Slopsquatting & Supply-Chain Verifier ([`scripts/verify_dependencies.py`](scripts/verify_dependencies.py))**
   - Checks Python (`pyproject.toml`, `requirements*.txt`, `requirements*.lock`, `uv.lock`) and npm (`package.json`, `package-lock.json`) manifests and lockfiles for registry-only sources, version floors, artifact hashes published by PyPI/npm, 90-day package age, and a 14-day release cooldown, governed by [`.mellyn-allowlist.toml`](.mellyn-allowlist.toml).
5. **Reusable CI Gate & 4-Hook Pre-Commit Pack**
   - [`.github/workflows/mellyn-reusable-ai-security-gate.yml`](.github/workflows/mellyn-reusable-ai-security-gate.yml) (`workflow_call`)
   - [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml) (`mellyn-verify-dependencies`, `mellyn-check-agent-rules`, `mellyn-gitleaks`, `mellyn-semgrep`)
   - See [**`docs/CLIENT_ONBOARDING.md`**](docs/CLIENT_ONBOARDING.md) and [**`docs/OWASP_AI_CODING_SECURITY.md`**](docs/OWASP_AI_CODING_SECURITY.md).

---

## Quickstart for Consumer Repositories

### 1. Reusable GitHub Actions Security Gate

Pin a full 40-character commit SHA in `.github/workflows/mellyn-security.yml`:

```yaml
name: Mellyn Security AI Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  mellyn-gate:
    uses: OramramLLC/mellyn-guardrails/.github/workflows/mellyn-reusable-ai-security-gate.yml@<40-char-commit-sha>
    with:
      min-package-age-days: 90
      check-agent-rules: true
      run-semgrep: true
      run-gitleaks: true
```

### 2. Pre-Commit Hook Pack (4 Hooks)

Add the same pinned commit SHA to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/OramramLLC/mellyn-guardrails
    rev: <40-char-commit-sha>
    hooks:
      - id: mellyn-verify-dependencies
        args: [--online]
      - id: mellyn-check-agent-rules
      - id: mellyn-gitleaks
      - id: mellyn-semgrep
```

`mellyn-verify-dependencies` and `mellyn-check-agent-rules` use the Python 3.12+ standard library only. `mellyn-gitleaks` and `mellyn-semgrep` invoke locally installed `gitleaks` and `semgrep` binaries with this pack's pinned `.gitleaks.toml` and `.semgrep/owasp-ai-code-rules.yaml`. They fail closed if the local tool is missing, and they refuse every flag except output options (`--no-banner` and `--no-color` for Gitleaks; `--quiet` and `--verbose` for Semgrep).

**Local hooks are a fast first check, not the gate.** Like the upstream Gitleaks and Semgrep hooks, they still honour `# nosemgrep` and `# gitleaks:allow` comments and a local `.gitleaksignore`, and anyone can skip them with `git commit --no-verify`. The reusable CI workflow ignores all of those, so make it a required check on your default branch.

To hold a repository's copy of the agent rules to this pack's wording, pass `--require-pack-canonical` (hook: `args: [--check, --require-pack-canonical]`; workflow: `require-pack-rules: true`). Without it, the check only confirms that the repository's generated copies match the repository's own `.agent/rules/owasp-secure-ai-coding.md`, so a repository that edits that file and regenerates still passes.

---

## How the Baseline-vs-Candidate Guarantee Holds Under SHA Pinning

A common weakness in PR security gates is letting a pull request weaken the rules, scripts, or allowlists that evaluate it. That guarantee is preserved across both modes:

1. **Consumer repositories calling the reusable workflow by SHA:**
   - [`.github/workflows/mellyn-reusable-ai-security-gate.yml`](.github/workflows/mellyn-reusable-ai-security-gate.yml) checks out the caller's code into `caller/` and checks out **this** guardrail repository into `mellyn/` using `${{ job.workflow_repository }}` at `${{ job.workflow_sha }}` (never `github.workflow_*`, which reflects the caller). Both checkouts set `persist-credentials: false`.
   - All scanner configs (`.gitleaks.toml`, `.semgrep/owasp-ai-code-rules.yaml`), scripts (`scripts/ci_guardrails.py`, `scripts/verify_dependencies.py`, `scripts/sync_agent_rules.py`), and hash-locked scanner dependencies (`deploy/requirements-ci-scanners.lock`) execute strictly from `mellyn/`, while Gitleaks is downloaded and verified against `GITLEAKS_LINUX_X64_SHA256`.
   - Suppressions inside `caller/` are disabled (`--disable-nosem`, `--ignore-gitleaks-allow`), and any `.semgrepignore` or `.gitleaksignore` in `caller/` is replaced or bypassed.
   - For `.mellyn-allowlist.toml`, on `pull_request` / `pull_request_target` events [`scripts/ci_guardrails.py`](scripts/ci_guardrails.py) reads the exemption file strictly from `HEAD^1` (the PR's base commit), never from the PR head—so a pull request cannot self-exempt new dependencies.
   - Pair the workflow with `.github/CODEOWNERS` and branch protection on `main` in the consumer repository so PRs cannot edit `.github/workflows/` to unpin the commit SHA without owner review.
   - *(Note: `job.workflow_*` requires GitHub.com or GitHub Enterprise Cloud; for private cross-org distribution, mirror a reviewed commit into an internal org repo.)*
2. **This repository's own CI ([`.github/workflows/guardrails-ci.yml`](.github/workflows/guardrails-ci.yml)):**
   - Required baseline jobs (`secrets` and `sast-and-supply-chain`) check out `baseline/` at `github.event.pull_request.base.sha || github.sha` and evaluate `candidate/` using baseline's scripts, rules, allowlist, and `pyproject.toml` (`ruff --config ../baseline/pyproject.toml`).
   - A separate `candidate-guardrails` job validates proposed rule/script edits (`semgrep --test .`, plus candidate Gitleaks and `run-suite --use-candidate-guardrails` on PRs).

---

## Local Verification

```bash
python -m unittest discover -s tests -v
python scripts/sync_agent_rules.py --check
python scripts/sync_agent_rules.py --check --root ../V1 --require-pack-canonical   # a consumer's rules match this pack
python scripts/verify_dependencies.py --online
cd .semgrep && semgrep --test --metrics=off .
pre-commit run --all-files
```

---

## Sibling Repositories

- **`OramramLLC/mellyn_security`**: Core MCP runtime engine — MCP Airlock, Runtime Authorization Engine, Forensic Flight Recorder, and optional self-hosted container + Squid egress stack.
- **`OramramLLC/mellyn-redteam`**: Adversarial MCP red-team harness and OWASP/ATLAS conformance evaluation suite.
