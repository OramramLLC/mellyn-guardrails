# Mellyn Guardrails — Client Onboarding Guide (Planes 1 & 2)

Adopt Mellyn Guardrails' OWASP-aligned AI-assisted coding controls in **under 10 minutes** with **zero copy-pasted scripts**. Every control is pinned by full Git commit SHA so your team pulls updates deliberately and never suffers rule drift.

> **Before you start (Repository Visibility & Cross-Org Access):** in the snippets below, `<owner>/<guardrails-repo>` is typically `OramramLLC/mellyn-guardrails`, and `<MELLYN_COMMIT_SHA>` is the full 40-character commit SHA you reviewed.
> - **Public repository**: Any external GitHub.com organization or user repository can call the reusable workflow directly.
> - **Private B2B distribution**: GitHub Actions does **not** allow a private repository in one organization to share `workflow_call` workflows across external customer organizations (*Settings → Actions → General → Access* applies only within the **same** GitHub Organization or GitHub Enterprise). For private B2B deployments, mirror the reviewed commit into an internal/private repository inside **your own** GitHub Organization (`<your-org>/mellyn-guardrails`), enable *Accessible from repositories in the organization* there, and point `uses:` at `<your-org>/mellyn-guardrails/...` (`job.workflow_repository` and `job.workflow_sha` resolve automatically to your mirror). Note that `job.workflow_*` requires GitHub.com / GitHub Enterprise Cloud (not GitHub Enterprise Server).

---

## 1. Add the Reusable GitHub Actions Security Gate (~10 Lines)

Create `.github/workflows/mellyn-security.yml` in your repository:

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
    uses: OramramLLC/mellyn-guardrails/.github/workflows/mellyn-reusable-ai-security-gate.yml@<MELLYN_COMMIT_SHA>
    with:
      min-package-age-days: 90
      check-agent-rules: true
      run-semgrep: true
      run-gitleaks: true
```

The gate runs the Gitleaks CLI directly (pinned and checksum-verified), so no Gitleaks license is needed. It checks out your code (`caller/`) and Mellyn Guardrails (`mellyn/`) into separate directories and always uses the rules from the exact commit SHA you pinned (`job.workflow_repository@job.workflow_sha`), never files from the pull request under review.

### What This Enforces Automatically on Every PR
1. **AI & Cloud Secret Scanning (Gitleaks)**: Blocks OpenAI, Anthropic, Gemini, HuggingFace, LangSmith, AWS, and GitHub credentials before merge.
2. **Anti-Slopsquatting & Lockfile Supply-Chain Check**: Verifies direct manifests (`pyproject.toml`, `requirements*.txt`, `package.json`) **and** transitive lockfiles (`requirements*.lock`, `uv.lock`, `package-lock.json`) exist on PyPI/npm, are older than `min-package-age-days` (default 90), meet a 14-day release-upload cooldown on exact-pinned versions, use registry-only sources, and carry meaningful version floors. Lockfiles may not switch the package index (`--index-url`, `--extra-index-url`, `--find-links`) or include other files, and every artifact hash they pin must be one the registry itself publishes for that release; npm aliases are checked under their real package name. Audited exemptions go in `.mellyn-allowlist.toml` (expiring within 180 days; the release cooldown only for listed `versions`). **On pull requests the gate reads that file from the PR's base commit (`HEAD^1`)**, so a PR cannot exempt its own dependencies: add an exemption in its own reviewed PR first.
3. **OWASP AI-Targeted SAST (Semgrep)**: Catches classic LLM-generated flaws (`eval`/`exec`, `shell=True`, unsafe `pickle`/`yaml.load`/`torch.load`, SQL string building, weak crypto/randomness, and unsanitized HTML).
4. **Hidden-Unicode & Rules Sync Check**: Blocks invisible bidi/tag characters ("Rules File Backdoor" prompt injection) in AI assistant instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/`, `.github/copilot-instructions.md`, `.github/instructions/`, ...). If you also adopt the canonical `.agent/rules/owasp-secure-ai-coding.md`, it checks the generated copies are in sync. Set `require-pack-rules: true` to also require that file to match the pinned pack's copy exactly; otherwise edits to it go unchecked.

### Suppressions are not honored

Code under review cannot switch the gate off. `# nosemgrep` and `# gitleaks:allow` comments are ignored, any `.semgrepignore` or `.gitleaksignore` in your repository is not used, and the gate supplies its own ignore list (`/node_modules/`). `tests/` **is** scanned. A genuine false positive is fixed by changing the code, or by asking for a rule change in `mellyn-guardrails`, which then goes through review there. On pull requests Gitleaks scans the PR's commits; on pushes, the pushed commits (full history for a new branch).

---

## 2. Add the Versioned Local Pre-Commit Hooks

Add Mellyn Guardrails to your repository's `.pre-commit-config.yaml` (pinned to the same commit SHA):

```yaml
repos:
  - repo: https://github.com/OramramLLC/mellyn-guardrails
    rev: <MELLYN_COMMIT_SHA>
    hooks:
      - id: mellyn-verify-dependencies
        args: [--online] # omit to skip the live registry lookups locally (CI always runs them)
      - id: mellyn-check-agent-rules
      - id: mellyn-gitleaks
      - id: mellyn-semgrep
```

`mellyn-verify-dependencies` and `mellyn-check-agent-rules` run using the Python 3.12+ standard library only. `mellyn-gitleaks` and `mellyn-semgrep` invoke locally installed `gitleaks` and `semgrep` binaries with this pack's pinned `.gitleaks.toml` and `.semgrep/owasp-ai-code-rules.yaml` (failing closed if the tool is missing, and refusing every flag except output options). Local hooks are a developer convenience: they still honour `# nosemgrep`, `# gitleaks:allow` and a local `.gitleaksignore`, and `git commit --no-verify` skips them. The reusable CI gate is the enforcement boundary; it ignores all of those and brings its own checksum-verified Gitleaks and hash-locked Semgrep.

Then activate locally:

```bash
pre-commit install
pre-commit run --all-files
```

---

## 3. Lock Down Governance (Recommended)

1. Enable **Branch Protection** on `main` requiring the `mellyn-gate` status checks to pass before merge.
2. Add a `.github/CODEOWNERS` file requiring security/lead-engineer review on `.github/workflows/`, `.pre-commit-config.yaml`, `.mellyn-allowlist.toml`, `.agent/`, `CLAUDE.md`, `.cursorrules`, and `.claude/settings.json` so an AI coding agent cannot weaken or unpin its own guardrails.
3. Update Mellyn Guardrails pins deliberately via `pre-commit autoupdate --freeze` and Dependabot for GitHub Actions.

---

## 4. Next Step: Runtime MCP Tool-Call Protection

Once your repositories are protected at commit and PR time, deploy **Mellyn Security** (`OramramLLC/mellyn_security`) — the **MCP Airlock, Runtime Authorization Engine, and Forensic Flight Recorder** — to enforce deterministic tool-call authorization, provenance taint tracking, AgBOM manifest pinning, and optional Docker + Squid network egress containment at runtime.
