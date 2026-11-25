#!/usr/bin/env python3
"""Pre-commit wrapper running Semgrep with Mellyn Guardrails' OWASP AI SAST rules."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from _precommit_common import GUARDRAILS_ROOT, find_tool, run_pinned_scanner, validate_extra_args  # noqa: E402

DEFAULT_RULES = GUARDRAILS_ROOT / ".semgrep" / "owasp-ai-code-rules.yaml"

# Output-only flags. Everything else (config, excludes, severity, baselines, size limits) is refused; positional
# arguments are the file names pre-commit passes.
_ALLOWED_FLAGS = frozenset({"--quiet", "--verbose"})


def build_precommit_semgrep_command(
    semgrep_bin: str,
    *,
    rules_path: Path = DEFAULT_RULES,
    targets: Sequence[str] = (),
) -> list[str]:
    """Build a fail-closed `semgrep scan` command pinned to `rules_path`."""
    if not rules_path.is_file():
        raise FileNotFoundError(f"mellyn-semgrep: pinned Semgrep rules not found: {rules_path}")

    validate_extra_args(
        targets,
        allowed_flags=_ALLOWED_FLAGS,
        allow_positional=True,
        tool_label="mellyn-semgrep",
    )

    scan_targets = list(targets) if targets else ["."]
    return [
        semgrep_bin,
        "scan",
        "--config",
        str(rules_path.resolve()),
        "--error",
        "--metrics=off",
        *scan_targets,
    ]


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for the `mellyn-semgrep` pre-commit hook."""
    semgrep_bin = find_tool("semgrep")
    if semgrep_bin is None:
        sys.stderr.write(
            "mellyn-semgrep: `semgrep` binary was not found on PATH or in the active Python environment. "
            "Install Semgrep locally (or run the Mellyn reusable CI workflow, which installs hash-locked Semgrep).\n"
        )
        return 1

    raw_args = list(sys.argv[1:] if argv is None else argv)
    try:
        cmd = build_precommit_semgrep_command(semgrep_bin, rules_path=DEFAULT_RULES, targets=raw_args)
    except (FileNotFoundError, ValueError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 2

    return run_pinned_scanner(cmd)


if __name__ == "__main__":
    sys.exit(main())
