#!/usr/bin/env python3
"""Pre-commit wrapper running Gitleaks with Mellyn Guardrails' pinned `.gitleaks.toml`."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from _precommit_common import GUARDRAILS_ROOT, find_tool, run_pinned_scanner, validate_extra_args  # noqa: E402

DEFAULT_CONFIG = GUARDRAILS_ROOT / ".gitleaks.toml"

# Output-only flags. Everything else (config, baseline, ignore paths, exit codes, size limits) is refused.
_ALLOWED_FLAGS = frozenset({"--no-banner", "--no-color"})


def build_precommit_gitleaks_command(
    gitleaks_bin: str,
    *,
    config_path: Path = DEFAULT_CONFIG,
    extra_args: Sequence[str] = (),
) -> list[str]:
    """Build a fail-closed `gitleaks git --pre-commit` command pinned to `config_path`."""
    if not config_path.is_file():
        raise FileNotFoundError(f"mellyn-gitleaks: pinned Gitleaks config not found: {config_path}")

    validate_extra_args(
        extra_args,
        allowed_flags=_ALLOWED_FLAGS,
        allow_positional=False,
        tool_label="mellyn-gitleaks",
    )

    return [
        gitleaks_bin,
        "git",
        "--pre-commit",
        "--redact",
        "--staged",
        "--verbose",
        "--config",
        str(config_path.resolve()),
        *extra_args,
    ]


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for the `mellyn-gitleaks` pre-commit hook."""
    gitleaks_bin = find_tool("gitleaks")
    if gitleaks_bin is None:
        sys.stderr.write(
            "mellyn-gitleaks: `gitleaks` binary was not found on PATH or in the active Python environment. "
            "Install Gitleaks locally (or use the Mellyn reusable CI workflow, which installs a "
            "SHA-256-verified binary).\n"
        )
        return 1

    raw_args = list(sys.argv[1:] if argv is None else argv)
    try:
        cmd = build_precommit_gitleaks_command(gitleaks_bin, config_path=DEFAULT_CONFIG, extra_args=raw_args)
    except (FileNotFoundError, ValueError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 2

    return run_pinned_scanner(cmd)


if __name__ == "__main__":
    sys.exit(main())
