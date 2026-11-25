"""Shared fail-closed helpers for Mellyn Guardrails `language: script` pre-commit wrappers."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

GUARDRAILS_ROOT = Path(__file__).resolve().parent.parent


def find_tool(name: str) -> str | None:
    """Locate `name` in the active Python environment, `.venv`, or PATH."""
    exe_names = (f"{name}.exe", name) if sys.platform == "win32" else (name,)
    search_dirs: list[Path] = [Path(sys.executable).resolve().parent]

    for base_raw in (os.environ.get("VIRTUAL_ENV"), str(Path.cwd() / ".venv")):
        if not base_raw:
            continue
        base = Path(base_raw)
        search_dirs.extend((base / "Scripts", base / "bin"))

    seen: set[Path] = set()
    for directory in search_dirs:
        if directory in seen:
            continue
        seen.add(directory)
        for exe_name in exe_names:
            candidate = directory / exe_name
            if candidate.is_file():
                return str(candidate)

    for exe_name in exe_names:
        found = shutil.which(exe_name)
        if found:
            return found
    return None


def validate_extra_args(
    args: Sequence[str],
    *,
    allowed_flags: frozenset[str],
    allow_positional: bool,
    tool_label: str,
) -> None:
    """
    Accept only the flags in `allowed_flags`, plus positional arguments (file names) when `allow_positional`.

    An allow-list, not a block-list: Gitleaks and Semgrep keep adding options that narrow a scan or hide findings
    (`--baseline-path`, `--baseline-commit`, size and include limits), so any flag not listed here is refused.
    A file name that starts with "-" is refused as well, so it can never be read as an option.
    """
    for arg in args:
        if arg.startswith("-"):
            if arg not in allowed_flags:
                raise ValueError(f"{tool_label}: refusing flag {arg!r}; only {sorted(allowed_flags)} are accepted")
        elif not allow_positional:
            raise ValueError(f"{tool_label}: refusing argument {arg!r}; this hook takes no file names")


def run_pinned_scanner(cmd: Sequence[str]) -> int:
    """Execute a validated scanner command directly without invoking a shell."""
    completed = subprocess.run(list(cmd), check=False)  # noqa: S603 - validated binary and fixed pinned config flags
    return int(completed.returncode)
