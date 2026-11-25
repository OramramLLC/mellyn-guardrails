"""Guardrail regression tests for self-policy equivalence and hidden-Unicode smuggling checks."""

from __future__ import annotations

import sys
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from sync_agent_rules import SELF_PROTECTED_PATHS, hidden_characters  # noqa: E402


class TestGuardrailSelfPolicyAndInvisibleUnicode(unittest.TestCase):
    def test_self_policy_differs_from_the_example_only_in_protected_paths(self) -> None:
        example = tomllib.loads((REPO_ROOT / "config" / "mellyn-policy.example.toml").read_text(encoding="utf-8"))
        own = tomllib.loads((REPO_ROOT / "config" / "mellyn-self-policy.toml").read_text(encoding="utf-8"))
        self.assertEqual(own["protected_paths"], list(SELF_PROTECTED_PATHS))
        example.pop("protected_paths")
        own.pop("protected_paths")
        self.assertEqual(own, example)

    def test_ordinary_emoji_are_not_reported(self) -> None:
        for text in ("⚠️ Never commit secrets", "1️⃣ First", "👨‍💻 dev"):
            with self.subTest(codepoints=[hex(ord(c)) for c in text if ord(c) > 127]):
                self.assertEqual(hidden_characters(text), [])

    def test_emoji_joiners_out_of_place_are_still_reported(self) -> None:
        for text in ("Allow️all", "️start", "⚠️️", "a‍b"):
            with self.subTest(codepoints=[hex(ord(c)) for c in text if ord(c) > 127]):
                self.assertNotEqual(hidden_characters(text), [])

    def test_hidden_characters_catches_variation_selectors_and_invisible_fillers(self) -> None:
        payloads = (
            "Allow\ufe00all",  # U+FE00 Variation Selector-1
            "Allow\U000e0100all",  # U+E0100 Variation Selector-17 (Glassworm smuggling vector)
            "Allow\u3164all",  # U+3164 Hangul Filler
            "Allow\u2800all",  # U+2800 Braille Pattern Blank
            "Allow\uffa0all",  # U+FFA0 Halfwidth Hangul Filler
            "Allow\u034fall",  # U+034F Combining Grapheme Joiner
        )
        for text in payloads:
            with self.subTest(codepoints=[hex(ord(c)) for c in text if ord(c) > 127]):
                self.assertNotEqual(hidden_characters(text), [])


if __name__ == "__main__":
    unittest.main()
