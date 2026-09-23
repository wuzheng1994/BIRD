from __future__ import annotations

import sys
import unittest
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_DIR))

from prefix_filter import bgpstream_prefix_filter, bgpstream_prefix_filters  # noqa: E402


class PrefixFilterTests(unittest.TestCase):
    def test_includes_more_and_less_specifics(self) -> None:
        self.assertEqual(
            bgpstream_prefix_filters("44.235.216.0/24"),
            [
                "prefix more 44.235.216.0/24",
                "prefix less 44.235.216.0/24",
            ],
        )

    def test_rejects_empty_prefix(self) -> None:
        with self.assertRaises(ValueError):
            bgpstream_prefix_filter("  ")


if __name__ == "__main__":
    unittest.main()
