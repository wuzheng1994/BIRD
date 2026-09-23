from __future__ import annotations

import sys
import unittest
from pathlib import Path


SKILL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_DIR))

from detect_change import (  # noqa: E402
    classify_prefix_relation,
    find_rib_matches,
)


def rib(prefix: str, peer: str, path: str) -> dict:
    return {
        "prefix": prefix,
        "peer_asn": peer,
        "as_path": path.split(),
        "raw_path": path,
    }


class PrefixRelationTests(unittest.TestCase):
    def test_exact_and_covering(self) -> None:
        self.assertEqual(
            classify_prefix_relation("44.235.216.0/24", "44.235.216.0/24"),
            "exact",
        )
        self.assertEqual(
            classify_prefix_relation("44.224.0.0/11", "44.235.216.0/24"),
            "more_specific",
        )
        self.assertEqual(
            classify_prefix_relation("44.235.216.0/24", "44.224.0.0/11"),
            "less_specific",
        )


class RibMatchTests(unittest.TestCase):
    def test_exact_match_is_preferred_over_covering(self) -> None:
        index = {
            "203.0.113.0/24": [rib("203.0.113.0/24", "1", "100 200 300")],
            "203.0.112.0/23": [rib("203.0.112.0/23", "1", "100 200 300")],
        }
        matches = find_rib_matches(index, "203.0.113.0/24", "1")
        self.assertEqual([row["prefix"] for row in matches], ["203.0.113.0/24"])

    def test_longest_covering_prefix_when_exact_missing(self) -> None:
        index = {
            "44.224.0.0/11": [rib("44.224.0.0/11", "1", "34854 1299 16509")],
            "44.0.0.0/8": [rib("44.0.0.0/8", "1", "1 16509")],
        }
        matches = find_rib_matches(index, "44.235.216.0/24", "1")
        self.assertEqual([row["prefix"] for row in matches], ["44.224.0.0/11"])
        self.assertEqual(
            classify_prefix_relation(matches[0]["prefix"], "44.235.216.0/24"),
            "more_specific",
        )


if __name__ == "__main__":
    unittest.main()
