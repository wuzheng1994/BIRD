"""Tests for validate_relationships.py.

The tests use an in-memory SQLite database so they do not depend on the real
``bgp.db`` or network access.
"""

from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path


SKILL_DIR = Path(__file__).resolve().parents[1] / "skills" / "root-cause-analysis"
sys.path.insert(0, str(SKILL_DIR))

from validate_relationships import (  # noqa: E402
    analyze_path,
    lookup_rel,
    parse_event_month,
    resolve_rel_table,
    validate_update_path,
)


def build_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE rel_202511 (as1 TEXT, as2 TEXT, rel INTEGER);
        CREATE TABLE rel_202512 (as1 TEXT, as2 TEXT, rel INTEGER);
        INSERT INTO rel_202512 VALUES ('64073', '44393', 0);
        INSERT INTO rel_202512 VALUES ('64073', '55850', 1);
        INSERT INTO rel_202512 VALUES ('55850', '4637', 1);
        INSERT INTO rel_202512 VALUES ('4637', '6939', 0);
        INSERT INTO rel_202512 VALUES ('6939', '15412', -1);
        INSERT INTO rel_202512 VALUES ('15412', '152144', 0);
        INSERT INTO rel_202512 VALUES ('152144', '15412', 0);
        INSERT INTO rel_202512 VALUES ('152144', '141047', 0);
        INSERT INTO rel_202512 VALUES ('141047', '152144', 0);
        INSERT INTO rel_202512 VALUES ('141047', '4007', -1);
        INSERT INTO rel_202512 VALUES ('4007', '132856', -1);

        -- November has different values for two pairs (historical drift).
        INSERT INTO rel_202511 VALUES ('15412', '152144', -1);
        INSERT INTO rel_202511 VALUES ('152144', '141047', -1);
        """
    )
    return conn


class ResolveRelTableTest(unittest.TestCase):
    def test_exact_month_preferred(self) -> None:
        conn = build_conn()
        self.assertEqual(resolve_rel_table(conn, 2025, 12), "rel_202512")
        conn.close()

    def test_fallback_to_most_recent_earlier_month(self) -> None:
        conn = build_conn()
        # No exact January table exists; the resolver must fall back to the
        # most recent available table (rel_202512).
        self.assertEqual(resolve_rel_table(conn, 2025, 1), "rel_202512")
        conn.close()


class LookupRelTest(unittest.TestCase):
    def test_direct_row(self) -> None:
        conn = build_conn()
        rel, source = lookup_rel(conn, "rel_202512", "64073", "55850")
        self.assertEqual((rel, source), (1, "direct"))
        conn.close()

    def test_reverse_row_negated(self) -> None:
        conn = build_conn()
        # Only (64073, 44393, 0) is stored; the pair resolves via reverse.
        rel, source = lookup_rel(conn, "rel_202512", "44393", "64073")
        self.assertEqual((rel, source), (0, "reverse"))
        # Reverse of -1 must become +1.
        rel, source = lookup_rel(conn, "rel_202512", "4637", "55850")
        self.assertEqual((rel, source), (-1, "reverse"))
        conn.close()

    def test_missing_pair_returns_two(self) -> None:
        conn = build_conn()
        rel, source = lookup_rel(conn, "rel_202512", "65001", "65002")
        self.assertEqual((rel, source), (2, "missing"))
        conn.close()


class AnalyzePathTest(unittest.TestCase):
    def test_correct_relationships_and_leak_candidates(self) -> None:
        asns = [
            "44393", "64073", "55850", "4637", "6939",
            "15412", "152144", "141047", "4007", "132856",
        ]
        rels = [0, 1, 1, 0, -1, 0, 0, -1, -1]
        result = analyze_path(asns, rels)
        self.assertEqual(result["conclusion"], "route_leak_candidate")
        self.assertEqual(result["abnormal_triplet_count"], 3)
        leakers = {c["leaking_as"] for c in result["route_leak_candidates"]}
        self.assertEqual(leakers, {"64073", "15412", "152144"})

    def test_no_leak_pattern(self) -> None:
        asns = ["65001", "65002", "65003", "65004"]
        rels = [1, 1, 1]
        result = analyze_path(asns, rels)
        self.assertEqual(result["conclusion"], "no_leak_pattern")
        self.assertEqual(result["abnormal_triplet_count"], 0)

    def test_missing_relationship_leads_to_insufficient_data(self) -> None:
        asns = ["65001", "65002", "65003", "65004"]
        rels = [1, 2, -1]
        result = analyze_path(asns, rels)
        self.assertEqual(result["conclusion"], "insufficient_relationship_data")


class ValidateUpdatePathTest(unittest.TestCase):
    def test_dec2025_event_uses_rel_202512(self) -> None:
        conn = build_conn()
        path = [
            "44393", "64073", "55850", "4637", "6939",
            "15412", "152144", "141047", "4007", "132856",
        ]
        result = validate_update_path(conn, path, 2025, 12)
        self.assertEqual(result["relationship_table"], "rel_202512")
        self.assertEqual(
            result["path_relationships"],
            [0, 1, 1, 0, -1, 0, 0, -1, -1],
        )
        self.assertEqual(result["conclusion"], "route_leak_candidate")
        conn.close()


class ParseEventMonthTest(unittest.TestCase):
    def test_various_formats(self) -> None:
        self.assertEqual(parse_event_month("2025/12/30 3:02:00"), (2025, 12))
        self.assertEqual(parse_event_month("2025-12-30 03:02:00"), (2025, 12))
        self.assertEqual(parse_event_month("2025-12-30T03:02:00Z"), (2025, 12))
        self.assertIsNone(parse_event_month(""))


if __name__ == "__main__":
    unittest.main()
