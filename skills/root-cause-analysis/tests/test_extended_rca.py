from __future__ import annotations

import sys
import unittest
from pathlib import Path


SKILL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_DIR))

from extended_rca import (  # noqa: E402
    analyze_outage,
    analyze_type1,
    build_evidence,
    build_outage_report,
    build_type1_report,
)


def route(
    path: str,
    peer: str,
    timestamp: int = 1000,
    prefix: str = "203.0.113.0/24",
) -> dict[str, str]:
    return {
        "timestamp": str(timestamp),
        "prefix": prefix,
        "peer_asn": peer,
        "collector": "rrc00",
        "peer_ip": f"192.0.2.{peer[-1]}",
        "as_path": path,
    }


def withdrawal(
    peer: str,
    timestamp: int,
    prefix: str = "203.0.113.0/24",
) -> dict[str, str]:
    row = route("", peer, timestamp, prefix)
    row.pop("as_path")
    return row


class Type1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.baseline = [
            route("100 200 300", "1"),
            route("101 200 300", "2"),
        ]
        self.after = [
            route("100 666 300", "1", 1100),
            route("101 666 300", "2", 1101),
        ]

    def test_detects_strict_multi_vp_type1(self) -> None:
        scores = [
            {
                "rib_path": "100 200 300",
                "update_path": "100 666 300",
                "score": 0.9,
            },
            {
                "rib_path": "101 200 300",
                "update_path": "101 666 300",
                "score": 0.8,
            },
        ]
        result = analyze_type1(scores, self.baseline, self.after)
        self.assertTrue(result["detected"])
        candidate = result["best_candidate"]
        self.assertEqual(candidate["attacker_as"], "666")
        self.assertEqual(candidate["victim_as"], "300")
        self.assertEqual(candidate["supporting_vp_count"], 2)
        self.assertTrue(candidate["novel_adjacency"])

    def test_single_vp_upstream_change_is_not_detected(self) -> None:
        scores = [
            {
                "rib_path": "100 200 300",
                "update_path": "100 666 300",
                "score": 0.9,
            }
        ]
        result = analyze_type1(scores, self.baseline, self.after[:1])
        self.assertFalse(result["detected"])

    def test_repeated_attacker_prepend_is_collapsed(self) -> None:
        scores = [
            {
                "rib_path": "100 200 300",
                "update_path": "100 666 666 300",
                "score": 0.9,
            },
            {
                "rib_path": "101 200 300",
                "update_path": "101 666 666 300",
                "score": 0.8,
            },
        ]
        after = [
            route("100 666 666 300", "1", 1100),
            route("101 666 666 300", "2", 1101),
        ]
        result = analyze_type1(scores, self.baseline, after)
        self.assertTrue(result["detected"])
        self.assertEqual(
            result["best_candidate"]["forged_adjacency"], ["666", "300"]
        )

    def test_origin_change_remains_ordinary_hijack_candidate(self) -> None:
        result = analyze_type1(
            [{"rib_path": "100 200 300", "update_path": "100 200 999"}],
            self.baseline,
            self.after,
        )
        self.assertFalse(result["detected"])
        self.assertEqual(result["origin_changed_record_count"], 1)

    def test_route_leak_insertion_not_adjacent_to_origin_is_not_type1(self) -> None:
        result = analyze_type1(
            [
                {
                    "rib_path": "100 200 300",
                    "update_path": "100 777 200 300",
                }
            ],
            self.baseline,
            [route("100 777 200 300", "1")],
        )
        self.assertFalse(result["detected"])
        self.assertEqual(result["candidates"], [])

    def test_historical_upstream_change_is_not_novel(self) -> None:
        baseline = self.baseline + [route("110 666 300", "3")]
        scores = [
            {
                "rib_path": "100 200 300",
                "update_path": "100 666 300",
                "score": 0.9,
            },
            {
                "rib_path": "101 200 300",
                "update_path": "101 666 300",
                "score": 0.8,
            },
        ]
        after = [
            route("100 666 300", "1", 1100),
            route("101 666 300", "2", 1101),
        ]
        result = analyze_type1(scores, baseline, after)
        self.assertFalse(result["detected"])
        self.assertFalse(result["best_candidate"]["novel_adjacency"])

    def test_detects_subprefix_type1_with_covering_origin_change(self) -> None:
        covering = "44.224.0.0/11"
        announced = "44.235.216.0/24"
        scores = [
            {
                "rib_prefix": covering,
                "upd_prefix": announced,
                "prefix_relation": "more_specific",
                "rib_path": "34854 1299 16509",
                "update_path": "34854 1299 209243 14618",
                "score": 0.9,
            },
            {
                "rib_prefix": covering,
                "upd_prefix": announced,
                "prefix_relation": "more_specific",
                "rib_path": "7018 1299 16509",
                "update_path": "7018 1299 209243 14618",
                "score": 0.8,
            },
        ]
        baseline = [
            route("34854 1299 16509", "1", prefix=covering),
            route("7018 1299 16509", "2", prefix=covering),
        ]
        after = [
            route("34854 1299 209243 14618", "1", 1100, announced),
            route("7018 1299 209243 14618", "2", 1101, announced),
        ]
        result = analyze_type1(scores, baseline, after)
        self.assertTrue(result["detected"])
        candidate = result["best_candidate"]
        self.assertEqual(candidate["hijack_subtype"], "S|1")
        self.assertEqual(candidate["attacker_as"], "209243")
        self.assertEqual(candidate["victim_as"], "14618")
        self.assertEqual(candidate["covering_origin_as"], "16509")
        self.assertFalse(candidate["origin_unchanged"])
        self.assertTrue(candidate["novel_adjacency"])

    def test_type1_vp_support_counts_shared_adjacency(self) -> None:
        covering = "44.224.0.0/11"
        announced = "44.235.216.0/24"
        scores = [
            {
                "rib_prefix": covering,
                "upd_prefix": announced,
                "prefix_relation": "more_specific",
                "rib_path": "34854 1299 16509",
                "update_path": "34854 1299 209243 14618",
                "score": 0.9,
            }
        ]
        result = analyze_type1(
            scores,
            [
                route("34854 1299 16509", "1", prefix=covering),
                route("7018 1299 16509", "2", prefix=covering),
            ],
            [
                route("34854 1299 209243 14618", "1", 1100, announced),
                route("7018 174 209243 14618", "2", 1101, announced),
            ],
        )
        self.assertTrue(result["detected"])
        self.assertEqual(result["best_candidate"]["supporting_vp_count"], 2)
        self.assertEqual(result["best_candidate"]["attacker_as"], "209243")

    def test_legitimate_deaggregation_is_not_type1(self) -> None:
        covering = "203.0.112.0/23"
        announced = "203.0.113.0/24"
        scores = [
            {
                "rib_prefix": covering,
                "upd_prefix": announced,
                "prefix_relation": "more_specific",
                "rib_path": "100 200 300",
                "update_path": "100 200 300",
                "score": 0.4,
            },
            {
                "rib_prefix": covering,
                "upd_prefix": announced,
                "prefix_relation": "more_specific",
                "rib_path": "101 200 300",
                "update_path": "101 200 300",
                "score": 0.3,
            },
        ]
        result = analyze_type1(
            scores,
            [
                route("100 200 300", "1", prefix=covering),
                route("101 200 300", "2", prefix=covering),
            ],
            [
                route("100 200 300", "1", 1100, announced),
                route("101 200 300", "2", 1101, announced),
            ],
        )
        self.assertFalse(result["detected"])
        self.assertEqual(result["candidates"], [])

    def test_type1_and_leak_conflict_is_ambiguous(self) -> None:
        scores = [
            {
                "rib_path": "100 200 300",
                "update_path": "100 666 300",
                "score": 0.9,
            },
            {
                "rib_path": "101 200 300",
                "update_path": "101 666 300",
                "score": 0.8,
            },
            {
                "rib_path": "102 200 300",
                "update_path": "102 777 200 300",
                "score": 0.7,
            },
        ]
        after = self.after + [route("102 777 200 300", "3", 1102)]
        evidence = build_evidence(
            "event",
            {"prefix": "203.0.113.0/24"},
            scores,
            self.baseline + [route("102 200 300", "3")],
            after,
            [],
        )
        self.assertEqual(
            evidence["classification"]["recommended_anomaly_type"],
            "ambiguous",
        )
        self.assertTrue(evidence["type_1_hijack"]["ambiguous_with_route_leak"])
        report = build_type1_report(evidence)
        self.assertEqual(report["anomaly_type"], "other")
        self.assertEqual(report["root_cause"]["confidence"], "low")


class OutageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.baseline = [
            route("1 50 300", "1"),
            route("2 50 300", "2"),
            route("3 50 300", "3"),
            route("4 50 300", "4"),
        ]
        self.withdrawals = [
            withdrawal("1", 1000),
            withdrawal("2", 1010),
            withdrawal("3", 1020),
        ]

    def test_detects_synchronized_multi_vp_outage(self) -> None:
        result = analyze_outage(self.withdrawals, self.baseline, [])
        self.assertTrue(result["detected"])
        self.assertEqual(result["affected_origin_as"], "300")
        self.assertEqual(result["suspected_failure_as"], "50")
        self.assertEqual(result["withdrawal_ratio"], 0.75)

    def test_single_vp_flap_is_not_outage(self) -> None:
        result = analyze_outage(self.withdrawals[:1], self.baseline, [])
        self.assertFalse(result["detected"])

    def test_immediate_replacements_reject_outage(self) -> None:
        alternatives = [
            route("1 60 300", "1", 1030),
            route("2 60 300", "2", 1031),
            route("3 60 300", "3", 1032),
        ]
        result = analyze_outage(
            self.withdrawals, self.baseline, alternatives
        )
        self.assertFalse(result["detected"])
        self.assertEqual(result["alternative_path_ratio"], 1.0)

    def test_no_unique_common_internal_as_limits_attribution(self) -> None:
        baseline = [
            route("1 50 300", "1"),
            route("2 60 300", "2"),
            route("3 70 300", "3"),
        ]
        result = analyze_outage(self.withdrawals, baseline, [])
        self.assertTrue(result["detected"])
        self.assertIsNone(result["suspected_failure_as"])
        self.assertEqual(result["attribution_scope"], "affected_origin_only")

    def test_missing_required_withdrawal_values_raise(self) -> None:
        malformed = [dict(self.withdrawals[0], peer_asn="")]
        with self.assertRaises(ValueError):
            analyze_outage(malformed, self.baseline, [])

    def test_missing_withdrawals_are_unavailable_not_negative(self) -> None:
        result = analyze_outage([], self.baseline, [])
        self.assertFalse(result["detected"])
        self.assertFalse(result["available"])
        self.assertEqual(result["attribution_scope"], "unavailable")

    def test_previous_as_path_supports_common_component_attribution(self) -> None:
        withdrawals = [
            {
                **withdrawal("1", 1000),
                "previous_as_path": "1 50 300",
            },
            {
                **withdrawal("2", 1010),
                "previous_as_path": "2 50 300",
            },
            {
                **withdrawal("3", 1020),
                "previous_as_path": "3 50 300",
            },
        ]
        result = analyze_outage(withdrawals, self.baseline, [])
        self.assertTrue(result["detected"])
        self.assertEqual(result["suspected_failure_as"], "50")
        report = build_outage_report(
            {
                "prefix": "203.0.113.0/24",
                "start_time": "2026-01-01 00:00:00",
                "end_time": "2026-01-01 00:30:00",
                "route_outage": result,
            }
        )
        self.assertEqual(report["anomaly_type"], "route_outage")
        self.assertEqual(report["root_cause"]["suspected_failure_as"], 50)


class ClassificationRegressionTests(unittest.TestCase):
    def test_origin_change_has_priority_over_type1(self) -> None:
        evidence = build_evidence(
            "event",
            {"prefix": "203.0.113.0/24"},
            [{"rib_path": "1 2 3", "update_path": "1 2 9"}],
            [route("1 2 3", "1")],
            [route("1 2 9", "1")],
            [],
        )
        self.assertEqual(
            evidence["classification"]["recommended_anomaly_type"],
            "prefix_hijack",
        )

    def test_subprefix_type1_outranks_origin_change(self) -> None:
        covering = "44.224.0.0/11"
        announced = "44.235.216.0/24"
        evidence = build_evidence(
            "event",
            {"prefix": announced},
            [
                {
                    "rib_prefix": covering,
                    "upd_prefix": announced,
                    "prefix_relation": "more_specific",
                    "rib_path": "34854 1299 16509",
                    "update_path": "34854 1299 209243 14618",
                    "score": 0.9,
                },
                {
                    "rib_prefix": covering,
                    "upd_prefix": announced,
                    "prefix_relation": "more_specific",
                    "rib_path": "7018 1299 16509",
                    "update_path": "7018 1299 209243 14618",
                    "score": 0.8,
                },
            ],
            [
                route("34854 1299 16509", "1", prefix=covering),
                route("7018 1299 16509", "2", prefix=covering),
            ],
            [
                route("34854 1299 209243 14618", "1", 1100, announced),
                route("7018 1299 209243 14618", "2", 1101, announced),
            ],
            [],
        )
        self.assertEqual(
            evidence["classification"]["recommended_anomaly_type"],
            "type_1_hijack",
        )
        report = build_type1_report(evidence)
        self.assertEqual(report["anomaly_type"], "type_1_hijack")
        self.assertEqual(report["root_cause"]["hijack_subtype"], "S|1")
        self.assertEqual(report["root_cause"]["attacker_as"], 209243)
        self.assertEqual(report["root_cause"]["victim_as"], 14618)

    def test_existing_route_leak_shape_is_deferred(self) -> None:
        evidence = build_evidence(
            "event",
            {"prefix": "203.0.113.0/24"},
            [
                {
                    "rib_path": "1 20 300",
                    "update_path": "1 99 20 300",
                }
            ],
            [route("1 20 300", "1")],
            [route("1 99 20 300", "1")],
            [],
        )
        self.assertEqual(
            evidence["classification"]["recommended_anomaly_type"],
            "defer_existing_route_leak_or_other",
        )

    def test_case_update_compatible_scalar_fields(self) -> None:
        evidence = build_evidence(
            "event",
            {
                "prefix": "203.0.113.0/24",
                "start_time": "2026-01-01 00:00:00",
                "end_time": "2026-01-01 00:20:00",
            },
            [
                {
                    "rib_path": "100 200 300",
                    "update_path": "100 666 300",
                    "score": 0.9,
                },
                {
                    "rib_path": "101 200 300",
                    "update_path": "101 666 300",
                    "score": 0.8,
                },
            ],
            [
                route("100 200 300", "1"),
                route("101 200 300", "2"),
            ],
            [
                route("100 666 300", "1", 1100),
                route("101 666 300", "2", 1101),
            ],
            [],
        )
        report = build_type1_report(evidence)
        root_cause = report["root_cause"]
        for value in root_cause.values():
            self.assertTrue(
                isinstance(value, (str, int, float, bool, list)) or value is None
            )


if __name__ == "__main__":
    unittest.main()
