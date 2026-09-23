#!/usr/bin/env python3
"""Deterministic evidence extraction for route outage and Type-1 hijack RCA.

This module does not collect BGP data.  It consumes the existing event files
plus an optional ``withdrawals.csv`` supplied by an upstream collector and
writes ``root_cause_evidence.json`` for the root-cause-analysis skill.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [
            {str(key): str(value or "").strip() for key, value in row.items()}
            for row in csv.DictReader(handle)
        ]


def collapse_prepends(value: Any) -> tuple[str, ...]:
    collapsed: list[str] = []
    for token in str(value or "").replace(",", " ").split():
        if not collapsed or collapsed[-1] != token:
            collapsed.append(token)
    return tuple(collapsed)


def as_timestamp(value: Any) -> Optional[float]:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def vp_id(row: dict[str, str]) -> str:
    collector = row.get("collector") or "legacy"
    peer_asn = row.get("peer_asn") or "unknown"
    peer_ip = row.get("peer_ip") or "-"
    return f"{collector}:{peer_asn}:{peer_ip}"


def prefix_matches(candidate: str, event_prefix: str) -> bool:
    try:
        candidate_network = ipaddress.ip_network(candidate, strict=False)
        event_network = ipaddress.ip_network(event_prefix, strict=False)
    except ValueError:
        return candidate == event_prefix
    return (
        candidate_network.version == event_network.version
        and candidate_network.subnet_of(event_network)
    )


def prefixes_related(candidate: str, event_prefix: str) -> bool:
    """True if one prefix equals, covers, or is covered by the other."""
    try:
        candidate_network = ipaddress.ip_network(candidate, strict=False)
        event_network = ipaddress.ip_network(event_prefix, strict=False)
    except ValueError:
        return candidate == event_prefix
    if candidate_network.version != event_network.version:
        return False
    return candidate_network.subnet_of(event_network) or event_network.subnet_of(
        candidate_network
    )


def filter_rows(
    rows: Iterable[dict[str, str]], event_prefix: str
) -> list[dict[str, str]]:
    return [
        row
        for row in rows
        if row.get("prefix") and prefix_matches(row["prefix"], event_prefix)
    ]


def filter_related_rows(
    rows: Iterable[dict[str, str]], event_prefix: str
) -> list[dict[str, str]]:
    return [
        row
        for row in rows
        if row.get("prefix") and prefixes_related(row["prefix"], event_prefix)
    ]


def classify_prefix_relation(rib_prefix: str, upd_prefix: str) -> str:
    if not rib_prefix or not upd_prefix:
        return "exact"
    try:
        rib_net = ipaddress.ip_network(rib_prefix, strict=False)
        upd_net = ipaddress.ip_network(upd_prefix, strict=False)
    except ValueError:
        return "exact" if rib_prefix == upd_prefix else "unrelated"
    if rib_net.version != upd_net.version:
        return "unrelated"
    if rib_net == upd_net:
        return "exact"
    if upd_net.subnet_of(rib_net):
        return "more_specific"
    if rib_net.subnet_of(upd_net):
        return "less_specific"
    return "unrelated"


def record_prefix_relation(record: dict[str, Any]) -> str:
    explicit = record.get("prefix_relation")
    if explicit in {"exact", "more_specific", "less_specific", "unrelated"}:
        return str(explicit)
    return classify_prefix_relation(
        str(record.get("rib_prefix") or ""),
        str(record.get("upd_prefix") or ""),
    )


def _supporting_vps_by_path(
    after_rows: Sequence[dict[str, str]],
) -> dict[tuple[str, ...], set[str]]:
    supporters: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for row in after_rows:
        path = collapse_prepends(row.get("as_path"))
        if path:
            supporters[path].add(vp_id(row))
    return supporters


def _supporting_vps_by_adjacency(
    after_rows: Sequence[dict[str, str]],
) -> dict[tuple[str, str], set[str]]:
    """VPs that observe the same origin-adjacent edge ``A-V``."""
    supporters: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in after_rows:
        path = collapse_prepends(row.get("as_path"))
        if len(path) >= 2:
            supporters[(path[-2], path[-1])].add(vp_id(row))
    return supporters


def competing_route_leak_candidates(
    score_records: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Identify same-origin insertions that are not strict Type-1 adjacencies.

    These are competing route-leak shaped explanations. Relationship validation
    remains required before a final leak classification.
    """
    candidates: list[dict[str, Any]] = []
    for index, record in enumerate(score_records):
        normal_path = collapse_prepends(record.get("rib_path"))
        update_path = collapse_prepends(record.get("update_path"))
        if (
            not normal_path
            or not update_path
            or normal_path[-1] != update_path[-1]
            or update_path == normal_path
        ):
            continue
        if len(update_path) < 3:
            continue
        # Strict Type-1 is ... A V. A leak-shaped insertion keeps the old
        # predecessor of V and inserts AS hops elsewhere.
        if (
            len(normal_path) >= 2
            and len(update_path) >= 2
            and update_path[-2] != normal_path[-2]
        ):
            continue
        inserted = [
            asn
            for asn in update_path[:-1]
            if asn not in set(normal_path)
        ]
        if not inserted:
            continue
        candidates.append(
            {
                "score_record_index": index,
                "origin_as": update_path[-1],
                "inserted_ases": inserted,
                "update_path": " ".join(update_path),
                "rib_path": " ".join(normal_path),
                "relationship_validation_required": True,
            }
        )
    return candidates


def analyze_type1(
    score_records: Sequence[dict[str, Any]],
    baseline_rows: Sequence[dict[str, str]],
    after_rows: Sequence[dict[str, str]],
) -> dict[str, Any]:
    """Detect E|1 and S|1 Type-1 candidates.

    E|1 keeps the exact prefix and origin ``V`` while a novel AS ``A`` appears
    immediately to its left. S|1 announces a more-specific whose covering
    origin may differ; ``A`` is still the novel neighbor of claimed origin
    ``V``. Multi-VP support and historical adjacency novelty are required.
    """
    historical_predecessors: dict[str, set[str]] = defaultdict(set)
    historical_origins: set[str] = set()
    for row in baseline_rows:
        path = collapse_prepends(row.get("as_path"))
        if not path:
            continue
        historical_origins.add(path[-1])
        if len(path) >= 2:
            historical_predecessors[path[-1]].add(path[-2])

    supporters_by_path = _supporting_vps_by_path(after_rows)
    supporters_by_adjacency = _supporting_vps_by_adjacency(after_rows)
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    origin_changed_records = 0
    same_origin_records = 0
    more_specific_records = 0
    exact_origin_changed_records = 0
    for index, record in enumerate(score_records):
        normal_path = collapse_prepends(record.get("rib_path"))
        update_path = collapse_prepends(record.get("update_path"))
        if not normal_path or not update_path:
            continue
        relation = record_prefix_relation(record)
        if relation in {"unrelated", "less_specific"}:
            continue
        origin_changed = normal_path[-1] != update_path[-1]
        if origin_changed:
            origin_changed_records += 1
        else:
            same_origin_records += 1
        if relation == "more_specific":
            more_specific_records += 1
        if relation == "exact" and origin_changed:
            exact_origin_changed_records += 1
            continue
        if len(normal_path) < 2 or len(update_path) < 2:
            continue

        victim = update_path[-1]
        attacker = update_path[-2]
        covering_origin = normal_path[-1]
        normal_predecessor = normal_path[-2]
        if attacker == victim:
            continue
        subtype = "S|1" if relation == "more_specific" else "E|1"
        if subtype == "E|1" and attacker == normal_predecessor:
            continue
        if (
            subtype == "S|1"
            and covering_origin == victim
            and attacker == normal_predecessor
        ):
            continue

        key = (attacker, victim, subtype)
        candidate = grouped.setdefault(
            key,
            {
                "attacker_as": attacker,
                "victim_as": victim,
                "hijack_subtype": subtype,
                "prefix_relation": relation,
                "forged_adjacency": [attacker, victim],
                "normal_predecessors": set(),
                "anomalous_paths": set(),
                "supporting_vps": set(),
                "score_record_indexes": [],
                "maximum_path_change_score": None,
                "attacker_absent_from_normal_paths": True,
                "covering_prefixes": set(),
                "announced_prefixes": set(),
                "covering_origins": set(),
            },
        )
        if subtype == "E|1":
            candidate["normal_predecessors"].add(normal_predecessor)
        candidate["normal_predecessors"].update(
            historical_predecessors.get(victim, set())
        )
        candidate["anomalous_paths"].add(" ".join(update_path))
        candidate["supporting_vps"].update(
            supporters_by_path.get(update_path, set())
        )
        candidate["supporting_vps"].update(
            supporters_by_adjacency.get((attacker, victim), set())
        )
        candidate["score_record_indexes"].append(index)
        rib_prefix = str(record.get("rib_prefix") or "")
        upd_prefix = str(record.get("upd_prefix") or "")
        if rib_prefix:
            candidate["covering_prefixes"].add(rib_prefix)
        if upd_prefix:
            candidate["announced_prefixes"].add(upd_prefix)
        candidate["covering_origins"].add(covering_origin)
        score = record.get("score")
        if isinstance(score, (int, float)):
            previous = candidate["maximum_path_change_score"]
            candidate["maximum_path_change_score"] = (
                float(score)
                if previous is None
                else max(previous, float(score))
            )
        if attacker in normal_path:
            candidate["attacker_absent_from_normal_paths"] = False

    leak_candidates = competing_route_leak_candidates(score_records)
    candidates: list[dict[str, Any]] = []
    for (attacker, victim, subtype), candidate in grouped.items():
        known_predecessors = historical_predecessors.get(victim, set())
        novel_adjacency = attacker not in known_predecessors
        vp_count = len(candidate["supporting_vps"])
        record_count = len(candidate["score_record_indexes"])
        covering_origins = set(candidate["covering_origins"])
        origin_unchanged = bool(covering_origins) and all(
            origin == victim for origin in covering_origins
        )
        claimed_origin_seen = victim in historical_origins
        if subtype == "E|1":
            evidence_score = 0.4
            evidence_score += 0.25 if novel_adjacency else 0.0
            evidence_score += 0.2 if vp_count >= 2 else 0.05 if vp_count == 1 else 0.0
            evidence_score += 0.1 if record_count >= 2 else 0.0
            evidence_score += (
                0.05 if candidate["attacker_absent_from_normal_paths"] else 0.0
            )
        else:
            evidence_score = 0.3
            evidence_score += 0.2 if novel_adjacency else 0.0
            evidence_score += 0.2 if vp_count >= 2 else 0.05 if vp_count == 1 else 0.0
            evidence_score += 0.15 if not origin_unchanged else 0.05
            evidence_score += 0.1 if record_count >= 2 else 0.0
            evidence_score += (
                0.05 if candidate["attacker_absent_from_normal_paths"] else 0.0
            )
        evidence_score = min(1.0, evidence_score)
        detected = novel_adjacency and vp_count >= 2 and evidence_score >= 0.75
        confidence = (
            "high"
            if detected and evidence_score >= 0.9 and not leak_candidates
            else "medium"
            if detected and not leak_candidates
            else "low"
        )
        covering_prefix_list = sorted(candidate["covering_prefixes"])
        announced_prefix_list = sorted(candidate["announced_prefixes"])
        covering_origin_list = sorted(covering_origins)
        serialized = {
            key: value
            for key, value in candidate.items()
            if key
            not in {
                "normal_predecessors",
                "anomalous_paths",
                "supporting_vps",
                "covering_prefixes",
                "announced_prefixes",
                "covering_origins",
            }
        }
        candidates.append(
            {
                **serialized,
                "normal_predecessors": sorted(candidate["normal_predecessors"]),
                "anomalous_paths": sorted(candidate["anomalous_paths"]),
                "supporting_vps": sorted(candidate["supporting_vps"]),
                "supporting_vp_count": vp_count,
                "supporting_score_record_count": record_count,
                "covering_prefix": covering_prefix_list[0]
                if covering_prefix_list
                else None,
                "announced_prefix": announced_prefix_list[0]
                if announced_prefix_list
                else None,
                "covering_origin_as": covering_origin_list[0]
                if covering_origin_list
                else None,
                "origin_unchanged": origin_unchanged,
                "claimed_origin_seen_in_baseline": claimed_origin_seen,
                "adjacent_to_origin": True,
                "novel_adjacency": novel_adjacency,
                "evidence_score": round(evidence_score, 6),
                "detected": detected,
                "confidence": confidence,
                "competing_route_leak_candidates": leak_candidates,
                "ambiguous_with_route_leak": bool(detected and leak_candidates),
                "relationship_validation_required": True,
                "ownership_validation_required": True,
            }
        )

    candidates.sort(
        key=lambda item: (
            -item["evidence_score"],
            -item["supporting_vp_count"],
            item["hijack_subtype"],
            item["attacker_as"],
        )
    )
    detected = any(candidate["detected"] for candidate in candidates)
    ambiguous = any(
        candidate.get("ambiguous_with_route_leak") for candidate in candidates
    )
    return {
        "definition": (
            "Type-1 hijack: a novel AS A appears immediately before origin V "
            "(... A V). E|1 uses the same prefix and unchanged origin; S|1 uses "
            "a new more-specific whose covering-prefix origin may differ."
        ),
        "detected": detected,
        "ambiguous_with_route_leak": ambiguous,
        "best_candidate": candidates[0] if candidates else None,
        "candidates": candidates,
        "competing_route_leak_candidates": leak_candidates,
        "origin_changed_record_count": origin_changed_records,
        "same_origin_record_count": same_origin_records,
        "more_specific_record_count": more_specific_records,
        "exact_origin_changed_record_count": exact_origin_changed_records,
        "limitations": [
            "A changed penultimate AS can be a legitimate upstream change.",
            "AS relationship and prefix ownership must be validated before final classification.",
            "VP support is reconstructed from post-event paths because score.json has no VP fields.",
            "When competing leak-shaped insertions exist, retain both candidates and avoid forced classification.",
            "S|1 adjacency novelty is measured against historical predecessors of the claimed origin V, including covering-prefix paths.",
            "If the claimed origin is unauthorized for the covering prefix, reclassify as prefix_hijack (S|0) rather than Type-1.",
        ],
    }


def _densest_timestamp_window(
    timestamps: Sequence[float], window_seconds: int
) -> tuple[Optional[float], Optional[float], int]:
    if not timestamps:
        return None, None, 0
    ordered = sorted(timestamps)
    best_left = best_right = 0
    left = 0
    for right, timestamp in enumerate(ordered):
        while timestamp - ordered[left] > window_seconds:
            left += 1
        if right - left > best_right - best_left:
            best_left, best_right = left, right
    return ordered[best_left], ordered[best_right], best_right - best_left + 1


def _common_path_components(
    path_rows: Sequence[dict[str, str]],
    affected_vps: set[str],
    path_field: str = "as_path",
) -> tuple[list[str], list[list[str]], Optional[str], Optional[str]]:
    paths = [
        collapse_prepends(row.get(path_field))
        for row in path_rows
        if vp_id(row) in affected_vps and collapse_prepends(row.get(path_field))
    ]
    if not paths:
        return [], [], None, None
    origins = Counter(path[-1] for path in paths)
    affected_origin = origins.most_common(1)[0][0]
    internal_sets = [set(path[1:-1]) for path in paths if len(path) >= 3]
    common_asns = (
        set.intersection(*internal_sets) if internal_sets else set()
    )
    edge_sets = [set(zip(path, path[1:])) for path in paths if len(path) >= 2]
    common_edges = set.intersection(*edge_sets) if edge_sets else set()
    suspected_failure_as = (
        next(iter(common_asns)) if len(common_asns) == 1 else None
    )
    return (
        sorted(common_asns),
        [list(edge) for edge in sorted(common_edges)],
        suspected_failure_as,
        affected_origin,
    )


def validate_withdrawal_rows(
    withdrawal_rows: Sequence[dict[str, str]],
) -> None:
    required_fields = {"timestamp", "prefix", "peer_asn"}
    missing = sorted(
        field
        for field in required_fields
        if any(not row.get(field) for row in withdrawal_rows)
    )
    if missing:
        raise ValueError(
            "withdrawals.csv is missing required values: "
            + ", ".join(missing)
        )


def analyze_outage(
    withdrawal_rows: Sequence[dict[str, str]],
    baseline_rows: Sequence[dict[str, str]],
    after_rows: Sequence[dict[str, str]],
    synchronization_window_seconds: int = 300,
    minimum_withdrawal_ratio: float = 0.5,
    maximum_alternative_ratio: float = 0.5,
) -> dict[str, Any]:
    limitations = [
        "BGP withdrawals do not contain AS_PATH, so the trigger AS is usually not directly observable.",
        "A synchronized control-plane withdrawal burst does not by itself prove data-plane unreachability.",
        "A suspected failure AS is emitted only when one internal AS is common to every affected baseline path.",
    ]
    if not withdrawal_rows:
        return {
            "detected": False,
            "available": False,
            "confidence": "low",
            "evidence_score": 0.0,
            "affected_origin_as": None,
            "suspected_failure_as": None,
            "attribution_scope": "unavailable",
            "baseline_vp_count": len(
                {vp_id(row) for row in baseline_rows if row.get("as_path")}
            ),
            "withdrawal_vp_count": 0,
            "affected_baseline_vp_count": 0,
            "withdrawal_ratio": 0.0,
            "synchronization_window_seconds": synchronization_window_seconds,
            "synchronized_withdrawal_count": 0,
            "synchronization_ratio": 0.0,
            "cluster_start_timestamp": None,
            "cluster_end_timestamp": None,
            "alternative_path_vp_count": 0,
            "alternative_path_ratio": 0.0,
            "recovery_timestamp": None,
            "duration_seconds": None,
            "common_path_asns": [],
            "common_path_edges": [],
            "thresholds": {
                "minimum_withdrawal_ratio": minimum_withdrawal_ratio,
                "maximum_alternative_ratio": maximum_alternative_ratio,
            },
            "limitations": limitations
            + [
                "withdrawals.csv was absent or empty; route-outage evidence is unavailable, not negative."
            ],
        }

    validate_withdrawal_rows(withdrawal_rows)

    unique_withdrawals: dict[tuple[float, str, str], dict[str, str]] = {}
    for row in withdrawal_rows:
        timestamp = as_timestamp(row.get("timestamp"))
        if timestamp is None:
            continue
        unique_withdrawals[(timestamp, row["prefix"], vp_id(row))] = row

    baseline_vps = {vp_id(row) for row in baseline_rows if row.get("as_path")}
    withdrawal_vps = {vp_id(row) for row in unique_withdrawals.values()}
    affected_vps = baseline_vps & withdrawal_vps
    # If the collector provided previous_as_path, use it as last-known paths.
    previous_path_rows = [
        row
        for row in unique_withdrawals.values()
        if collapse_prepends(row.get("previous_as_path"))
    ]
    attribution_rows: list[dict[str, str]] = list(baseline_rows)
    for row in previous_path_rows:
        attribution_rows.append(
            {
                **row,
                "as_path": row["previous_as_path"],
            }
        )
    if previous_path_rows and not affected_vps:
        # Withdrawals may name VPs absent from the RIB baseline; previous paths
        # still allow coverage analysis against the withdrawal set itself.
        affected_vps = {
            vp_id(row)
            for row in previous_path_rows
            if vp_id(row) in withdrawal_vps
        }
        baseline_vps = baseline_vps | affected_vps

    timestamps = [
        timestamp
        for timestamp, _, withdrawal_vp in unique_withdrawals
        if withdrawal_vp in affected_vps
    ]
    cluster_start, cluster_end, clustered_count = _densest_timestamp_window(
        timestamps, synchronization_window_seconds
    )
    withdrawal_ratio = (
        len(affected_vps) / len(baseline_vps) if baseline_vps else 0.0
    )
    synchronization_ratio = (
        clustered_count / len(timestamps) if timestamps else 0.0
    )

    alternative_vps: set[str] = set()
    recovery_timestamps: list[float] = []
    if cluster_start is not None:
        for row in after_rows:
            timestamp = as_timestamp(row.get("timestamp"))
            row_vp = vp_id(row)
            if (
                timestamp is None
                or row_vp not in affected_vps
                or not row.get("as_path")
                or timestamp < cluster_start
            ):
                continue
            if timestamp <= cluster_start + synchronization_window_seconds:
                alternative_vps.add(row_vp)
            else:
                recovery_timestamps.append(timestamp)
        for row in unique_withdrawals.values():
            recovered = collapse_prepends(row.get("recovered_as_path"))
            if not recovered or vp_id(row) not in affected_vps:
                continue
            timestamp = as_timestamp(row.get("timestamp"))
            if timestamp is None:
                continue
            # recovered_as_path is an optional recovery hint supplied with the
            # withdrawal record; use a conservative later-window offset.
            recovery_timestamps.append(
                timestamp + synchronization_window_seconds + 1
            )
    alternative_ratio = (
        len(alternative_vps) / len(affected_vps) if affected_vps else 0.0
    )
    recovery_time = min(recovery_timestamps) if recovery_timestamps else None
    duration_seconds = (
        recovery_time - cluster_start
        if recovery_time is not None and cluster_start is not None
        else None
    )

    common_asns, common_edges, suspected_failure_as, affected_origin = (
        _common_path_components(attribution_rows, affected_vps)
    )
    detected = (
        len(affected_vps) >= 2
        and withdrawal_ratio >= minimum_withdrawal_ratio
        and synchronization_ratio >= 0.5
        and alternative_ratio <= maximum_alternative_ratio
    )
    evidence_score = (
        (
            0.35 * min(1.0, withdrawal_ratio / minimum_withdrawal_ratio)
            + 0.25 * synchronization_ratio
            + 0.25 * (1.0 - alternative_ratio)
            + 0.15 * min(1.0, len(affected_vps) / 3)
        )
        if affected_vps
        else 0.0
    )
    confidence = (
        "high"
        if detected and evidence_score >= 0.85
        else "medium"
        if detected
        else "low"
    )
    if suspected_failure_as is None:
        limitations = limitations + [
            "No unique common internal AS was found across affected last-known paths."
        ]
    return {
        "detected": detected,
        "available": True,
        "confidence": confidence,
        "evidence_score": round(evidence_score, 6),
        "affected_origin_as": affected_origin,
        "suspected_failure_as": suspected_failure_as,
        "attribution_scope": (
            "candidate_common_path_as"
            if suspected_failure_as is not None
            else "affected_origin_only"
        ),
        "baseline_vp_count": len(baseline_vps),
        "withdrawal_vp_count": len(withdrawal_vps),
        "affected_baseline_vp_count": len(affected_vps),
        "withdrawal_ratio": round(withdrawal_ratio, 6),
        "synchronization_window_seconds": synchronization_window_seconds,
        "synchronized_withdrawal_count": clustered_count,
        "synchronization_ratio": round(synchronization_ratio, 6),
        "cluster_start_timestamp": cluster_start,
        "cluster_end_timestamp": cluster_end,
        "alternative_path_vp_count": len(alternative_vps),
        "alternative_path_ratio": round(alternative_ratio, 6),
        "recovery_timestamp": recovery_time,
        "duration_seconds": duration_seconds,
        "common_path_asns": common_asns,
        "common_path_edges": common_edges,
        "thresholds": {
            "minimum_withdrawal_ratio": minimum_withdrawal_ratio,
            "maximum_alternative_ratio": maximum_alternative_ratio,
        },
        "limitations": limitations,
    }


def _has_origin_change(score_records: Sequence[dict[str, Any]]) -> bool:
    for record in score_records:
        normal = collapse_prepends(record.get("rib_path"))
        update = collapse_prepends(record.get("update_path"))
        if normal and update and normal[-1] != update[-1]:
            return True
    return False


def build_evidence(
    event_name: str,
    event_metadata: dict[str, Any],
    score_records: Sequence[dict[str, Any]],
    baseline_rows: Sequence[dict[str, str]],
    after_rows: Sequence[dict[str, str]],
    withdrawal_rows: Sequence[dict[str, str]],
) -> dict[str, Any]:
    event_prefix = str(event_metadata.get("prefix") or "")
    if not event_prefix and score_records:
        event_prefix = str(
            score_records[0].get("upd_prefix")
            or score_records[0].get("rib_prefix")
            or ""
        )
    if not event_prefix:
        raise ValueError("event prefix is required")

    if withdrawal_rows:
        validate_withdrawal_rows(withdrawal_rows)
    filtered_baseline = filter_rows(baseline_rows, event_prefix)
    filtered_after = filter_rows(after_rows, event_prefix)
    related_baseline = filter_related_rows(baseline_rows, event_prefix)
    related_after = filter_related_rows(after_rows, event_prefix)
    filtered_withdrawals = filter_rows(withdrawal_rows, event_prefix)
    outage = analyze_outage(
        filtered_withdrawals, filtered_baseline, filtered_after
    )
    type1 = analyze_type1(
        score_records, related_baseline, related_after
    )
    origin_changed = _has_origin_change(score_records)

    if outage["detected"]:
        recommendation = "route_outage"
        reason = "Multi-VP synchronized withdrawals without broad replacement paths"
    elif type1["detected"] and type1.get("ambiguous_with_route_leak"):
        recommendation = "ambiguous"
        reason = (
            "Strict Type-1 adjacency evidence coexists with competing "
            "same-origin leak-shaped insertions; retain both candidates"
        )
    elif type1["detected"]:
        recommendation = "type_1_hijack"
        subtype = (type1.get("best_candidate") or {}).get("hijack_subtype") or "E|1"
        reason = (
            "A novel multi-VP-supported AS is immediately adjacent to the "
            f"origin ({subtype})"
        )
    elif origin_changed:
        recommendation = "prefix_hijack"
        reason = "The observed origin AS changes; defer to existing ownership validation"
    else:
        recommendation = "defer_existing_route_leak_or_other"
        reason = "No conclusive outage, origin-change, or strict Type-1 evidence"

    return {
        "event_name": event_name,
        "prefix": event_prefix,
        "start_time": event_metadata.get("start_time"),
        "end_time": event_metadata.get("end_time"),
        "input_summary": {
            "score_record_count": len(score_records),
            "baseline_row_count": len(filtered_baseline),
            "after_row_count": len(filtered_after),
            "withdrawal_row_count": len(filtered_withdrawals),
            "withdrawals_available": bool(filtered_withdrawals),
        },
        "classification": {
            "recommended_anomaly_type": recommendation,
            "reason": reason,
            "requires_final_skill_validation": True,
            "priority": [
                "route_outage",
                "type_1_hijack",
                "prefix_hijack",
                "route_leak",
                "other",
            ],
        },
        "route_outage": outage,
        "type_1_hijack": type1,
    }


def as_number(value: Any) -> int | str | None:
    if value is None:
        return None
    text = str(value)
    return int(text) if text.isdigit() else text


def build_type1_report(
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Materialize the Case Template for a validated Type-1 candidate."""
    candidate = (evidence.get("type_1_hijack") or {}).get("best_candidate")
    if not candidate or not candidate.get("detected"):
        raise ValueError("no detected Type-1 candidate is available")
    ambiguous = bool(candidate.get("ambiguous_with_route_leak"))
    limitations = list((evidence.get("type_1_hijack") or {}).get("limitations") or [])
    if ambiguous:
        limitations.append(
            "Competing route-leak shaped insertions were also observed"
        )
    subtype = candidate.get("hijack_subtype") or "E|1"
    origin_unchanged = bool(candidate.get("origin_unchanged", subtype == "E|1"))
    root_cause = {
        "attacker_as": as_number(candidate["attacker_as"]),
        "victim_as": as_number(candidate["victim_as"]),
        "hijack_subtype": subtype,
        "forged_adjacency": [
            as_number(asn) for asn in candidate["forged_adjacency"]
        ],
        "normal_predecessors": [
            as_number(asn) for asn in candidate["normal_predecessors"]
        ],
        "origin_unchanged": origin_unchanged,
        "novel_adjacency": candidate["novel_adjacency"],
        "supporting_vp_count": candidate["supporting_vp_count"],
        "confidence": "low" if ambiguous else candidate["confidence"],
        "evidence_limitations": limitations,
    }
    if candidate.get("covering_prefix"):
        root_cause["covering_prefix"] = candidate["covering_prefix"]
    if candidate.get("announced_prefix"):
        root_cause["announced_prefix"] = candidate["announced_prefix"]
    if candidate.get("covering_origin_as") is not None:
        root_cause["covering_origin_as"] = as_number(candidate["covering_origin_as"])
    if candidate.get("prefix_relation"):
        root_cause["prefix_relation"] = candidate["prefix_relation"]
    description = (
        f"AS {candidate['attacker_as']} newly appeared immediately before "
        f"origin AS {candidate['victim_as']} across "
        f"{candidate['supporting_vp_count']} VPs ({subtype})."
    )
    if subtype == "S|1" and candidate.get("covering_prefix"):
        description += (
            f" The more-specific {candidate.get('announced_prefix')} is "
            f"compared against covering prefix {candidate['covering_prefix']}"
            + (
                f" origin AS {candidate.get('covering_origin_as')}."
                if candidate.get("covering_origin_as")
                else "."
            )
        )
    if ambiguous:
        description += " Competing leak-shaped insertions make the class ambiguous."
    return {
        "prefix": evidence.get("prefix"),
        "start_time": evidence.get("start_time"),
        "end_time": evidence.get("end_time"),
        "anomaly_type": "type_1_hijack" if not ambiguous else "other",
        "root_cause": root_cause,
        "description": description,
    }


def build_outage_report(
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Materialize the Case Template for a validated route-outage candidate."""
    outage = evidence.get("route_outage") or {}
    if not outage.get("detected"):
        raise ValueError("no detected route-outage candidate is available")
    return {
        "prefix": evidence.get("prefix"),
        "start_time": evidence.get("start_time"),
        "end_time": evidence.get("end_time"),
        "anomaly_type": "route_outage",
        "root_cause": {
            "affected_origin_as": as_number(outage.get("affected_origin_as")),
            "suspected_failure_as": as_number(outage.get("suspected_failure_as")),
            "attribution_scope": outage.get("attribution_scope"),
            "baseline_vp_count": outage.get("baseline_vp_count"),
            "affected_baseline_vp_count": outage.get(
                "affected_baseline_vp_count"
            ),
            "withdrawal_ratio": outage.get("withdrawal_ratio"),
            "synchronization_ratio": outage.get("synchronization_ratio"),
            "alternative_path_ratio": outage.get("alternative_path_ratio"),
            "outage_start_timestamp": outage.get("cluster_start_timestamp"),
            "recovery_timestamp": outage.get("recovery_timestamp"),
            "duration_seconds": outage.get("duration_seconds"),
            "confidence": outage.get("confidence"),
            "evidence_limitations": outage.get("limitations") or [],
        },
        "description": (
            f"{outage.get('affected_baseline_vp_count')} of "
            f"{outage.get('baseline_vp_count')} baseline VPs synchronously "
            "withdrew the prefix with few immediate alternatives."
        ),
    }


def resolve_event_metadata(
    project_root: Path, event_dir: Path, event_name: str
) -> dict[str, Any]:
    root_report = load_json(event_dir / "root_cause_report.json", {})
    project_event = load_json(project_root / "event.json", {})
    metadata: dict[str, Any] = {}
    if isinstance(root_report, dict):
        metadata.update(root_report)
    if (
        isinstance(project_event, dict)
        and project_event.get("event_name") == event_name
    ):
        metadata.update(project_event)
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract route-outage and Type-1 (E|1 / S|1) RCA evidence"
    )
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--project-root", default=None)
    parser.add_argument("--withdrawals", default=None)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    skill_dir = Path(__file__).resolve().parent
    project_root = (
        Path(args.project_root).resolve()
        if args.project_root
        else skill_dir.parents[1]
    )
    event_dir = project_root / "data" / "events" / args.event_name
    if not event_dir.is_dir():
        raise FileNotFoundError(f"event directory not found: {event_dir}")
    metadata = resolve_event_metadata(
        project_root, event_dir, args.event_name
    )
    scores = load_json(event_dir / "score.json", [])
    if not isinstance(scores, list):
        raise ValueError("score.json must contain a JSON array")

    history_file = event_dir / "rib_history.csv"
    if not history_file.exists():
        history_file = event_dir / "history_rib.csv"
    baseline_rows = read_csv(history_file) + read_csv(
        event_dir / "rib_before_incident.csv"
    )
    after_rows = read_csv(event_dir / "rib_after_incident.csv")
    withdrawal_file = (
        Path(args.withdrawals).resolve()
        if args.withdrawals
        else event_dir / "withdrawals.csv"
    )
    withdrawal_rows = read_csv(withdrawal_file)
    evidence = build_evidence(
        args.event_name,
        metadata,
        scores,
        baseline_rows,
        after_rows,
        withdrawal_rows,
    )
    output = (
        Path(args.output).resolve()
        if args.output
        else event_dir / "root_cause_evidence.json"
    )
    with output.open("w", encoding="utf-8") as handle:
        json.dump(evidence, handle, ensure_ascii=False, indent=2)
    print(f"Saved extended RCA evidence to {output}")


if __name__ == "__main__":
    main()
