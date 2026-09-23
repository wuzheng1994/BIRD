"""Bayesian BGP propagation analysis based on observed UPDATE paths.

The report is intentionally compact.  It contains only event metadata,
posterior probabilities for observed propagation edges, and rankings of
complete UPDATE paths that actually occur in ``paths.json``.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List, Optional, Sequence, Tuple


PathTokens = Tuple[str, ...]
DirectedEdge = Tuple[str, str]


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def as_path(value: Any) -> List[str]:
    return [token for token in str(value or "").replace(",", " ").split() if token]


def as_number(value: str) -> int | str:
    return int(value) if value.isdigit() else value


def as_timestamp(value: Any) -> Optional[float]:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def collapse_prepends(path: Sequence[str]) -> List[str]:
    """Remove consecutive AS prepends while preserving AS adjacencies."""
    collapsed: List[str] = []
    for asn in path:
        if not collapsed or collapsed[-1] != asn:
            collapsed.append(asn)
    return collapsed


def directed_edges(path: Sequence[str]) -> set[DirectedEdge]:
    collapsed = collapse_prepends(path)
    return set(zip(collapsed, collapsed[1:]))


def as_root_cause_object(report: Dict[str, Any]) -> Dict[str, Any]:
    root = report.get("root_cause")
    return root if isinstance(root, dict) else {}


def _asn_from_narrative(text: str) -> Optional[str]:
    by_match = re.search(r"\bby\s+AS(\d+)\b", text, re.IGNORECASE)
    if by_match:
        return by_match.group(1)
    match = re.search(r"\bAS(\d+)\b", text, re.IGNORECASE)
    return match.group(1) if match else None


def reported_root(report: Dict[str, Any]) -> Optional[str]:
    raw = report.get("root_cause")
    root = as_root_cause_object(report)
    if report.get("anomaly_type") == "route_leak":
        value = root.get("leaking_as")
    elif report.get("anomaly_type") in {"prefix_hijack", "type_1_hijack"}:
        value = root.get("attacker_as", root.get("hijacker_as"))
    else:
        value = root.get("origin_as")
    if value is None and isinstance(raw, str):
        value = _asn_from_narrative(raw)
    return str(value) if value is not None else None


def root_index(path: Sequence[str], root: str, anomaly_type: str) -> Optional[int]:
    indexes = [index for index, value in enumerate(path) if value == root]
    if not indexes:
        return None
    return indexes[-1] if anomaly_type in {"prefix_hijack", "type_1_hijack"} else indexes[0]


def propagation_chain(path: Sequence[str], root: str, anomaly_type: str) -> List[str]:
    """Reverse an observed AS_PATH segment into root-to-observer direction."""
    index = root_index(path, root, anomaly_type)
    return collapse_prepends(list(path[index::-1])) if index is not None else []


def read_path_pairs(event_dir: Path) -> List[Dict[str, str]]:
    records = load_json(event_dir / "paths.json", [])
    if not isinstance(records, list):
        raise ValueError("paths.json must contain a JSON array")
    fields = ("rib_prefix", "upd_prefix", "rib_path", "update_path")
    return [
        {field: str(record.get(field, "")).strip() for field in fields}
        for record in records
        if isinstance(record, dict) and all(field in record for field in fields)
    ]


def collect_leak_updates(
    records: Sequence[Dict[str, str]], root: str
) -> Tuple[List[Dict[str, str]], List[Dict[str, Any]]]:
    """Keep raw support, then deduplicate statistical samples by prefix and UPDATE."""
    raw_updates = [record for record in records if root in as_path(record["update_path"])]
    grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for record in raw_updates:
        key = (record["upd_prefix"], record["update_path"])
        update = grouped.setdefault(
            key,
            {
                "prefix": record["upd_prefix"],
                "update_path": record["update_path"],
                "update_tokens": collapse_prepends(as_path(record["update_path"])),
                "paired_rib_paths": set(),
                "raw_record_count": 0,
            },
        )
        update["paired_rib_paths"].add(record["rib_path"])
        update["raw_record_count"] += 1
    return raw_updates, list(grouped.values())


def read_normal_paths(path: Path) -> List[Tuple[str, PathTokens]]:
    if not path.exists():
        return []
    output = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            tokens = tuple(collapse_prepends(as_path(row.get("as_path", ""))))
            if tokens:
                output.append((str(row.get("prefix", "")).strip(), tokens))
    return output


def read_routes(path: Path) -> List[Dict[str, Any]]:
    """Read timestamped RIB/UPDATE observations for the descriptive report."""
    if not path.exists():
        return []
    routes = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            tokens = collapse_prepends(as_path(row.get("as_path", "")))
            if not tokens:
                continue
            peer = str(row.get("peer_asn", "")).strip()
            routes.append(
                {
                    "timestamp": as_timestamp(row.get("timestamp")),
                    "prefix": str(row.get("prefix", "")).strip(),
                    "peer_asn": as_number(peer) if peer else None,
                    "path": tokens,
                    "raw_path": " ".join(tokens),
                }
            )
    return routes


def normal_baseline_paths(
    event_dir: Path, records: Sequence[Dict[str, str]]
) -> List[Tuple[str, PathTokens]]:
    """Combine unique historical, pre-event, and paired RIB baseline paths."""
    baseline = set()
    # ``rib_history.csv`` is the pipeline filename; ``history_rib.csv`` is
    # accepted for backwards compatibility with existing event folders.
    for filename in ("rib_history.csv", "history_rib.csv"):
        baseline.update(read_normal_paths(event_dir / filename))
    baseline.update(read_normal_paths(event_dir / "rib_before_incident.csv"))
    for record in records:
        tokens = tuple(collapse_prepends(as_path(record["rib_path"])))
        if tokens:
            baseline.add((record["rib_prefix"], tokens))
    return sorted(baseline, key=lambda item: (item[0], item[1]))


def edge_presence_counts(paths: Sequence[Sequence[str]]) -> Counter[DirectedEdge]:
    counts: Counter[DirectedEdge] = Counter()
    for path in paths:
        counts.update(directed_edges(path))
    return counts


def beta_posterior(successes: int, trials: int) -> Tuple[int, int, float]:
    """Return Beta(1,1) posterior parameters and posterior mean."""
    alpha = 1 + successes
    beta = 1 + max(0, trials - successes)
    return alpha, beta, alpha / (alpha + beta)


def build_propagation_edges(
    updates: Sequence[Dict[str, Any]], root: str, anomaly_type: str
) -> List[Dict[str, Any]]:
    """Calculate conditional edge posteriors from deduplicated UPDATE samples."""
    source_counts: Counter[str] = Counter()
    edge_counts: Counter[DirectedEdge] = Counter()
    for update in updates:
        chain = propagation_chain(update["update_tokens"], root, anomaly_type)
        source_counts.update(set(chain[:-1]))
        edge_counts.update(set(zip(chain, chain[1:])))

    result = []
    for (source, target), count in edge_counts.items():
        alpha, beta, probability = beta_posterior(count, source_counts[source])
        result.append(
            {
                "from_as": as_number(source),
                "to_as": as_number(target),
                "posterior": f"Beta({alpha}, {beta})",
                "propagation_probability": round(probability, 6),
                "edge_update_count": count,
                "source_update_count": source_counts[source],
            }
        )
    return sorted(
        result,
        key=lambda item: (-item["propagation_probability"], -item["edge_update_count"], str(item["from_as"]), str(item["to_as"])),
    )


def build_leak_specific_edge_evidence(
    updates: Sequence[Dict[str, Any]], normal_paths: Sequence[Tuple[str, PathTokens]]
) -> Dict[DirectedEdge, float]:
    """Compute the log posterior-mean leak/normal ratio for novel UPDATE edges."""
    leak_counts = edge_presence_counts([update["update_tokens"] for update in updates])
    normal_counts = edge_presence_counts([path for _, path in normal_paths])
    candidate_edges: set[DirectedEdge] = set()
    for update in updates:
        baseline_edges = set().union(
            *(directed_edges(as_path(path)) for path in update["paired_rib_paths"])
        )
        candidate_edges.update(directed_edges(update["update_tokens"]) - baseline_edges)

    evidence = {}
    for edge in candidate_edges:
        _, _, leak_mean = beta_posterior(leak_counts[edge], len(updates))
        _, _, normal_mean = beta_posterior(normal_counts[edge], len(normal_paths))
        evidence[edge] = math.log(leak_mean / normal_mean)
    return evidence


def geometric_mean(values: Sequence[float]) -> float:
    """Geometric mean of strictly positive values; empty or non-positive → 0."""
    positives = [value for value in values if value > 0]
    if not positives:
        return 0.0
    return math.exp(sum(math.log(value) for value in positives) / len(positives))


def rank_observed_paths(
    updates: Sequence[Dict[str, Any]],
    propagation_edges: Sequence[Dict[str, Any]],
    leak_specific_edges: Dict[DirectedEdge, float],
    root: str,
    anomaly_type: str,
) -> List[Dict[str, Any]]:
    """Rank observed paths by geometric-mean edge probability (maximum first)."""
    edge_probability = {
        (str(edge["from_as"]), str(edge["to_as"])): edge["propagation_probability"]
        for edge in propagation_edges
    }
    ranked = []
    for update in updates:
        update_edges = directed_edges(update["update_tokens"])
        baseline_edges = set().union(
            *(directed_edges(as_path(path)) for path in update["paired_rib_paths"])
        )
        novel_edges = update_edges - baseline_edges
        specificity = sum(leak_specific_edges[edge] for edge in novel_edges)
        chain = propagation_chain(update["update_tokens"], root, anomaly_type)
        hop_edges = list(zip(chain, chain[1:]))
        probabilities = [edge_probability[edge] for edge in hop_edges]
        path_probability = geometric_mean(probabilities)
        ranked.append(
            {
                "prefix": update["prefix"],
                "propagation_path": [as_number(asn) for asn in chain],
                "update_path": update["update_path"],
                "path_probability": round(path_probability, 6),
                "edge_probabilities": [round(value, 6) for value in probabilities],
                "leak_specificity_score": round(specificity, 6),
                "per_hop_propagation_probability": round(path_probability, 6),
                "minimum_edge_probability": round(min(probabilities), 6) if probabilities else None,
                "raw_update_record_count": update["raw_record_count"],
            }
        )
    ranked.sort(
        key=lambda item: (
            -item["path_probability"],
            -(item["minimum_edge_probability"] or 0.0),
            -item["raw_update_record_count"],
            -item["leak_specificity_score"],
            item["prefix"],
            item["update_path"],
        )
    )
    for rank, path in enumerate(ranked, start=1):
        path["rank"] = rank
    return ranked


def utc_datetime(timestamp: Optional[float]) -> Optional[str]:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def propagation_patterns(
    updates: Sequence[Dict[str, Any]], root: str, anomaly_type: str
) -> List[Dict[str, Any]]:
    """Summarize distinct complete observed root-to-observer paths."""
    groups: Dict[PathTokens, Dict[str, Any]] = defaultdict(
        lambda: {"raw_record_count": 0, "examples": []}
    )
    for update in updates:
        chain = tuple(propagation_chain(update["update_tokens"], root, anomaly_type))
        if len(chain) < 2:
            continue
        groups[chain]["raw_record_count"] += update["raw_record_count"]
        groups[chain]["examples"].append(update["update_path"])
    patterns = []
    for chain, item in groups.items():
        patterns.append(
            {
                "pattern": " -> ".join(chain),
                "example_paths": item["examples"][:3],
                "count": len(item["examples"]),
                "raw_record_count": item["raw_record_count"],
            }
        )
    return sorted(patterns, key=lambda item: (-item["raw_record_count"], item["pattern"]))


def propagation_timeline(
    after_routes: Sequence[Dict[str, Any]], root: str
) -> List[Dict[str, Any]]:
    """Return distinct timestamped post-event observations containing the root AS."""
    relevant = [route for route in after_routes if root in route["path"]]
    timestamps = [route["timestamp"] for route in relevant if route["timestamp"] is not None]
    first_timestamp = min(timestamps) if timestamps else None
    timeline = []
    seen = set()
    for route in sorted(relevant, key=lambda item: item["timestamp"] or float("inf")):
        key = (route["timestamp"], route["prefix"], route["peer_asn"], route["raw_path"])
        if key in seen:
            continue
        seen.add(key)
        timeline.append(
            {
                "timestamp": int(route["timestamp"]) if route["timestamp"] is not None else None,
                "datetime": utc_datetime(route["timestamp"]),
                "peer_asn": route["peer_asn"],
                "as_path": route["raw_path"],
                "prefix": route["prefix"],
                "root_relative_delay_seconds": round(route["timestamp"] - first_timestamp, 3)
                if route["timestamp"] is not None and first_timestamp is not None
                else None,
            }
        )
    return timeline


def path_length_stats(
    before_routes: Sequence[Dict[str, Any]], root_after_routes: Sequence[Dict[str, Any]]
) -> Dict[str, Any]:
    before_lengths = [len(route["path"]) for route in before_routes]
    after_lengths = [len(route["path"]) for route in root_after_routes]
    before_average = mean(before_lengths) if before_lengths else None
    after_average = mean(after_lengths) if after_lengths else None
    if before_average is not None and after_average is not None and before_average != 0:
        percentage = (after_average - before_average) / before_average * 100
        inflation = f"{percentage:.1f}% increase" if percentage >= 0 else f"{abs(percentage):.1f}% decrease"
    else:
        inflation = "Unavailable"
    return {
        "average_path_length_before": round(before_average, 3) if before_average is not None else None,
        "average_path_length_after": round(after_average, 3) if after_average is not None else None,
        "path_inflation_rate": inflation,
        "notes": "Computed from supplied pre-event RIB paths and post-event observations containing the root AS.",
    }


def propagation_nodes(
    updates: Sequence[Dict[str, Any]], root: str, anomaly_type: str
) -> set[str]:
    return {
        asn
        for update in updates
        for asn in propagation_chain(update["update_tokens"], root, anomaly_type)
    }


def analyze(event_dir: Path, top_k: Optional[int] = None) -> Dict[str, Any]:
    root_report = load_json(event_dir / "root_cause_report.json", {})
    anomaly_type = str(root_report.get("anomaly_type") or "other")
    root = reported_root(root_report)
    if not root:
        raise ValueError("root_cause_report.json must provide a leaking or hijacker AS")

    records = read_path_pairs(event_dir)
    raw_updates, updates = collect_leak_updates(records, root)
    if top_k is not None:
        updates = updates[:top_k]
        allowed = {(update["prefix"], update["update_path"]) for update in updates}
        raw_updates = [
            record
            for record in raw_updates
            if (record["upd_prefix"], record["update_path"]) in allowed
        ]
    normal_paths = normal_baseline_paths(event_dir, records)
    propagation_edges = build_propagation_edges(updates, root, anomaly_type)
    edge_evidence = build_leak_specific_edge_evidence(updates, normal_paths)
    ranked_paths = rank_observed_paths(
        updates, propagation_edges, edge_evidence, root, anomaly_type
    )

    after_routes = read_routes(event_dir / "rib_after_incident.csv")
    before_routes = read_routes(event_dir / "rib_before_incident.csv")
    root_after_routes = [route for route in after_routes if root in route["path"]]
    nodes = propagation_nodes(updates, root, anomaly_type)
    transit_counts: Counter[str] = Counter()
    direct_receivers = set()
    for update in updates:
        chain = propagation_chain(update["update_tokens"], root, anomaly_type)
        transit_counts.update(chain[1:-1])
        if len(chain) >= 2:
            direct_receivers.add(chain[1])

    scope = "global" if len(nodes) >= 10 else "regional" if len(nodes) >= 4 else "local"
    propagation_analysis: Dict[str, Any] = {
        "key_transit_asns": [as_number(asn) for asn, _ in transit_counts.most_common(20)],
        "transit_as_descriptions": {},
        "observed_peer_asns": sorted(
            {
                as_number(chain[-1])
                for update in updates
                if (chain := propagation_chain(update["update_tokens"], root, anomaly_type))
            },
            key=str,
        ),
        "propagation_patterns": propagation_patterns(updates, root, anomaly_type),
        "propagation_timeline": propagation_timeline(after_routes, root),
        "path_inflation_analysis": path_length_stats(before_routes, root_after_routes),
        "geographic_analysis": {
            "transit_network_coverage": "Unavailable: no AS geolocation metadata supplied",
            "propagation_scope": scope,
        },
        "data_summary": {
            "path_pair_count": len(records),
            "raw_root_related_update_count": len(raw_updates),
            "deduplicated_root_related_update_count": len(updates),
            "normal_baseline_path_count": len(normal_paths),
        },
        "propagation_edge_probabilities": {
            "direction": "root_as_to_observer_as",
            "sample": "deduplicated root-related UPDATEs, keyed by (upd_prefix, update_path)",
            "posterior": "Beta(1 + edge_update_count, 1 + source_update_count - edge_update_count)",
            "edges": propagation_edges,
        },
        "propagation_path_ranking": {
            "candidate_constraint": "Each candidate is a complete update_path observed in paths.json; graph edges are not recombined.",
            "path_probability_definition": "Geometric mean of connecting-edge propagation probabilities along the root-to-observer path.",
            "primary_ranking": "Maximum path_probability (geometric mean of connecting edges).",
            "secondary_ranking": "Minimum edge probability, then raw UPDATE frequency, then leak-specificity score.",
            "max_path_probability": ranked_paths[0]["path_probability"] if ranked_paths else None,
            "max_paths": [
                item
                for item in ranked_paths
                if ranked_paths and item["path_probability"] == ranked_paths[0]["path_probability"]
            ],
            "paths": ranked_paths,
        },
    }

    root_data = as_root_cause_object(root_report)
    if anomaly_type == "route_leak":
        propagation_analysis.update(
            {
                "leaking_as": as_number(root),
                "leaked_to": [as_number(asn) for asn in sorted(direct_receivers, key=str)],
                "direct_upstream": root_data.get("direct_upstream"),
                "leak_direction": root_data.get("leak_type"),
            }
        )
        propagation_analysis["geographic_analysis"]["leak_origin"] = "Unknown: no AS geolocation metadata supplied"
    elif anomaly_type in {"prefix_hijack", "type_1_hijack"}:
        propagation_analysis.update(
            {
                "hijacker_as": as_number(root),
                "direct_upstream": root_data.get("direct_upstream"),
                "hijack_type": root_data.get(
                    "hijack_subtype", root_data.get("hijack_type", "unknown")
                ),
            }
        )
        propagation_analysis["geographic_analysis"]["hijacker_location"] = "Unknown: no AS geolocation metadata supplied"

    root_timestamps = [
        route["timestamp"] for route in root_after_routes if route["timestamp"] is not None
    ]
    duration = (
        f"{max(root_timestamps) - min(root_timestamps):.1f} seconds of root-containing post-event observations"
        if len(root_timestamps) >= 2
        else "Unavailable: insufficient root-containing timestamps"
    )
    report: Dict[str, Any] = {
        "prefix": root_report.get("prefix"),
        "start_time": root_report.get("start_time"),
        "end_time": root_report.get("end_time"),
        "anomaly_type": anomaly_type,
        "propagation_analysis": propagation_analysis,
        "impact_assessment": {
            "visibility": f"{len(updates)} deduplicated root-related UPDATEs ({len(raw_updates)} raw records)",
            "reachability_impact": "Observed propagation paths are ranked by path probability: the geometric mean of connecting-edge probabilities. The reported value is the maximum.",
            "duration_impact": duration,
            "mitigation_difficulty": "Requires AS-relationship and operator context",
        },
        "recommendations": [
            "Prioritize highly ranked observed propagation paths for operator review.",
            "Treat duplicate UPDATE records as frequency support, not independent Bayesian samples.",
            "Expand and validate the pre-event normal RIB baseline before automated mitigation decisions.",
        ],
    }
    if root_timestamps:
        time_key = "leak_start_time" if anomaly_type == "route_leak" else "hijack_start_time"
        report[time_key] = utc_datetime(min(root_timestamps))
    return report


def resolve_event_dir(project_root: Path, event_name: str) -> Path:
    for candidate in (
        project_root / "events" / event_name,
        project_root / "data" / "events" / event_name,
    ):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"Event directory not found: {event_name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bayesian BGP propagation analysis")
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--project-root", default=None)
    parser.add_argument("--top-k", type=int, default=None)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    skill_root = Path(__file__).resolve().parents[2]
    project_root = Path(args.project_root).resolve() if args.project_root else skill_root
    event_dir = resolve_event_dir(project_root, args.event_name)
    output = Path(args.output).resolve() if args.output else event_dir / "propagation_report.json"
    with output.open("w", encoding="utf-8") as handle:
        json.dump(analyze(event_dir, args.top_k), handle, ensure_ascii=False, indent=2)
    print(f"Saved propagation report to {output}")


if __name__ == "__main__":
    main()
