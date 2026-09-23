#!/usr/bin/env python3
"""Create a simplified propagation report for 'other' anomaly types."""

import json
import csv
from collections import Counter
from pathlib import Path
from typing import Dict, List, Any


def as_path(value: Any) -> List[str]:
    return [token for token in str(value or "").replace(",", " ").split() if token]


def read_routes(csv_path: Path) -> List[Dict[str, Any]]:
    """Read routes from CSV file."""
    routes = []
    if not csv_path.exists():
        return routes
    
    with csv_path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            routes.append({
                "prefix": row.get("prefix", "").strip(),
                "path": row.get("as_path", "").strip(),
                "timestamp": row.get("timestamp", "").strip()
            })
    return routes


def analyze_propagation(event_dir: Path, root_report: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze propagation for 'other' anomaly types."""
    
    # Read post-event routes
    after_routes = read_routes(event_dir / "rib_after_incident.csv")
    
    # Read paths.json to get path pairs
    paths_json_path = event_dir / "paths.json"
    path_pairs = []
    if paths_json_path.exists():
        with paths_json_path.open("r", encoding="utf-8") as handle:
            path_pairs = json.load(handle)
    
    # Collect all ASes from post-event paths
    all_ases = set()
    transit_counter = Counter()
    observed_peers = set()
    
    for route in after_routes:
        path = as_path(route["path"])
        if path:
            all_ases.update(path)
            # Count transit ASes (excluding first and last)
            if len(path) > 3:
                transit_counter.update(path[1:-1])
            # Last AS is the observing peer
            observed_peers.add(path[0])
    
    # Also analyze from paths.json
    for pair in path_pairs:
        update_path = as_path(pair.get("update_path", ""))
        if update_path:
            all_ases.update(update_path)
            if len(update_path) > 3:
                transit_counter.update(update_path[1:-1])
            if update_path:
                observed_peers.add(update_path[0])
    
    # Analyze path inflation by comparing before/after paths
    before_routes = read_routes(event_dir / "rib_before_incident.csv")
    
    before_lengths = []
    after_lengths = []
    
    for route in before_routes:
        path = as_path(route["path"])
        if path:
            before_lengths.append(len(path))
    
    for route in after_routes:
        path = as_path(route["path"])
        if path:
            after_lengths.append(len(path))
    
    avg_before = sum(before_lengths) / len(before_lengths) if before_lengths else 0
    avg_after = sum(after_lengths) / len(after_lengths) if after_lengths else 0
    path_inflation = avg_after - avg_before
    
    # Identify propagation patterns from paths.json
    propagation_patterns = []
    pattern_counter = Counter()
    
    for pair in path_pairs:
        update_path = as_path(pair.get("update_path", ""))
        if update_path and len(update_path) >= 2:
            # Create pattern string
            pattern = " -> ".join(update_path[-2:])  # Last two ASes as pattern
            pattern_counter[pattern] += 1
    
    for pattern, count in pattern_counter.most_common(10):
        propagation_patterns.append({
            "pattern": pattern,
            "count": 1,  # Distinct pattern count
            "raw_record_count": count  # Total occurrences
        })
    
    # Determine impact scope
    node_count = len(all_ases)
    if node_count >= 10:
        scope = "global"
    elif node_count >= 4:
        scope = "regional"
    else:
        scope = "local"
    
    return {
        "key_transit_asns": [asn for asn, _ in transit_counter.most_common(20)],
        "transit_as_descriptions": {},
        "observed_peer_asns": sorted(list(observed_peers)),
        "propagation_patterns": propagation_patterns,
        "propagation_timeline": [],  # Simplified - no timeline without root AS
        "path_inflation_analysis": {
            "average_pre_event_path_length": avg_before,
            "average_post_event_path_length": avg_after,
            "path_inflation": path_inflation,
            "path_length_change_percentage": (path_inflation / avg_before * 100) if avg_before else 0
        },
        "geographic_analysis": {
            "coverage_estimate": scope,
            "estimated_countries_affected": "Unknown",
            "estimated_regions_affected": "Unknown"
        }
    }


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Create simplified propagation report for 'other' anomaly types")
    parser.add_argument("--event-name", required=True, help="Event name (YYYYMMDD_HHmm)")
    parser.add_argument("--project-root", required=True, help="Project root directory")
    
    args = parser.parse_args()
    
    project_root = Path(args.project_root)
    event_dir = project_root / "data" / "events" / args.event_name
    
    if not event_dir.exists():
        print(f"Error: Event directory {event_dir} does not exist")
        return 1
    
    # Read root cause report
    root_report_path = event_dir / "root_cause_report.json"
    if not root_report_path.exists():
        print(f"Error: {root_report_path} does not exist")
        return 1
    
    with root_report_path.open("r", encoding="utf-8") as handle:
        root_report = json.load(handle)
    
    # Analyze propagation
    propagation_analysis = analyze_propagation(event_dir, root_report)
    
    # Create final report
    report = {
        "prefix": root_report.get("prefix", ""),
        "start_time": root_report.get("start_time", ""),
        "end_time": root_report.get("end_time", ""),
        "anomaly_type": root_report.get("anomaly_type", "other"),
        "propagation_analysis": propagation_analysis,
        "impact_assessment": {
            "propagation_scope": propagation_analysis["geographic_analysis"]["coverage_estimate"],
            "estimated_ases_affected": len(propagation_analysis["observed_peer_asns"]),
            "path_inflation_severity": "moderate" if abs(propagation_analysis["path_inflation_analysis"]["path_inflation"]) > 1 else "minimal",
            "overall_impact": "limited"  # Default for 'other' anomaly types
        },
        "recommendations": [
            "Monitor prefix announcements for unusual path changes",
            "Verify AS relationships for abnormal propagation patterns",
            "Consider implementing route filtering for unexpected paths"
        ]
    }
    
    # Write report
    output_path = event_dir / "propagation_report.json"
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
    
    print(f"Created propagation report at {output_path}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())