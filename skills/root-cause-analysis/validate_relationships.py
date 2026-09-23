#!/usr/bin/env python3
"""Deterministic AS-relationship validation for route-leak / ``other`` RCA.

Resolves the correct ``rel_{YYYYMM}`` table from the event start time, queries
each adjacent AS pair with direction-normalized lookups (direct row first,
then the reverse row with a negated ``rel``), and emits ``path_relationships``
plus a valley-free triplet analysis.

This fixes two failure modes observed in manual SQL lookups:

1. Wrong-month table selection (e.g. ``rel_202511`` used for a 2025-12-30
   event instead of ``rel_202512``).
2. Direction-sensitive exact queries that mark pairs already present in the
   database as missing (``2``) because the stored row uses the reverse
   ``(as1, as2)`` order.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Optional, Sequence


REL_TABLE_RE = re.compile(r"^rel_(\d{6})$")


def resolve_bgp_db(project_root: Path, db_path: Optional[str] = None) -> Path:
    if db_path:
        return Path(db_path).resolve()
    for candidate in (
        project_root / "data" / "bgp.db",
        project_root / "data" / "db" / "bgp.db",
    ):
        if candidate.exists():
            return candidate
    return project_root / "data" / "bgp.db"

# Relationship codes per route_leak.md:
#   -1: Provider-to-Customer (p2c)
#    1: Customer-to-Provider (c2p)
#    0: Peer-to-Peer (p2p)
#    2: Missing / Unknown in the relationship database

ABNORMAL_PAIRS = {
    (-1, 1): "provider_to_provider",
    (-1, 0): "provider_to_peer",
    (0, 1): "peer_to_provider",
    (0, 0): "peer_to_peer",
}

NORMAL_PAIRS = {
    (1, -1),
    (0, -1),
    (1, 0),
    (1, 1),
}

LEAK_TYPE_LABELS = {
    "provider_to_provider": "p2c_to_c2p",
    "provider_to_peer": "p2c_to_p2p",
    "peer_to_provider": "p2p_to_c2p",
    "peer_to_peer": "p2p_to_p2p",
}


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def parse_path(value: Any) -> list[str]:
    """Split an AS path string into a list of ASN tokens."""
    return str(value or "").replace(",", " ").split()


def parse_event_month(start_time: Any) -> Optional[tuple[int, int]]:
    """Extract ``(year, month)`` from common event timestamp formats."""
    match = re.search(r"(\d{4})[/-](\d{1,2})", str(start_time or ""))
    if not match:
        return None
    year, month = int(match.group(1)), int(match.group(2))
    if month < 1 or month > 12:
        return None
    return year, month


def resolve_rel_table(
    conn: sqlite3.Connection, year: int, month: int
) -> Optional[str]:
    """Pick the ``rel_YYYYMM`` table for the event month.

    Prefers an exact month match; otherwise falls back to the most recent
    table that is earlier than or equal to the event month (matching the
    route_leak.md fallback convention).
    """
    rows = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name LIKE 'rel\\_%' ESCAPE '\\'"
    ).fetchall()
    tables: dict[int, str] = {}
    for (name,) in rows:
        match = REL_TABLE_RE.match(name)
        if match:
            tables[int(match.group(1))] = name
    if not tables:
        return None
    event_key = year * 100 + month
    if event_key in tables:
        return tables[event_key]
    older = [key for key in tables if key < event_key]
    if older:
        return tables[max(older)]
    return tables[max(tables)]


def lookup_rel(
    conn: sqlite3.Connection, table: str, left: str, right: str
) -> tuple[int, str]:
    """Return ``(rel, source)`` for the directed pair ``(left, right)``.

    ``source`` is ``direct`` when the database stores ``(left, right)``,
    ``reverse`` when only ``(right, left)`` is stored (negated), and
    ``missing`` when neither direction exists (rel ``2``).
    """
    row = conn.execute(
        f"SELECT rel FROM {table} WHERE as1 = ? AND as2 = ? LIMIT 1",
        (left, right),
    ).fetchone()
    if row is not None:
        return int(row[0]), "direct"
    row = conn.execute(
        f"SELECT rel FROM {table} WHERE as1 = ? AND as2 = ? LIMIT 1",
        (right, left),
    ).fetchone()
    if row is not None:
        return -int(row[0]), "reverse"
    return 2, "missing"


def classify_pair(pair: tuple[int, int]) -> str:
    if pair in ABNORMAL_PAIRS:
        return "abnormal"
    if pair in NORMAL_PAIRS:
        return "normal"
    return "unclassified"


def analyze_path(
    asns: Sequence[str], relationships: Sequence[int]
) -> dict[str, Any]:
    """Build path relationships plus right-to-left triplet analysis."""
    if len(asns) != len(relationships) + 1:
        raise ValueError("relationships must contain one entry per adjacent pair")

    triplets: list[dict[str, Any]] = []
    route_leak_candidates: list[dict[str, Any]] = []
    for index in range(len(asns) - 3, -1, -1):
        triplet = asns[index : index + 3]
        pair = (relationships[index], relationships[index + 1])
        status = classify_pair(pair)
        entry: dict[str, Any] = {
            "triplet": list(triplet),
            "pair": list(pair),
            "pattern": status,
        }
        if status == "abnormal":
            leak_type = ABNORMAL_PAIRS[pair]
            entry["leak_type"] = leak_type
            entry["leak_type_label"] = LEAK_TYPE_LABELS[leak_type]
            entry["leaking_as"] = triplet[1]
            route_leak_candidates.append(
                {
                    "leaking_as": triplet[1],
                    "leak_type": leak_type,
                    "leak_type_label": LEAK_TYPE_LABELS[leak_type],
                    "triplet": list(triplet),
                    "pair": list(pair),
                }
            )
        triplets.append(entry)

    if route_leak_candidates:
        conclusion = "route_leak_candidate"
    elif any(rel == 2 for rel in relationships):
        conclusion = "insufficient_relationship_data"
    elif any(entry["pattern"] == "unclassified" for entry in triplets):
        conclusion = "unclassified_pattern"
    else:
        conclusion = "no_leak_pattern"

    return {
        "path_relationships": [int(rel) for rel in relationships],
        "triplets": triplets,
        "abnormal_triplet_count": len(route_leak_candidates),
        "route_leak_candidates": route_leak_candidates,
        "conclusion": conclusion,
    }


def validate_update_path(
    conn: sqlite3.Connection,
    update_path: Sequence[str],
    year: int,
    month: int,
) -> dict[str, Any]:
    """Validate every adjacent pair in ``update_path`` and analyze triplets."""
    table = resolve_rel_table(conn, year, month)
    if table is None:
        raise ValueError(
            f"no rel_YYYYMM table found in database for {year}-{month:02d}"
        )

    pairs: list[dict[str, Any]] = []
    relationships: list[int] = []
    for left, right in zip(update_path, update_path[1:]):
        rel, source = lookup_rel(conn, table, left, right)
        pairs.append({"as1": left, "as2": right, "rel": rel, "source": source})
        relationships.append(rel)

    analysis = analyze_path(update_path, relationships)
    return {
        "relationship_table": table,
        "update_path": " ".join(update_path),
        "asn_list": list(update_path),
        "pairs": pairs,
        **analysis,
    }


def load_top_score_path(event_dir: Path, score_index: int) -> Optional[list[str]]:
    scores = load_json(event_dir / "score.json", [])
    if not isinstance(scores, list) or not scores:
        return None
    records = [r for r in scores if isinstance(r, dict)]
    if not records:
        return None
    record = records[score_index] if score_index < len(records) else records[-1]
    path = parse_path(record.get("update_path"))
    return path or None


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate AS relationships for an update path using the correct "
            "rel_YYYYMM table and direction-normalized lookups"
        )
    )
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--project-root", default=None)
    parser.add_argument("--db", default=None)
    parser.add_argument("--path", default=None, help="AS path to validate (overrides score.json)")
    parser.add_argument("--score-index", type=int, default=0)
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

    metadata = load_json(project_root / "event.json", {})
    if metadata.get("event_name") != args.event_name:
        metadata = load_json(event_dir / "root_cause_report.json", {})
    start_time = metadata.get("start_time") or ""
    event_month = parse_event_month(start_time)
    if event_month is None:
        raise ValueError(f"cannot parse event month from start_time: {start_time!r}")
    year, month = event_month

    update_path = parse_path(args.path) if args.path else load_top_score_path(
        event_dir, args.score_index
    )
    if not update_path:
        raise ValueError(
            "no update path available: provide --path or a score.json with update_path"
        )

    db_path = resolve_bgp_db(project_root, args.db)
    if not db_path.exists():
        raise FileNotFoundError(f"relationship database not found: {db_path}")

    conn = sqlite3.connect(str(db_path))
    try:
        result = validate_update_path(conn, update_path, year, month)
    finally:
        conn.close()

    result["event_name"] = args.event_name
    result["prefix"] = metadata.get("prefix", "")
    result["start_time"] = start_time

    output = (
        Path(args.output).resolve()
        if args.output
        else event_dir / "relationship_validation.json"
    )
    with output.open("w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    print(f"Saved relationship validation to {output}")
    print(f"Relationship table: {result['relationship_table']}")
    print(f"path_relationships: {result['path_relationships']}")
    print(f"Conclusion: {result['conclusion']}")
    if result["route_leak_candidates"]:
        for candidate in result["route_leak_candidates"]:
            print(
                f"  leak candidate AS {candidate['leaking_as']} "
                f"({candidate['leak_type_label']}) in "
                f"{' '.join(candidate['triplet'])}"
            )


if __name__ == "__main__":
    main()
