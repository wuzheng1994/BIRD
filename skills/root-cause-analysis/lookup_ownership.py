#!/usr/bin/env python3
"""Deterministic prefix-to-AS ownership lookup.

Writes ``ownership.json``. Query the network address only (no ``/len``).
This file is the only source of pfx2as evidence for finalize_report.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Optional


PFX2AS_RE = re.compile(r"^pfx2as_(\d{8})$")


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


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def network_address(prefix: str) -> str:
    text = str(prefix or "").strip()
    if "/" in text:
        return str(ipaddress.ip_network(text, strict=False).network_address)
    return text


def candidate_addresses(prefix: str) -> list[tuple[str, str]]:
    """Exact network address first, then supernet addresses (longest first)."""
    text = str(prefix or "").strip()
    if not text:
        return []
    try:
        net = ipaddress.ip_network(text if "/" in text else f"{text}/32", strict=False)
    except ValueError:
        addr = text.split("/", 1)[0]
        return [(addr, "exact")]
    seen: list[str] = []
    results: list[tuple[str, str]] = []
    addr = str(net.network_address)
    results.append((addr, "exact"))
    seen.append(addr)
    for plen in range(net.prefixlen - 1, 0, -1):
        try:
            super_net = net.supernet(new_prefix=plen)
        except ValueError:
            continue
        addr = str(super_net.network_address)
        if addr not in seen:
            seen.append(addr)
            results.append((addr, f"supernet_/{plen}"))
    return results


def parse_event_date(start_time: Any) -> Optional[str]:
    match = re.search(r"(\d{4})[/-](\d{1,2})[/-](\d{1,2})", str(start_time or ""))
    if not match:
        return None
    year, month, day = (int(match.group(i)) for i in range(1, 4))
    return f"{year:04d}{month:02d}{day:02d}"


def resolve_pfx2as_table(conn: sqlite3.Connection, event_date: str) -> Optional[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'pfx2as_%'"
    ).fetchall()
    dated = []
    for (name,) in rows:
        match = PFX2AS_RE.match(str(name))
        if match:
            dated.append((match.group(1), str(name)))
    if not dated:
        return None
    dated.sort()
    earlier = [name for stamp, name in dated if stamp <= event_date]
    if earlier:
        return earlier[-1]
    return dated[-1][1]


def query_asns(conn: sqlite3.Connection, table: str, address: str) -> list[str]:
    rows = conn.execute(
        f'SELECT DISTINCT asn FROM "{table}" WHERE prefix = ?', (address,)
    ).fetchall()
    return [str(row[0]).strip() for row in rows if str(row[0]).strip()]


def origin_from_path(path: Any) -> Optional[str]:
    tokens = [tok for tok in str(path or "").replace(",", " ").split() if tok]
    return tokens[-1] if tokens else None


def lookup_ownership(
    project_root: Path,
    event_name: str,
    db_path: Optional[Path] = None,
) -> dict[str, Any]:
    event_dir = project_root / "data" / "events" / event_name
    metadata = load_json(project_root / "event.json", {})
    if metadata.get("event_name") != event_name:
        metadata = load_json(event_dir / "root_cause_report.json", {})
    prefix = str(metadata.get("prefix") or "")
    start_time = metadata.get("start_time") or ""
    scores = load_json(event_dir / "score.json", [])
    top = scores[0] if isinstance(scores, list) and scores else {}
    observed_origin = origin_from_path(top.get("update_path"))
    covering_prefix = str(top.get("rib_prefix") or "")

    event_date = parse_event_date(start_time)
    if event_date is None:
        raise ValueError(f"cannot parse event date from start_time: {start_time!r}")

    resolved_db = resolve_bgp_db(project_root, db_path)
    if not resolved_db.exists():
        raise FileNotFoundError(f"ownership database not found: {resolved_db}")

    prefixes_to_scan = [prefix]
    if covering_prefix and covering_prefix != prefix:
        prefixes_to_scan.append(covering_prefix)

    queries: list[dict[str, Any]] = []
    legitimate: list[str] = []
    seen_asn: set[str] = set()
    seen_query: set[tuple[str, str]] = set()

    conn = sqlite3.connect(str(resolved_db))
    try:
        table = resolve_pfx2as_table(conn, event_date)
        if table is None:
            raise FileNotFoundError("no pfx2as_* table in bgp.db")
        for item in prefixes_to_scan:
            for address, kind in candidate_addresses(item):
                key = (item, address)
                if key in seen_query:
                    continue
                seen_query.add(key)
                asns = query_asns(conn, table, address)
                queries.append(
                    {
                        "source_prefix": item,
                        "network_address": address,
                        "match": kind,
                        "asns": asns,
                    }
                )
                for asn in asns:
                    if asn not in seen_asn:
                        seen_asn.add(asn)
                        legitimate.append(asn)
                if asns and kind == "exact":
                    break
    finally:
        conn.close()

    authorized: Optional[bool]
    if not observed_origin:
        authorized = None
    elif not legitimate:
        authorized = None
    else:
        authorized = observed_origin in seen_asn

    return {
        "event_name": event_name,
        "prefix": prefix,
        "network_address": network_address(prefix) if prefix else "",
        "start_time": start_time,
        "table": table,
        "observed_origin_as": observed_origin,
        "covering_prefix": covering_prefix or None,
        "queries": queries,
        "legitimate_asns": legitimate,
        "claimed_origin_authorized": authorized,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Lookup prefix ownership from pfx2as_* tables"
    )
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--project-root", default=None)
    parser.add_argument("--db", default=None)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    skill_dir = Path(__file__).resolve().parent
    project_root = (
        Path(args.project_root).resolve()
        if args.project_root
        else skill_dir.parents[1]
    )
    db_path = Path(args.db).resolve() if args.db else None
    result = lookup_ownership(project_root, args.event_name, db_path)
    event_dir = project_root / "data" / "events" / args.event_name
    output = (
        Path(args.output).resolve()
        if args.output
        else event_dir / "ownership.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    print(f"Saved ownership lookup to {output}")
    print(f"Table: {result['table']}")
    print(f"Observed origin: {result['observed_origin_as']}")
    print(f"Legitimate ASNs: {result['legitimate_asns']}")
    print(f"Claimed origin authorized: {result['claimed_origin_authorized']}")


if __name__ == "__main__":
    main()
