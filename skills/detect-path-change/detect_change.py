import csv
import json
import os
import ipaddress
from typing import List, Dict, Optional
from pathlib import Path

_root = Path(__file__).resolve().parents[2]


def load_csv_rows(csv_file: str) -> List[Dict]:
    rows = []
    if not os.path.exists(csv_file):
        raise FileNotFoundError(csv_file)
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            prefix = row.get("prefix").strip()
            peer_asn = row.get("peer_asn").strip()
            as_path = row.get("as_path").strip()

            rows.append(
                {
                    "prefix": prefix,
                    "peer_asn": peer_asn,
                    "as_path": [tok for tok in as_path.split() if tok],
                    "raw_path": as_path,
                }
            )
    return rows


def build_rib_index(rib_rows: List[Dict]) -> Dict[str, List[Dict]]:
    index = {}
    for r in rib_rows:
        prefix = r["prefix"]
        index.setdefault(prefix, []).append(r)
    return index


def classify_prefix_relation(rib_prefix: str, upd_prefix: str) -> str:
    """Return how the update prefix relates to a baseline RIB prefix."""
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


def _peer_rows(rows: List[Dict], peer: str) -> List[Dict]:
    return [row for row in rows if row["peer_asn"] == peer]


def _longest_covering_rows(rows: List[Dict]) -> List[Dict]:
    best_len = -1
    selected: List[Dict] = []
    for row in rows:
        try:
            prefixlen = ipaddress.ip_network(row["prefix"], strict=False).prefixlen
        except ValueError:
            continue
        if prefixlen > best_len:
            best_len = prefixlen
            selected = [row]
        elif prefixlen == best_len:
            selected.append(row)
    return selected


def find_rib_matches(
    rib_index: Dict[str, List[Dict]], update_prefix: str, peer: str
) -> List[Dict]:
    """Exact prefix first; otherwise the longest covering supernet.

    Exact matches are not also returned as supernets. When no same-peer row
    exists, fall back to prefix-only matching with the same exact-then-longest
    covering rule.
    """
    exact_all = list(rib_index.get(update_prefix) or [])
    exact_peer = _peer_rows(exact_all, peer)
    if exact_peer:
        return exact_peer

    covering_all: List[Dict] = []
    try:
        upd_net = ipaddress.ip_network(update_prefix, strict=False)
    except ValueError:
        return list(exact_all)

    for rib_prefix, rows in rib_index.items():
        if rib_prefix == update_prefix:
            continue
        try:
            rib_net = ipaddress.ip_network(rib_prefix, strict=False)
        except ValueError:
            continue
        if rib_net.version == upd_net.version and upd_net.subnet_of(rib_net):
            covering_all.extend(rows)

    covering_peer = _longest_covering_rows(_peer_rows(covering_all, peer))
    if covering_peer:
        return covering_peer
    if exact_all:
        return exact_all
    return _longest_covering_rows(covering_all)


def detect_change(event_name: str):
    _event_dir = _root / "data" / "events" / event_name
    ribs_csv = _event_dir / "rib_before_incident.csv"
    upds_csv = _event_dir / "rib_after_incident.csv"
    out_json = _event_dir / "paths.json"
    rib_rows = load_csv_rows(str(ribs_csv))
    upd_rows = load_csv_rows(str(upds_csv))

    rib_index = build_rib_index(rib_rows)

    results = []
    for upd in upd_rows:
        upd_ip = upd["prefix"]
        peer = upd["peer_asn"]
        upd_path = upd["as_path"]
        if not upd_ip or not peer or not upd_path:
            continue
        rib_matches = find_rib_matches(rib_index, upd_ip, peer)
        if not rib_matches:
            continue

        for rib_row in rib_matches:
            rib_path = rib_row["as_path"]
            if not rib_path:
                continue

            results.append(
                {
                    "rib_prefix": rib_row["prefix"],
                    "upd_prefix": upd_ip,
                    "prefix_relation": classify_prefix_relation(
                        rib_row["prefix"], upd_ip
                    ),
                    "rib_path": " ".join(rib_path),
                    "update_path": " ".join(upd_path),
                }
            )

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    event_json = _root / "event.json"
    with open(event_json, "r") as file:
        data = json.load(file)

    event_name = data.get("event_name")

    detect_change(event_name)
