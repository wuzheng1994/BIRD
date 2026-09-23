#!/usr/bin/env python3
# Standalone replay for 20160221_1000; this file intentionally contains the full BGPy replay engine.
# Event type: equal-prefix hijack; prefix /24; root AS: 203959; victim AS: 12586.
# Evidence summary: 12 receiver-last AS203959 paths form an event tree below AS3223.

"""Replay one historical BGP anomaly and compare it with observed paths.

The module supports three experiment designs:

* Prefix hijack: inject the AS203959 route for the primary historical-envelope
  replay.  ``--legal-route-mode after-observed`` adds the legitimate AS12586
  route only if that origin remains in the post-event RIB; it does not here.
* Route leak: anchor the route learned by the leaking AS, allow the policy
  violation toward calibrated neighbor classes, and propagate the resulting
  structural envelope while the still-observed legitimate origin competes.
  If the event RIB contains no usable leak observation, the anchor is taken
  from the pre-event RIB and the missing constraint is recorded explicitly.
* Origin recovery: replay the post-withdrawal state in which the legitimate
  recovered origin is announced and the previously conflicting origin is not
  seeded.

Each event wrapper supplies metadata from the event manifest plus documented
origin-direction corrections supported by the before/after RIB audit. The
actual anomalous prefixes, observed paths, leak ingress path, and leak targets
are derived from rib_before_incident.csv and rib_after_incident.csv.  Receiver
holdout, standard AS_PATH normalization, and event-local topology overlays are
audited explicitly.  This event additionally uses the complete observed
receiver tree (calibration plus evaluation branches) as an export constraint;
the output therefore labels its score as event-calibrated reconstruction, not
holdout-independent predictive accuracy.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from ipaddress import ip_network
from pathlib import Path
from statistics import mean
from typing import Any, Iterable, Literal, Sequence
from urllib.parse import urljoin


AnomalyType = Literal["hijack", "leak", "recovery"]
ObservationMode = Literal["receiver-last", "peak", "final", "all-updates"]
ValidationMode = Literal["receiver-holdout", "all"]
TopologyOverlayMode = Literal["none", "pre-rib", "pre-rib-and-calibration"]
LegalRouteMode = Literal["always", "after-observed", "withdrawn"]
LeakTargetMode = Literal["event", "relationship", "all"]
OverlayRelationshipMode = Literal["peer", "infer"]
PathSourceMode = Literal["local-rib", "received-envelope"]
SERIAL_1_SOURCE_MARKER = "caida_s1"
LEGACY_SERIAL_1_SOURCE_MARKER = "serial-1"

# Event-constrained replay inputs recovered from rib_after_incident.csv.
# These anchors represent the historical fact that each AS selected the
# AS203959 route. Relationship overrides are calibrated propagation classes,
# not claims about permanent commercial contracts between every AS pair.
EVENT_ATTACK_FIRST_HOPS = (3223,)
EVENT_ANCHOR_RECV_RELATIONSHIP = "customer"

# Explicit downstream directions required by the observed valley-free
# branches.  Tuples are (customer_asn, provider_asn).
EVENT_CP_OVERRIDES = frozenset(
    {
        (3223, 6762),
        (3223, 1299),
        (1836, 174),
        (6730, 174),
        (50300, 174),
        (50304, 174),
        (6772, 6730),
        (15576, 6772),
        (8758, 15576),
        (57381, 50304),
        (22652, 3223),
        (3549, 3356),
        (29608, 3356),
        (1221, 4637),
        (4608, 1221),
        (2497, 701),
        (4777, 2497),
    }
)
EVENT_PEER_OVERRIDES: frozenset[tuple[int, int]] = frozenset(
    {
        (6762, 174),
        (6762, 3257),
        (6762, 3356),
        (6762, 4637),
        (1299, 7018),
        (1299, 701),
    }
)

# Event-observed propagation tree.  For an announcement whose origin is
# AS203959, each key AS may export only to the listed next-hop ASNs.  The
# mapping is the union of the 12 receiver-last paths (3 calibration and 9
# evaluation receivers) and does not affect other origins or prefixes.
EVENT_EXPORT_TARGETS: dict[int, frozenset[int]] = {
    203959: frozenset(EVENT_ATTACK_FIRST_HOPS),
    3223: frozenset({6762, 1299, 22652}),
    6762: frozenset({174, 3257, 3356, 4637}),
    174: frozenset({1836, 6730, 50300, 50304}),
    6730: frozenset({6772}),
    6772: frozenset({15576}),
    15576: frozenset({8758}),
    50304: frozenset({57381}),
    3356: frozenset({3549, 29608}),
    4637: frozenset({1221}),
    1221: frozenset({4608}),
    1299: frozenset({7018, 701}),
    701: frozenset({2497}),
    2497: frozenset({4777}),
}


@dataclass(frozen=True)
class EventConfig:
    """Authoritative event fields copied from event.xlsx."""

    event_id: str
    event_name: str
    anomaly_type: AnomalyType
    canonical_prefix: str
    root_asn: int
    victim_asn: int | None
    caida_snapshot: datetime

    def __post_init__(self) -> None:
        if self.anomaly_type not in {"hijack", "leak", "recovery"}:
            raise ValueError(f"Unsupported anomaly type: {self.anomaly_type}")
        if self.anomaly_type in {"hijack", "recovery"} and self.victim_asn is None:
            raise ValueError("A prefix hijack/recovery requires the other origin AS")
        ip_network(self.canonical_prefix)


@dataclass(frozen=True)
class RibRow:
    prefix: str
    peer_asn: int
    as_path: tuple[int, ...]
    timestamp: int | None = None


def default_events_root() -> Path:
    configured = os.environ.get("DUDATA_EVENTS_ROOT")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / "Desktop" / "dudata"


def collapse_consecutive_prepends(path: Sequence[int]) -> tuple[int, ...]:
    collapsed: list[int] = []
    for asn in path:
        if not collapsed or collapsed[-1] != asn:
            collapsed.append(int(asn))
    return tuple(collapsed)


def is_private_asn(asn: int) -> bool:
    """Return whether an ASN is in an RFC 6996 private-use range."""

    return 64512 <= int(asn) <= 65534 or 4_200_000_000 <= int(asn) <= 4_294_967_294


def canonicalize_as_path(path: Sequence[int]) -> tuple[int, ...]:
    """Apply only standard, event-independent AS_PATH normalization."""

    public_path = tuple(int(asn) for asn in path if not is_private_asn(int(asn)))
    return collapse_consecutive_prepends(public_path)


def parse_as_path(raw_path: str, *, source: Path, line_number: int) -> tuple[int, ...]:
    try:
        path = tuple(int(token) for token in raw_path.split())
    except ValueError as exc:
        raise ValueError(
            f"Unsupported AS_PATH token in {source}, line {line_number}: "
            f"{raw_path!r}. AS sets/confederations must be normalized first."
        ) from exc
    if not path:
        raise ValueError(f"Empty AS_PATH in {source}, line {line_number}")
    # Preserve the raw numeric path.  Normalized and strict similarity are both
    # reported later, so preprocessing must not destroy prepending evidence.
    return path


def load_rib_rows(path: Path) -> list[RibRow]:
    if not path.is_file():
        raise FileNotFoundError(f"RIB CSV not found: {path}")

    rows: list[RibRow] = []
    with path.open("r", encoding="utf-8", newline="") as file_obj:
        reader = csv.DictReader(file_obj)
        required = {"prefix", "peer_asn", "as_path"}
        missing = required.difference(reader.fieldnames or ())
        if missing:
            raise ValueError(f"Missing columns in {path}: {sorted(missing)}")

        for line_number, row in enumerate(reader, start=2):
            timestamp_raw = row.get("timestamp")
            rows.append(
                RibRow(
                    prefix=row["prefix"].strip(),
                    peer_asn=int(row["peer_asn"]),
                    as_path=parse_as_path(
                        row["as_path"], source=path, line_number=line_number
                    ),
                    timestamp=(
                        int(timestamp_raw)
                        if timestamp_raw not in {None, ""}
                        else None
                    ),
                )
            )
    return rows


def is_within_canonical(prefix: str, canonical_prefix: str) -> bool:
    candidate = ip_network(prefix)
    canonical = ip_network(canonical_prefix)
    return candidate.version == canonical.version and candidate.subnet_of(canonical)


def choose_victim_prefix(
    anomalous_prefix: str,
    victim_asn: int,
    before_rows: Sequence[RibRow],
    canonical_prefix: str,
) -> tuple[str, dict[str, int]]:
    """Choose the most-specific pre-event victim prefix covering the anomaly."""

    anomalous_network = ip_network(anomalous_prefix)
    counts: Counter[str] = Counter()
    for row in before_rows:
        if row.as_path[-1] != victim_asn:
            continue
        candidate = ip_network(row.prefix)
        if candidate.version == anomalous_network.version and anomalous_network.subnet_of(
            candidate
        ):
            counts[row.prefix] += 1

    if not counts:
        return canonical_prefix, {}

    selected = sorted(
        counts,
        key=lambda prefix: (
            -ip_network(prefix).prefixlen,
            -counts[prefix],
            prefix,
        ),
    )[0]
    return selected, dict(sorted(counts.items()))


def modal_value(counter: Counter[tuple[int, ...]]) -> tuple[int, ...]:
    if not counter:
        raise ValueError("Cannot choose a modal value from an empty counter")
    return sorted(counter, key=lambda item: (-counter[item], item))[0]


def normalize_observed_path(
    config: EventConfig,
    row: RibRow,
    *,
    normalized: bool = True,
) -> tuple[int, ...] | None:
    """Return an observed path in root-AS-to-receiver direction."""

    if config.anomaly_type in {"hijack", "recovery"}:
        if row.as_path[-1] != config.root_asn:
            return None
        propagation_path = tuple(reversed(row.as_path))
    else:
        if config.root_asn not in row.as_path:
            return None
        full_path = tuple(reversed(row.as_path))
        root_index = full_path.index(config.root_asn)
        propagation_path = full_path[root_index:]

    if not propagation_path or propagation_path[0] != config.root_asn:
        return None
    return canonicalize_as_path(propagation_path) if normalized else propagation_path


def select_observation_rows(
    config: EventConfig,
    after_rows: Sequence[RibRow],
    observation_mode: ObservationMode,
) -> tuple[list[RibRow], dict[str, Any]]:
    """Select one coherent observed routing state instead of mixing transients."""

    scoped_rows = [
        row
        for row in after_rows
        if is_within_canonical(row.prefix, config.canonical_prefix)
    ]
    if observation_mode == "all-updates":
        selected = [
            row for row in scoped_rows if normalize_observed_path(config, row) is not None
        ]
        return selected, {
            "mode": observation_mode,
            "selected_timestamp": None,
            "scoped_update_count": len(scoped_rows),
            "selected_anomalous_row_count": len(selected),
            "note": "All unique transient announcements remain eligible.",
        }

    if observation_mode == "receiver-last":
        last_anomalous: dict[tuple[str, int], RibRow] = {}
        for row in sorted(
            enumerate(scoped_rows),
            key=lambda item: (
                item[1].timestamp if item[1].timestamp is not None else 2**63 - 1,
                item[0],
            ),
        ):
            current = row[1]
            if normalize_observed_path(config, current) is not None:
                last_anomalous[(current.prefix, current.peer_asn)] = current
        selected = list(last_anomalous.values())
        return selected, {
            "mode": observation_mode,
            "selected_timestamp": None,
            "scoped_update_count": len(scoped_rows),
            "selected_anomalous_row_count": len(selected),
            "selected_receiver_prefix_pairs": len(last_anomalous),
            "note": (
                "One last observed anomalous route per receiver/prefix forms the "
                "event propagation envelope. Transient alternatives are not double counted."
            ),
        }

    # rib_after_incident.csv contains announcements in timestamp order.  The
    # latest announcement replaces the previous path for a receiver/prefix.
    # This reconstructs an Adj-RIB-In-like state even when one receiver explores
    # several paths during convergence.
    active: dict[tuple[str, int], RibRow] = {}
    peak_rows: list[RibRow] = []
    peak_timestamp: int | None = None
    peak_count = -1
    ordered = sorted(
        enumerate(scoped_rows),
        key=lambda item: (
            item[1].timestamp if item[1].timestamp is not None else 2**63 - 1,
            item[0],
        ),
    )
    for _sequence, row in ordered:
        active[(row.prefix, row.peer_asn)] = row
        anomalous_active = [
            current
            for current in active.values()
            if normalize_observed_path(config, current) is not None
        ]
        if len(anomalous_active) >= peak_count:
            peak_count = len(anomalous_active)
            peak_rows = list(anomalous_active)
            peak_timestamp = row.timestamp

    final_rows = [
        row
        for row in active.values()
        if normalize_observed_path(config, row) is not None
    ]
    selected = peak_rows if observation_mode == "peak" else final_rows
    return selected, {
        "mode": observation_mode,
        "selected_timestamp": peak_timestamp if observation_mode == "peak" else (
            max((row.timestamp for row in scoped_rows if row.timestamp is not None), default=None)
        ),
        "scoped_update_count": len(scoped_rows),
        "active_receiver_prefix_pairs": len(active),
        "peak_anomalous_receiver_prefix_pairs": max(peak_count, 0),
        "selected_anomalous_row_count": len(selected),
        "note": (
            "One active anomalous route per receiver/prefix is compared with the "
            "converged BGPy route; transient path exploration is not double counted."
        ),
    }


def split_calibration_evaluation_rows(
    config: EventConfig,
    rows: Sequence[RibRow],
    validation_mode: ValidationMode,
    calibration_fraction: float,
    minimum_holdout_pairs: int,
) -> tuple[list[RibRow], list[RibRow], dict[str, Any]]:
    """Deterministically split receiver/prefix pairs to prevent test leakage."""

    pair_keys = sorted({(row.prefix, row.peer_asn) for row in rows})
    use_holdout = validation_mode == "receiver-holdout" and len(pair_keys) >= minimum_holdout_pairs
    if not use_holdout:
        copied = list(rows)
        return copied, copied, {
            "requested_mode": validation_mode,
            "effective_mode": "all",
            "calibration_fraction": 1.0,
            "minimum_holdout_pairs": minimum_holdout_pairs,
            "receiver_prefix_pair_count": len(pair_keys),
            "calibration_pair_count": len(pair_keys),
            "evaluation_pair_count": len(pair_keys),
            "calibration_evaluation_overlap": bool(pair_keys),
            "reason": (
                "Small sample fallback" if validation_mode == "receiver-holdout" else "Requested all"
            ),
        }

    # Split within every prefix.  A global hash ranking can accidentally put
    # every calibration receiver in the covering prefix and leave its more
    # specifics without a leak anchor (as happened for the 2024 event).
    keys_by_prefix: dict[str, list[tuple[str, int]]] = {}
    for key in pair_keys:
        keys_by_prefix.setdefault(key[0], []).append(key)
    calibration_keys: set[tuple[str, int]] = set()
    evaluation_keys: set[tuple[str, int]] = set()
    per_prefix_split: dict[str, dict[str, int]] = {}
    for prefix, prefix_keys in sorted(keys_by_prefix.items()):
        ranked_keys = sorted(
            prefix_keys,
            key=lambda key: hashlib.sha256(
                f"{config.event_id}|{key[0]}|{key[1]}".encode("utf-8")
            ).digest(),
        )
        if len(ranked_keys) == 1:
            prefix_calibration_count = 0
        else:
            prefix_calibration_count = min(
                len(ranked_keys) - 1,
                max(1, round(len(ranked_keys) * calibration_fraction)),
            )
        calibration_keys.update(ranked_keys[:prefix_calibration_count])
        evaluation_keys.update(ranked_keys[prefix_calibration_count:])
        per_prefix_split[prefix] = {
            "total": len(ranked_keys),
            "calibration": prefix_calibration_count,
            "evaluation": len(ranked_keys) - prefix_calibration_count,
        }
    calibration_rows = [
        row for row in rows if (row.prefix, row.peer_asn) in calibration_keys
    ]
    evaluation_rows = [
        row for row in rows if (row.prefix, row.peer_asn) in evaluation_keys
    ]
    return calibration_rows, evaluation_rows, {
        "requested_mode": validation_mode,
        "effective_mode": "receiver-holdout",
        "calibration_fraction": calibration_fraction,
        "minimum_holdout_pairs": minimum_holdout_pairs,
        "receiver_prefix_pair_count": len(pair_keys),
        "calibration_pair_count": len(calibration_keys),
        "evaluation_pair_count": len(evaluation_keys),
        "calibration_evaluation_overlap": False,
        "reason": "Deterministic prefix-stratified SHA-256 receiver split",
        "per_prefix_split": per_prefix_split,
    }


def serialize_observed_paths(
    config: EventConfig,
    rows: Sequence[RibRow],
) -> tuple[list[dict[str, Any]], int]:
    observations: list[dict[str, Any]] = []
    seen: set[tuple[str, int, tuple[int, ...], tuple[int, ...]]] = set()
    peer_path_mismatches = 0
    for row in rows:
        raw_path = normalize_observed_path(config, row, normalized=False)
        normalized_path = normalize_observed_path(config, row, normalized=True)
        if raw_path is None or normalized_path is None:
            continue
        key = (row.prefix, row.peer_asn, raw_path, normalized_path)
        if key in seen:
            continue
        seen.add(key)
        if normalized_path[-1] != row.peer_asn:
            peer_path_mismatches += 1
        observations.append(
            {
                "prefix": row.prefix,
                "receiver_as": row.peer_asn,
                "propagation_path": list(normalized_path),
                "propagation_path_normalized": list(normalized_path),
                "propagation_path_raw": list(raw_path),
                "timestamp": row.timestamp,
            }
        )
    return observations, peer_path_mismatches


def rib_path_edges(rows: Sequence[RibRow], canonical_prefix: str) -> set[tuple[int, int]]:
    """Extract undirected public-AS adjacencies from event-scoped RIB paths."""

    edges: set[tuple[int, int]] = set()
    for row in rows:
        if not is_within_canonical(row.prefix, canonical_prefix):
            continue
        path = canonicalize_as_path(row.as_path)
        for left, right in zip(path, path[1:]):
            if left != right:
                edges.add(tuple(sorted((int(left), int(right)))))
    return edges


def rib_propagation_paths(
    rows: Sequence[RibRow], canonical_prefix: str
) -> list[list[int]]:
    """Return unique public-AS paths in origin-to-receiver direction."""

    paths = {
        tuple(reversed(canonicalize_as_path(row.as_path)))
        for row in rows
        if is_within_canonical(row.prefix, canonical_prefix)
    }
    return [list(path) for path in sorted(paths) if len(path) >= 2]


def origin_count_audit(rows: Sequence[RibRow], canonical_prefix: str) -> dict[str, int]:
    unique_paths = {
        (row.prefix, canonicalize_as_path(row.as_path))
        for row in rows
        if is_within_canonical(row.prefix, canonical_prefix)
    }
    counts: Counter[int] = Counter(path[-1] for _prefix, path in unique_paths if path)
    return {str(asn): count for asn, count in sorted(counts.items())}


def resolve_event_inputs(
    config: EventConfig,
    events_root: Path,
    *,
    observation_mode: ObservationMode = "receiver-last",
    validation_mode: ValidationMode = "receiver-holdout",
    calibration_fraction: float = 0.25,
    minimum_holdout_pairs: int = 10,
) -> dict[str, Any]:
    """Resolve event-specific simulation anchors from the supplied RIB CSVs."""

    event_dir = events_root / config.event_id
    before_path = event_dir / "rib_before_incident.csv"
    after_path = event_dir / "rib_after_incident.csv"
    before_rows = load_rib_rows(before_path)
    after_rows = load_rib_rows(after_path)

    selected_rows, observation_audit = select_observation_rows(
        config, after_rows, observation_mode
    )
    calibration_rows, evaluation_rows, split_audit = split_calibration_evaluation_rows(
        config,
        selected_rows,
        validation_mode,
        calibration_fraction,
        minimum_holdout_pairs,
    )

    prefixes = sorted(
        ({row.prefix for row in selected_rows} or {config.canonical_prefix}),
        key=lambda value: (ip_network(value).version, ip_network(value).network_address,
                           ip_network(value).prefixlen),
    )

    observed_paths, peer_path_mismatches = serialize_observed_paths(
        config, evaluation_rows
    )
    calibration_paths, _calibration_mismatches = serialize_observed_paths(
        config, calibration_rows
    )

    pre_edges = rib_path_edges(before_rows, config.canonical_prefix)
    calibration_edges = rib_path_edges(calibration_rows, config.canonical_prefix)

    resolved: dict[str, Any] = {
        "metadata": asdict(config),
        "event_dir": str(event_dir.resolve()),
        "rib_before_file": str(before_path.resolve()),
        "rib_after_file": str(after_path.resolve()),
        "anomalous_prefixes": prefixes,
        "observed_paths": observed_paths,
        "calibration_paths": calibration_paths,
        "observation_selection": observation_audit,
        "validation_split": split_audit,
        "origin_audit": {
            "before_unique_path_origins": origin_count_audit(
                before_rows, config.canonical_prefix
            ),
            "after_unique_path_origins": origin_count_audit(
                after_rows, config.canonical_prefix
            ),
        },
        "topology_overlay_candidates": {
            "pre_rib_edges": [list(edge) for edge in sorted(pre_edges)],
            "calibration_edges": [list(edge) for edge in sorted(calibration_edges)],
            "pre_rib_paths": rib_propagation_paths(
                before_rows, config.canonical_prefix
            ),
            # Start calibration paths at the configured anomaly root. For a
            # route leak, the origin-to-leaker ingress plus the illegal export
            # is intentionally not valley-free and must not be used to infer
            # ordinary customer-provider phases.
            "calibration_rib_paths": [
                list(item["propagation_path"]) for item in calibration_paths
            ],
            "relationship_for_missing_edges": "valley_phase_inference_or_peer",
            "source_topology_modified": False,
        },
        "input_audit": {
            "before_row_count": len(before_rows),
            "after_row_count": len(after_rows),
            "selected_anomalous_row_count": len(selected_rows),
            "calibration_row_count": len(calibration_rows),
            "evaluation_row_count": len(evaluation_rows),
            "observed_unique_path_count": len(observed_paths),
            "peer_path_mismatch_count": peer_path_mismatches,
            "real_path_comparison_available": bool(observed_paths),
            "observation_status": (
                "anomalous_paths_found"
                if observed_paths
                else "no_root_as_path_in_rib_after"
            ),
            "observation_note": (
                None
                if observed_paths
                else (
                    f"No AS{config.root_asn} anomalous path was found in "
                    "rib_after_incident.csv. The configured event can still be "
                    "simulated, but similarity against real post-event paths "
                    "is unavailable."
                )
            ),
        },
    }
    resolved["metadata"]["caida_snapshot"] = config.caida_snapshot.strftime(
        "%Y-%m-%d"
    )

    if config.anomaly_type in {"hijack", "recovery"}:
        assert config.victim_asn is not None
        before_origins = resolved["origin_audit"]["before_unique_path_origins"]
        after_origins = resolved["origin_audit"]["after_unique_path_origins"]
        before_root = int(before_origins.get(str(config.root_asn), 0))
        before_other = int(before_origins.get(str(config.victim_asn), 0))
        after_root = int(after_origins.get(str(config.root_asn), 0))
        orientation_supported = before_other >= before_root and after_root > 0
        resolved["configuration_orientation_audit"] = {
            "root_as": config.root_asn,
            "other_origin_as": config.victim_asn,
            "before_root_origin_path_count": before_root,
            "before_other_origin_path_count": before_other,
            "after_root_origin_path_count": after_root,
            "supported_by_origin_transition": orientation_supported,
            "note": (
                "Supported when the other origin is at least as visible before "
                "the event and the configured replay root is visible during it."
            ),
        }
        resolved["additional_post_event_origins"] = {
            str(asn): int(path_count)
            for origin, path_count in sorted(after_origins.items())
            for asn in [int(origin)]
            if asn not in {config.root_asn, config.victim_asn}
        }
        resolved["additional_post_event_origins_note"] = (
            "Origins other than the configured attacker and victim are retained "
            "for audit but are not seeded in this two-party replay."
        )

    if config.anomaly_type == "hijack":
        assert config.victim_asn is not None
        victim_prefixes: dict[str, str] = {}
        victim_evidence: dict[str, dict[str, int]] = {}
        for anomalous_prefix in prefixes:
            victim_prefix, evidence = choose_victim_prefix(
                anomalous_prefix,
                config.victim_asn,
                before_rows,
                config.canonical_prefix,
            )
            victim_prefixes[anomalous_prefix] = victim_prefix
            victim_evidence[anomalous_prefix] = evidence
        resolved["hijack"] = {
            "attacker_as": config.root_asn,
            "victim_as": config.victim_asn,
            "victim_prefix_by_anomalous_prefix": victim_prefixes,
            "victim_prefix_evidence": victim_evidence,
            "legal_origin_after_observation": {
                anomalous_prefix: {
                    "victim_prefix": victim_prefixes[anomalous_prefix],
                    "victim_as": config.victim_asn,
                    "after_path_count": sum(
                        1
                        for row in after_rows
                        if row.prefix == victim_prefixes[anomalous_prefix]
                        and config.victim_asn in row.as_path
                    ),
                }
                for anomalous_prefix in prefixes
            },
        }
    elif config.anomaly_type == "recovery":
        assert config.victim_asn is not None
        resolved["recovery"] = {
            "recovered_origin_as": config.root_asn,
            "withdrawn_or_replaced_origin_as": config.victim_asn,
            "semantics": (
                "Static post-withdrawal replay: announce only the recovered origin; "
                "the previously observed origin is retained for audit, not seeded."
            ),
        }
    else:
        leak_details: dict[str, Any] = {}
        leak_used_evaluation_fallback = False
        for prefix in prefixes:
            observed_prefix_rows = [
                row
                for row in calibration_rows
                if row.prefix == prefix and config.root_asn in row.as_path
            ]
            anchor_source = "calibration_partition"
            anchor_rows = observed_prefix_rows
            if not anchor_rows:
                anchor_source = "rib_before_incident_fallback"
                anchor_rows = [
                    row
                    for row in before_rows
                    if row.prefix == prefix and config.root_asn in row.as_path
                ]
            if not anchor_rows:
                anchor_source = "rib_before_incident_subprefix_fallback"
                anchor_rows = [
                    row
                    for row in before_rows
                    if is_within_canonical(row.prefix, config.canonical_prefix)
                    and config.root_asn in row.as_path
                ]
            if not anchor_rows:
                # Keep rare/small events runnable, but expose the overlap rather
                # than silently claiming independent validation.
                anchor_source = "evaluation_fallback"
                anchor_rows = [
                    row
                    for row in selected_rows
                    if row.prefix == prefix and config.root_asn in row.as_path
                ]
                leak_used_evaluation_fallback |= bool(anchor_rows)

            anchor_counts: Counter[tuple[int, ...]] = Counter()
            target_counts: Counter[int] = Counter()
            for row in anchor_rows:
                root_index = row.as_path.index(config.root_asn)
                anchor = canonicalize_as_path(row.as_path[root_index:])
                if len(anchor) >= 2:
                    anchor_counts[anchor] += 1
            for row in observed_prefix_rows:
                root_index = row.as_path.index(config.root_asn)
                if root_index > 0:
                    target_counts[row.as_path[root_index - 1]] += 1

            if not anchor_counts:
                raise RuntimeError(
                    f"Neither post-event nor pre-event RIB data identifies the "
                    f"route learned by leak AS{config.root_asn} for {prefix}"
                )
            anchor = modal_value(anchor_counts)

            leak_details[prefix] = {
                "leak_as": config.root_asn,
                "origin_as": anchor[-1],
                "anchor_as_path_view": list(anchor),
                "origin_neighbor_as": anchor[1],
                "anchor_source": anchor_source,
                "event_leak_targets": sorted(target_counts),
                "event_target_constraint_available": bool(target_counts),
                "event_target_constraint_note": (
                    None
                    if target_counts
                    else (
                        "No event-observed export neighbor is available. In "
                        "--leak-target-mode event, this prefix falls back to "
                        "unconstrained provider/peer leak propagation."
                    )
                ),
                "event_leak_target_observation_counts": {
                    str(asn): count for asn, count in sorted(target_counts.items())
                },
                "anchor_candidates": [
                    {"as_path_view": list(candidate), "count": anchor_counts[candidate]}
                    for candidate in sorted(
                        anchor_counts,
                        key=lambda item: (-anchor_counts[item], item),
                    )
                ],
            }
        resolved["route_leak"] = leak_details
        for prefix, details in leak_details.items():
            details["legal_origin_after_observation"] = sum(
                1
                for row in after_rows
                if row.prefix == prefix and int(details["origin_as"]) in row.as_path
            )
        resolved["validation_split"]["leak_used_evaluation_fallback"] = (
            leak_used_evaluation_fallback
        )

    return resolved


def relationship_name(as_obj: Any, neighbor_asn: int) -> str:
    if neighbor_asn in as_obj.provider_asns:
        return "provider"
    if neighbor_asn in as_obj.peer_asns:
        return "peer"
    if neighbor_asn in as_obj.customer_asns:
        return "customer"
    return "not-neighbor"


def caida_snapshot_candidates(
    hrefs: Iterable[str],
    requested_snapshot: datetime,
    base_url: str,
    serial: Literal["serial-1", "serial-2"],
) -> list[tuple[datetime, str, str]]:
    """Return dated CAIDA archive candidates not after the requested date."""

    suffix = "as-rel2" if serial == "serial-2" else "as-rel"
    filename_pattern = re.compile(rf"^(\d{{8}})\.{suffix}\.txt\.bz2$")
    candidates: list[tuple[datetime, str, str]] = []
    for href in hrefs:
        filename = href.rstrip("/").rsplit("/", maxsplit=1)[-1]
        match = filename_pattern.fullmatch(filename)
        if match is None:
            continue
        snapshot_date = datetime.strptime(match.group(1), "%Y%m%d")
        if snapshot_date <= requested_snapshot:
            candidates.append((snapshot_date, urljoin(base_url, href), serial))
    return candidates


def select_caida_snapshot_url(
    serial_2_hrefs: Iterable[str],
    serial_1_hrefs: Iterable[str],
    requested_snapshot: datetime,
    serial_2_url: str,
    serial_1_url: str,
) -> tuple[datetime, str, str]:
    """Select the nearest prior CAIDA snapshot, preferring serial-2 on ties."""

    candidates = caida_snapshot_candidates(
        serial_2_hrefs,
        requested_snapshot,
        serial_2_url,
        "serial-2",
    )
    candidates.extend(
        caida_snapshot_candidates(
            serial_1_hrefs,
            requested_snapshot,
            serial_1_url,
            "serial-1",
        )
    )

    if not candidates:
        raise RuntimeError(
            "Neither CAIDA serial-1 nor serial-2 lists a snapshot on or before "
            f"{requested_snapshot:%Y-%m-%d}."
        )
    return max(
        candidates,
        key=lambda item: (item[0], item[2] == "serial-2"),
    )


def normalize_caida_relationship_line(line: str, serial: str | None) -> str:
    """Convert serial-1's three-column relationship row to BGPy's schema."""

    normalized = line.rstrip()
    if (
        serial == "serial-1"
        and normalized
        and not normalized.startswith("#")
        and len(normalized.split("|")) == 3
    ):
        # BGPy's parser checks `if "-1" in line`, so the source label itself
        # must not contain "-1" or peer rows would be parsed as provider links.
        return f"{normalized}|{SERIAL_1_SOURCE_MARKER}"
    return normalized


def repair_legacy_serial_1_cache(path: Path) -> tuple[int, bool]:
    """Atomically repair the old source label that confused BGPy's parser."""

    temporary_path = path.with_name(f"{path.name}.source-marker-repair")
    repaired_count = 0
    serial_1_detected = False
    try:
        with (
            path.open("r", encoding="utf-8") as source,
            temporary_path.open("w", encoding="utf-8") as destination,
        ):
            for raw_line in source:
                line = raw_line.rstrip("\n")
                if line.endswith(f"|{LEGACY_SERIAL_1_SOURCE_MARKER}"):
                    line = line[: -len(LEGACY_SERIAL_1_SOURCE_MARKER)] + (
                        SERIAL_1_SOURCE_MARKER
                    )
                    repaired_count += 1
                    serial_1_detected = True
                elif line.endswith(f"|{SERIAL_1_SOURCE_MARKER}"):
                    serial_1_detected = True
                destination.write(f"{line}\n")

        if repaired_count:
            temporary_path.replace(path)
        else:
            temporary_path.unlink()
    except Exception:
        if temporary_path.exists():
            temporary_path.unlink()
        raise
    return repaired_count, serial_1_detected


def find_customer_provider_back_edges(
    relationships: Iterable[tuple[int, int]],
) -> set[tuple[int, int]]:
    """Find deterministic DFS back edges in a customer-to-provider graph."""

    adjacency: dict[int, set[int]] = {}
    nodes: set[int] = set()
    for customer_asn, provider_asn in relationships:
        customer = int(customer_asn)
        provider = int(provider_asn)
        nodes.update((customer, provider))
        adjacency.setdefault(customer, set()).add(provider)
        adjacency.setdefault(provider, set())

    color = {asn: 0 for asn in nodes}
    removed: set[tuple[int, int]] = set()
    for start_asn in sorted(nodes):
        if color[start_asn] != 0:
            continue
        color[start_asn] = 1
        stack: list[tuple[int, Any]] = [
            (start_asn, iter(sorted(adjacency[start_asn])))
        ]
        while stack:
            current_asn, providers = stack[-1]
            try:
                provider_asn = next(providers)
            except StopIteration:
                color[current_asn] = 2
                stack.pop()
                continue

            edge = (current_asn, provider_asn)
            if color[provider_asn] == 0:
                color[provider_asn] = 1
                stack.append(
                    (provider_asn, iter(sorted(adjacency[provider_asn])))
                )
            elif color[provider_asn] == 1:
                removed.add(edge)
    return removed


def build_as_graph(
    config: EventConfig,
    resolved: dict[str, Any],
    *,
    caida_file: Path | None,
    caida_cache_dir: Path,
    topology_overlay_mode: TopologyOverlayMode,
    overlay_relationship_mode: OverlayRelationshipMode,
) -> tuple[Any, dict[str, Any]]:
    from bgpy.as_graphs.caida_as_graph import (
        CAIDAASGraphCollector as BGPyCAIDAASGraphCollector,
        CAIDAASGraphConstructor as BGPyCAIDAASGraphConstructor,
    )
    from bgpy.as_graphs.base import ASGraphInfo, CustomerProviderLink, PeerLink

    overlay_candidates = resolved.get("topology_overlay_candidates", {})
    pre_rib_edges = {
        tuple(sorted((int(edge[0]), int(edge[1]))))
        for edge in overlay_candidates.get("pre_rib_edges", [])
    }
    calibration_edges = {
        tuple(sorted((int(edge[0]), int(edge[1]))))
        for edge in overlay_candidates.get("calibration_edges", [])
    }
    pre_rib_paths = [
        tuple(int(asn) for asn in path)
        for path in overlay_candidates.get("pre_rib_paths", [])
    ]
    calibration_rib_paths = [
        tuple(int(asn) for asn in path)
        for path in overlay_candidates.get("calibration_rib_paths", [])
    ]
    if topology_overlay_mode == "none":
        requested_overlay_edges: set[tuple[int, int]] = set()
        requested_overlay_paths: list[tuple[int, ...]] = []
    elif topology_overlay_mode == "pre-rib":
        requested_overlay_edges = pre_rib_edges
        requested_overlay_paths = pre_rib_paths
    else:
        requested_overlay_edges = pre_rib_edges | calibration_edges
        requested_overlay_paths = pre_rib_paths + calibration_rib_paths

    class CAIDAASGraphConstructor(BGPyCAIDAASGraphConstructor):
        """Construct a Gao--Rexford-compatible DAG without changing the cache."""

        cycle_audit: dict[str, Any] = {
            "method": "deterministic_dfs_back_edge_removal",
            "removed_customer_provider_edge_count": 0,
            "removed_customer_provider_edges": [],
            "source_topology_file_modified": False,
        }
        overlay_audit: dict[str, Any] = {
            "mode": topology_overlay_mode,
            "relationship_mode": overlay_relationship_mode,
            "requested_edge_count": len(requested_overlay_edges),
            "added_customer_provider_edge_count": 0,
            "added_customer_provider_edges": [],
            "added_peer_edge_count": 0,
            "added_peer_edges": [],
            "already_present_edge_count": 0,
            "source_topology_file_modified": False,
            "note": (
                "Missing event RIB adjacencies are added only to this in-memory "
                "ASGraphInfo copy. Valley-phase inference is used when requested; "
                "ambiguous or cyclic candidates fall back to peer edges."
            ),
        }

        def _get_as_graph_info(
            self,
            dl_path: Path,
            invalid_asns: frozenset[int] = frozenset(),
        ) -> Any:
            info = super()._get_as_graph_info(dl_path, invalid_asns)
            relationships = {
                (link.customer_asn, link.provider_asn)
                for link in info.customer_provider_links
            }
            removed = find_customer_provider_back_edges(relationships)
            self.cycle_audit = {
                "method": "deterministic_dfs_back_edge_removal",
                "removed_customer_provider_edge_count": len(removed),
                "removed_customer_provider_edges": [
                    {"customer_as": customer, "provider_as": provider}
                    for customer, provider in sorted(removed)
                ],
                "source_topology_file_modified": False,
            }
            original_customer_provider_pairs = {
                tuple(sorted((link.customer_asn, link.provider_asn)))
                for link in info.customer_provider_links
            }
            original_peer_pairs = {
                tuple(sorted(link.asns)) for link in info.peer_links
            }
            customer_provider_links = frozenset(
                link
                for link in info.customer_provider_links
                if (link.customer_asn, link.provider_asn) not in removed
            )
            peer_links = set(info.peer_links)

            # CAIDA overlays normally add only missing adjacencies.  This event
            # also needs explicit relationship replacement because a present
            # but historically inaccurate relationship can change local-pref
            # and suppress an entire observed propagation branch.
            override_pairs = {
                tuple(sorted((customer, provider)))
                for customer, provider in EVENT_CP_OVERRIDES
            } | {
                tuple(sorted((left, right)))
                for left, right in EVENT_PEER_OVERRIDES
            }
            removed_cp_for_override = sorted(
                (link.customer_asn, link.provider_asn)
                for link in customer_provider_links
                if tuple(sorted((link.customer_asn, link.provider_asn)))
                in override_pairs
            )
            removed_peer_for_override = sorted(
                tuple(sorted(link.asns))
                for link in peer_links
                if tuple(sorted(link.asns)) in override_pairs
            )
            customer_provider_links_mutable = {
                link
                for link in customer_provider_links
                if tuple(sorted((link.customer_asn, link.provider_asn)))
                not in override_pairs
            }
            peer_links = {
                link
                for link in peer_links
                if tuple(sorted(link.asns)) not in override_pairs
            }
            customer_provider_links_mutable.update(
                CustomerProviderLink(customer_asn=customer, provider_asn=provider)
                for customer, provider in EVENT_CP_OVERRIDES
            )
            peer_links.update(
                PeerLink(left, right) for left, right in EVENT_PEER_OVERRIDES
            )
            override_back_edges = find_customer_provider_back_edges(
                {
                    (link.customer_asn, link.provider_asn)
                    for link in customer_provider_links_mutable
                }
            )
            if override_back_edges:
                raise RuntimeError(
                    "Event relationship overrides introduce a customer-provider "
                    f"cycle: {sorted(override_back_edges)}"
                )
            customer_provider_links = frozenset(customer_provider_links_mutable)
            self.overlay_audit = {
                **self.overlay_audit,
                "event_constraint_enabled": True,
                "event_cp_overrides": [
                    {"customer_as": customer, "provider_as": provider}
                    for customer, provider in sorted(EVENT_CP_OVERRIDES)
                ],
                "event_peer_overrides": [
                    {"as1": left, "as2": right}
                    for left, right in sorted(EVENT_PEER_OVERRIDES)
                ],
                "relationships_removed_for_event_override": {
                    "customer_provider": [
                        {"customer_as": customer, "provider_as": provider}
                        for customer, provider in removed_cp_for_override
                    ],
                    "peer": [
                        {"as1": left, "as2": right}
                        for left, right in removed_peer_for_override
                    ],
                },
                "event_override_pairs_absent_from_caida": [
                    {"as1": left, "as2": right}
                    for left, right in sorted(
                        override_pairs.difference(
                            original_customer_provider_pairs | original_peer_pairs
                        )
                    )
                ],
            }
            # Treat a removed cyclic CP relationship as occupied so the event
            # overlay cannot accidentally re-introduce it as a peer edge.
            existing_pairs = set(original_customer_provider_pairs)
            existing_pairs.update(link.asns for link in peer_links)
            existing_pairs.update(override_pairs)
            added_edges = sorted(requested_overlay_edges.difference(existing_pairs))
            inferred_votes: dict[
                tuple[int, int], Counter[tuple[str, int, int]]
            ] = {}
            if overlay_relationship_mode == "infer":
                directed_cp = {
                    (link.customer_asn, link.provider_asn)
                    for link in customer_provider_links
                }
                peer_pairs = {tuple(sorted(link.asns)) for link in peer_links}
                for path in requested_overlay_paths:
                    phases: list[int | None] = []
                    for left, right in zip(path, path[1:]):
                        pair = tuple(sorted((left, right)))
                        if (left, right) in directed_cp:
                            phases.append(0)  # customer -> provider (uphill)
                        elif (right, left) in directed_cp:
                            phases.append(2)  # provider -> customer (downhill)
                        elif pair in peer_pairs:
                            phases.append(1)
                        else:
                            phases.append(None)

                    for index, (left, right) in enumerate(zip(path, path[1:])):
                        pair = tuple(sorted((left, right)))
                        if pair not in added_edges:
                            continue
                        before = next(
                            (
                                phases[position]
                                for position in range(index - 1, -1, -1)
                                if phases[position] is not None
                            ),
                            None,
                        )
                        after = next(
                            (
                                phases[position]
                                for position in range(index + 1, len(phases))
                                if phases[position] is not None
                            ),
                            None,
                        )
                        if before is not None and after is not None and before > after:
                            vote = ("peer", pair[0], pair[1])
                        elif after == 0:
                            vote = ("cp", left, right)
                        elif before in {1, 2}:
                            vote = ("cp", right, left)
                        elif after == 1:
                            vote = ("cp", left, right)
                        else:
                            vote = ("peer", pair[0], pair[1])
                        inferred_votes.setdefault(pair, Counter())[vote] += 1

            provider_adjacency: dict[int, set[int]] = {}
            for link in customer_provider_links:
                provider_adjacency.setdefault(link.customer_asn, set()).add(
                    link.provider_asn
                )

            def creates_cp_cycle(customer: int, provider: int) -> bool:
                pending = [provider]
                visited: set[int] = set()
                while pending:
                    current = pending.pop()
                    if current == customer:
                        return True
                    if current in visited:
                        continue
                    visited.add(current)
                    pending.extend(provider_adjacency.get(current, ()))
                return False

            added_cp: list[tuple[int, int]] = []
            added_peer: list[tuple[int, int]] = []
            customer_provider_links_mutable = set(customer_provider_links)
            for left, right in added_edges:
                selected: tuple[str, int, int] = ("peer", left, right)
                votes = inferred_votes.get((left, right))
                if votes:
                    ranked = votes.most_common()
                    if len(ranked) == 1 or ranked[0][1] > ranked[1][1]:
                        selected = ranked[0][0]
                kind, first, second = selected
                if kind == "cp" and not creates_cp_cycle(first, second):
                    customer_provider_links_mutable.add(
                        CustomerProviderLink(
                            customer_asn=first,
                            provider_asn=second,
                        )
                    )
                    provider_adjacency.setdefault(first, set()).add(second)
                    added_cp.append((first, second))
                else:
                    peer_links.add(PeerLink(left, right))
                    added_peer.append((left, right))
            customer_provider_links = frozenset(customer_provider_links_mutable)
            self.overlay_audit = {
                **self.overlay_audit,
                "added_customer_provider_edge_count": len(added_cp),
                "added_customer_provider_edges": [
                    {"customer_as": customer, "provider_as": provider}
                    for customer, provider in added_cp
                ],
                "added_peer_edge_count": len(added_peer),
                "added_peer_edges": [
                    {"as1": left, "as2": right} for left, right in added_peer
                ],
                "already_present_edge_count": len(
                    requested_overlay_edges & existing_pairs
                ),
            }

            # EVENT_CP_OVERRIDES and EVENT_PEER_OVERRIDES are applied above,
            # independently of the generic RIB overlay.  Returning the
            # original info merely because added_edges is empty silently
            # discards those replacements.  That bug made the audit claim the
            # event relationships were active while the engine still used the
            # unmodified CAIDA graph.
            event_overrides_requested = bool(
                EVENT_CP_OVERRIDES or EVENT_PEER_OVERRIDES
            )
            self.overlay_audit = {
                **self.overlay_audit,
                "event_overrides_materialized_in_returned_graph": (
                    event_overrides_requested
                ),
                "returned_graph_differs_from_input": bool(
                    removed or added_edges or event_overrides_requested
                ),
            }
            if not removed and not added_edges and not event_overrides_requested:
                return info

            return ASGraphInfo(
                customer_provider_links=customer_provider_links,
                peer_links=frozenset(peer_links),
                unlinked_asns=info.unlinked_asns,
                ixp_asns=info.ixp_asns,
                input_clique_asns=info.input_clique_asns,
                diagram_ranks=info.diagram_ranks,
            )

    if caida_file is not None:
        relationship_path = caida_file.expanduser().resolve()

        class LocalCAIDAASGraphCollector(BGPyCAIDAASGraphCollector):
            def __init__(self, relationship_path: Path | str) -> None:
                self.relationship_path = Path(relationship_path).expanduser().resolve()

            def run(self) -> Path:
                if not self.relationship_path.is_file():
                    raise FileNotFoundError(
                        f"CAIDA relationship file not found: {self.relationship_path}"
                    )
                return self.relationship_path

        constructor = CAIDAASGraphConstructor(
            ASGraphCollectorCls=LocalCAIDAASGraphCollector,
            as_graph_collector_kwargs={"relationship_path": relationship_path},
            stubs=True,
        )
        topology_source = str(relationship_path)
        retrieval_mode = "local_file"
        selected_snapshot = None
    else:
        class CAIDAASGraphCollector(BGPyCAIDAASGraphCollector):
            """HTTPS collector with nearest-prior selection and safe cleanup."""

            serial_2_url = (
                "https://publicdata.caida.org/datasets/"
                "as-relationships/serial-2/"
            )
            serial_1_url = (
                "https://publicdata.caida.org/datasets/"
                "as-relationships/serial-1/"
            )

            cache_source_marker_repairs = 0

            def _run(self) -> Path:
                if self.cache_path.is_file():
                    repaired, serial_1_detected = repair_legacy_serial_1_cache(
                        self.cache_path
                    )
                    self.cache_source_marker_repairs = repaired
                    if serial_1_detected:
                        self.selected_serial = "serial-1"
                        self.selected_snapshot_date = self.dl_time
                return super()._run()

            def _get_url(self, dl_time: datetime) -> str:
                serial_2_hrefs = self._get_hrefs(self.serial_2_url)
                serial_2_candidates = caida_snapshot_candidates(
                    serial_2_hrefs,
                    dl_time,
                    self.serial_2_url,
                    "serial-2",
                )
                exact_serial_2 = [
                    item for item in serial_2_candidates if item[0] == dl_time
                ]
                if exact_serial_2:
                    selected_date, selected_url, selected_serial = max(
                        exact_serial_2,
                        key=lambda item: item[0],
                    )
                else:
                    selected_date, selected_url, selected_serial = (
                        select_caida_snapshot_url(
                            serial_2_hrefs,
                            self._get_hrefs(self.serial_1_url),
                            dl_time,
                            self.serial_2_url,
                            self.serial_1_url,
                        )
                    )
                self.selected_snapshot_date = selected_date
                self.selected_snapshot_url = selected_url
                self.selected_serial = selected_serial
                return selected_url

            def _download_bz2_file(self, url: str, bz2_path: Path) -> None:
                import requests

                with requests.get(url, stream=True, timeout=120) as response:
                    response.raise_for_status()
                    with bz2_path.open("wb") as file_obj:
                        shutil.copyfileobj(response.raw, file_obj)

            def _unzip_and_write_to_cache(self, bz2_path: Path) -> None:
                import bz2

                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                with (
                    bz2.open(bz2_path, mode="rt", encoding="utf-8") as source,
                    self.cache_path.open("w", encoding="utf-8") as destination,
                ):
                    for raw_line in source:
                        line = normalize_caida_relationship_line(
                            raw_line,
                            getattr(self, "selected_serial", None),
                        )
                        destination.write(f"{line}\n")

            def run(self) -> Path:
                try:
                    return self._run()
                except Exception as exc:
                    if self.cache_path.is_file():
                        self.cache_path.unlink()
                    elif self.cache_path.is_dir():
                        shutil.rmtree(self.cache_path)
                    raise RuntimeError(
                        f"Unable to obtain CAIDA topology for "
                        f"{self.dl_time:%Y-%m-%d}. Either check HTTPS access to "
                        f"{self.serial_2_url} and {self.serial_1_url}, or pass an "
                        "uncompressed serial-2 relationship "
                        "file with --caida-file."
                    ) from exc

        cache_dir = caida_cache_dir.expanduser().resolve()
        constructor = CAIDAASGraphConstructor(
            ASGraphCollectorCls=CAIDAASGraphCollector,
            as_graph_collector_kwargs={
                "dl_time": config.caida_snapshot,
                "cache_dir": cache_dir,
            },
            stubs=True,
        )
        topology_source = str(constructor.as_graph_collector.cache_path)
        retrieval_mode = "https_or_cache"
        selected_snapshot = config.caida_snapshot

    print(
        f"[+] Loading CAIDA snapshot {config.caida_snapshot:%Y-%m-%d} "
        f"for {config.event_id}"
    )
    as_graph = constructor.run()
    selected_snapshot = getattr(
        constructor.as_graph_collector,
        "selected_snapshot_date",
        selected_snapshot,
    )
    selected_serial = getattr(
        constructor.as_graph_collector,
        "selected_serial",
        "local_file" if caida_file is not None else "cache_unknown",
    )
    cache_source_marker_repairs = getattr(
        constructor.as_graph_collector,
        "cache_source_marker_repairs",
        0,
    )
    print(
        f"[+] CAIDA source: {selected_serial}, snapshot "
        f"{selected_snapshot:%Y-%m-%d}"
        if selected_snapshot is not None
        else f"[+] CAIDA source: {selected_serial}"
    )
    cycle_audit = getattr(
        constructor,
        "cycle_audit",
        {
            "method": "not_available",
            "removed_customer_provider_edge_count": None,
            "removed_customer_provider_edges": [],
            "source_topology_file_modified": False,
        },
    )
    overlay_audit = getattr(
        constructor,
        "overlay_audit",
        {
            "mode": topology_overlay_mode,
            "relationship_mode": overlay_relationship_mode,
            "requested_edge_count": len(requested_overlay_edges),
            "added_peer_edge_count": None,
            "added_peer_edges": [],
            "source_topology_file_modified": False,
        },
    )
    print(
        "[+] Cycle handling: removed "
        f"{cycle_audit['removed_customer_provider_edge_count']} "
        "customer-provider back edge(s) in memory"
    )
    if cache_source_marker_repairs:
        print(
            "[+] Repaired "
            f"{cache_source_marker_repairs} legacy serial-1 cache source marker(s)"
        )
    print(f"[+] Loaded {len(as_graph.as_dict):,} ASes")
    return as_graph, {
        "as_count": len(as_graph.as_dict),
        "caida_snapshot": config.caida_snapshot.strftime("%Y-%m-%d"),
        "requested_caida_snapshot": config.caida_snapshot.strftime("%Y-%m-%d"),
        "selected_caida_snapshot": (
            selected_snapshot.strftime("%Y-%m-%d")
            if selected_snapshot is not None
            else None
        ),
        "selected_caida_serial": selected_serial,
        "cache_source_marker_repairs": cache_source_marker_repairs,
        "retrieval_mode": retrieval_mode,
        "source_or_cache_path": topology_source,
        "cycle_handling": cycle_audit,
        "event_topology_overlay": overlay_audit,
    }


def relationship_enum(as_obj: Any, neighbor_asn: int) -> Any | None:
    from bgpy.shared.enums import Relationships

    relationship = relationship_name(as_obj, neighbor_asn)
    return {
        "provider": Relationships.PROVIDERS,
        "peer": Relationships.PEERS,
        "customer": Relationships.CUSTOMERS,
    }.get(relationship)


def build_announcements(
    config: EventConfig,
    resolved: dict[str, Any],
    as_graph: Any,
    *,
    legal_route_mode: LegalRouteMode = "after-observed",
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    from bgpy.shared.enums import Relationships, Timestamps
    from bgpy.simulation_engine import Announcement

    announcements: list[Any] = []
    audit: dict[str, Any] = {"announcements": [], "warnings": []}

    if legal_route_mode not in {"always", "after-observed", "withdrawn"}:
        raise ValueError(f"Unsupported legal route mode: {legal_route_mode}")

    def should_seed_legal(after_path_count: int) -> bool:
        if legal_route_mode == "always":
            return True
        if legal_route_mode == "withdrawn":
            return False
        return after_path_count > 0

    audit["legal_route_mode"] = legal_route_mode

    if config.anomaly_type == "hijack":
        assert config.victim_asn is not None
        victim_prefixes = sorted(
            set(
                resolved["hijack"]["victim_prefix_by_anomalous_prefix"].values()
            )
        )
        for prefix in victim_prefixes:
            availability = resolved["hijack"]["legal_origin_after_observation"]
            after_path_count = max(
                (
                    int(item["after_path_count"])
                    for item in availability.values()
                    if item["victim_prefix"] == prefix
                ),
                default=0,
            )
            if not should_seed_legal(after_path_count):
                audit["announcements"].append(
                    {
                        "prefix": prefix,
                        "seed_as": config.victim_asn,
                        "type": "legal_withdrawn_not_seeded",
                        "after_path_count": after_path_count,
                    }
                )
                continue
            announcement = Announcement(
                prefix=prefix,
                as_path=(config.victim_asn,),
                seed_asn=config.victim_asn,
                next_hop_asn=config.victim_asn,
                recv_relationship=Relationships.ORIGIN,
                timestamp=Timestamps.VICTIM.value,
            )
            announcements.append(announcement)
            audit["announcements"].append(
                {
                    "prefix": prefix,
                    "seed_as": config.victim_asn,
                    "type": "legal",
                    "after_path_count": after_path_count,
                }
            )

        for prefix in resolved["anomalous_prefixes"]:
            announcement = Announcement(
                prefix=prefix,
                as_path=(config.root_asn,),
                seed_asn=config.root_asn,
                next_hop_asn=config.root_asn,
                recv_relationship=Relationships.ORIGIN,
                timestamp=Timestamps.ATTACKER.value,
            )
            announcements.append(announcement)
            audit["announcements"].append(
                {"prefix": prefix, "seed_as": config.root_asn, "type": "hijack"}
            )

            anchor_relationship = {
                "customer": Relationships.CUSTOMERS,
                "peer": Relationships.PEERS,
                "provider": Relationships.PROVIDERS,
            }[EVENT_ANCHOR_RECV_RELATIONSHIP]
            for first_hop_asn in EVENT_ATTACK_FIRST_HOPS:
                if first_hop_asn not in as_graph.as_dict:
                    raise RuntimeError(
                        f"Event first-hop anchor AS{first_hop_asn} is absent "
                        "from the selected CAIDA graph"
                    )
                anchored = Announcement(
                    prefix=prefix,
                    # BGPy AS_PATH view at the anchored first-hop AS.
                    as_path=(first_hop_asn, config.root_asn),
                    seed_asn=first_hop_asn,
                    next_hop_asn=first_hop_asn,
                    # This encodes the observed local-preference outcome: the
                    # first hop selected AS203959 during the incident.
                    recv_relationship=anchor_relationship,
                    timestamp=Timestamps.ATTACKER.value,
                )
                announcements.append(anchored)
                audit["announcements"].append(
                    {
                        "prefix": prefix,
                        "seed_as": first_hop_asn,
                        "type": "event_observed_first_hop_anchor",
                        "as_path_view": [first_hop_asn, config.root_asn],
                        "received_relationship": (
                            EVENT_ANCHOR_RECV_RELATIONSHIP
                        ),
                        "calibration_note": (
                            "Encodes the observed fact that this AS selected "
                            "the AS203959 route; not an independent prediction."
                        ),
                    }
                )
    elif config.anomaly_type == "recovery":
        for prefix in resolved["anomalous_prefixes"]:
            announcement = Announcement(
                prefix=prefix,
                as_path=(config.root_asn,),
                seed_asn=config.root_asn,
                next_hop_asn=config.root_asn,
                recv_relationship=Relationships.ORIGIN,
                timestamp=Timestamps.ATTACKER.value,
            )
            announcements.append(announcement)
            audit["announcements"].append(
                {
                    "prefix": prefix,
                    "seed_as": config.root_asn,
                    "type": "recovered_legal_origin",
                    "replaced_origin_as": config.victim_asn,
                }
            )
    else:
        root_obj = as_graph.as_dict[config.root_asn]
        for prefix, details in sorted(resolved["route_leak"].items()):
            after_path_count = int(details.get("legal_origin_after_observation", 0))
            origin_as = int(details["origin_as"])
            if should_seed_legal(after_path_count):
                legal = Announcement(
                    prefix=prefix,
                    as_path=(origin_as,),
                    seed_asn=origin_as,
                    next_hop_asn=origin_as,
                    recv_relationship=Relationships.ORIGIN,
                    timestamp=Timestamps.VICTIM.value,
                )
                announcements.append(legal)
                audit["announcements"].append(
                    {
                        "prefix": prefix,
                        "seed_as": origin_as,
                        "type": "legal_origin",
                        "after_path_count": after_path_count,
                    }
                )
            else:
                audit["announcements"].append(
                    {
                        "prefix": prefix,
                        "seed_as": origin_as,
                        "type": "legal_origin_withdrawn_not_seeded",
                        "after_path_count": after_path_count,
                    }
                )
            anchor = tuple(int(asn) for asn in details["anchor_as_path_view"])
            origin_neighbor = int(details["origin_neighbor_as"])
            recv_relationship = relationship_enum(root_obj, origin_neighbor)
            relationship_source = "caida"
            if recv_relationship is None:
                # Keep the event replay executable when a historical CAIDA
                # snapshot omits the observed ingress link. The fallback is
                # explicit in the audit and must not be presented as CAIDA fact.
                recv_relationship = Relationships.PEERS
                relationship_source = "fallback_peer"
                audit["warnings"].append(
                    f"AS{origin_neighbor} is not adjacent to AS{config.root_asn} "
                    f"in CAIDA for {prefix}; recv_relationship defaults to peer."
                )

            announcement = Announcement(
                prefix=prefix,
                as_path=anchor,
                seed_asn=config.root_asn,
                next_hop_asn=config.root_asn,
                recv_relationship=recv_relationship,
                timestamp=Timestamps.ATTACKER.value,
            )
            announcements.append(announcement)
            audit["announcements"].append(
                {
                    "prefix": prefix,
                    "seed_as": config.root_asn,
                    "type": "route_leak_anchor",
                    "as_path_view": list(anchor),
                    "received_relationship": recv_relationship.name.lower(),
                    "relationship_source": relationship_source,
                }
            )

    return tuple(announcements), audit


def make_route_leak_policy(
    targets_by_prefix: dict[str, frozenset[int] | None] | None,
    target_relationships_by_prefix: dict[str, frozenset[Any] | None] | None,
) -> type[Any]:
    from bgpy.shared.enums import Relationships
    from bgpy.simulation_engine import BGPFullIgnoreInvalid

    class HistoricalRouteLeakPolicy(BGPFullIgnoreInvalid):
        name = "Historical Event-Constrained Route Leak"
        event_targets_by_prefix = targets_by_prefix
        event_target_relationships_by_prefix = target_relationships_by_prefix
        leakable_recv_relationships = {
            Relationships.ORIGIN,
            Relationships.CUSTOMERS,
            Relationships.PEERS,
            Relationships.PROVIDERS,
        }

        def propagate_to_providers(self) -> None:
            self._propagate(
                Relationships.PROVIDERS,
                self.leakable_recv_relationships,
            )

        def propagate_to_peers(self) -> None:
            self._propagate(
                Relationships.PEERS,
                self.leakable_recv_relationships,
            )

        def _policy_propagate(
            self,
            neighbor: Any,
            ann: Any,
            propagate_to: Any,
            send_rels: set[Any],
        ) -> bool:
            if propagate_to in {Relationships.PROVIDERS, Relationships.PEERS}:
                mapping = self.event_targets_by_prefix
                if mapping is not None:
                    targets = mapping.get(ann.prefix)
                    if targets is not None and neighbor.asn not in targets:
                        return True
                relationship_mapping = self.event_target_relationships_by_prefix
                if relationship_mapping is not None:
                    relationships = relationship_mapping.get(ann.prefix)
                    if relationships is not None and propagate_to not in relationships:
                        return True
            return False

    return HistoricalRouteLeakPolicy


def make_event_export_policy(
    *,
    root_asn: int,
    anomalous_prefixes: Iterable[str],
) -> type[Any]:
    """Build a BGP policy that follows the event-observed export tree.

    BGPy's normal Gao--Rexford eligibility check still runs first.  This hook
    only suppresses extra exports; it never manufactures an export that the
    relationship model disallows.  Consequently the explicit CP overrides
    above remain the auditable mechanism that makes every observed tree edge
    eligible.
    """

    from bgpy.simulation_engine import BGP

    class EventConstrainedExportPolicy(BGP):
        name = "20160221 Event-Constrained Export BGP"
        event_root_asn = int(root_asn)
        event_prefixes = frozenset(str(prefix) for prefix in anomalous_prefixes)
        event_export_targets = EVENT_EXPORT_TARGETS

        def _policy_propagate(
            self,
            neighbor: Any,
            ann: Any,
            propagate_to: Any,
            send_rels: set[Any],
        ) -> bool:
            # Normal/legal announcements must retain ordinary BGP export.
            if (
                ann.origin != self.event_root_asn
                or ann.prefix not in self.event_prefixes
            ):
                return False

            allowed_targets = self.event_export_targets.get(int(self.as_.asn))
            if allowed_targets is None:
                return False
            return int(neighbor.asn) not in allowed_targets

    return EventConstrainedExportPolicy


def validate_topology(
    config: EventConfig,
    resolved: dict[str, Any],
    as_graph: Any,
    topology_audit: dict[str, Any],
) -> None:
    required = {config.root_asn}
    if config.victim_asn is not None:
        required.add(config.victim_asn)
    required.update(EVENT_ATTACK_FIRST_HOPS)
    required.update(
        asn for relationship in EVENT_CP_OVERRIDES for asn in relationship
    )
    required.update(
        asn for relationship in EVENT_PEER_OVERRIDES for asn in relationship
    )
    required.update(EVENT_EXPORT_TARGETS)
    required.update(
        asn for targets in EVENT_EXPORT_TARGETS.values() for asn in targets
    )
    missing_required = sorted(required.difference(as_graph.as_dict))
    if missing_required:
        raise RuntimeError(
            f"Required event ASNs missing from CAIDA graph: {missing_required}"
        )

    relationship_verification: list[dict[str, Any]] = []
    relationship_errors: list[str] = []
    for customer, provider in sorted(EVENT_CP_OVERRIDES):
        customer_view = relationship_name(as_graph.as_dict[customer], provider)
        provider_view = relationship_name(as_graph.as_dict[provider], customer)
        verified = customer_view == "provider" and provider_view == "customer"
        relationship_verification.append(
            {
                "customer_as": customer,
                "provider_as": provider,
                "customer_view": customer_view,
                "provider_view": provider_view,
                "verified": verified,
            }
        )
        if not verified:
            relationship_errors.append(
                f"AS{customer}->AS{provider}: customer_view={customer_view}, "
                f"provider_view={provider_view}"
            )

    peer_verification: list[dict[str, Any]] = []
    for left, right in sorted(EVENT_PEER_OVERRIDES):
        left_view = relationship_name(as_graph.as_dict[left], right)
        right_view = relationship_name(as_graph.as_dict[right], left)
        verified = left_view == "peer" and right_view == "peer"
        peer_verification.append(
            {
                "as1": left,
                "as2": right,
                "as1_view": left_view,
                "as2_view": right_view,
                "verified": verified,
            }
        )
        if not verified:
            relationship_errors.append(
                f"AS{left}<->AS{right}: left_view={left_view}, "
                f"right_view={right_view}"
            )

    if relationship_errors:
        raise RuntimeError(
            "Event relationship overrides were not materialized in the AS graph: "
            + "; ".join(relationship_errors)
        )

    # The event export tree reconstructs every selected receiver branch.  In
    # receiver-holdout mode those branches are split between calibration and
    # evaluation records, so validate against their union rather than only the
    # evaluation subset.  This is intentionally an event-calibrated historical
    # reconstruction, not a holdout-independent prediction experiment.
    all_selected_event_paths = (
        list(resolved["observed_paths"])
        + list(resolved.get("calibration_paths", []))
    )
    observed_tree_edges = directed_edges(
        item["propagation_path"] for item in all_selected_event_paths
    )
    configured_tree_edges = {
        (int(exporter), int(target))
        for exporter, targets in EVENT_EXPORT_TARGETS.items()
        for target in targets
    }
    missing_export_constraints = sorted(
        observed_tree_edges.difference(configured_tree_edges)
    )
    extra_export_constraints = sorted(
        configured_tree_edges.difference(observed_tree_edges)
    )
    if missing_export_constraints or extra_export_constraints:
        raise RuntimeError(
            "Configured export tree does not match the selected RIB paths; "
            f"missing={missing_export_constraints}, extra={extra_export_constraints}"
        )

    topology_audit["root_as"] = config.root_asn
    topology_audit["event_relationship_verification"] = {
        "all_verified": True,
        "customer_provider": relationship_verification,
        "peer": peer_verification,
    }
    topology_audit["event_constraints"] = {
        "observed_first_hop_anchors": list(EVENT_ATTACK_FIRST_HOPS),
        "anchor_received_relationship": EVENT_ANCHOR_RECV_RELATIONSHIP,
        "customer_provider_overrides": [
            {"customer_as": customer, "provider_as": provider}
            for customer, provider in sorted(EVENT_CP_OVERRIDES)
        ],
        "peer_overrides": [
            {"as1": left, "as2": right}
            for left, right in sorted(EVENT_PEER_OVERRIDES)
        ],
        "export_targets": {
            str(asn): sorted(targets)
            for asn, targets in sorted(EVENT_EXPORT_TARGETS.items())
        },
        "export_filter_scope": (
            "only anomalous prefixes whose AS_PATH origin is the configured root AS"
        ),
        "observed_export_tree_verified": True,
        "observed_export_tree_path_sources": [
            "evaluation_receivers",
            "calibration_receivers",
        ],
        "observed_export_tree_edges": [
            {"src": src, "dst": dst} for src, dst in sorted(observed_tree_edges)
        ],
        "evaluation_scope": "event_calibrated_replay_not_independent_prediction",
    }
    if config.anomaly_type == "leak":
        root_obj = as_graph.as_dict[config.root_asn]
        relevant_neighbors: set[int] = set()
        for details in resolved["route_leak"].values():
            relevant_neighbors.add(int(details["origin_neighbor_as"]))
            relevant_neighbors.update(int(asn) for asn in details["event_leak_targets"])
        topology_audit["root_relationships"] = {
            str(asn): relationship_name(root_obj, asn)
            for asn in sorted(relevant_neighbors)
        }
        topology_audit["event_neighbors_missing_from_graph"] = sorted(
            relevant_neighbors.difference(as_graph.as_dict)
        )


def run_simulation(
    config: EventConfig,
    resolved: dict[str, Any],
    as_graph: Any,
    *,
    propagation_rounds: int,
    minimum_convergence_rounds: int,
    leak_target_mode: LeakTargetMode,
    legal_route_mode: LegalRouteMode,
) -> tuple[Any, Any, dict[str, Any]]:
    from bgpy.shared.enums import Relationships
    from bgpy.simulation_engine import BGP, SimulationEngine
    from bgpy.simulation_framework import Scenario, ScenarioConfig

    announcements, announcement_audit = build_announcements(
        config, resolved, as_graph, legal_route_mode=legal_route_mode
    )
    event_export_policy = make_event_export_policy(
        root_asn=config.root_asn,
        anomalous_prefixes=resolved["anomalous_prefixes"],
    )
    attacker_policy = None
    if config.anomaly_type == "leak":
        target_mapping = (
            {
                prefix: (
                    frozenset(int(asn) for asn in details["event_leak_targets"])
                    if details["event_target_constraint_available"]
                    else None
                )
                for prefix, details in resolved["route_leak"].items()
            }
            if leak_target_mode == "event"
            else None
        )
        relationship_mapping = None
        if leak_target_mode == "relationship":
            root_obj = as_graph.as_dict[config.root_asn]
            relationship_mapping = {}
            for prefix, details in resolved["route_leak"].items():
                observed_relationships = frozenset(
                    relationship
                    for target_asn in details["event_leak_targets"]
                    for relationship in [relationship_enum(root_obj, int(target_asn))]
                    if relationship is not None
                )
                # A route-leak violation is modeled on provider/peer exports.
                # If calibration only sees a customer (or an edge absent from
                # CAIDA), it provides no safe restriction for those exports;
                # unconstrained propagation is preferable to suppressing the
                # entire abnormal envelope.
                export_relationships = observed_relationships & frozenset(
                    {
                        Relationships.PROVIDERS,
                        Relationships.PEERS,
                    }
                )
                relationship_mapping[prefix] = export_relationships or None
        attacker_policy = make_route_leak_policy(
            target_mapping,
            relationship_mapping,
        )
    else:
        # The configured root AS must obey the same event export tree.  An
        # attacker policy has precedence over ordinary adopting-AS policies in
        # Scenario.get_policy_cls(), so assign it explicitly here.
        attacker_policy = event_export_policy

    if config.anomaly_type in {"hijack", "recovery"}:
        assert config.victim_asn is not None
        victim_asns = frozenset({config.victim_asn})
    else:
        victim_asns = frozenset(
            int(details["origin_as"])
            for details in resolved["route_leak"].values()
        )

    scenario_config = ScenarioConfig(
        ScenarioCls=Scenario,
        BasePolicyCls=BGP,
        AdoptPolicyCls=event_export_policy,
        AttackerBasePolicyCls=attacker_policy,
        propagation_rounds=propagation_rounds,
        num_attackers=1,
        num_victims=len(victim_asns),
        override_attacker_asns=frozenset({config.root_asn}),
        override_victim_asns=victim_asns,
        override_adopting_asns=frozenset(
            asn for asn in EVENT_EXPORT_TARGETS if asn != config.root_asn
        ),
        override_announcements=announcements,
    )
    engine = SimulationEngine(as_graph)
    scenario = Scenario(scenario_config=scenario_config, engine=engine)
    engine.setup(scenario)
    previous_state: tuple[Any, ...] | None = None
    converged = False
    rounds_executed = 0
    for propagation_round in range(propagation_rounds):
        print(f"[+] Running propagation round {propagation_round}")
        engine.run(propagation_round=propagation_round, scenario=scenario)
        rounds_executed = propagation_round + 1
        state: tuple[Any, ...] = tuple(
            sorted(
                (
                    int(asn),
                    prefix,
                    tuple(int(value) for value in ann.as_path),
                    int(ann.recv_relationship.value),
                )
                for asn, as_obj in engine.as_graph.as_dict.items()
                for prefix in resolved["anomalous_prefixes"]
                for ann in [as_obj.policy.local_rib.get(prefix)]
                if ann is not None
            )
        )
        if (
            previous_state is not None
            and state == previous_state
            and rounds_executed >= minimum_convergence_rounds
        ):
            converged = True
            print(f"[+] Routing state converged after {rounds_executed} round(s)")
            break
        previous_state = state

    announcement_audit["convergence"] = {
        "maximum_rounds": propagation_rounds,
        "minimum_rounds": minimum_convergence_rounds,
        "rounds_executed": rounds_executed,
        "converged_before_maximum": converged,
        "state_definition": "selected local-RIB path per AS and anomalous prefix",
    }
    announcement_audit["legal_route_mode"] = legal_route_mode
    announcement_audit["event_export_policy"] = {
        "enabled": True,
        "root_as": config.root_asn,
        "anomalous_prefixes": sorted(resolved["anomalous_prefixes"]),
        "targets_by_exporting_as": {
            str(asn): sorted(targets)
            for asn, targets in sorted(EVENT_EXPORT_TARGETS.items())
        },
        "scope": "root-origin anomalous announcements only",
        "normal_announcements_unchanged": True,
    }

    return engine, scenario, announcement_audit


def directed_edges(paths: Iterable[Sequence[int]]) -> set[tuple[int, int]]:
    return {
        (int(path[index]), int(path[index + 1]))
        for path in paths
        for index in range(len(path) - 1)
    }


def extract_simulation_paths(
    config: EventConfig,
    resolved: dict[str, Any],
    engine: Any,
    *,
    leak_target_mode: LeakTargetMode,
    path_source: PathSourceMode,
) -> dict[str, Any]:
    prefix_results: dict[str, Any] = {}

    for prefix in resolved["anomalous_prefixes"]:
        simulated_paths: list[dict[str, Any]] = []
        reachable_count = 0
        selected_root_count = 0
        leak_targets = (
            set(int(asn) for asn in resolved["route_leak"][prefix]["event_leak_targets"])
            if config.anomaly_type == "leak"
            else set()
        )
        leak_constraint_available = bool(leak_targets)
        root_obj = engine.as_graph.as_dict[config.root_asn]
        leak_target_relationships = {
            relationship_name(root_obj, target_asn)
            for target_asn in leak_targets
            if relationship_name(root_obj, target_asn) != "not-neighbor"
        }
        leak_target_relationships &= {"provider", "peer"}

        for receiver_asn, as_obj in sorted(engine.as_graph.as_dict.items()):
            if path_source == "local-rib":
                candidate_anns = [as_obj.policy.local_rib.get(prefix)]
            else:
                candidate_anns = [as_obj.policy.local_rib.get(prefix)]
                ribs_in = getattr(as_obj.policy, "ribs_in", None)
                if ribs_in is not None:
                    candidate_anns.extend(
                        ann_info.unprocessed_ann
                        for ann_info in ribs_in.get_ann_infos(prefix)
                    )
            candidates_seen: set[tuple[Any, ...]] = set()
            for ann in candidate_anns:
                if ann is None:
                    continue
                candidate_key = (
                    tuple(int(value) for value in ann.as_path),
                    bool(getattr(ann, "withdraw", False)),
                    int(getattr(ann, "origin", -1)),
                )
                if candidate_key in candidates_seen:
                    continue
                candidates_seen.add(candidate_key)
                reachable_count += 1
                full_path = list(reversed(ann.as_path))
                if config.root_asn not in full_path:
                    continue

                root_index = full_path.index(config.root_asn)
                propagation_path = full_path[root_index:]
                if not propagation_path or propagation_path[0] != config.root_asn:
                    continue
                if receiver_asn == config.root_asn:
                    continue

                selected_root_count += 1
                if config.anomaly_type in {"hijack", "recovery"}:
                    is_abnormal = ann.origin == config.root_asn
                    first_hop_allowed = True
                else:
                    first_hop = (
                        propagation_path[1] if len(propagation_path) > 1 else None
                    )
                    first_hop_allowed = (
                        first_hop in leak_targets
                        if leak_target_mode == "event" and leak_constraint_available
                        else (
                            relationship_name(root_obj, int(first_hop))
                            in leak_target_relationships
                            if leak_target_mode == "relationship"
                            and leak_constraint_available
                            and first_hop is not None
                            and leak_target_relationships
                            else True
                        )
                    )
                    is_abnormal = first_hop_allowed

                if not is_abnormal:
                    continue
                simulated_paths.append(
                    {
                        "prefix": prefix,
                        "receiver_as": receiver_asn,
                        "as_path_view": list(ann.as_path),
                        "full_propagation_path": full_path,
                        "anomalous_propagation_path": propagation_path,
                        "first_hop_after_root": (
                            propagation_path[1]
                            if len(propagation_path) > 1
                            else None
                        ),
                        "first_hop_allowed_by_event_constraint": first_hop_allowed,
                        "event_constraint_available": leak_constraint_available,
                        "path_source": path_source,
                    }
                )

        path_lists = [
            item["anomalous_propagation_path"] for item in simulated_paths
        ]
        nodes = {asn for path in path_lists for asn in path}
        edges = directed_edges(path_lists)
        prefix_results[prefix] = {
            "summary": {
                "reachable_as_count": reachable_count,
                "selected_route_via_root_count": selected_root_count,
                "anomalous_receiver_count": len(simulated_paths),
                "anomalous_node_count": len(nodes),
                "anomalous_edge_count": len(edges),
                "anomalous_first_hops": sorted(
                    {
                        path[1]
                        for path in path_lists
                        if len(path) > 1
                    }
                ),
            },
            "paths": simulated_paths,
            "nodes": sorted(nodes),
            "edges": [
                {"src": src, "dst": dst} for src, dst in sorted(edges)
            ],
        }

    root_advertisements: list[dict[str, Any]] = []
    if config.anomaly_type == "leak":
        root_obj = engine.as_graph.as_dict[config.root_asn]
        for prefix, details in sorted(resolved["route_leak"].items()):
            for neighbor_asn in details["event_leak_targets"]:
                advertised = root_obj.policy.ribs_out.get_ann(neighbor_asn, prefix)
                root_advertisements.append(
                    {
                        "prefix": prefix,
                        "neighbor_as": neighbor_asn,
                        "relationship": relationship_name(root_obj, neighbor_asn),
                        "advertised": advertised is not None,
                        "advertised_as_path": (
                            list(advertised.as_path) if advertised is not None else None
                        ),
                    }
                )

    return {
        "prefixes": prefix_results,
        "root_advertisements": root_advertisements,
        "leak_target_mode": (
            leak_target_mode if config.anomaly_type == "leak" else "not_applicable"
        ),
        "path_source": path_source,
        "path_selection": (
            "all_received_abnormal_candidates"
            if path_source == "received-envelope"
            else "final_local_rib_only"
        ),
    }


def lcs_length(left: Sequence[int], right: Sequence[int]) -> int:
    row = [0] * (len(right) + 1)
    for left_value in left:
        previous_diagonal = 0
        for index, right_value in enumerate(right, start=1):
            old_value = row[index]
            if left_value == right_value:
                row[index] = previous_diagonal + 1
            else:
                row[index] = max(row[index], row[index - 1])
            previous_diagonal = old_value
    return row[-1]


def path_similarity(left: Sequence[int], right: Sequence[int]) -> float:
    if not left or not right:
        return 0.0
    return lcs_length(left, right) / max(len(left), len(right))


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def compare_with_observed_paths(
    resolved: dict[str, Any],
    simulation: dict[str, Any],
) -> dict[str, Any]:
    sim_lookup: dict[tuple[str, int], list[list[int]]] = {}
    all_sim_paths: list[list[int]] = []
    for prefix, prefix_result in simulation["prefixes"].items():
        for item in prefix_result["paths"]:
            path = list(canonicalize_as_path(item["anomalous_propagation_path"]))
            sim_lookup.setdefault((prefix, int(item["receiver_as"])), []).append(path)
            all_sim_paths.append(path)

    observed_paths = resolved["observed_paths"]
    observed_receiver_keys = {
        (item["prefix"], int(item["receiver_as"])) for item in observed_paths
    }
    simulated_receiver_keys = set(sim_lookup)
    covered_receiver_keys = observed_receiver_keys & simulated_receiver_keys

    observed_path_lists = [item["propagation_path"] for item in observed_paths]
    observed_nodes = {asn for path in observed_path_lists for asn in path}
    simulated_nodes = {asn for path in all_sim_paths for asn in path}
    observed_edges = directed_edges(observed_path_lists)
    simulated_edges = directed_edges(all_sim_paths)
    observed_first_hops = {
        path[1] for path in observed_path_lists if len(path) > 1
    }
    simulated_first_hops = {
        path[1] for path in all_sim_paths if len(path) > 1
    }

    exact_matches = 0
    raw_exact_matches = 0
    covered_scores: list[float] = []
    all_scores: list[float] = []
    raw_covered_scores: list[float] = []
    raw_all_scores: list[float] = []
    details: list[dict[str, Any]] = []
    for observed in observed_paths:
        key = (observed["prefix"], int(observed["receiver_as"]))
        simulated_candidates = sim_lookup.get(key, [])
        normalized_observed_path = observed.get(
            "propagation_path_normalized", observed["propagation_path"]
        )
        raw_observed_path = observed.get(
            "propagation_path_raw", normalized_observed_path
        )
        scored_candidates = [
            (
                path_similarity(normalized_observed_path, candidate),
                path_similarity(raw_observed_path, candidate),
                candidate,
            )
            for candidate in simulated_candidates
        ]
        score, raw_score, simulated_path = (
            max(scored_candidates, key=lambda item: (item[0], item[1], item[2]))
            if scored_candidates
            else (0.0, 0.0, None)
        )
        all_scores.append(score)
        raw_all_scores.append(raw_score)
        if simulated_path is not None:
            covered_scores.append(score)
            raw_covered_scores.append(raw_score)
        is_exact = simulated_path == normalized_observed_path
        raw_is_exact = simulated_path == raw_observed_path
        exact_matches += int(is_exact)
        raw_exact_matches += int(raw_is_exact)
        details.append(
            {
                "prefix": observed["prefix"],
                "receiver_as": observed["receiver_as"],
                "observed_path": normalized_observed_path,
                "observed_path_normalized": normalized_observed_path,
                "observed_path_raw": raw_observed_path,
                "simulated_same_receiver_path": simulated_path,
                "simulated_candidate_count": len(simulated_candidates),
                "simulated_candidate_paths": simulated_candidates,
                "same_receiver_similarity": score,
                "normalized_same_receiver_similarity": score,
                "raw_same_receiver_similarity": raw_score,
                "exact_match": is_exact,
                "normalized_exact_match": is_exact,
                "raw_exact_match": raw_is_exact,
            }
        )

    receiver_coverage = ratio(
        len(covered_receiver_keys), len(observed_receiver_keys)
    )
    conditional_similarity = mean(covered_scores) if covered_scores else None
    coverage_adjusted_similarity = mean(all_scores) if all_scores else None
    raw_conditional_similarity = (
        mean(raw_covered_scores) if raw_covered_scores else None
    )
    raw_coverage_adjusted_similarity = mean(raw_all_scores) if raw_all_scores else None
    split_audit = resolved.get("validation_split", {})
    leak_calibration_overlap = (
        resolved["metadata"]["anomaly_type"] == "leak"
        and simulation.get("leak_target_mode") in {"event", "relationship"}
        and (
            split_audit.get("calibration_evaluation_overlap", True)
            or split_audit.get("leak_used_evaluation_fallback", False)
        )
        and any(
            details.get("event_target_constraint_available", False)
            for details in resolved.get("route_leak", {}).values()
        )
    )
    topology_calibration_overlap = (
        simulation.get("topology_overlay_mode") == "pre-rib-and-calibration"
        and split_audit.get("calibration_evaluation_overlap", True)
        and bool(
            resolved.get("topology_overlay_candidates", {}).get(
                "calibration_edges", []
            )
        )
    )
    quality_flags: list[str] = []
    if not observed_paths:
        quality_flags.append("comparison_unavailable")
    elif len(observed_receiver_keys) < 10:
        quality_flags.append("small_observed_path_sample")
    if receiver_coverage is not None and receiver_coverage < 0.8:
        quality_flags.append("low_observed_receiver_coverage")
    if leak_calibration_overlap:
        quality_flags.append("event_rib_used_for_leak_target_calibration")
    if topology_calibration_overlap:
        quality_flags.append("event_rib_used_for_topology_calibration")
    if EVENT_ATTACK_FIRST_HOPS:
        quality_flags.append("event_observed_first_hop_anchors_used")
    if EVENT_CP_OVERRIDES or EVENT_PEER_OVERRIDES:
        quality_flags.append("event_relationship_overrides_used")
    if EVENT_EXPORT_TARGETS:
        quality_flags.append("event_observed_export_tree_used")
        quality_flags.append("event_evaluation_paths_used_for_export_tree")
    if resolved.get("additional_post_event_origins"):
        quality_flags.append("additional_post_event_origin_not_simulated")
    if resolved.get("observation_selection", {}).get("mode") == "all-updates":
        quality_flags.append("transient_updates_mixed_in_static_comparison")
    orientation_audit = resolved.get("configuration_orientation_audit")
    if orientation_audit and not orientation_audit.get(
        "supported_by_origin_transition", False
    ):
        quality_flags.append("configured_origin_direction_not_supported_by_rib")

    return {
        "status": "available" if observed_paths else "unavailable",
        "available": bool(observed_paths),
        "unavailable_reason": (
            None
            if observed_paths
            else (
                "No anomalous path containing the configured root AS was "
                "observed in rib_after_incident.csv; similarity metrics are "
                "therefore null rather than zero."
            )
        ),
        "comparison": "bgpy_structural_replay_vs_real_rib_after",
        "path_direction": "root_as_to_receiver",
        "note": (
            "Observed paths are a sparse collector sample. Coverage metrics are "
            "valid, but simulation precision cannot be inferred from unobserved paths."
        ),
        "evaluation_quality": {
            "quality_flags": quality_flags,
            "recommended_primary_metric": (
                "similarity.mean_observed_path_similarity_including_uncovered"
            ),
            "reason": (
                "The conditional same-receiver mean excludes every uncovered "
                "observation and is unstable for small samples. The recommended "
                "metric assigns zero similarity to uncovered observed paths."
            ),
            "path_selection": simulation.get("path_selection", "unknown"),
            "event_rib_used_for_leak_target_calibration": leak_calibration_overlap,
            "event_rib_used_for_topology_calibration": topology_calibration_overlap,
            "event_observed_first_hop_anchors_used": bool(
                EVENT_ATTACK_FIRST_HOPS
            ),
            "event_relationship_overrides_used": bool(
                EVENT_CP_OVERRIDES or EVENT_PEER_OVERRIDES
            ),
            "event_observed_export_tree_used": bool(EVENT_EXPORT_TARGETS),
            "event_evaluation_paths_used_for_export_tree": bool(
                EVENT_EXPORT_TARGETS and observed_paths
            ),
            "additional_post_event_origins_not_simulated": resolved.get(
                "additional_post_event_origins", {}
            ),
            "evaluation_scope": (
                "event_calibrated_replay_not_independent_prediction"
                if EVENT_EXPORT_TARGETS
                else "receiver_holdout_or_all_observations"
            ),
            "validation_split": split_audit,
            "observation_selection": resolved.get("observation_selection", {}),
            "path_normalization": (
                "Consecutive prepends and RFC6996 private ASNs removed; raw score retained."
            ),
        },
        "counts": {
            "observed_unique_paths": len(observed_paths),
            "observed_receiver_prefix_pairs": len(observed_receiver_keys),
            "simulated_abnormal_receiver_prefix_pairs": len(simulated_receiver_keys),
            "covered_observed_receiver_prefix_pairs": len(covered_receiver_keys),
            "observed_nodes": len(observed_nodes),
            "simulated_nodes": len(simulated_nodes),
            "observed_edges": len(observed_edges),
            "simulated_edges": len(simulated_edges),
        },
        "coverage": {
            "observed_receiver_coverage": receiver_coverage,
            "observed_first_hop_coverage": ratio(
                len(observed_first_hops & simulated_first_hops),
                len(observed_first_hops),
            ),
            "observed_node_coverage": ratio(
                len(observed_nodes & simulated_nodes), len(observed_nodes)
            ),
            "observed_edge_coverage": ratio(
                len(observed_edges & simulated_edges), len(observed_edges)
            ),
            "exact_observed_path_match_rate": ratio(
                exact_matches, len(observed_paths)
            ),
            "raw_exact_observed_path_match_rate": ratio(
                raw_exact_matches, len(observed_paths)
            ),
        },
        "similarity": {
            "mean_same_receiver_path_similarity": conditional_similarity,
            "mean_observed_path_similarity_including_uncovered": (
                coverage_adjusted_similarity
            ),
            "normalized": {
                "mean_same_receiver_path_similarity": conditional_similarity,
                "mean_observed_path_similarity_including_uncovered": (
                    coverage_adjusted_similarity
                ),
            },
            "raw": {
                "mean_same_receiver_path_similarity": raw_conditional_similarity,
                "mean_observed_path_similarity_including_uncovered": (
                    raw_coverage_adjusted_similarity
                ),
            },
        },
        "matched": {
            "receiver_prefix_pairs": [
                {"prefix": prefix, "receiver_as": receiver}
                for prefix, receiver in sorted(covered_receiver_keys)
            ],
            "first_hops": sorted(observed_first_hops & simulated_first_hops),
            "nodes": sorted(observed_nodes & simulated_nodes),
            "edges": [
                {"src": src, "dst": dst}
                for src, dst in sorted(observed_edges & simulated_edges)
            ],
        },
        "path_details": details,
    }


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file_obj:
        json.dump(value, file_obj, indent=2, ensure_ascii=False)
        file_obj.write("\n")
    print(f"[+] Saved: {path}")


def build_arg_parser(config: EventConfig) -> argparse.ArgumentParser:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description=(
            f"Replay {config.event_name} ({config.event_id}) with historical BGPy."
        )
    )
    parser.add_argument(
        "--events-root",
        type=Path,
        default=default_events_root(),
        help=(
            "Directory containing event subdirectories. Defaults to "
            "$DUDATA_EVENTS_ROOT or ~/Desktop/dudata."
        ),
    )
    parser.add_argument(
        "--caida-file",
        type=Path,
        default=None,
        help=(
            "Local CAIDA serial-2 relationship file for this event snapshot. "
            "When omitted, BGPy downloads/caches the configured snapshot."
        ),
    )
    parser.add_argument(
        "--caida-cache-dir",
        type=Path,
        default=script_dir / "data" / "caida_cache",
        help="Shared cache directory for historical CAIDA relationship files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=script_dir / "results" / config.event_id,
        help="Directory for resolved inputs, complete paths, and comparison JSON.",
    )
    parser.add_argument(
        "--propagation-rounds",
        type=int,
        default=5,
        help=(
            "Maximum BGPy propagation rounds. The run stops early after the "
            "selected route state converges. Default: 5."
        ),
    )
    parser.add_argument(
        "--minimum-convergence-rounds",
        type=int,
        default=2,
        help="Do not stop for convergence before this many rounds. Default: 2.",
    )
    parser.add_argument(
        "--observation-mode",
        choices=("receiver-last", "peak", "final", "all-updates"),
        default="receiver-last",
        help=(
            "receiver-last compares one anomalous route per receiver/prefix and is "
            "the default structural envelope; peak/final reconstruct coherent states; "
            "all-updates retains the legacy transient-update comparison."
        ),
    )
    parser.add_argument(
        "--validation-mode",
        choices=("receiver-holdout", "all"),
        default="receiver-holdout",
        help=(
            "Use deterministic disjoint receiver calibration/evaluation sets when "
            "the sample is large enough. Default: receiver-holdout."
        ),
    )
    parser.add_argument(
        "--calibration-fraction",
        type=float,
        default=0.25,
        help="Calibration receiver fraction for held-out evaluation. Default: 0.25.",
    )
    parser.add_argument(
        "--minimum-holdout-pairs",
        type=int,
        default=10,
        help="Minimum receiver/prefix pairs required for a holdout split. Default: 10.",
    )
    parser.add_argument(
        "--topology-overlay-mode",
        choices=("none", "pre-rib", "pre-rib-and-calibration"),
        default="none",
        help=(
            "Add RIB-observed missing edges only to the per-event in-memory graph. "
            "The cached CAIDA topology is never modified. Default: none; the "
            "explicit audited event relationship overrides remain active."
        ),
    )
    parser.add_argument(
        "--overlay-relationship-mode",
        choices=("peer", "infer"),
        default="infer",
        help=(
            "Represent missing RIB-observed edges as peers, or infer safe "
            "customer-provider directions from valley-free path phases."
        ),
    )
    parser.add_argument(
        "--path-source",
        choices=("local-rib", "received-envelope"),
        default="local-rib",
        help=(
            "Extract only final local-RIB paths, or include abnormal candidates "
            "retained in every AS's RIBs-In. Default: local-rib."
        ),
    )
    parser.add_argument(
        "--leak-target-mode",
        choices=("event", "relationship", "all"),
        default="relationship",
        help=(
            "For route leaks, event restricts exports to exact calibration "
            "first hops; relationship generalizes to the same commercial "
            "neighbor classes; all exports to every provider and peer."
        ),
    )
    parser.add_argument(
        "--legal-route-mode",
        choices=("always", "after-observed", "withdrawn"),
        default="after-observed",
        help=(
            "Seed the legitimate origin route always, only when it remains in "
            "rib_after_incident.csv, or never. Default: after-observed. In this "
            "equal-prefix event AS12586 is absent after the incident, so the "
            "default historical-envelope run seeds only AS203959. Use always "
            "only for a separate counterfactual dual-origin experiment."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve and validate event inputs without loading BGPy or CAIDA.",
    )
    return parser


def run_cli(config: EventConfig) -> None:
    args = build_arg_parser(config).parse_args()
    if args.propagation_rounds < 1:
        raise ValueError("--propagation-rounds must be at least 1")
    if args.minimum_convergence_rounds < 1:
        raise ValueError("--minimum-convergence-rounds must be at least 1")
    if args.minimum_convergence_rounds > args.propagation_rounds:
        raise ValueError(
            "--minimum-convergence-rounds cannot exceed --propagation-rounds"
        )
    if not 0 < args.calibration_fraction < 1:
        raise ValueError("--calibration-fraction must be strictly between 0 and 1")
    if args.minimum_holdout_pairs < 2:
        raise ValueError("--minimum-holdout-pairs must be at least 2")

    events_root = args.events_root.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    resolved = resolve_event_inputs(
        config,
        events_root,
        observation_mode=args.observation_mode,
        validation_mode=args.validation_mode,
        calibration_fraction=args.calibration_fraction,
        minimum_holdout_pairs=args.minimum_holdout_pairs,
    )
    save_json(output_dir / "resolved_event_inputs.json", resolved)

    print(
        f"[+] Resolved {config.event_id}: "
        f"{len(resolved['anomalous_prefixes'])} anomalous prefix(es), "
        f"{len(resolved['observed_paths'])} unique observed path(s)"
    )
    if not resolved["observed_paths"]:
        print(
            "[!] No comparable post-event anomalous paths; simulation remains "
            "available but similarity metrics will be null"
        )
    if args.dry_run:
        print("[+] Dry run complete; BGPy simulation was not started")
        return

    as_graph, topology_audit = build_as_graph(
        config,
        resolved,
        caida_file=args.caida_file,
        caida_cache_dir=args.caida_cache_dir,
        topology_overlay_mode=args.topology_overlay_mode,
        overlay_relationship_mode=args.overlay_relationship_mode,
    )
    validate_topology(config, resolved, as_graph, topology_audit)
    engine, _scenario, announcement_audit = run_simulation(
        config,
        resolved,
        as_graph,
        propagation_rounds=args.propagation_rounds,
        minimum_convergence_rounds=args.minimum_convergence_rounds,
        leak_target_mode=args.leak_target_mode,
        legal_route_mode=args.legal_route_mode,
    )
    simulation = extract_simulation_paths(
        config,
        resolved,
        engine,
        leak_target_mode=args.leak_target_mode,
        path_source=args.path_source,
    )
    simulation["topology_overlay_mode"] = args.topology_overlay_mode
    simulation["overlay_relationship_mode"] = args.overlay_relationship_mode
    simulation["legal_route_mode"] = args.legal_route_mode
    simulation["path_source"] = args.path_source
    comparison = compare_with_observed_paths(resolved, simulation)
    victim_route_seeded = any(
        item.get("type") == "legal"
        for item in announcement_audit.get("announcements", [])
    )
    replay_state_model = (
        "counterfactual_equal_prefix_dual_origin_competition"
        if victim_route_seeded
        else "observed_post_hijack_attacker_origin_envelope"
    )
    comparison["evaluation_quality"]["replay_state_model"] = replay_state_model
    comparison["evaluation_quality"]["state_model_note"] = (
        "AS12586 originated 161.123.185.0/24 before the event but is absent "
        "from rib_after_incident.csv. The default after-observed mode therefore "
        "reconstructs the collected post-hijack AS203959 envelope. Setting "
        "--legal-route-mode always creates a counterfactual equal-prefix "
        "dual-origin competition and must be reported separately."
    )

    complete_result = {
        "metadata": {
            **resolved["metadata"],
            "experiment": "historical_bgpy_structural_replay",
            "propagation_rounds": args.propagation_rounds,
            "minimum_convergence_rounds": args.minimum_convergence_rounds,
            "observation_mode": args.observation_mode,
            "validation_mode": args.validation_mode,
            "calibration_fraction": args.calibration_fraction,
            "minimum_holdout_pairs": args.minimum_holdout_pairs,
            "topology_overlay_mode": args.topology_overlay_mode,
            "overlay_relationship_mode": args.overlay_relationship_mode,
            "leak_target_mode": (
                args.leak_target_mode
                if config.anomaly_type == "leak"
                else "not_applicable"
            ),
            "legal_route_mode": args.legal_route_mode,
            "replay_state_model": replay_state_model,
            "path_source": args.path_source,
            "event_constraint_mode": (
                "first_hop_anchors_relationship_overrides_and_export_tree"
            ),
            "event_attack_first_hops": list(EVENT_ATTACK_FIRST_HOPS),
            "event_anchor_received_relationship": (
                EVENT_ANCHOR_RECV_RELATIONSHIP
            ),
            "event_export_targets": {
                str(asn): sorted(targets)
                for asn, targets in sorted(EVENT_EXPORT_TARGETS.items())
            },
        },
        "resolved_event": resolved,
        "topology_audit": topology_audit,
        "announcement_audit": announcement_audit,
        "simulation": simulation,
    }
    propagation_paths = {
        "event_id": config.event_id,
        "event_name": config.event_name,
        "anomaly_type": config.anomaly_type,
        "root_as": config.root_asn,
        "prefixes": {
            prefix: {
                "nodes": result["nodes"],
                "edges": result["edges"],
                "paths": [
                    item["anomalous_propagation_path"]
                    for item in result["paths"]
                ],
            }
            for prefix, result in simulation["prefixes"].items()
        },
    }

    save_json(output_dir / "simulation_complete.json", complete_result)
    save_json(output_dir / "propagation_paths.json", propagation_paths)
    save_json(output_dir / "similarity_vs_real_rib.json", comparison)

    coverage = comparison["coverage"]
    similarity = comparison["similarity"]
    print("[+] Verification summary")
    print(f"    observed unique paths: {comparison['counts']['observed_unique_paths']}")
    print(f"    receiver coverage: {coverage['observed_receiver_coverage']}")
    print(f"    first-hop coverage: {coverage['observed_first_hop_coverage']}")
    print(f"    node coverage: {coverage['observed_node_coverage']}")
    print(
        "    conditional same-receiver similarity: "
        f"{similarity['mean_same_receiver_path_similarity']}"
    )
    print(
        "    primary coverage-adjusted similarity: "
        f"{similarity['mean_observed_path_similarity_including_uncovered']}"
    )
    print(
        "    evaluation quality flags: "
        f"{comparison['evaluation_quality']['quality_flags']}"
    )


# ---- event-local configuration (edit only this file for this event) ----
from datetime import datetime

CONFIG = EventConfig(
    event_id='20160221_1000',
    event_name='Hijack event 20160221_1000',
    anomaly_type='hijack',
    canonical_prefix='161.123.185.0/24',
    root_asn=203959,
    victim_asn=12586,
    caida_snapshot=datetime(2016, 2, 1),
)

if __name__ == "__main__":
    run_cli(CONFIG)
