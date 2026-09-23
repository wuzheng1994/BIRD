#!/usr/bin/env python3
"""Graded wrong-attribution experiments for audited BGP replays."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import importlib.util
import json
import math
import statistics
import subprocess
import sys
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from pathlib import Path
from typing import Any

try:
    from plot_misattribution_cdfs import (
        plot_cdf,
        plot_delta_c_cdf,
    )
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from plot_misattribution_cdfs import (
        plot_cdf,
        plot_delta_c_cdf,
    )


PRIMARY_METRIC = "mean_observed_path_similarity_including_uncovered"
ALGORITHM_VERSION = "graded-wrong-attribution-v2"
ERROR_DISTANCES = (1, 2, 3, 4, 5)
CATEGORY_ORDER = (
    "origin_hijack",
    "leak",
    "type1_hijack",
)
DEFAULT_TARGET_SAMPLES = 100
DEFAULT_MAX_CANDIDATES_PER_DISTANCE = 40

RELATIONSHIP_ATTRIBUTES = (
    ("providers", "provider"),
    ("peers", "peer"),
    ("customers", "customer"),
)


def event_category(scenario: dict[str, Any]) -> str | None:
    event_type = scenario.get("type")
    if event_type == "leak":
        return "leak"
    if event_type == "hijack":
        if scenario.get("forged_origin_as") is not None:
            return "type1_hijack"
        return "origin_hijack"
    return None


def eligible_event_ids(
    scenarios: dict[str, dict[str, Any]],
) -> list[str]:
    return [
        event_id
        for event_id, scenario in scenarios.items()
        if event_category(scenario) is not None
    ]


def variant_label(
    hypothesis: str,
    level: int,
    candidate_index: int = 0,
    variant: str = "case",
) -> str:
    suffix = "_cf" if variant == "counterfactual" else ""
    if hypothesis == "correct":
        return f"correct{suffix}"
    if hypothesis == "enumerate":
        return "enumerate"
    return f"wrong_d{level}_i{candidate_index}{suffix}"


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(value, file, indent=2, sort_keys=True)


def json_digest(value: Any) -> str:
    data = json.dumps(
        value, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def asn_of(value: Any) -> int:
    return int(getattr(value, "asn", value))


def graph_neighbors(as_graph: Any, asn: int) -> dict[int, str]:
    as_obj = as_graph.as_dict[int(asn)]
    result: dict[int, str] = {}
    for attribute, label in RELATIONSHIP_ATTRIBUTES:
        for neighbor in getattr(as_obj, attribute, ()):
            result[asn_of(neighbor)] = label
    return result


def relationship(
    as_graph: Any,
    local_asn: int,
    neighbor_asn: int,
) -> str | None:
    if int(local_asn) not in as_graph.as_dict:
        return None
    return graph_neighbors(as_graph, int(local_asn)).get(int(neighbor_asn))


def graph_degree(as_graph: Any, asn: int) -> int:
    return len(graph_neighbors(as_graph, int(asn)))


def graph_distances(
    as_graph: Any,
    sources: list[int],
    maximum: int | None = None,
) -> dict[int, int]:
    distances: dict[int, int] = {}
    queue: deque[int] = deque()

    for source in sorted(set(int(value) for value in sources)):
        if source in as_graph.as_dict:
            distances[source] = 0
            queue.append(source)

    while queue:
        current = queue.popleft()
        current_distance = distances[current]

        if maximum is not None and current_distance >= maximum:
            continue

        for neighbor in sorted(graph_neighbors(as_graph, current)):
            if neighbor not in distances:
                distances[neighbor] = current_distance + 1
                queue.append(neighbor)

    return distances


def valley_free_states(
    as_graph: Any,
    origin_asn: int,
) -> tuple[
    dict[tuple[int, int], tuple[int, int] | None],
    dict[int, list[tuple[int, int]]],
]:
    """Find Gao-Rexford paths from an origin to all reachable ASes.

    Phase 0: customer-to-provider uphill segment.
    Phase 1: optional peer edge has been traversed.
    Phase 2: provider-to-customer downhill segment.
    """

    start = (int(origin_asn), 0)
    predecessor: dict[
        tuple[int, int], tuple[int, int] | None
    ] = {start: None}
    states_by_asn: dict[int, list[tuple[int, int]]] = defaultdict(list)
    states_by_asn[int(origin_asn)].append(start)
    queue: deque[tuple[int, int]] = deque([start])

    while queue:
        current_asn, phase = queue.popleft()

        for neighbor, relation in sorted(
            graph_neighbors(as_graph, current_asn).items()
        ):
            next_phase: int | None = None

            if relation == "provider" and phase == 0:
                next_phase = 0
            elif relation == "peer" and phase == 0:
                next_phase = 1
            elif relation == "customer":
                next_phase = 2

            if next_phase is None:
                continue

            state = (neighbor, next_phase)
            if state in predecessor:
                continue

            predecessor[state] = (current_asn, phase)
            states_by_asn[neighbor].append(state)
            queue.append(state)

    return predecessor, states_by_asn


def reconstruct_path(
    predecessor: dict[
        tuple[int, int], tuple[int, int] | None
    ],
    state: tuple[int, int],
) -> list[int]:
    path: list[int] = []
    current: tuple[int, int] | None = state

    while current is not None:
        path.append(int(current[0]))
        current = predecessor[current]

    path.reverse()
    return path


def best_false_leak_anchor(
    as_graph: Any,
    candidate_asn: int,
    predecessor: dict[
        tuple[int, int], tuple[int, int] | None
    ],
    candidate_states: list[tuple[int, int]],
) -> tuple[list[int], str] | None:
    choices = []

    for state in candidate_states:
        path = reconstruct_path(predecessor, state)

        if len(path) < 2:
            continue
        if len(path) != len(set(path)):
            continue

        learned_from = path[-2]
        ingress_relationship = relationship(
            as_graph, candidate_asn, learned_from
        )

        # A leak counterfactual must first learn a route from a
        # provider or peer, then export it to another provider/peer.
        if ingress_relationship not in {"provider", "peer"}:
            continue

        anchor_nodes = set(path)
        illegal_targets = [
            neighbor
            for neighbor, relation in graph_neighbors(
                as_graph, candidate_asn
            ).items()
            if relation in {"provider", "peer"}
            and neighbor not in anchor_nodes
        ]

        if not illegal_targets:
            continue

        choices.append(
            (
                len(path),
                tuple(path),
                path,
                ingress_relationship,
                sorted(illegal_targets),
            )
        )

    if not choices:
        return None

    _length, _key, path, ingress, targets = sorted(choices)[0]
    return path, ingress, targets


def candidate_rank(
    event_id: str,
    level: int,
    root_degree: int,
    candidate_asn: int,
    candidate_degree: int,
) -> tuple[float, bytes, int]:
    # Match network role first; SHA-256 gives a deterministic tie-break.
    degree_difference = abs(
        math.log1p(candidate_degree) - math.log1p(root_degree)
    )
    digest = hashlib.sha256(
        (
            f"{event_id}|wrong-attribution|"
            f"{level}|{candidate_asn}"
        ).encode("utf-8")
    ).digest()
    return degree_difference, digest, candidate_asn


def leak_tree_asns(
    scenario: dict[str, Any],
    resolved: dict[str, Any],
) -> set[int]:
    """ASes already on the true leak, so they are not false roots."""

    excluded: set[int] = set()
    for path in scenario.get("anchor_paths", []):
        excluded.update(int(asn) for asn in path)
    for targets in scenario.get("targets_by_prefix", {}).values():
        excluded.update(int(asn) for asn in targets)
    for stage in scenario.get("secondary_exports", []):
        excluded.add(int(stage["exporter"]))
        learned_from = stage.get("learned_from")
        if learned_from is not None:
            excluded.add(int(learned_from))
        excluded.update(int(asn) for asn in stage.get("targets", []))
    for details in resolved.get("route_leak", {}).values():
        for key in ("leak_as", "origin_neighbor_as"):
            value = details.get(key)
            if value is not None:
                excluded.add(int(value))
        for target in details.get("event_leak_targets", []):
            excluded.add(int(target))
    for item in resolved.get("observed_paths", []):
        hops = item.get("propagation_path_normalized")
        if hops is None:
            hops = item.get("propagation_path")
        if not isinstance(hops, list):
            continue
        for hop in hops:
            try:
                excluded.add(int(hop))
            except (TypeError, ValueError):
                continue
    return excluded


def leak_targets_for_candidate(
    event_id: str,
    level: int,
    resolved: dict[str, Any],
    target_candidates: dict[str, list[int]],
) -> dict[str, list[int]]:
    targets_by_prefix: dict[str, list[int]] = {}
    for prefix, details in resolved["route_leak"].items():
        origin = str(int(details["origin_as"]))
        targets = target_candidates[origin]
        target = min(
            targets,
            key=lambda asn: (
                hashlib.sha256(
                    (
                        f"{event_id}|{level}|"
                        f"{prefix}|{asn}"
                    ).encode("utf-8")
                ).digest(),
                asn,
            ),
        )
        targets_by_prefix[prefix] = [target]
    return targets_by_prefix


def list_wrong_candidates(
    as_graph: Any,
    resolved: dict[str, Any],
    scenario: dict[str, Any],
    event_id: str,
    level: int,
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    true_root = int(scenario["root_as"])
    category = event_category(scenario) or scenario["type"]
    distances = graph_distances(
        as_graph, [true_root], maximum=level
    )

    excluded = {true_root}
    if scenario.get("victim_as") is not None:
        excluded.add(int(scenario["victim_as"]))

    origins = sorted({
        int(details["origin_as"])
        for details in resolved.get("route_leak", {}).values()
    })
    excluded.update(origins)
    true_tree: set[int] = set()
    if scenario["type"] == "leak":
        true_tree = leak_tree_asns(scenario, resolved)
        excluded.update(true_tree)

    candidates = [
        asn for asn, distance in distances.items()
        if distance == level and asn not in excluded
    ]
    root_degree = graph_degree(as_graph, true_root)
    plans: list[dict[str, Any]] = []

    if scenario["type"] == "hijack":
        ranked = sorted(
            candidates,
            key=lambda asn: candidate_rank(
                event_id,
                level,
                root_degree,
                asn,
                graph_degree(as_graph, asn),
            ),
        )
        if limit is not None:
            ranked = ranked[:limit]
        for index, selected in enumerate(ranked):
            plans.append({
                "algorithm": ALGORITHM_VERSION,
                "event_id": event_id,
                "event_type": scenario["type"],
                "event_category": category,
                "candidate_index": index,
                "true_root_as": true_root,
                "hypothesis_root_as": selected,
                "requested_distance": level,
                "actual_distance": distances[selected],
                "true_root_degree": root_degree,
                "hypothesis_root_degree": graph_degree(
                    as_graph, selected
                ),
                "selection_data": "historical_caida_topology_only",
            })
        return plans

    valley_data = {
        origin: valley_free_states(as_graph, origin)
        for origin in origins
    }
    viable = []

    for candidate in candidates:
        anchors = {}
        ingress_relationships = {}
        target_candidates = {}
        valid = True

        for origin in origins:
            predecessor, states_by_asn = valley_data[origin]
            result = best_false_leak_anchor(
                as_graph,
                candidate,
                predecessor,
                states_by_asn.get(candidate, []),
            )

            if result is None:
                valid = False
                break

            path, ingress, targets = result
            off_tree = [
                target for target in targets
                if target not in true_tree
            ]
            if not off_tree:
                valid = False
                break

            anchors[str(origin)] = list(reversed(path))
            ingress_relationships[str(origin)] = ingress
            target_candidates[str(origin)] = off_tree

        if not valid:
            continue

        if len(set(ingress_relationships.values())) != 1:
            continue

        viable.append((
            candidate_rank(
                event_id,
                level,
                root_degree,
                candidate,
                graph_degree(as_graph, candidate),
            ),
            candidate,
            anchors,
            ingress_relationships,
            target_candidates,
        ))

    viable.sort(key=lambda item: item[0])
    if limit is not None:
        viable = viable[:limit]

    for index, item in enumerate(viable):
        (
            _rank,
            selected,
            anchors,
            ingress_relationships,
            target_candidates,
        ) = item
        plans.append({
            "algorithm": ALGORITHM_VERSION,
            "event_id": event_id,
            "event_type": "leak",
            "event_category": category,
            "candidate_index": index,
            "true_root_as": true_root,
            "hypothesis_root_as": selected,
            "requested_distance": level,
            "actual_distance": distances[selected],
            "true_root_degree": root_degree,
            "hypothesis_root_degree": graph_degree(
                as_graph, selected
            ),
            "anchor_by_origin": anchors,
            "ingress_relationship_by_origin": (
                ingress_relationships
            ),
            "targets_by_prefix": leak_targets_for_candidate(
                event_id,
                level,
                resolved,
                target_candidates,
            ),
            "selection_data": (
                "historical_caida_topology_and_calibration_origin"
            ),
            "gao_rexford_violation_required": True,
        })
    return plans


def select_wrong_candidate(
    as_graph: Any,
    resolved: dict[str, Any],
    scenario: dict[str, Any],
    event_id: str,
    level: int,
    candidate_index: int = 0,
) -> dict[str, Any]:
    plans = list_wrong_candidates(
        as_graph,
        resolved,
        scenario,
        event_id,
        level,
    )
    if candidate_index >= len(plans):
        raise RuntimeError(
            "No candidate at topology distance "
            f"{level} index {candidate_index}"
        )
    plan = plans[candidate_index]
    if int(plan["actual_distance"]) != level:
        raise RuntimeError("Candidate distance audit failed")
    return plan


def calibration_leak_targets(
    as_graph: Any,
    resolved: dict[str, Any],
    root_asn: int,
) -> tuple[
    dict[str, frozenset[int]],
    dict[str, Any],
]:
    event_id = str(
        resolved.get("metadata", {}).get("event_id", "unknown")
    )
    accepted_by_prefix: dict[str, set[int]] = {}
    rejected_by_prefix: dict[str, list[dict[str, Any]]] = {}
    prefix_origins: dict[str, int] = {}
    pools_by_origin: dict[int, set[int]] = defaultdict(set)

    for prefix, details in sorted(
        resolved["route_leak"].items()
    ):
        origin = int(details["origin_as"])
        prefix_origins[prefix] = origin
        accepted: set[int] = set()
        rejected = []

        for target in sorted({
            int(value)
            for value in details.get("event_leak_targets", [])
        }):
            target_relationship = relationship(
                as_graph, root_asn, target
            )
            if target_relationship in {"provider", "peer"}:
                accepted.add(target)
                pools_by_origin[origin].add(target)
            else:
                rejected.append({
                    "target_as": target,
                    "caida_relationship": target_relationship,
                    "reason": "not_provider_or_peer_in_caida",
                })

        accepted_by_prefix[prefix] = accepted
        rejected_by_prefix[prefix] = rejected

    mapping: dict[str, frozenset[int]] = {}
    fallback_prefixes = []

    for prefix, details in sorted(
        resolved["route_leak"].items()
    ):
        accepted = accepted_by_prefix[prefix]

        if accepted:
            mapping[prefix] = frozenset(accepted)
            continue

        origin = prefix_origins[prefix]
        fallback_pool = pools_by_origin.get(origin, set())

        if not fallback_pool:
            raise RuntimeError(
                "No calibration-only provider/peer leak target "
                f"is available for origin AS{origin}; "
                f"prefix={prefix}, rejected="
                f"{rejected_by_prefix[prefix]}"
            )

        requested_count = max(
            1,
            len(details.get("event_leak_targets", [])),
        )
        ranked = sorted(
            fallback_pool,
            key=lambda target: (
                hashlib.sha256(
                    (
                        f"{event_id}|cross-prefix-calibration|"
                        f"{prefix}|{target}"
                    ).encode("utf-8")
                ).digest(),
                target,
            ),
        )
        selected = ranked[
            :min(requested_count, len(ranked))
        ]
        mapping[prefix] = frozenset(selected)
        fallback_prefixes.append({
            "prefix": prefix,
            "origin_as": origin,
            "original_calibration_targets": sorted({
                int(value)
                for value in details.get(
                    "event_leak_targets", []
                )
            }),
            "selected_fallback_targets": selected,
            "candidate_pool": sorted(fallback_pool),
            "rejected_targets": rejected_by_prefix[prefix],
            "fallback_scope": (
                "same_event_same_origin_calibration_prefixes"
            ),
        })

    audit = {
        "source": "calibration_partition_only",
        "evaluation_paths_used": False,
        "accepted_targets_by_prefix": {
            prefix: sorted(targets)
            for prefix, targets in accepted_by_prefix.items()
        },
        "rejected_targets_by_prefix": rejected_by_prefix,
        "effective_targets_by_prefix": {
            prefix: sorted(targets)
            for prefix, targets in mapping.items()
        },
        "cross_prefix_fallback_used": bool(fallback_prefixes),
        "fallback_prefixes": fallback_prefixes,
    }
    return mapping, audit

def install_correct_leak_policy(
    module: Any,
    native_policy_factory: Any,
    state: dict[str, Any],
) -> None:
    original_run = module.run_simulation

    def run_simulation(
        config: Any,
        resolved: dict[str, Any],
        as_graph: Any,
        **kwargs: Any,
    ) -> Any:
        target_mapping, target_audit = calibration_leak_targets(
            as_graph,
            resolved,
            int(config.root_asn),
        )
        module.make_route_leak_policy = (
            lambda _targets, _relationships:
            native_policy_factory(target_mapping, None)
        )
        state["candidate_plan"] = {
            "algorithm": ALGORITHM_VERSION,
            "event_type": "leak",
            "true_root_as": int(config.root_asn),
            "hypothesis_root_as": int(config.root_asn),
            "requested_distance": 0,
            "actual_distance": 0,
            "calibration_targets": {
                prefix: sorted(targets)
                for prefix, targets in target_mapping.items()
            },
            "calibration_target_audit": target_audit,
        }
        return original_run(
            config, resolved, as_graph, **kwargs
        )

    module.run_simulation = run_simulation


def install_wrong_source(
    module: Any,
    native_policy_factory: Any,
    scenario: dict[str, Any],
    event_id: str,
    level: int,
    state: dict[str, Any],
    candidate_index: int = 0,
    *,
    counterfactual: bool = False,
    install_valley_free: Any = None,
) -> None:
    original_build = module.build_as_graph
    original_run = module.run_simulation
    original_extract = module.extract_simulation_paths

    def build_as_graph(
        config: Any,
        resolved: dict[str, Any],
        **kwargs: Any,
    ) -> Any:
        as_graph, audit = original_build(
            config, resolved, **kwargs
        )
        plan = select_wrong_candidate(
            as_graph,
            resolved,
            scenario,
            event_id,
            level,
            candidate_index,
        )
        state["candidate_plan"] = plan
        audit["wrong_attribution_candidate"] = plan
        return as_graph, audit

    def run_simulation(
        config: Any,
        resolved: dict[str, Any],
        as_graph: Any,
        **kwargs: Any,
    ) -> Any:
        plan = state["candidate_plan"]
        candidate = int(plan["hypothesis_root_as"])
        false_config = replace(
            config, root_asn=candidate
        )
        adjusted = copy.deepcopy(resolved)

        if scenario["type"] == "leak":
            ingress_values = set()

            for prefix, details in adjusted[
                "route_leak"
            ].items():
                origin = str(int(details["origin_as"]))
                anchor = plan["anchor_by_origin"][origin]
                ingress = plan[
                    "ingress_relationship_by_origin"
                ][origin]
                ingress_values.add(ingress)

                details["leak_as"] = candidate
                details["anchor_as_path_view"] = anchor
                details["origin_neighbor_as"] = int(
                    anchor[1]
                )
                details["anchor_source"] = (
                    "caida_valley_free_false_hypothesis"
                )
                details["event_leak_targets"] = (
                    plan["targets_by_prefix"][prefix]
                )

            if len(ingress_values) != 1:
                raise RuntimeError(
                    "Replay module supports one leak ingress "
                    f"relationship, got {ingress_values}"
                )

            module.EVENT_ANCHOR_RECV_RELATIONSHIP = (
                next(iter(ingress_values))
            )
            if counterfactual and install_valley_free is not None:
                install_valley_free(module)
            else:
                target_mapping = {
                    prefix: frozenset(targets)
                    for prefix, targets
                    in plan["targets_by_prefix"].items()
                }
                module.make_route_leak_policy = (
                    lambda _targets, _relationships:
                    native_policy_factory(
                        target_mapping, None
                    )
                )

        state["false_config"] = false_config
        state["adjusted_resolved"] = adjusted

        return original_run(
            false_config,
            adjusted,
            as_graph,
            **kwargs,
        )

    def extract_simulation_paths(
        _config: Any,
        _resolved: dict[str, Any],
        engine: Any,
        **kwargs: Any,
    ) -> Any:
        return original_extract(
            state["false_config"],
            state["adjusted_resolved"],
            engine,
            **kwargs,
        )

    module.build_as_graph = build_as_graph
    module.run_simulation = run_simulation
    module.extract_simulation_paths = (
        extract_simulation_paths
    )


def evaluation_digest(output_dir: Path) -> str | None:
    path = output_dir / "resolved_event_inputs.json"
    if not path.exists():
        return None

    resolved = load_json(path)
    return json_digest({
        "observed_paths": resolved.get(
            "observed_paths", []
        ),
        "validation_split": resolved.get(
            "validation_split", {}
        ),
        "observation_selection": resolved.get(
            "observation_selection", {}
        ),
    })


def validate_output(
    output_dir: Path,
    expected_root: int,
    *,
    counterfactual: bool = False,
) -> dict[str, Any]:
    resolved = load_json(
        output_dir / "resolved_event_inputs.json"
    )
    split = resolved["validation_split"]

    if split.get("effective_mode") != (
        "receiver-holdout"
    ):
        raise RuntimeError(
            "Receiver holdout was not formed"
        )
    if split.get(
        "calibration_evaluation_overlap"
    ) is not False:
        raise RuntimeError(
            "Calibration/evaluation overlap detected"
        )

    complete = load_json(
        output_dir / "simulation_complete.json"
    )
    simulation = complete.get("simulation", {})

    if simulation.get(
        "topology_overlay_mode"
    ) != "none":
        raise RuntimeError(
            "RIB topology overlay is enabled"
        )
    if simulation.get(
        "legal_route_mode"
    ) != "withdrawn":
        raise RuntimeError(
            "Another legal route was injected"
        )

    if not counterfactual:
        unexpected = []
        for item in complete.get(
            "announcement_audit", {}
        ).get("announcements", []):
            if "not_seeded" in str(
                item.get("type", "")
            ):
                continue
            seed = item.get("seed_as")
            if (
                seed is not None
                and int(seed) != expected_root
            ):
                unexpected.append(item)

        if unexpected:
            raise RuntimeError(
                "Unexpected route seeds: "
                f"{unexpected[:3]}"
            )

    return {
        "calibration_pairs": split.get(
            "calibration_pair_count"
        ),
        "evaluation_pairs": split.get(
            "evaluation_pair_count"
        ),
        "evaluation_digest": (
            evaluation_digest(output_dir)
        ),
    }


def annotate_outputs(
    output_dir: Path,
    annotation: dict[str, Any],
) -> None:
    for filename in (
        "simulation_complete.json",
        "propagation_paths.json",
        "similarity_vs_real_rib.json",
    ):
        path = output_dir / filename
        document = load_json(path)
        document["misattribution_replay"] = annotation

        if filename == "similarity_vs_real_rib.json":
            quality = document.setdefault(
                "evaluation_quality", {}
            )
            flags = quality.setdefault(
                "quality_flags", []
            )
            for flag in annotation["quality_flags"]:
                if flag not in flags:
                    flags.append(flag)

        save_json(path, document)


def option_value(
    arguments: list[str],
    option: str,
    default: str | None = None,
) -> str | None:
    try:
        index = arguments.index(option)
    except ValueError:
        return default
    if index + 1 >= len(arguments):
        return default
    return arguments[index + 1]


def summarize_candidate(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_index": plan["candidate_index"],
        "hypothesis_root_as": plan["hypothesis_root_as"],
        "actual_distance": plan["actual_distance"],
        "hypothesis_root_degree": plan.get(
            "hypothesis_root_degree"
        ),
    }


def enumerate_event(
    args: argparse.Namespace,
    replay_arguments: list[str],
    causal: Any,
    scenario: dict[str, Any],
    module: Any,
) -> int:
    for option, value in {
        "--topology-overlay-mode": "none",
        "--legal-route-mode": "withdrawn",
        "--path-source": "local-rib",
        "--observation-mode": "receiver-last",
        "--validation-mode": "receiver-holdout",
        "--calibration-fraction": "0.25",
        "--minimum-holdout-pairs": "10",
    }.items():
        causal.set_option(replay_arguments, option, value)

    source = args.replay_script.resolve().read_text(
        encoding="utf-8"
    )
    causal.disable_event_helpers(replay_arguments, source)
    causal.configure_module(module, scenario, "case")

    parsed = module.build_arg_parser(
        module.CONFIG
    ).parse_args(replay_arguments)
    output_dir = parsed.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    category = event_category(scenario)
    document: dict[str, Any] = {
        "algorithm": ALGORITHM_VERSION,
        "event_id": args.event_id,
        "event_category": category,
        "run_signature": args.run_signature,
        "holdout_ok": True,
        "skip_reason": None,
        "by_distance": {
            str(level): []
            for level in ERROR_DISTANCES
        },
    }

    resolved = module.resolve_event_inputs(
        module.CONFIG,
        parsed.events_root.expanduser().resolve(),
        observation_mode=parsed.observation_mode,
        validation_mode=parsed.validation_mode,
        calibration_fraction=parsed.calibration_fraction,
        minimum_holdout_pairs=parsed.minimum_holdout_pairs,
    )
    save_json(
        output_dir / "resolved_event_inputs.json",
        resolved,
    )

    split = resolved.get("validation_split", {})
    if split.get("effective_mode") != "receiver-holdout":
        document["holdout_ok"] = False
        document["skip_reason"] = (
            "receiver_holdout_unavailable"
        )
        save_json(
            output_dir / "wrong_candidates.json",
            document,
        )
        print(
            f"[!] {args.event_id}: skipped, "
            "receiver holdout unavailable"
        )
        return 0

    as_graph, topology_audit = module.build_as_graph(
        module.CONFIG,
        resolved,
        caida_file=parsed.caida_file,
        caida_cache_dir=parsed.caida_cache_dir,
        topology_overlay_mode=parsed.topology_overlay_mode,
        overlay_relationship_mode=(
            parsed.overlay_relationship_mode
        ),
    )
    if hasattr(module, "validate_topology"):
        module.validate_topology(
            module.CONFIG,
            resolved,
            as_graph,
            topology_audit,
        )

    for level in ERROR_DISTANCES:
        plans = list_wrong_candidates(
            as_graph,
            resolved,
            scenario,
            args.event_id,
            level,
            limit=args.max_candidates_per_distance,
        )
        document["by_distance"][str(level)] = [
            summarize_candidate(plan)
            for plan in plans
        ]

    save_json(
        output_dir / "wrong_candidates.json",
        document,
    )
    counts = {
        level: len(values)
        for level, values in document[
            "by_distance"
        ].items()
    }
    print(
        f"[+] {args.event_id}: enumerated "
        f"candidates {counts}"
    )
    return 0


def worker_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--worker", action="store_true"
    )
    parser.add_argument(
        "--enumerate", action="store_true"
    )
    parser.add_argument("--event-id", required=True)
    parser.add_argument(
        "--hypothesis",
        choices=("correct", "wrong", "enumerate"),
        default="correct",
    )
    parser.add_argument(
        "--error-level", type=int, default=0
    )
    parser.add_argument(
        "--candidate-index", type=int, default=0
    )
    parser.add_argument(
        "--max-candidates-per-distance",
        type=int,
        default=DEFAULT_MAX_CANDIDATES_PER_DISTANCE,
    )
    parser.add_argument(
        "--replay-script",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--causal-driver",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--run-signature", required=True
    )
    parser.add_argument(
        "--variant",
        choices=("case", "counterfactual"),
        default="case",
    )
    args, replay_arguments = (
        parser.parse_known_args(argv)
    )

    causal = load_module(
        args.causal_driver.resolve(),
        (
            f"causal_{args.event_id}_"
            f"{args.hypothesis}_{args.error_level}_"
            f"{args.candidate_index}_{args.variant}"
        ),
    )
    scenario = causal.SCENARIOS[args.event_id]
    script = args.replay_script.resolve()
    module = causal.import_replay(script)

    if args.enumerate or args.hypothesis == "enumerate":
        return enumerate_event(
            args,
            replay_arguments,
            causal,
            scenario,
            module,
        )

    native_policy_factory = getattr(
        module, "make_route_leak_policy", None
    )
    is_counterfactual = args.variant == "counterfactual"
    causal.configure_module(
        module,
        scenario,
        (
            "counterfactual"
            if args.hypothesis == "correct" and is_counterfactual
            else "case"
        ),
    )

    state: dict[str, Any] = {}
    category = event_category(scenario)
    correct_plan = {
        "algorithm": ALGORITHM_VERSION,
        "event_type": scenario["type"],
        "event_category": category,
        "true_root_as": scenario["root_as"],
        "hypothesis_root_as": scenario["root_as"],
        "requested_distance": 0,
        "actual_distance": 0,
        "candidate_index": 0,
    }

    if args.hypothesis == "wrong":
        if hasattr(module, "EVENT_EXPORT_TARGETS"):
            module.EVENT_EXPORT_TARGETS = {}
        if hasattr(module, "EVENT_FORCE_EXPORT_TREE"):
            module.EVENT_FORCE_EXPORT_TREE = False

        install_wrong_source(
            module,
            native_policy_factory,
            scenario,
            args.event_id,
            args.error_level,
            state,
            args.candidate_index,
            counterfactual=is_counterfactual,
            install_valley_free=(
                causal.install_valley_free_policy
                if is_counterfactual
                else None
            ),
        )
        if is_counterfactual and scenario["type"] != "leak":
            causal.install_origin_removal(module)
    elif is_counterfactual:
        state["candidate_plan"] = correct_plan
    elif scenario["type"] == "leak":
        install_correct_leak_policy(
            module,
            native_policy_factory,
            state,
        )
    else:
        state["candidate_plan"] = correct_plan

    enforced = {
        "--topology-overlay-mode": "none",
        "--legal-route-mode": "withdrawn",
        "--path-source": "local-rib",
        "--observation-mode": "receiver-last",
        "--validation-mode": "receiver-holdout",
        "--calibration-fraction": "0.25",
        "--minimum-holdout-pairs": "10",
    }
    for option, value in enforced.items():
        causal.set_option(
            replay_arguments, option, value
        )

    source = script.read_text(encoding="utf-8")
    causal.disable_event_helpers(
        replay_arguments, source
    )

    output_index = replay_arguments.index(
        "--output-dir"
    )
    output_dir = Path(
        replay_arguments[output_index + 1]
    ).resolve()

    sys.argv = [script.name, *replay_arguments]
    module.run_cli(module.CONFIG)

    plan = state["candidate_plan"]
    plan.setdefault("event_category", category)
    plan.setdefault(
        "candidate_index", args.candidate_index
    )
    audit = validate_output(
        output_dir,
        int(plan["hypothesis_root_as"]),
        counterfactual=is_counterfactual,
    )

    quality_flags = [
        "misattribution_discrimination_experiment",
        "receiver_holdout_evaluation",
        "no_other_legal_route_injected",
    ]
    if is_counterfactual:
        quality_flags.append(
            "counterfactual_undo_hypothesized_cause"
        )

    if args.hypothesis == "correct":
        quality_flags.append("correct_attribution")

        if scenario["type"] == "leak":
            target_audit = plan.get(
                "calibration_target_audit", {}
            )
            if target_audit.get(
                "cross_prefix_fallback_used", False
            ):
                quality_flags.append(
                    "cross_prefix_calibration_target_fallback"
                )
    else:
        quality_flags.extend([
            "false_source_attribution",
            (
                "false_source_topology_distance_"
                f"{args.error_level}"
            ),
            f"false_source_candidate_index_{args.candidate_index}",
        ])

        if scenario["type"] == "leak":
            quality_flags.append(
                "false_leak_scope_is_generous_upper_bound"
            )

    annotation = {
        "algorithm": ALGORITHM_VERSION,
        "event_id": args.event_id,
        "event_category": category,
        "hypothesis": args.hypothesis,
        "variant": args.variant,
        "error_level": args.error_level,
        "candidate_index": args.candidate_index,
        "run_signature": args.run_signature,
        "candidate_plan": plan,
        "paired_input_audit": audit,
        "quality_flags": quality_flags,
    }
    annotate_outputs(output_dir, annotation)
    save_json(
        output_dir / "candidate_plan.json",
        annotation,
    )
    return 0


def read_result(output_dir: Path) -> dict[str, Any]:
    similarity_path = (
        output_dir / "similarity_vs_real_rib.json"
    )
    plan_path = output_dir / "candidate_plan.json"

    if not similarity_path.exists():
        return {
            "score": None,
            "digest": None,
            "error": "missing similarity output",
        }

    document = load_json(similarity_path)
    annotation = load_json(plan_path)
    score = document.get(
        "similarity", {}
    ).get(PRIMARY_METRIC)

    return {
        "score": score,
        "digest": evaluation_digest(output_dir),
        "plan": annotation["candidate_plan"],
        "quality_flags": document.get(
            "evaluation_quality", {}
        ).get("quality_flags", []),
    }


def run_signature(
    driver: Path,
    causal_driver: Path,
    replay_script: Path,
    event_id: str,
    hypothesis: str,
    level: int,
    arguments: list[str],
    candidate_index: int = 0,
    variant: str = "case",
) -> str:
    payload = {
        "algorithm": ALGORITHM_VERSION,
        "driver": hashlib.sha256(
            driver.read_bytes()
        ).hexdigest(),
        "causal_driver": hashlib.sha256(
            causal_driver.read_bytes()
        ).hexdigest(),
        "replay": hashlib.sha256(
            replay_script.read_bytes()
        ).hexdigest(),
        "event_id": event_id,
        "hypothesis": hypothesis,
        "level": level,
        "candidate_index": candidate_index,
        "arguments": arguments,
    }
    if variant == "counterfactual":
        payload["variant"] = "counterfactual"
    return json_digest(payload)


def replay_arguments_for(
    args: argparse.Namespace,
    output_dir: Path,
) -> list[str]:
    replay_arguments = [
        "--events-root",
        str(args.events_root.resolve()),
        "--output-dir",
        str(output_dir),
        "--observation-mode",
        "receiver-last",
        "--validation-mode",
        "receiver-holdout",
        "--calibration-fraction",
        "0.25",
        "--minimum-holdout-pairs",
        "10",
        "--topology-overlay-mode",
        "none",
        "--legal-route-mode",
        "withdrawn",
        "--path-source",
        "local-rib",
        "--leak-target-mode",
        "event",
    ]
    if args.caida_cache_dir:
        replay_arguments.extend([
            "--caida-cache-dir",
            str(args.caida_cache_dir.resolve()),
        ])
    if args.caida_file:
        replay_arguments.extend([
            "--caida-file",
            str(args.caida_file.resolve()),
        ])
    return replay_arguments


def build_worker_job(
    args: argparse.Namespace,
    event_id: str,
    hypothesis: str,
    level: int = 0,
    candidate_index: int = 0,
    *,
    variant: str = "case",
    enumerate_only: bool = False,
) -> dict[str, Any]:
    script = (
        args.scripts_dir.resolve()
        / f"replay_{event_id}.py"
    )
    causal_driver = args.causal_driver.resolve()
    label = (
        "enumerate"
        if enumerate_only
        else variant_label(
            hypothesis, level, candidate_index, variant
        )
    )
    output_dir = (
        args.output_root.resolve() / event_id
        if enumerate_only
        else args.output_root.resolve() / event_id / label
    )
    replay_arguments = replay_arguments_for(
        args, output_dir
    )
    causal = load_module(
        causal_driver,
        f"parent_causal_{event_id}_{label}",
    )
    causal.disable_event_helpers(
        replay_arguments,
        script.read_text(encoding="utf-8"),
    )
    signature = run_signature(
        Path(__file__).resolve(),
        causal_driver,
        script,
        event_id,
        "enumerate" if enumerate_only else hypothesis,
        level,
        replay_arguments,
        candidate_index,
        variant,
    )
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        "--event-id",
        event_id,
        "--hypothesis",
        "enumerate" if enumerate_only else hypothesis,
        "--error-level",
        str(level),
        "--candidate-index",
        str(candidate_index),
        "--max-candidates-per-distance",
        str(args.max_candidates_per_distance),
        "--replay-script",
        str(script),
        "--causal-driver",
        str(causal_driver),
        "--run-signature",
        signature,
        "--variant",
        variant,
        *replay_arguments,
    ]
    if enumerate_only:
        command.insert(command.index("--worker") + 1, "--enumerate")
    return {
        "event_id": event_id,
        "hypothesis": hypothesis,
        "variant": variant,
        "level": level,
        "candidate_index": candidate_index,
        "label": label,
        "output_dir": output_dir,
        "script": script,
        "signature": signature,
        "command": command,
        "enumerate_only": enumerate_only,
    }


def execute_job(
    args: argparse.Namespace,
    job: dict[str, Any],
) -> dict[str, Any]:
    output_dir: Path = job["output_dir"]
    label = job["label"]
    event_id = job["event_id"]
    print(f"[+] {event_id}: {label}")

    if args.dry_run:
        print("    " + " ".join(job["command"]))
        return {
            "score": None,
            "digest": None,
            "job": job,
        }

    complete_name = (
        "wrong_candidates.json"
        if job["enumerate_only"]
        else "simulation_complete.json"
    )
    complete_path = output_dir / complete_name
    reusable = False
    if args.reuse and complete_path.exists():
        variant = job.get("variant", "case")
        if job["enumerate_only"] or variant == "case":
            reusable = existing_outputs_reusable(
                job, output_dir, complete_path
            )
        else:
            annotation = load_json(
                complete_path
            ).get("misattribution_replay", {})
            reusable = (
                annotation.get("run_signature")
                == job["signature"]
            )

    if not reusable:
        output_dir.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            job["command"],
            cwd=job["script"].parent,
            text=True,
            capture_output=True,
            check=False,
        )
        (output_dir / "run.log").write_text(
            completed.stdout
            + "\n"
            + completed.stderr,
            encoding="utf-8",
        )
        if completed.returncode:
            message = (
                completed.stderr
                or completed.stdout
                or "unknown worker failure"
            )[-8000:]
            raise RuntimeError(
                f"{event_id}/{label} failed:\n"
                f"{message}"
            )

    if job["enumerate_only"]:
        return {
            "document": load_json(
                output_dir / "wrong_candidates.json"
            ),
            "job": job,
        }
    result = read_result(output_dir)
    result["job"] = job
    return result


def existing_outputs_reusable(
    job: dict[str, Any],
    output_dir: Path,
    complete_path: Path,
) -> bool:
    if job["enumerate_only"]:
        return True
    similarity = output_dir / "similarity_vs_real_rib.json"
    plan = output_dir / "candidate_plan.json"
    if not similarity.exists() or not plan.exists():
        return False
    annotation = load_json(complete_path).get(
        "misattribution_replay", {}
    )
    expected_variant = job.get("variant", "case")
    recorded_variant = annotation.get("variant")
    if expected_variant == "case":
        if recorded_variant not in (None, "case"):
            return False
    elif recorded_variant != expected_variant:
        return False
    return (
        annotation.get("event_id") == job["event_id"]
        and annotation.get("hypothesis") == job["hypothesis"]
        and int(annotation.get("error_level", -1))
        == int(job["level"])
        and int(annotation.get("candidate_index", 0))
        == int(job["candidate_index"])
    )


def run_variant(
    args: argparse.Namespace,
    event_id: str,
    hypothesis: str,
    level: int,
    candidate_index: int = 0,
    variant: str = "case",
) -> dict[str, Any]:
    job = build_worker_job(
        args,
        event_id,
        hypothesis,
        level,
        candidate_index,
        variant=variant,
    )
    return execute_job(args, job)


def run_jobs(
    args: argparse.Namespace,
    jobs: list[dict[str, Any]],
    *,
    fail_fast: bool,
) -> list[tuple[dict[str, Any], dict[str, Any] | None, str | None]]:
    outcomes: list[
        tuple[dict[str, Any], dict[str, Any] | None, str | None]
    ] = []

    def run_one(
        job: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any] | None, str | None]:
        try:
            return job, execute_job(args, job), None
        except Exception as exc:
            if fail_fast:
                raise
            return job, None, str(exc)[-500:]

    if args.jobs <= 1 or args.dry_run:
        for job in jobs:
            outcomes.append(run_one(job))
        return outcomes

    ordered: list[
        tuple[dict[str, Any], dict[str, Any] | None, str | None] | None
    ] = [None] * len(jobs)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {
            pool.submit(run_one, job): index
            for index, job in enumerate(jobs)
        }
        for future in as_completed(futures):
            ordered[futures[future]] = future.result()
    return [item for item in ordered if item is not None]


def allocate_quota(
    pools: dict[str, dict[str, list[dict[str, Any]]]],
    target: int,
) -> list[dict[str, Any]]:
    events = sorted(pools)
    selected: list[dict[str, Any]] = []
    index = 0
    while len(selected) < target:
        added = False
        for level in ERROR_DISTANCES:
            for event_id in events:
                pool = pools[event_id].get(
                    str(level), []
                )
                if index >= len(pool):
                    continue
                candidate = pool[index]
                selected.append({
                    "event_id": event_id,
                    "error_level": level,
                    "candidate_index": int(
                        candidate["candidate_index"]
                    ),
                    "hypothesis_root_as": int(
                        candidate["hypothesis_root_as"]
                    ),
                    "actual_distance": int(
                        candidate["actual_distance"]
                    ),
                })
                added = True
                if len(selected) >= target:
                    return selected
        if not added:
            break
        index += 1
    return selected


def mean_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    return statistics.mean(values)


def median_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    return statistics.median(values)


def roc_auc(
    correct: list[float],
    wrong: list[float],
) -> float:
    wins = 0.0
    for correct_score in correct:
        for wrong_score in wrong:
            if correct_score > wrong_score:
                wins += 1.0
            elif correct_score == wrong_score:
                wins += 0.5
    return wins / (len(correct) * len(wrong))


def threshold_metrics(
    correct: list[float],
    wrong: list[float],
    threshold: float,
) -> dict[str, float]:
    tp = sum(value >= threshold for value in correct)
    fp = sum(value >= threshold for value in wrong)
    tpr = tp / len(correct)
    fpr = fp / len(wrong)
    tnr = 1.0 - fpr

    return {
        "threshold": threshold,
        "tpr": tpr,
        "fpr": fpr,
        "tnr": tnr,
        "youden_j": tpr - fpr,
        "balanced_accuracy": (tpr + tnr) / 2,
    }


def choose_threshold(
    correct: list[float],
    wrong: list[float],
) -> dict[str, float]:
    values = sorted(set(correct + wrong))
    candidates = [values[0] - 1e-12]
    candidates.extend(
        (left + right) / 2
        for left, right
        in zip(values, values[1:])
    )
    candidates.append(values[-1] + 1e-12)

    metrics = [
        threshold_metrics(
            correct, wrong, threshold
        )
        for threshold in candidates
    ]
    return max(
        metrics,
        key=lambda item: (
            item["youden_j"],
            item["balanced_accuracy"],
            item["threshold"],
        ),
    )


def leave_one_event_out(
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    events = sorted({
        row["event_id"] for row in rows
    })
    folds = []
    true_positives = 0
    false_positives = 0
    wrong_count = 0

    for held_out in events:
        training = [
            row for row in rows
            if row["event_id"] != held_out
        ]
        testing = [
            row for row in rows
            if row["event_id"] == held_out
        ]

        train_correct = [
            row["score"] for row in training
            if row["label"] == "correct"
        ]
        train_wrong = [
            row["score"] for row in training
            if row["label"] == "wrong"
        ]
        test_correct = [
            row["score"] for row in testing
            if row["label"] == "correct"
        ]
        if not train_correct or not train_wrong or not test_correct:
            continue

        threshold = choose_threshold(
            train_correct,
            train_wrong,
        )["threshold"]

        correct_score = test_correct[0]
        wrong_scores = [
            row["score"] for row in testing
            if row["label"] == "wrong"
        ]

        correct_prediction = (
            correct_score >= threshold
        )
        fold_false_positives = sum(
            score >= threshold
            for score in wrong_scores
        )

        true_positives += int(
            correct_prediction
        )
        false_positives += (
            fold_false_positives
        )
        wrong_count += len(wrong_scores)

        folds.append({
            "event_id": held_out,
            "threshold": threshold,
            "correct_score": correct_score,
            "correct_classified": (
                correct_prediction
            ),
            "wrong_false_positives": (
                fold_false_positives
            ),
        })

    tpr = true_positives / len(folds) if folds else None
    fpr = (
        false_positives / wrong_count
        if wrong_count
        else None
    )

    return {
        "folds": folds,
        "tpr": tpr,
        "fpr": fpr,
        "balanced_accuracy": (
            None
            if tpr is None or fpr is None
            else (tpr + 1.0 - fpr) / 2
        ),
        "median_threshold": (
            None
            if not folds
            else statistics.median(
                fold["threshold"] for fold in folds
            )
        ),
    }


def write_cdf(
    rows: list[dict[str, Any]],
    path: Path,
) -> None:
    groups: dict[str, list[float]] = {
        "correct": sorted(
            row["score"] for row in rows
            if row["label"] == "correct"
        ),
        "wrong": sorted(
            row["score"] for row in rows
            if row["label"] == "wrong"
        ),
    }

    output = []
    for group, values in groups.items():
        for index, value in enumerate(
            values, start=1
        ):
            output.append({
                "group": group,
                "score": value,
                "cdf": index / len(values),
                "sample_count": len(values),
            })

    with path.open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=(
                "group",
                "score",
                "cdf",
                "sample_count",
            ),
        )
        writer.writeheader()
        writer.writerows(output)


def write_delta_c_csv(
    rows: list[dict[str, Any]],
    path: Path,
) -> None:
    fields = (
        "event_id",
        "event_category",
        "error_level",
        "candidate_index",
        "true_root_as",
        "hypothesis_root_as",
        "topology_distance",
        "case_m",
        "counterfactual_m",
        "delta_c",
    )
    scored_rows = [
        row for row in rows
        if row.get("delta_c") is not None
    ]
    with path.open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=fields
        )
        writer.writeheader()
        for row in scored_rows:
            writer.writerow({
                "event_id": row["event_id"],
                "event_category": row[
                    "event_category"
                ],
                "error_level": row["error_level"],
                "candidate_index": row[
                    "candidate_index"
                ],
                "true_root_as": row["true_root_as"],
                "hypothesis_root_as": row[
                    "hypothesis_root_as"
                ],
                "topology_distance": row[
                    "topology_distance"
                ],
                "case_m": row.get("case_m", row.get("score")),
                "counterfactual_m": row.get(
                    "counterfactual_m"
                ),
                "delta_c": row["delta_c"],
            })


def summarize_rows(
    rows: list[dict[str, Any]],
    event_ids: list[str],
    skipped_events: list[dict[str, Any]],
    target: int,
    args: argparse.Namespace,
) -> dict[str, Any]:
    correct_scores = [
        row["score"] for row in rows
        if row["label"] == "correct"
    ]
    wrong_scores = [
        row["score"] for row in rows
        if row["label"] == "wrong"
    ]
    deltas = [
        float(row["delta_c"])
        for row in rows
        if row["label"] == "wrong"
        and row.get("delta_c") is not None
    ]
    correct_deltas = [
        float(row["delta_c"])
        for row in rows
        if row["label"] == "correct"
        and row.get("delta_c") is not None
    ]
    threshold = None
    if correct_scores and wrong_scores:
        threshold = choose_threshold(
            correct_scores, wrong_scores
        )

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["event_id"]].append(row)

    per_event = []
    for event_id, event_rows in sorted(grouped.items()):
        correct_row = next(
            (
                row for row in event_rows
                if row["label"] == "correct"
            ),
            None,
        )
        wrong_event_rows = [
            row for row in event_rows
            if row["label"] == "wrong"
        ]
        wrong_event_scores = [
            row["score"] for row in wrong_event_rows
        ]
        per_event.append({
            "event_id": event_id,
            "event_category": (
                correct_row or wrong_event_rows[0]
            )["event_category"],
            "correct_score": (
                None if correct_row is None
                else correct_row["score"]
            ),
            "wrong_sample_count": len(wrong_event_rows),
            "correct_delta_c": (
                None if correct_row is None
                else correct_row.get("delta_c")
            ),
            "mean_delta_c": mean_or_none([
                float(row["delta_c"])
                for row in wrong_event_rows
                if row.get("delta_c") is not None
            ]),
            "correct_above_all_wrong": (
                correct_row is not None
                and wrong_event_scores
                and correct_row["score"]
                > max(wrong_event_scores)
            ),
        })

    per_type: dict[str, Any] = {}
    for category in CATEGORY_ORDER:
        type_correct = [
            row["score"] for row in rows
            if row["event_category"] == category
            and row["label"] == "correct"
        ]
        type_wrong = [
            row for row in rows
            if row["event_category"] == category
            and row["label"] == "wrong"
        ]
        type_deltas = [
            float(row["delta_c"])
            for row in type_wrong
            if row.get("delta_c") is not None
        ]
        type_correct_deltas = [
            float(row["delta_c"])
            for row in rows
            if row["event_category"] == category
            and row["label"] == "correct"
            and row.get("delta_c") is not None
        ]
        by_distance = {
            "0": {
                "n": len(type_correct_deltas),
                "mean_delta_c": mean_or_none(
                    type_correct_deltas
                ),
                "median_delta_c": median_or_none(
                    type_correct_deltas
                ),
            }
        }
        for level in ERROR_DISTANCES:
            level_deltas = [
                float(row["delta_c"])
                for row in type_wrong
                if row["error_level"] == level
                and row.get("delta_c") is not None
            ]
            by_distance[str(level)] = {
                "n": len(level_deltas),
                "mean_delta_c": mean_or_none(level_deltas),
                "median_delta_c": median_or_none(
                    level_deltas
                ),
            }
        type_wrong_scores = [
            row["score"] for row in type_wrong
        ]
        per_type[category] = {
            "n_events": len({
                row["event_id"] for row in rows
                if row["event_category"] == category
            }),
            "n_wrong_samples": len(type_wrong),
            "n_correct_samples": len(type_correct),
            "mean_delta_c_correct": mean_or_none(
                type_correct_deltas
            ),
            "target_samples": target,
            "mean_correct_m": mean_or_none(type_correct),
            "mean_wrong_m": mean_or_none(type_wrong_scores),
            "mean_delta_c": mean_or_none(type_deltas),
            "median_delta_c": median_or_none(type_deltas),
            "mean_gap": (
                None
                if not type_correct or not type_wrong_scores
                else statistics.mean(type_correct)
                - statistics.mean(type_wrong_scores)
            ),
            "roc_auc": (
                None
                if not type_correct or not type_wrong_scores
                else roc_auc(type_correct, type_wrong_scores)
            ),
            "by_distance": by_distance,
        }

    ranking_items = [
        item for item in per_event
        if item["wrong_sample_count"]
        and item["correct_score"] is not None
    ]
    return {
        "algorithm": ALGORITHM_VERSION,
        "primary_metric": PRIMARY_METRIC,
        "delta_definition": "M_case(H) - M_counterfactual(H)",
        "correct_delta_c_count": len(correct_deltas),
        "event_count": len(event_ids),
        "correct_score_count": len(correct_scores),
        "wrong_score_count": len(wrong_scores),
        "selected_events": event_ids,
        "skipped_events": skipped_events,
        "configuration": {
            "wrong_distances": list(ERROR_DISTANCES),
            "target_samples_per_type": target,
            "max_candidates_per_distance": (
                args.max_candidates_per_distance
            ),
            "jobs": args.jobs,
            "observation_mode": "receiver-last",
            "validation_mode": "receiver-holdout",
            "calibration_fraction": 0.25,
            "topology_overlay": False,
            "other_legal_routes": False,
            "candidate_tie_break": (
                "degree-role match then SHA-256"
            ),
        },
        "overall": {
            "mean_correct_m": mean_or_none(correct_scores),
            "mean_wrong_m": mean_or_none(wrong_scores),
            "mean_delta_c": mean_or_none(deltas),
            "median_delta_c": median_or_none(deltas),
            "mean_delta_c_correct": mean_or_none(correct_deltas),
            "median_delta_c_correct": median_or_none(
                correct_deltas
            ),
            "mean_gap": (
                None
                if not correct_scores or not wrong_scores
                else statistics.mean(correct_scores)
                - statistics.mean(wrong_scores)
            ),
            "median_correct_m": median_or_none(
                correct_scores
            ),
            "median_wrong_m": median_or_none(wrong_scores),
            "roc_auc": (
                None
                if not correct_scores or not wrong_scores
                else roc_auc(correct_scores, wrong_scores)
            ),
        },
        "exploratory_threshold": threshold,
        "leave_one_event_out": (
            leave_one_event_out(rows)
            if correct_scores and wrong_scores
            and grouped
            else None
        ),
        "per_type": per_type,
        "per_event": per_event,
        "ranking": {
            "correct_above_all_wrong_fraction": (
                mean_or_none([
                    float(item["correct_above_all_wrong"])
                    for item in ranking_items
                ])
            ),
        },
    }


def parent_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--scripts-dir",
        type=Path,
        default=Path("."),
    )
    parser.add_argument(
        "--events-root",
        type=Path,
        default=Path("dudata"),
    )
    parser.add_argument(
        "--causal-driver",
        type=Path,
        default=Path("run_causal_replays.py"),
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("results_misattribution"),
    )
    parser.add_argument("--caida-cache-dir", type=Path)
    parser.add_argument("--caida-file", type=Path)
    parser.add_argument(
        "--event",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--target-samples-per-type",
        type=int,
        default=DEFAULT_TARGET_SAMPLES,
    )
    parser.add_argument(
        "--max-candidates-per-distance",
        type=int,
        default=DEFAULT_MAX_CANDIDATES_PER_DISTANCE,
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
    )
    parser.add_argument("--reuse", action="store_true")
    parser.add_argument(
        "--fail-fast", action="store_true"
    )
    parser.add_argument(
        "--dry-run", action="store_true"
    )
    args = parser.parse_args(argv)

    causal = load_module(
        args.causal_driver.resolve(),
        "misattribution_parent_causal",
    )
    if args.event:
        event_ids = list(args.event)
    else:
        event_ids = eligible_event_ids(causal.SCENARIOS)

    for event_id in event_ids:
        if event_id not in causal.SCENARIOS:
            raise ValueError(f"Unknown event: {event_id}")
        if event_category(causal.SCENARIOS[event_id]) is None:
            raise ValueError(
                f"{event_id} is not origin hijack, "
                "leak, or type-1 hijack"
            )

    args.output_root.mkdir(parents=True, exist_ok=True)
    skipped_events: list[dict[str, Any]] = []
    enumerate_jobs = [
        build_worker_job(
            args,
            event_id,
            "enumerate",
            enumerate_only=True,
        )
        for event_id in event_ids
    ]

    pools: dict[
        str, dict[str, dict[str, list[dict[str, Any]]]]
    ] = {
        category: {}
        for category in CATEGORY_ORDER
    }
    usable_events: list[str] = []

    if args.dry_run:
        for job in enumerate_jobs:
            print(f"[+] {job['event_id']}: enumerate")
            print("    " + " ".join(job["command"]))
        for event_id in event_ids:
            category = event_category(
                causal.SCENARIOS[event_id]
            )
            if category is None:
                continue
            fake_pool = {
                str(level): [
                    {
                        "candidate_index": index,
                        "hypothesis_root_as": 0,
                        "actual_distance": level,
                    }
                    for index in range(
                        args.max_candidates_per_distance
                    )
                ]
                for level in ERROR_DISTANCES
            }
            pools[category][event_id] = fake_pool
            usable_events.append(event_id)
    else:
        for job, result, error in run_jobs(
            args, enumerate_jobs, fail_fast=args.fail_fast
        ):
            if error is not None or result is None:
                skipped_events.append({
                    "event_id": job["event_id"],
                    "skip_reason": "enumerate_failed",
                    "error": error,
                })
                print(
                    f"[!] {job['event_id']}: "
                    "enumerate failed, skipped"
                )
                continue
            document = result["document"]
            category = document.get("event_category")
            if not document.get("holdout_ok"):
                skipped_events.append({
                    "event_id": job["event_id"],
                    "skip_reason": document.get(
                        "skip_reason"
                    ),
                })
                continue
            if category not in pools:
                skipped_events.append({
                    "event_id": job["event_id"],
                    "skip_reason": "unknown_category",
                })
                continue
            pools[category][job["event_id"]] = (
                document.get("by_distance", {})
            )
            usable_events.append(job["event_id"])

    selected_by_type: dict[str, list[dict[str, Any]]] = {}
    for category in CATEGORY_ORDER:
        selected_by_type[category] = allocate_quota(
            pools[category],
            args.target_samples_per_type,
        )
        print(
            f"[+] quota {category}: "
            f"{len(selected_by_type[category])}/"
            f"{args.target_samples_per_type} "
            f"from {len(pools[category])} event(s)"
        )

    selected_wrong = [
        item
        for category in CATEGORY_ORDER
        for item in selected_by_type[category]
    ]
    events_needed = sorted({
        item["event_id"] for item in selected_wrong
    })
    if args.dry_run and not events_needed:
        events_needed = usable_events

    simulation_jobs = [
        build_worker_job(
            args, event_id, "correct", 0, 0, variant=variant
        )
        for event_id in events_needed
        for variant in ("case", "counterfactual")
    ]
    simulation_jobs.extend(
        build_worker_job(
            args,
            item["event_id"],
            "wrong",
            item["error_level"],
            item["candidate_index"],
            variant=variant,
        )
        for item in selected_wrong
        for variant in ("case", "counterfactual")
    )

    if args.dry_run:
        for job in simulation_jobs:
            print(f"[+] {job['event_id']}: {job['label']}")
            print("    " + " ".join(job["command"]))
        return 0

    results_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
    for job, result, error in run_jobs(
        args, simulation_jobs, fail_fast=args.fail_fast
    ):
        if error is not None or result is None:
            skipped_events.append({
                "event_id": job["event_id"],
                "skip_reason": "simulation_failed",
                "label": job["label"],
                "error": error,
            })
            continue
        results_by_key[(
            job["event_id"],
            job["hypothesis"],
            job["level"],
            job["candidate_index"],
            job.get("variant", "case"),
        )] = result

    rows: list[dict[str, Any]] = []
    for event_id in events_needed:
        scenario = causal.SCENARIOS[event_id]
        category = event_category(scenario)
        correct_case = results_by_key.get(
            (event_id, "correct", 0, 0, "case")
        )
        correct_cf = results_by_key.get(
            (event_id, "correct", 0, 0, "counterfactual")
        )
        if correct_case is None or correct_case.get("score") is None:
            skipped_events.append({
                "event_id": event_id,
                "skip_reason": "correct_run_unavailable",
            })
            continue
        correct_digest = correct_case["digest"]
        if correct_digest is None:
            skipped_events.append({
                "event_id": event_id,
                "skip_reason": "correct_digest_unavailable",
            })
            continue
        if (
            correct_cf is not None
            and correct_cf.get("digest") not in (None, correct_digest)
        ):
            raise RuntimeError(
                f"{event_id}/correct_cf: "
                "evaluation SHA-256 mismatch"
            )

        correct_score = float(correct_case["score"])
        correct_cf_score = (
            None if correct_cf is None or correct_cf.get("score") is None
            else float(correct_cf["score"])
        )
        correct_plan = correct_case["plan"]
        rows.append({
            "event_id": event_id,
            "event_type": scenario["type"],
            "event_category": category,
            "label": "correct",
            "error_level": 0,
            "candidate_index": 0,
            "true_root_as": scenario["root_as"],
            "hypothesis_root_as": correct_plan[
                "hypothesis_root_as"
            ],
            "topology_distance": 0,
            "score": correct_score,
            "case_m": correct_score,
            "counterfactual_m": correct_cf_score,
            "correct_score": correct_score,
            "delta_c": (
                None if correct_cf_score is None
                else correct_score - correct_cf_score
            ),
            "evaluation_digest": correct_digest,
            "quality_flags": sorted(set(
                correct_case.get("quality_flags", [])
            )),
        })

        for item in selected_wrong:
            if item["event_id"] != event_id:
                continue
            key_case = (
                event_id,
                "wrong",
                item["error_level"],
                item["candidate_index"],
                "case",
            )
            key_cf = (
                event_id,
                "wrong",
                item["error_level"],
                item["candidate_index"],
                "counterfactual",
            )
            result = results_by_key.get(key_case)
            result_cf = results_by_key.get(key_cf)
            if result is None or result.get("score") is None:
                skipped_events.append({
                    "event_id": event_id,
                    "skip_reason": "wrong_run_unavailable",
                    "error_level": item["error_level"],
                    "candidate_index": item[
                        "candidate_index"
                    ],
                })
                continue
            if result["digest"] != correct_digest:
                raise RuntimeError(
                    f"{event_id}/"
                    f"wrong_d{item['error_level']}_"
                    f"i{item['candidate_index']}: "
                    "evaluation SHA-256 mismatch"
                )
            if (
                result_cf is not None
                and result_cf.get("digest") not in (None, correct_digest)
            ):
                raise RuntimeError(
                    f"{event_id}/"
                    f"wrong_d{item['error_level']}_"
                    f"i{item['candidate_index']}_cf: "
                    "evaluation SHA-256 mismatch"
                )
            plan = result["plan"]
            wrong_score = float(result["score"])
            wrong_cf_score = (
                None
                if result_cf is None or result_cf.get("score") is None
                else float(result_cf["score"])
            )
            rows.append({
                "event_id": event_id,
                "event_type": scenario["type"],
                "event_category": category,
                "label": "wrong",
                "error_level": item["error_level"],
                "candidate_index": item["candidate_index"],
                "true_root_as": scenario["root_as"],
                "hypothesis_root_as": plan[
                    "hypothesis_root_as"
                ],
                "topology_distance": plan[
                    "actual_distance"
                ],
                "score": wrong_score,
                "case_m": wrong_score,
                "counterfactual_m": wrong_cf_score,
                "correct_score": correct_score,
                "delta_c": (
                    None if wrong_cf_score is None
                    else wrong_score - wrong_cf_score
                ),
                "evaluation_digest": result["digest"],
                "quality_flags": sorted(set(
                    result.get("quality_flags", [])
                )),
            })

    if not rows:
        raise RuntimeError("No attribution scores were produced")

    score_path = args.output_root / "attribution_scores.csv"
    fields = (
        "event_id",
        "event_type",
        "event_category",
        "label",
        "error_level",
        "candidate_index",
        "true_root_as",
        "hypothesis_root_as",
        "topology_distance",
        "score",
        "case_m",
        "counterfactual_m",
        "correct_score",
        "delta_c",
        "evaluation_digest",
        "quality_flags",
    )
    with score_path.open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            serialized = {
                field: row.get(field) for field in fields
            }
            serialized["quality_flags"] = "|".join(
                row["quality_flags"]
            )
            writer.writerow(serialized)

    delta_path = (
        args.output_root / "attribution_delta_c_by_type.csv"
    )
    write_delta_c_csv(rows, delta_path)

    correct_scores = [
        row["score"] for row in rows
        if row["label"] == "correct"
    ]
    wrong_scores = [
        row["score"] for row in rows
        if row["label"] == "wrong"
    ]
    threshold = choose_threshold(
        correct_scores, wrong_scores
    ) if correct_scores and wrong_scores else {
        "threshold": 0.0
    }

    cdf_path = args.output_root / "attribution_cdf.csv"
    write_cdf(rows, cdf_path)
    plot_cdf(rows, threshold["threshold"], args.output_root)
    plot_delta_c_cdf(rows, args.output_root)

    summary = summarize_rows(
        rows,
        event_ids,
        skipped_events,
        args.target_samples_per_type,
        args,
    )
    summary_path = args.output_root / "attribution_summary.json"
    save_json(summary_path, summary)

    print(f"[+] Saved: {score_path}")
    print(f"[+] Saved: {delta_path}")
    print(f"[+] Saved: {cdf_path}")
    print(f"[+] Saved: {summary_path}")
    print(
        "[+] Saved: "
        f"{args.output_root / 'attribution_score_cdf.png'}"
    )
    print(
        "[+] Saved: "
        f"{args.output_root / 'attribution_delta_c_cdf.png'}"
    )
    return 0


if __name__ == "__main__":
    if "--worker" in sys.argv[1:]:
        raise SystemExit(
            worker_main(sys.argv[1:])
        )
    raise SystemExit(
        parent_main(sys.argv[1:])
    )