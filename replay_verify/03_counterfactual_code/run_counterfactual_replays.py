#!/usr/bin/env python3
"""Paired counterfactual experiments for standalone BGPy replay scripts.

The program has two roles:

1. Parent process:
   - discovers independent replay_EVENT.py scripts;
   - runs Case and counterfactual variants in isolated directories;
   - verifies that every paired run uses the same evaluation paths;
   - computes Delta M = M_case - M_counterfactual.

2. Worker process:
   - imports one standalone replay script;
   - optionally removes the configured root-origin announcement;
   - extracts the alternative-origin path selected in that counterfactual;
   - optionally replaces illegal route-leak export with policy-compliant export;
   - calls the replay script's original run_cli() implementation.

Primary metric:
    similarity.mean_observed_path_similarity_including_uncovered
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import random
import re
import statistics
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Sequence


PRIMARY_METRIC = "mean_observed_path_similarity_including_uncovered"

EVENT_ID_PATTERN = re.compile(
    r"event_id\s*=\s*['\"]([^'\"]+)['\"]"
)
EVENT_TYPE_PATTERN = re.compile(
    r"anomaly_type\s*=\s*['\"](hijack|leak|recovery)['\"]"
)

ORIGIN_TYPES = {"hijack", "recovery"}
SUPPORTED_TYPES = ORIGIN_TYPES | {"leak"}
LEAK_REMOVAL_AUDIT_VERSION = 5


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(value, file, indent=2, sort_keys=True)


def first_present(
    mapping: dict[str, Any],
    keys: Sequence[str],
) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return None


def detect_script_metadata(script: Path) -> tuple[str, str]:
    source = script.read_text(encoding="utf-8")

    event_match = EVENT_ID_PATTERN.search(source)
    type_match = EVENT_TYPE_PATTERN.search(source)

    if event_match is None:
        event_id = script.stem.removeprefix("replay_")
    else:
        event_id = event_match.group(1)

    if type_match is None:
        raise ValueError(
            f"Cannot determine anomaly_type from {script}"
        )

    event_type = type_match.group(1)
    if event_type not in SUPPORTED_TYPES:
        raise ValueError(
            f"Unsupported event type {event_type}: {script}"
        )

    return event_id, event_type


def evaluation_digest(output_dir: Path) -> str | None:
    """Fingerprint the actual evaluation paths and receiver split."""

    resolved_file = output_dir / "resolved_event_inputs.json"
    if not resolved_file.exists():
        return None

    resolved = load_json(resolved_file)
    comparable_state = {
        "observed_paths": resolved.get("observed_paths", []),
        "validation_split": resolved.get(
            "validation_split",
            {},
        ),
        "observation_selection": resolved.get(
            "observation_selection",
            {},
        ),
    }

    encoded = json.dumps(
        comparable_state,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


def read_similarity(output_dir: Path) -> dict[str, Any]:
    result_file = output_dir / "similarity_vs_real_rib.json"

    if not result_file.exists():
        return {
            "available": False,
            "score": None,
            "observed_paths": None,
            "receiver_coverage": None,
            "quality_flags": ["missing_similarity_file"],
        }

    result = load_json(result_file)

    similarity = result.get("similarity", {})
    coverage = result.get("coverage", {})
    counts = result.get("counts", {})
    quality = result.get("evaluation_quality", {})

    score = similarity.get(PRIMARY_METRIC)

    observed_count = first_present(
        counts,
        (
            "observed_unique_paths",
            "observed_unique_path_count",
            "observed_path_count",
        ),
    )

    receiver_coverage = first_present(
        coverage,
        (
            "observed_receiver_coverage",
            "receiver_coverage",
        ),
    )

    quality_flags = (
        quality.get("quality_flags")
        or result.get("evaluation_quality_flags")
        or []
    )

    return {
        "available": bool(
            result.get("available", score is not None)
        ),
        "score": score,
        "observed_paths": observed_count,
        "receiver_coverage": receiver_coverage,
        "quality_flags": quality_flags,
    }


def annotate_worker_outputs(
    output_dir: Path,
    intervention: str,
    effective_event_type: str,
    run_signature: str,
    intervention_audit: dict[str, Any] | None = None,
) -> None:
    annotation = {
        "intervention": intervention,
        "effective_event_type": effective_event_type,
        "primary_metric": PRIMARY_METRIC,
        "audit_version": LEAK_REMOVAL_AUDIT_VERSION,
        "run_signature": run_signature,
    }
    if intervention_audit is not None:
        annotation["intervention_audit"] = intervention_audit

    for filename in (
        "simulation_complete.json",
        "similarity_vs_real_rib.json",
        "propagation_paths.json",
    ):
        path = output_dir / filename
        if not path.exists():
            continue

        document = load_json(path)
        document["counterfactual_experiment"] = annotation
        save_json(path, document)


def leak_removal_residuals(output_dir: Path) -> list[str]:
    """Return event-only export mechanisms still active after leak removal."""

    path = output_dir / "simulation_complete.json"
    if not path.exists():
        return ["missing_simulation_complete"]

    document = load_json(path)
    simulation = document.get("simulation", {})
    announcement_audit = document.get("announcement_audit", {})
    topology_audit = document.get("topology_audit", {})
    residuals: list[str] = []

    checks = {
        "calibration_stage_anchors": simulation.get(
            "calibration_stage_anchors_used", False
        ),
        "calibration_stage_forced_export": simulation.get(
            "calibration_stage_forced_export_policy_used", False
        ),
        "pre_rib_export_tree": simulation.get(
            "pre_rib_export_tree_used", False
        ),
        "announcement_stage_anchors": announcement_audit.get(
            "calibration_stage_anchors", {}
        ).get("enabled", False),
        "announcement_forced_export": announcement_audit.get(
            "calibration_stage_anchors", {}
        ).get("forced_export_policy_enabled", False),
        "announcement_pre_rib_export_tree": announcement_audit.get(
            "pre_rib_export_tree", {}
        ).get("enabled", False),
        "legacy_forced_export_tree": topology_audit.get(
            "event_constraints", {}
        ).get("event_export_tree_forces_observed_edges", False),
    }
    residuals.extend(name for name, enabled in checks.items() if enabled)
    return residuals


def reusable_result_is_valid(
    output_dir: Path,
    intervention: str,
    expected_run_signature: str,
) -> bool:
    """Only reuse a result produced by the identical experiment config."""

    path = output_dir / "simulation_complete.json"
    if not path.exists():
        return False
    annotation = load_json(path).get("counterfactual_experiment", {})
    if annotation.get("run_signature") != expected_run_signature:
        return False
    if intervention == "leak-policy-compliant":
        return (
            annotation.get("audit_version") == LEAK_REMOVAL_AUDIT_VERSION
            and not leak_removal_residuals(output_dir)
        )
    return True


def experiment_run_signature(
    script: Path,
    effective_event_type: str,
    intervention: str,
    replay_arguments: Sequence[str],
) -> str:
    """Fingerprint code and arguments that define one replay result."""

    payload = {
        "driver_audit_version": LEAK_REMOVAL_AUDIT_VERSION,
        "driver_sha256": hashlib.sha256(
            Path(__file__).resolve().read_bytes()
        ).hexdigest(),
        "script_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
        "effective_event_type": effective_event_type,
        "intervention": intervention,
        "replay_arguments": list(replay_arguments),
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def read_intervention_audit(output_dir: Path) -> dict[str, Any]:
    path = output_dir / "simulation_complete.json"
    if not path.exists():
        return {}
    return load_json(path).get("counterfactual_experiment", {}).get(
        "intervention_audit", {}
    )


def topology_ablation_residuals(output_dir: Path) -> list[str]:
    """Return RIB-derived topology mechanisms left in topology-only runs."""

    path = output_dir / "simulation_complete.json"
    if not path.exists():
        return ["missing_simulation_complete"]
    document = load_json(path)
    topology_audit = document.get("topology_audit", {})
    overlay = topology_audit.get("event_topology_overlay", {})
    residuals: list[str] = []
    if overlay.get("mode") not in {None, "none"}:
        residuals.append("generic_rib_topology_overlay")
    if overlay.get("requested_edge_count", 0):
        residuals.append("requested_rib_overlay_edges")
    if overlay.get("event_cp_overrides"):
        residuals.append("event_customer_provider_overrides")
    if overlay.get("event_peer_overrides"):
        residuals.append("event_peer_overrides")
    constraints = topology_audit.get("event_constraints", {})
    if constraints.get("customer_provider_overrides"):
        residuals.append("event_constraint_customer_provider_overrides")
    if constraints.get("peer_overrides"):
        residuals.append("event_constraint_peer_overrides")
    return residuals


def alternative_prefix_for_origin_counterfactual(
    config: Any,
    resolved: dict[str, Any],
    anomalous_prefix: str,
) -> str:
    """Return the legitimate prefix used after removing root_asn.

    In a more-specific-prefix hijack, the legitimate route may be a covering
    prefix. The counterfactual must therefore query that covering prefix
    instead of querying the removed anomalous prefix.
    """

    if config.anomaly_type != "hijack":
        return anomalous_prefix

    hijack = resolved.get("hijack", {})
    mapping = hijack.get(
        "victim_prefix_by_anomalous_prefix",
        {},
    )

    return str(mapping.get(anomalous_prefix, anomalous_prefix))


def install_origin_counterfactual_extractor(
    module: Any,
) -> None:
    """Extract selected paths through the remaining alternative origin.

    The original replay extractor intentionally keeps only paths containing
    config.root_asn. That is correct for Case replay but invalid after root_asn
    has been removed: every legitimate alternative path would otherwise be
    discarded and the counterfactual score would mechanically become zero.

    This extractor instead:
      - queries the legitimate prefix, including a covering victim prefix;
      - retains routes whose origin is config.victim_asn;
      - emits the path from that alternative origin to the same receiver;
      - keeps the comparison key as the anomalous prefix.
    """

    def extract_other_origin_paths(
        config: Any,
        resolved: dict[str, Any],
        engine: Any,
        *,
        leak_target_mode: Any,
        path_source: str,
    ) -> dict[str, Any]:
        del leak_target_mode

        if config.victim_asn is None:
            raise RuntimeError(
                "Origin-removal counterfactual requires victim_asn/"
                "other-origin ASN."
            )

        other_origin_as = int(config.victim_asn)
        removed_root_as = int(config.root_asn)

        prefix_results: dict[str, Any] = {}

        for anomalous_prefix in resolved.get(
            "anomalous_prefixes",
            [],
        ):
            anomalous_prefix = str(anomalous_prefix)
            route_prefix = alternative_prefix_for_origin_counterfactual(
                config,
                resolved,
                anomalous_prefix,
            )

            simulated_paths: list[dict[str, Any]] = []
            reachable_count = 0
            selected_other_origin_count = 0

            for receiver_asn, as_obj in sorted(
                engine.as_graph.as_dict.items()
            ):
                if path_source == "local-rib":
                    candidate_anns = [
                        as_obj.policy.local_rib.get(route_prefix)
                    ]
                else:
                    candidate_anns = [
                        as_obj.policy.local_rib.get(route_prefix)
                    ]

                    ribs_in = getattr(
                        as_obj.policy,
                        "ribs_in",
                        None,
                    )
                    if ribs_in is not None:
                        candidate_anns.extend(
                            ann_info.unprocessed_ann
                            for ann_info in ribs_in.get_ann_infos(
                                route_prefix
                            )
                        )

                candidates_seen: set[tuple[Any, ...]] = set()

                for announcement in candidate_anns:
                    if announcement is None:
                        continue

                    announcement_origin = int(
                        getattr(
                            announcement,
                            "origin",
                            announcement.as_path[-1],
                        )
                    )

                    candidate_key = (
                        tuple(
                            int(value)
                            for value in announcement.as_path
                        ),
                        bool(
                            getattr(
                                announcement,
                                "withdraw",
                                False,
                            )
                        ),
                        announcement_origin,
                    )

                    if candidate_key in candidates_seen:
                        continue
                    candidates_seen.add(candidate_key)

                    reachable_count += 1

                    # Only compare the selected route through the remaining
                    # legitimate/alternative origin.
                    if announcement_origin != other_origin_as:
                        continue

                    full_path = [
                        int(asn)
                        for asn in reversed(
                            announcement.as_path
                        )
                    ]

                    if other_origin_as not in full_path:
                        continue

                    origin_index = full_path.index(
                        other_origin_as
                    )
                    propagation_path = full_path[origin_index:]

                    if not propagation_path:
                        continue
                    if propagation_path[0] != other_origin_as:
                        continue

                    # Do not treat the origin itself as an observation
                    # receiver.
                    if int(receiver_asn) == other_origin_as:
                        continue

                    # The configured anomalous root may learn the legitimate
                    # route after its own origin announcement is removed, but
                    # it is not a RouteViews/RIS receiver for this comparison.
                    if int(receiver_asn) == removed_root_as:
                        continue

                    selected_other_origin_count += 1

                    simulated_paths.append(
                        {
                            # Keep the anomalous prefix as the comparison key.
                            "prefix": anomalous_prefix,
                            "route_prefix": route_prefix,
                            "receiver_as": int(receiver_asn),
                            "as_path_view": [
                                int(asn)
                                for asn in announcement.as_path
                            ],
                            "full_propagation_path": full_path,
                            "anomalous_propagation_path": (
                                propagation_path
                            ),
                            "first_hop_after_root": (
                                propagation_path[1]
                                if len(propagation_path) > 1
                                else None
                            ),
                            "first_hop_allowed_by_event_constraint": (
                                True
                            ),
                            "event_constraint_available": False,
                            "path_source": path_source,
                            "counterfactual_origin_as": (
                                other_origin_as
                            ),
                            "removed_root_origin_as": (
                                removed_root_as
                            ),
                            "counterfactual_path_role": (
                                "alternative_origin_to_receiver"
                            ),
                        }
                    )

            path_lists = [
                item["anomalous_propagation_path"]
                for item in simulated_paths
            ]

            nodes = {
                asn
                for path in path_lists
                for asn in path
            }
            edges = module.directed_edges(path_lists)

            prefix_results[anomalous_prefix] = {
                "summary": {
                    "reachable_as_count": reachable_count,
                    "selected_route_via_root_count": 0,
                    "selected_route_via_other_origin_count": (
                        selected_other_origin_count
                    ),
                    "anomalous_receiver_count": len(
                        simulated_paths
                    ),
                    "anomalous_node_count": len(nodes),
                    "anomalous_edge_count": len(edges),
                    "anomalous_first_hops": sorted(
                        {
                            path[1]
                            for path in path_lists
                            if len(path) > 1
                        }
                    ),
                    "counterfactual_route_prefix": (
                        route_prefix
                    ),
                    "counterfactual_origin_as": (
                        other_origin_as
                    ),
                    "removed_root_origin_as": (
                        removed_root_as
                    ),
                },
                "paths": simulated_paths,
                "nodes": sorted(nodes),
                "edges": [
                    {
                        "src": int(src),
                        "dst": int(dst),
                    }
                    for src, dst in sorted(edges)
                ],
            }

        return {
            "prefixes": prefix_results,
            "root_advertisements": [],
            "leak_target_mode": "not_applicable",
            "path_source": path_source,
            "path_selection": (
                "counterfactual_alternative_origin_"
                + (
                    "all_received_candidates"
                    if path_source == "received-envelope"
                    else "final_local_rib_only"
                )
            ),
            "counterfactual_origin_extraction": {
                "enabled": True,
                "removed_root_origin_as": removed_root_as,
                "remaining_other_origin_as": other_origin_as,
                "covering_prefix_fallback_enabled": True,
            },
        }

    module.extract_simulation_paths = (
        extract_other_origin_paths
    )


def install_origin_removal(module: Any) -> None:
    """Remove root_asn and retain the other origin.

    For a hijack, the worker is run with --legal-route-mode always, so the
    legitimate origin is normally already present.

    Some recovery implementations seed only root_asn. For those scripts, the
    worker explicitly inserts victim_asn/other-origin before removing root_asn.
    """

    original = module.build_announcements

    def counterfactual_build_announcements(
        config: Any,
        resolved: dict[str, Any],
        as_graph: Any,
        **kwargs: Any,
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        announcements, audit = original(
            config,
            resolved,
            as_graph,
            **kwargs,
        )

        retained_without_root = tuple(
            announcement
            for announcement in announcements
            if int(announcement.seed_asn)
            != int(config.root_asn)
        )

        retained = retained_without_root

        # Recovery implementations may never seed victim_asn. Insert the
        # alternative origin explicitly if necessary.
        if config.victim_asn is not None and not any(
            int(announcement.seed_asn)
            == int(config.victim_asn)
            for announcement in retained
        ):
            from bgpy.shared.enums import (
                Relationships,
                Timestamps,
            )
            from bgpy.simulation_engine import Announcement

            if (
                config.anomaly_type == "hijack"
                and "hijack" in resolved
            ):
                prefixes = sorted(
                    {
                        str(prefix)
                        for prefix in resolved["hijack"][
                            "victim_prefix_by_anomalous_prefix"
                        ].values()
                    }
                )
            else:
                prefixes = [
                    str(prefix)
                    for prefix in resolved.get(
                        "anomalous_prefixes",
                        [],
                    )
                ]

            inserted = []

            for prefix in prefixes:
                inserted.append(
                    Announcement(
                        prefix=prefix,
                        as_path=(
                            int(config.victim_asn),
                        ),
                        seed_asn=int(config.victim_asn),
                        next_hop_asn=int(
                            config.victim_asn
                        ),
                        recv_relationship=(
                            Relationships.ORIGIN
                        ),
                        timestamp=Timestamps.VICTIM.value,
                    )
                )

                audit.setdefault(
                    "announcements",
                    [],
                ).append(
                    {
                        "prefix": prefix,
                        "seed_as": int(
                            config.victim_asn
                        ),
                        "type": (
                            "counterfactual_other_origin"
                        ),
                    }
                )

            retained = tuple(inserted) + retained

        audit["counterfactual_intervention"] = {
            "name": "origin_root_removed",
            "removed_origin_as": int(config.root_asn),
            "remaining_other_origin_as": (
                int(config.victim_asn)
                if config.victim_asn is not None
                else None
            ),
            "removed_announcement_count": (
                len(announcements)
                - len(retained_without_root)
            ),
            "alternative_origin_inserted": (
                len(retained)
                > len(retained_without_root)
            ),
            "alternative_origin_paths_are_evaluated": True,
        }

        return retained, audit

    module.build_announcements = (
        counterfactual_build_announcements
    )

    # This is essential. Without it, the original extractor discards every
    # path that no longer contains root_asn and the counterfactual score is
    # mechanically forced to zero.
    install_origin_counterfactual_extractor(module)


def set_replay_option(
    arguments: list[str],
    option: str,
    value: str,
) -> None:
    """Replace a replay CLI option or append it when absent."""

    try:
        index = arguments.index(option)
    except ValueError:
        arguments.extend([option, value])
    else:
        if index + 1 >= len(arguments):
            raise RuntimeError(f"Missing value for replay option {option}")
        arguments[index + 1] = value


def leak_removal_replay_arguments(script: Path) -> list[str]:
    """Return native switches that disable event-only leak helpers."""

    source = script.read_text(encoding="utf-8")
    arguments: list[str] = []
    if '"--leak-stage-anchor-mode"' in source:
        arguments.extend(["--leak-stage-anchor-mode", "off"])
    if '"--pre-rib-export-tree-mode"' in source:
        arguments.extend(["--pre-rib-export-tree-mode", "off"])
    return arguments


def install_policy_compliant_leak(module: Any) -> dict[str, Any]:
    """Disable illegal export while retaining the observed ingress anchor.

    BGPFullIgnoreInvalid is required because the replay injects the historical
    route as a route learned by the leaking AS rather than as a locally
    originated prefix. Its normal export methods still enforce Gao--Rexford
    export policy.
    """

    def policy_compliant_export(
        targets_by_prefix: Any,
        target_relationships_by_prefix: Any,
    ) -> type[Any]:
        del targets_by_prefix
        del target_relationships_by_prefix

        from bgpy.simulation_engine import (
            BGPFullIgnoreInvalid,
        )

        return BGPFullIgnoreInvalid

    module.make_route_leak_policy = (
        policy_compliant_export
    )

    disabled_mechanisms = ["illegal_root_export_policy"]

    # Some event-specific replays install a second policy on downstream ASes
    # to force the observed export tree. Restoring only the leaking AS leaves
    # that calibrated tree alive and makes Case and cf_leak_removed identical.
    if hasattr(module, "make_event_export_policy"):
        def ordinary_downstream_export(*args: Any, **kwargs: Any) -> type[Any]:
            del args
            del kwargs
            from bgpy.simulation_engine import BGP
            return BGP

        module.make_event_export_policy = ordinary_downstream_export
        disabled_mechanisms.append("event_downstream_export_policy")

    if hasattr(module, "EVENT_FORCE_EXPORT_TREE"):
        module.EVENT_FORCE_EXPORT_TREE = False
        disabled_mechanisms.append("legacy_forced_export_tree")

    return {
        "leak_policy_restored": True,
        "stage_anchors_disabled": False,
        "pre_rib_export_tree_disabled": False,
        "forced_export_tree_disabled": (
            "legacy_forced_export_tree" in disabled_mechanisms
            or "event_downstream_export_policy" in disabled_mechanisms
        ),
        "disabled_mechanisms": disabled_mechanisms,
        "residual_mechanisms": [],
        "validated": False,
    }


def install_topology_ablation(module: Any) -> dict[str, Any]:
    """Disable both generic and event-specific RIB topology calibration."""

    disabled: list[str] = ["generic_rib_topology_overlay"]
    if hasattr(module, "EVENT_CP_OVERRIDES"):
        module.EVENT_CP_OVERRIDES = frozenset()
        disabled.append("event_customer_provider_overrides")
    if hasattr(module, "EVENT_PEER_OVERRIDES"):
        module.EVENT_PEER_OVERRIDES = frozenset()
        disabled.append("event_peer_overrides")
    return {
        "topology_overlay_disabled": True,
        "disabled_mechanisms": disabled,
        "residual_mechanisms": [],
        "validated": False,
    }


def worker_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument(
        "--replay-script",
        type=Path,
        required=True,
    )
    parser.add_argument(
    "--intervention",
    choices=(
        "case",
        "origin-root-removed",
        "leak-policy-compliant",
        "topology-rib-disabled",
    ),
    required=True,
    )
    parser.add_argument(
        "--effective-event-type",
        choices=("hijack", "leak", "recovery"),
        required=True,
    )
    parser.add_argument("--run-signature", required=True)

    args, replay_arguments = parser.parse_known_args(argv)

    script = args.replay_script.resolve()
    module_name = f"counterfactual_{script.stem}"

    spec = importlib.util.spec_from_file_location(
        module_name,
        script,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Cannot import replay script: {script}"
        )

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    # Correct event classification only inside this worker. The original
    # standalone script remains unchanged.
    if (
        module.CONFIG.anomaly_type
        != args.effective_event_type
    ):
        module.CONFIG = replace(
            module.CONFIG,
            anomaly_type=args.effective_event_type,
        )

    intervention_audit: dict[str, Any] | None = None

    if args.intervention == "origin-root-removed":
        install_origin_removal(module)
    elif (
        args.intervention
        == "leak-policy-compliant"
    ):
        intervention_audit = install_policy_compliant_leak(module)

        # Newer optimized replay scripts expose their calibration anchors as
        # CLI switches. They must be off in the anomaly-removal experiment;
        # otherwise a downstream AS injects or force-exports the leaked path
        # even though the leaking AS itself is policy compliant.
        native_arguments = leak_removal_replay_arguments(script)
        if "--leak-stage-anchor-mode" in native_arguments:
            set_replay_option(
                replay_arguments,
                "--leak-stage-anchor-mode",
                "off",
            )
            intervention_audit["stage_anchors_disabled"] = True
            intervention_audit["disabled_mechanisms"].append(
                "calibration_leak_export_stage_anchor"
            )
            intervention_audit["forced_export_tree_disabled"] = True

        if "--pre-rib-export-tree-mode" in native_arguments:
            set_replay_option(
                replay_arguments,
                "--pre-rib-export-tree-mode",
                "off",
            )
            intervention_audit["pre_rib_export_tree_disabled"] = True
            intervention_audit["disabled_mechanisms"].append(
                "pre_rib_export_tree_stage_anchor"
            )
            intervention_audit["forced_export_tree_disabled"] = True

    elif args.intervention == "topology-rib-disabled":
        intervention_audit = install_topology_ablation(module)
        set_replay_option(
            replay_arguments,
            "--topology-overlay-mode",
            "none",
        )

        native_arguments = leak_removal_replay_arguments(script)
        if "--pre-rib-export-tree-mode" in native_arguments:
            set_replay_option(
                replay_arguments,
                "--pre-rib-export-tree-mode",
                "off",
            )
            intervention_audit["pre_rib_export_tree_disabled"] = True
            intervention_audit["disabled_mechanisms"].append(
                "pre_rib_export_tree_stage_anchor"
            )
            intervention_audit["forced_export_tree_disabled"] = True

    output_dir: Path | None = None

    for index, value in enumerate(replay_arguments):
        if (
            value == "--output-dir"
            and index + 1 < len(replay_arguments)
        ):
            output_dir = Path(
                replay_arguments[index + 1]
            ).resolve()
            break

    sys.argv = [script.name, *replay_arguments]
    module.run_cli(module.CONFIG)

    if output_dir is not None:
        if intervention_audit is not None:
            if args.intervention == "leak-policy-compliant":
                residuals = leak_removal_residuals(output_dir)
            elif args.intervention == "topology-rib-disabled":
                residuals = topology_ablation_residuals(output_dir)
            else:
                residuals = []
            intervention_audit["residual_mechanisms"] = residuals
            intervention_audit["validated"] = not residuals
        annotate_worker_outputs(
            output_dir,
            args.intervention,
            args.effective_event_type,
            args.run_signature,
            intervention_audit,
        )
        if intervention_audit is not None and residuals:
            raise RuntimeError(
                f"{args.intervention} is invalid because disabled "
                "mechanisms remain active: " + ", ".join(residuals)
            )

    return 0


def parse_type_overrides(
    values: Sequence[str],
) -> dict[str, str]:
    overrides: dict[str, str] = {}

    for value in values:
        if "=" not in value:
            raise ValueError(
                f"Invalid --type-override {value!r}; "
                "expected EVENT=TYPE"
            )

        event_id, event_type = value.split("=", 1)
        event_id = event_id.strip()
        event_type = event_type.strip()

        if event_type not in SUPPORTED_TYPES:
            raise ValueError(
                f"Unsupported override type: {event_type}"
            )

        overrides[event_id] = event_type

    return overrides


def experiment_variants(
    event_type: str,
    case_legal_route_mode: str | None,
    case_topology_mode: str | None,
) -> list[dict[str, Any]]:
    # None means that the standalone replay script retains its audited default.
    case_legal_arguments = (
        []
        if case_legal_route_mode is None
        else ["--legal-route-mode", case_legal_route_mode]
    )
    if event_type == "hijack":
        variants = [
            {
                "name": "case",
                "family": "case",
                "intervention": "case",
                "arguments": [
                    *case_legal_arguments,
                ],
            },
            {
                "name": "cf_origin_removed",
                "family": "anomaly_removal",
                "intervention": (
                    "origin-root-removed"
                ),
                "arguments": [
                    # The other origin must be present after
                    # root_asn is removed.
                    "--legal-route-mode",
                    "always",
                ],
            },
            {
                "name": "cf_legal_always",
                "family": "mechanism_specificity",
                "intervention": "case",
                "arguments": [
                    "--legal-route-mode",
                    "always",
                ],
            },
            {
                "name": "cf_legal_withdrawn",
                "family": "mechanism_specificity",
                "intervention": "case",
                "arguments": [
                    "--legal-route-mode",
                    "withdrawn",
                ],
            },
        ]

    elif event_type == "recovery":
        # The current recovery implementations do not use legal_route_mode.
        # Running cf_legal_always and cf_legal_withdrawn would therefore create
        # duplicate no-op experiments. Keep only the meaningful paired
        # intervention: remove the recovered/configured root origin and restore
        # the other pre-event origin.
        variants = [
            {
                "name": "case",
                "family": "case",
                "intervention": "case",
                "arguments": [
                    *case_legal_arguments,
                ],
            },
            {
                "name": "cf_origin_removed",
                "family": "anomaly_removal",
                "intervention": (
                    "origin-root-removed"
                ),
                "arguments": [
                    "--legal-route-mode",
                    "always",
                ],
            },
        ]

    else:
        variants = [
            {
                "name": "case",
                "family": "case",
                "intervention": "case",
                "arguments": [
                    "--leak-target-mode",
                    "event",
                    *case_legal_arguments,
                ],
            },
            {
                "name": "cf_leak_removed",
                "family": "anomaly_removal",
                "intervention": (
                    "leak-policy-compliant"
                ),
                "arguments": [
                    # "all" prevents the extraction stage from
                    # retaining the event-neighbor filter. The
                    # worker replaces propagation with ordinary
                    # Gao--Rexford export.
                    "--leak-target-mode",
                    "all",
                    *case_legal_arguments,
                ],
            },
            {
                "name": "cf_scope_relationship",
                "family": "mechanism_specificity",
                "intervention": "case",
                "arguments": [
                    "--leak-target-mode",
                    "relationship",
                    *case_legal_arguments,
                ],
            },
            {
                "name": "cf_scope_all",
                "family": "mechanism_specificity",
                "intervention": "case",
                "arguments": [
                    "--leak-target-mode",
                    "all",
                    *case_legal_arguments,
                ],
            },
        ]

    if case_topology_mode != "none":
        case_arguments = list(
            variants[0]["arguments"]
        )
        variants.append(
            {
                "name": "cf_topology_only",
                "family": "topology_ablation",
                "intervention": "topology-rib-disabled",
                "arguments": case_arguments,
                "topology_mode": "none",
            }
        )

    return variants


def bootstrap_mean_ci(
    values: Sequence[float],
    repetitions: int = 10_000,
) -> list[float] | None:
    if not values:
        return None

    if len(values) == 1:
        return [values[0], values[0]]

    generator = random.Random(20260809)
    sample_size = len(values)
    bootstrap_means = []

    for _ in range(repetitions):
        sample = [
            values[generator.randrange(sample_size)]
            for _ in range(sample_size)
        ]
        bootstrap_means.append(
            statistics.mean(sample)
        )

    bootstrap_means.sort()
    lower_index = int(
        0.025 * (repetitions - 1)
    )
    upper_index = int(
        0.975 * (repetitions - 1)
    )

    return [
        bootstrap_means[lower_index],
        bootstrap_means[upper_index],
    ]


def summarize_deltas(
    deltas: Sequence[float],
) -> dict[str, Any] | None:
    if not deltas:
        return None

    return {
        "paired_event_count": len(deltas),
        "mean_delta_m": statistics.mean(deltas),
        "median_delta_m": statistics.median(deltas),
        "positive_delta_fraction": (
            sum(delta > 0 for delta in deltas)
            / len(deltas)
        ),
        "zero_delta_fraction": (
            sum(delta == 0 for delta in deltas)
            / len(deltas)
        ),
        "negative_delta_fraction": (
            sum(delta < 0 for delta in deltas)
            / len(deltas)
        ),
        "bootstrap_95pct_ci": bootstrap_mean_ci(
            deltas
        ),
    }


def parent_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run paired counterfactual experiments "
            "for BGPy replays."
        )
    )

    parser.add_argument(
        "--scripts-dir",
        type=Path,
        default=Path("."),
        help=(
            "Directory containing replay_EVENT.py files."
        ),
    )
    parser.add_argument(
        "--events-root",
        type=Path,
        default=Path(__file__).resolve().parent / "dudata",
        help=(
            "Directory containing the per-event RIB folders. "
            "Default: the dudata directory beside this script."
        ),
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("results_counterfactual"),
    )
    parser.add_argument(
        "--caida-cache-dir",
        type=Path,
    )
    parser.add_argument(
        "--caida-file",
        type=Path,
    )
    parser.add_argument(
        "--event",
        action="append",
        default=[],
        help=(
            "Run only this event ID; may be repeated."
        ),
    )
    parser.add_argument(
        "--type-override",
        action="append",
        default=[],
        metavar="EVENT=TYPE",
        help=(
            "Correct a script's event type without "
            "modifying the script."
        ),
    )
    parser.add_argument(
        "--case-topology-mode",
        choices=(
            "none",
            "pre-rib",
            "pre-rib-and-calibration",
        ),
        default=None,
        help=(
            "Override the Case topology overlay. By default the option is "
            "omitted and each standalone replay retains its audited default. "
            "cf_topology_only explicitly disables RIB-derived topology input."
        ),
    )
    parser.add_argument(
        "--case-legal-route-mode",
        choices=(
            "always",
            "after-observed",
            "withdrawn",
        ),
        default=None,
        help=(
            "Override the Case legal-route state. By default each standalone "
            "replay retains its audited event-specific default."
        ),
    )
    parser.add_argument(
        "--observation-mode",
        choices=(
            "receiver-last",
            "peak",
            "final",
            "all-updates",
        ),
        default="receiver-last",
    )
    parser.add_argument(
        "--validation-mode",
        choices=(
            "receiver-holdout",
            "all",
        ),
        default="receiver-holdout",
    )
    parser.add_argument(
        "--calibration-fraction",
        type=float,
        default=0.25,
    )
    parser.add_argument(
        "--minimum-holdout-pairs",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--path-source",
        choices=(
            "local-rib",
            "received-envelope",
        ),
        default=None,
        help=(
            "Override the path extraction source. By default each standalone "
            "replay retains its audited event-specific default."
        ),
    )
    parser.add_argument(
        "--reuse",
        action="store_true",
        help=(
            "Reuse an existing similarity file unless "
            "its variant is listed by --force-variant."
        ),
    )
    parser.add_argument(
        "--force-variant",
        action="append",
        default=[],
        metavar="VARIANT",
        help=(
            "Force this variant to rerun even with --reuse. "
            "May be repeated."
        ),
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
    )

    args = parser.parse_args(argv)

    if not 0 < args.calibration_fraction < 1:
        parser.error(
            "--calibration-fraction must be "
            "strictly between 0 and 1"
        )

    if args.minimum_holdout_pairs < 2:
        parser.error(
            "--minimum-holdout-pairs must be at least 2"
        )

    if not args.events_root.exists():
        parser.error(
            f"--events-root does not exist: "
            f"{args.events_root}"
        )

    overrides = parse_type_overrides(
        args.type_override
    )
    selected_events = set(args.event)
    forced_variants = set(args.force_variant)

    scripts = sorted(
        args.scripts_dir.glob("replay_*.py")
    )
    scripts = [
        script
        for script in scripts
        if script.name != Path(__file__).name
    ]

    if not scripts:
        raise RuntimeError(
            f"No replay_*.py files found in "
            f"{args.scripts_dir}"
        )

    rows: list[dict[str, Any]] = []
    failures = 0

    for script in scripts:
        event_id, configured_type = (
            detect_script_metadata(script)
        )

        if (
            selected_events
            and event_id not in selected_events
        ):
            continue

        event_type = overrides.get(
            event_id,
            configured_type,
        )

        event_directory = (
            args.events_root / event_id
        )
        if not event_directory.exists():
            raise RuntimeError(
                f"Missing event directory for "
                f"{event_id}: {event_directory}"
            )

        variants = experiment_variants(
            event_type,
            args.case_legal_route_mode,
            args.case_topology_mode,
        )

        event_rows: list[dict[str, Any]] = []

        for variant in variants:
            variant_name = variant["name"]
            topology_mode = variant.get(
                "topology_mode",
                args.case_topology_mode,
            )

            output_dir = (
                args.output_root.resolve()
                / event_id
                / variant_name
            )
            result_file = (
                output_dir
                / "similarity_vs_real_rib.json"
            )

            replay_arguments = [
                "--events-root",
                str(args.events_root.resolve()),
                "--output-dir",
                str(output_dir),
                "--observation-mode",
                args.observation_mode,
                "--validation-mode",
                args.validation_mode,
                "--calibration-fraction",
                str(args.calibration_fraction),
                "--minimum-holdout-pairs",
                str(args.minimum_holdout_pairs),
            ]

            if topology_mode is not None:
                replay_arguments.extend(
                    ["--topology-overlay-mode", topology_mode]
                )
            if args.path_source is not None:
                replay_arguments.extend(
                    ["--path-source", args.path_source]
                )
            replay_arguments.extend(variant["arguments"])

            if variant["intervention"] == "leak-policy-compliant":
                # Include these in the parent command as well as enforcing
                # them in the worker, so --dry-run fully exposes the actual
                # anomaly-removal configuration.
                leak_removal_arguments = leak_removal_replay_arguments(script)
                for option, value in zip(
                    leak_removal_arguments[::2],
                    leak_removal_arguments[1::2],
                ):
                    set_replay_option(replay_arguments, option, value)

            if args.caida_cache_dir is not None:
                replay_arguments.extend(
                    [
                        "--caida-cache-dir",
                        str(
                            args.caida_cache_dir.resolve()
                        ),
                    ]
                )

            if args.caida_file is not None:
                replay_arguments.extend(
                    [
                        "--caida-file",
                        str(args.caida_file.resolve()),
                    ]
                )

            run_signature = experiment_run_signature(
                script,
                event_type,
                variant["intervention"],
                replay_arguments,
            )

            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--worker",
                "--replay-script",
                str(script.resolve()),
                "--intervention",
                variant["intervention"],
                "--effective-event-type",
                event_type,
                "--run-signature",
                run_signature,
                *replay_arguments,
            ]

            print(
                f"[+] {event_id}: {variant_name}"
            )

            return_code = 0
            error_message = None

            may_reuse = (
                args.reuse
                and result_file.exists()
                and variant_name
                not in forced_variants
                and reusable_result_is_valid(
                    output_dir,
                    variant["intervention"],
                    run_signature,
                )
            )

            if args.dry_run:
                print(
                    "    " + " ".join(command)
                )

            elif may_reuse:
                print(
                    "    reusing existing result"
                )

            else:
                output_dir.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                completed = subprocess.run(
                    command,
                    cwd=script.parent,
                    text=True,
                    capture_output=True,
                    check=False,
                )

                return_code = completed.returncode

                log_text = (
                    completed.stdout
                    + (
                        "\n[stderr]\n"
                        if completed.stderr
                        else ""
                    )
                    + completed.stderr
                )

                (
                    output_dir / "run.log"
                ).write_text(
                    log_text,
                    encoding="utf-8",
                )

                if return_code != 0:
                    failures += 1

                    error_message = (
                        completed.stderr.strip()
                        or completed.stdout.strip()
                        or (
                            "worker exited with "
                            f"{return_code}"
                        )
                    )

                    print(
                        f"[!] Failed: "
                        f"{event_id}/{variant_name}",
                        file=sys.stderr,
                    )
                    print(
                        error_message[-6000:],
                        file=sys.stderr,
                    )

                    if args.fail_fast:
                        raise RuntimeError(
                            f"{event_id}/"
                            f"{variant_name} failed:\n"
                            f"{error_message}"
                        )

            metrics = (
                read_similarity(output_dir)
                if (
                    not args.dry_run
                    and return_code == 0
                )
                else {
                    "available": False,
                    "score": None,
                    "observed_paths": None,
                    "receiver_coverage": None,
                    "quality_flags": [],
                }
            )
            intervention_audit = (
                read_intervention_audit(output_dir)
                if not args.dry_run and return_code == 0
                else {}
            )

            row = {
                "event_id": event_id,
                "replay_script": str(script.resolve()),
                "replay_script_sha256": hashlib.sha256(
                    script.read_bytes()
                ).hexdigest(),
                "configured_event_type": (
                    configured_type
                ),
                "effective_event_type": (
                    event_type
                ),
                "variant": variant_name,
                "intervention_family": (
                    variant["family"]
                ),
                "intervention": (
                    variant["intervention"]
                ),
                "topology_mode": topology_mode,
                "available": metrics["available"],
                "score": metrics["score"],
                "case_score": None,
                "delta_m": None,
                "paired_evaluation": False,
                "evaluation_digest": (
                    evaluation_digest(output_dir)
                    if (
                        not args.dry_run
                        and return_code == 0
                    )
                    else None
                ),
                "observed_paths": (
                    metrics["observed_paths"]
                ),
                "receiver_coverage": (
                    metrics["receiver_coverage"]
                ),
                "intervention_validated": intervention_audit.get(
                    "validated"
                ),
                "disabled_mechanisms": intervention_audit.get(
                    "disabled_mechanisms", []
                ),
                "residual_mechanisms": intervention_audit.get(
                    "residual_mechanisms", []
                ),
                "quality_flags": (
                    metrics["quality_flags"]
                ),
                "return_code": return_code,
                "error": error_message,
                "output_dir": str(output_dir),
            }

            event_rows.append(row)

        case_row = next(
            row
            for row in event_rows
            if row["variant"] == "case"
        )

        for row in event_rows:
            row["case_score"] = case_row["score"]

            same_evaluation = (
                case_row["evaluation_digest"] is not None
                and row["evaluation_digest"]
                == case_row["evaluation_digest"]
            )
            row["paired_evaluation"] = (
                same_evaluation
            )

            if row["variant"] == "case":
                continue

            if (
                same_evaluation
                and case_row["score"] is not None
                and row["score"] is not None
            ):
                row["delta_m"] = (
                    float(case_row["score"])
                    - float(row["score"])
                )

        rows.extend(event_rows)

    if args.dry_run:
        return 0

    args.output_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    csv_file = (
        args.output_root
        / "counterfactual_event_results.csv"
    )

    fields = [
        "event_id",
        "replay_script",
        "replay_script_sha256",
        "configured_event_type",
        "effective_event_type",
        "variant",
        "intervention_family",
        "intervention",
        "topology_mode",
        "available",
        "score",
        "case_score",
        "delta_m",
        "paired_evaluation",
        "observed_paths",
        "receiver_coverage",
        "intervention_validated",
        "disabled_mechanisms",
        "residual_mechanisms",
        "quality_flags",
        "return_code",
        "error",
        "output_dir",
        "evaluation_digest",
    ]

    with csv_file.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
        )
        writer.writeheader()

        for row in rows:
            serialized = dict(row)
            serialized["quality_flags"] = "|".join(
                row["quality_flags"]
            )
            serialized["disabled_mechanisms"] = "|".join(
                row["disabled_mechanisms"]
            )
            serialized["residual_mechanisms"] = "|".join(
                row["residual_mechanisms"]
            )
            writer.writerow(serialized)

    grouped: dict[
        tuple[str, str],
        list[float],
    ] = {}

    for row in rows:
        if (
            row["variant"] == "case"
            or row["delta_m"] is None
        ):
            continue

        key = (
            row["effective_event_type"],
            row["variant"],
        )
        grouped.setdefault(
            key,
            [],
        ).append(float(row["delta_m"]))

    aggregate_rows = []

    for (
        event_type,
        variant,
    ), deltas in sorted(grouped.items()):
        summary = summarize_deltas(deltas)
        assert summary is not None

        aggregate_rows.append(
            {
                "event_type": event_type,
                "variant": variant,
                **summary,
            }
        )

    anomaly_removal_deltas = [
        float(row["delta_m"])
        for row in rows
        if (
            row["intervention_family"]
            == "anomaly_removal"
            and row["delta_m"] is not None
        )
    ]

    unavailable_pairs = [
        {
            "event_id": row["event_id"],
            "effective_event_type": (
                row["effective_event_type"]
            ),
            "variant": row["variant"],
            "available": row["available"],
            "observed_paths": (
                row["observed_paths"]
            ),
            "quality_flags": (
                row["quality_flags"]
            ),
        }
        for row in rows
        if (
            row["variant"] != "case"
            and row["delta_m"] is None
        )
    ]

    evaluation_mismatches = [
        {
            "event_id": row["event_id"],
            "variant": row["variant"],
        }
        for row in rows
        if (
            row["variant"] != "case"
            and not row["paired_evaluation"]
        )
    ]

    complete_summary = {
        "primary_metric": (
            "similarity."
            "mean_observed_path_similarity_"
            "including_uncovered"
        ),
        "delta_definition": (
            "case_score - counterfactual_score"
        ),
        "method_notes": {
            "origin_removed_path_extraction": (
                "Alternative-origin paths are retained "
                "and evaluated rather than discarded "
                "for not containing root_asn."
            ),
            "covering_prefix_fallback": True,
            "recovery_legal_route_noops_excluded": True,
            "leak_removed_policy": (
                "BGPFullIgnoreInvalid with normal "
                "Gao--Rexford export; all event-only "
                "stage anchors and forced downstream "
                "export policies are disabled and audited"
            ),
            "leak_removal_audit_version": LEAK_REMOVAL_AUDIT_VERSION,
        },
        "run_configuration": {
            "case_parameter_source": {
                "topology_overlay_mode": (
                    "standalone-script-default"
                    if args.case_topology_mode is None
                    else "driver-override"
                ),
                "legal_route_mode": (
                    "standalone-script-default"
                    if args.case_legal_route_mode is None
                    else "driver-override"
                ),
                "path_source": (
                    "standalone-script-default"
                    if args.path_source is None
                    else "driver-override"
                ),
            },
            "case_topology_mode": (
                args.case_topology_mode
            ),
            "case_legal_route_mode": (
                args.case_legal_route_mode
            ),
            "observation_mode": (
                args.observation_mode
            ),
            "validation_mode": (
                args.validation_mode
            ),
            "calibration_fraction": (
                args.calibration_fraction
            ),
            "minimum_holdout_pairs": (
                args.minimum_holdout_pairs
            ),
            "path_source": args.path_source,
            "forced_variants": sorted(
                forced_variants
            ),
            "type_overrides": overrides,
        },
        "event_rows": rows,
        "aggregate_results": aggregate_rows,
        "overall_anomaly_removal": (
            summarize_deltas(
                anomaly_removal_deltas
            )
        ),
        "unavailable_pairs": unavailable_pairs,
        "evaluation_mismatches": (
            evaluation_mismatches
        ),
        "failed_runs": failures,
    }

    save_json(
        args.output_root
        / "counterfactual_summary.json",
        complete_summary,
    )

    print(f"[+] Saved: {csv_file}")
    print(
        "[+] Saved: "
        f"{args.output_root / 'counterfactual_summary.json'}"
    )
    print(
        f"[+] Failed runs: {failures}"
    )
    print(
        "[+] Evaluation mismatches: "
        f"{len(evaluation_mismatches)}"
    )
    print(
        "[+] Unavailable pairs: "
        f"{len(unavailable_pairs)}"
    )

    return 1 if failures else 0


if __name__ == "__main__":
    if "--worker" in sys.argv[1:]:
        raise SystemExit(
            worker_main(sys.argv[1:])
        )

    raise SystemExit(
        parent_main(sys.argv[1:])
    )
