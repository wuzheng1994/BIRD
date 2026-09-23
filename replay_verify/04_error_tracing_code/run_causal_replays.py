#!/usr/bin/env python3
"""Run paired causal replays for the audited 24 BGP events."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import statistics
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any


PRIMARY_METRIC = "mean_observed_path_similarity_including_uncovered"


def hijack(attacker: int, victim: int, form: str, *flags: str) -> dict[str, Any]:
    return {
        "type": "hijack",
        "root_as": attacker,
        "victim_as": victim,
        "form": form,
        "flags": list(flags),
    }


def type1_hijack(
    attacker: int,
    forged_origin: int,
    legal_origin: int,
    form: str,
    *flags: str,
) -> dict[str, Any]:
    return {
        "type": "hijack",
        "root_as": attacker,
        "victim_as": legal_origin,
        "forged_origin_as": forged_origin,
        "form": form,
        "flags": list(flags),
    }


def leak(
    leaking_as: int,
    targets: dict[str, list[int]],
    anchors: list[list[int]],
    *,
    secondary: list[dict[str, Any]] | None = None,
    flags: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "type": "leak",
        "root_as": leaking_as,
        "victim_as": None,
        "targets_by_prefix": targets,
        "anchor_paths": anchors,
        "secondary_exports": secondary or [],
        "flags": list(flags),
    }


SCENARIOS: dict[str, dict[str, Any]] = {
    "20080224_1800": hijack(17557, 36561, "more-specific"),
    "20140909_1356": hijack(1239, 34547, "exact-prefix"),
    "20140910_0030": hijack(57807, 52775, "exact-prefix"),
    "20151204_1930": hijack(
        203959,
        46664,
        "more-specific",
        "anomalous_prefix_already_present_before_event",
    ),
    "20160221_1000": hijack(203959, 12586, "more-specific"),
    "20180629_1300": hijack(197426, 131486, "more-specific"),
    "20251003_0057": hijack(401152, 20473, "exact-prefix"),
    "20251110_1808": hijack(205784, 210644, "exact-prefix"),
    "20251120_1240": hijack(7029, 397373, "exact-prefix"),
    "20251121_0301": hijack(834, 53850, "exact-prefix"),
    "20251203_1907": hijack(834, 214025, "exact-prefix"),

    "20150612_0843": leak(
        4788,
        {"91.213.204.0/24": [3549]},
        [[4788, 1257, 8437, 39393]],
    ),
    "20170825_0322": leak(
        15169,
        {
            "5.206.240.0/21": [701],
            "5.206.248.0/21": [701],
        },
        [[15169, 21395, 57332]],
    ),
    "20171106_1747": {
    "type": "unconfirmed",
    "root_as": 1239,
    "victim_as": None,
    "form": "valley_free_path_change",
    "flags": [
        "no_verified_valley_free_violation",
        "peer_learned_route_exported_only_to_customers",
    ],
    },
    "20190624_1030": leak(
        396531,
        {"97.107.66.0/23": [701]},
        [[396531, 33154, 3356, 393436]],
        secondary=[
            {
                "exporter": 1273,
                "learned_from": 701,
                "targets": [3333],
            }
        ],
    ),
    "20210211_0436": leak(
        28548,
        {"194.99.25.0/24": [18734]},
        [[28548, 14178, 174, 36352]],
    ),
    "20241030_1316": leak(
        49981,
        {
            "108.171.108.0/23": [
                12389, 1764, 202365, 28917, 5511, 60068
            ],
            "108.171.108.0/24": [
                12389, 1764, 202365, 28917, 60068
            ],
            "108.171.109.0/24": [
                12389, 1764, 202365, 28917, 60068
            ],
        },
        [[49981, 137409, 140952]],
    ),
    "20251114_0017": {
    "type": "unconfirmed",
    "root_as": 45489,
    "victim_as": None,
    "form": "preexisting_valley_free_path_change",
    "flags": [
        "no_verified_valley_free_violation",
        "candidate_path_present_before_event",
        "customer_learned_route_legally_exported",
    ],
    },
    "20251114_1950": leak(
        30998,
        {"102.135.220.0/24": [37662]},
        [[30998, 37148, 37088]],
        flags=("pre_withdrawal_history_used",),
    ),
    "20251120_2147": leak(
        58389,
        {
            "103.31.132.0/23": [174, 58552, 6762],
            "103.31.132.0/24": [174, 58552, 6762],
            "103.31.133.0/24": [174, 58552, 6762],
        },
        [[58389, 131749]],
    ),
    "20251203_1514": leak(
        24691,
        {"197.214.32.0/22": [174]},
        [
            [24691, 37613, 36873, 37531],
            [24691, 6939, 16637, 37531],
        ],
        flags=("multiple_ingress_paths_in_observation_window",),
    ),
    "20251227_1513": {
    "type": "unconfirmed",
    "root_as": 59257,
    "victim_as": None,
    "form": "preexisting_valley_free_path_change",
    "flags": [
        "no_verified_valley_free_violation",
        "candidate_path_present_before_event",
        "entire_observed_path_is_valley_free",
    ],
    },

    "20250921_0007": {
        "type": "recovery",
        "root_as": 32613,
        "victim_as": 14843,
        "form": "origin-recovery",
        "flags": [],
    },
    "7-20160416_fp": type1_hijack(
        203959,
        27176,
        12586,
        "type-1-more-specific",
        "fp",
        "s1_more_specific",
    ),
    "20110322_fp": type1_hijack(
        9318,
        32934,
        32934,
        "type-1-exact-prefix",
        "fp",
        "e1_exact_prefix",
        "caida_snapshot_2008_02_01",
    ),
    "20140926_fp": type1_hijack(
        6461,
        1273,
        11888,
        "type-1-exact-prefix",
        "fp",
        "origin_changed_forged_origin",
    ),
    "20160220_fp": type1_hijack(
        134830,
        203959,
        25761,
        "type-1-more-specific",
        "fp",
        "s1_more_specific",
        "covering_prefix_72_20_0_0_19",
    ),
    "20220203_fp": type1_hijack(
        6461,
        9457,
        9457,
        "type-1-more-specific",
        "fp",
        "s1_more_specific",
        "caida_snapshot_2021_02_01",
    ),
    "20220817_fp": type1_hijack(
        209243,
        14618,
        16509,
        "type-1-more-specific",
        "fp",
        "s1_more_specific",
        "caida_snapshot_2024_10_01",
    ),
    "20251202_1826": {
        "type": "unconfirmed",
        "root_as": 24323,
        "victim_as": None,
        "form": "ordinary-path-change",
        "flags": ["no_origin_change_or_verified_export_violation"],
    },
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(value, file, indent=2, sort_keys=True)


def set_option(arguments: list[str], option: str, value: str) -> None:
    try:
        index = arguments.index(option)
    except ValueError:
        arguments.extend([option, value])
    else:
        arguments[index + 1] = value
EVENT_HELPER_OPTIONS = {
    "--calibration-route-anchor-mode": "none",
    "--hijack-stage-anchor-mode": "off",
    "--hijack-export-mode": "all",
    "--leak-stage-anchor-mode": "off",
    "--pre-rib-export-tree-mode": "off",
}

def disable_event_helpers(
    arguments: list[str],
    source: str,
) -> None:
    for option, disabled_value in EVENT_HELPER_OPTIONS.items():
        if f'"{option}"' in source:
            set_option(arguments, option, disabled_value)

def import_replay(script: Path) -> Any:
    name = f"causal_{script.stem}"
    spec = importlib.util.spec_from_file_location(name, script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot import {script}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def ordinary_bgp_policy(*args: Any, **kwargs: Any) -> type[Any]:
    del args, kwargs
    from bgpy.simulation_engine import BGP
    return BGP


def install_origin_removal(module: Any) -> None:
    """Remove the event origin without injecting an alternative route."""

    original = module.build_announcements

    def build_without_event_origin(
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
        retained = tuple(
            announcement
            for announcement in announcements
            if int(announcement.seed_asn) != int(config.root_asn)
        )
        audit["causal_intervention"] = {
            "name": "event_origin_removed",
            "removed_origin_as": int(config.root_asn),
            "removed_count": len(announcements) - len(retained),
            "alternative_route_injected": False,
        }
        return retained, audit

    module.build_announcements = build_without_event_origin


def install_exact_leak_policy(
    module: Any,
    scenario: dict[str, Any],
) -> None:
    """Allow only the observed provider/peer leak exits in Case."""

    original = module.make_route_leak_policy
    exact_targets = {
        prefix: frozenset(int(asn) for asn in targets)
        for prefix, targets in scenario["targets_by_prefix"].items()
    }

    def exact_policy(
        targets_by_prefix: Any,
        target_relationships_by_prefix: Any,
    ) -> type[Any]:
        del targets_by_prefix, target_relationships_by_prefix
        return original(exact_targets, None)

    module.make_route_leak_policy = exact_policy


def install_valley_free_policy(module: Any) -> None:
    """Restore standard Gao-Rexford export at every anomalous exporter."""

    def compliant_policy(
        targets_by_prefix: Any,
        target_relationships_by_prefix: Any,
    ) -> type[Any]:
        del targets_by_prefix, target_relationships_by_prefix
        from bgpy.simulation_engine import BGPFullIgnoreInvalid
        return BGPFullIgnoreInvalid

    module.make_route_leak_policy = compliant_policy

    if hasattr(module, "make_event_export_policy"):
        module.make_event_export_policy = ordinary_bgp_policy

def install_causal_topology_validator(
    module: Any,
    scenario: dict[str, Any],
) -> None:
    """Validate clean CAIDA topology without requiring an observed export tree."""

    def relationship(
        as_graph: Any,
        local_asn: int,
        neighbor_asn: int,
    ) -> str:
        if local_asn not in as_graph.as_dict:
            return "missing-local-as"
        if neighbor_asn not in as_graph.as_dict:
            return "missing-neighbor-as"

        local_obj = as_graph.as_dict[local_asn]

        if hasattr(module, "relationship_name"):
            return str(module.relationship_name(local_obj, neighbor_asn))

        for attribute, label in (
            ("providers", "provider"),
            ("peers", "peer"),
            ("customers", "customer"),
        ):
            if any(
                int(getattr(neighbor, "asn", neighbor)) == neighbor_asn
                for neighbor in getattr(local_obj, attribute, ())
            ):
                return label

        return "not-neighbor"

    def causal_validate_topology(
        config: Any,
        resolved: dict[str, Any],
        as_graph: Any,
        topology_audit: dict[str, Any],
    ) -> None:
        required_asns = {int(config.root_asn)}

        if config.victim_asn is not None:
            required_asns.add(int(config.victim_asn))

        forged_origin = scenario.get("forged_origin_as")
        if forged_origin is not None:
            required_asns.add(int(forged_origin))

        if scenario["type"] == "leak":
            for details in resolved.get("route_leak", {}).values():
                origin_as = details.get("origin_as")
                if origin_as is not None:
                    required_asns.add(int(origin_as))

            for stage in scenario.get("secondary_exports", []):
                required_asns.add(int(stage["exporter"]))
                required_asns.add(int(stage["learned_from"]))
                required_asns.update(
                    int(asn) for asn in stage["targets"]
                )

        missing = sorted(required_asns.difference(as_graph.as_dict))
        if missing:
            raise RuntimeError(
                "Required causal-event ASNs are missing from the "
                f"historical CAIDA graph: {missing}"
            )

        checks: list[dict[str, Any]] = []

        if scenario["type"] == "leak":
            route_leak = resolved.get("route_leak", {})

            for prefix, targets in sorted(
                scenario.get("targets_by_prefix", {}).items()
            ):
                details = route_leak.get(prefix, {})
                ingress_as = details.get("origin_neighbor_as")

                ingress_relationship = (
                    relationship(
                        as_graph,
                        int(config.root_asn),
                        int(ingress_as),
                    )
                    if ingress_as is not None
                    else "unresolved"
                )

                for target_as in targets:
                    export_relationship = relationship(
                        as_graph,
                        int(config.root_asn),
                        int(target_as),
                    )
                    checks.append({
                        "prefix": prefix,
                        "stage": "root_leak",
                        "exporter_as": int(config.root_asn),
                        "learned_from_as": (
                            int(ingress_as)
                            if ingress_as is not None
                            else None
                        ),
                        "target_as": int(target_as),
                        "ingress_relationship": ingress_relationship,
                        "export_relationship": export_relationship,
                        "gao_rexford_violation": (
                            ingress_relationship in {"provider", "peer"}
                            and export_relationship in {"provider", "peer"}
                        ),
                    })

            for stage in scenario.get("secondary_exports", []):
                exporter = int(stage["exporter"])
                learned_from = int(stage["learned_from"])
                ingress_relationship = relationship(
                    as_graph,
                    exporter,
                    learned_from,
                )

                for target_as in stage["targets"]:
                    export_relationship = relationship(
                        as_graph,
                        exporter,
                        int(target_as),
                    )
                    checks.append({
                        "prefix": None,
                        "stage": "secondary_leak",
                        "exporter_as": exporter,
                        "learned_from_as": learned_from,
                        "target_as": int(target_as),
                        "ingress_relationship": ingress_relationship,
                        "export_relationship": export_relationship,
                        "gao_rexford_violation": (
                            ingress_relationship in {"provider", "peer"}
                            and export_relationship in {"provider", "peer"}
                        ),
                    })

        unresolved_names = {
            "unresolved",
            "not-neighbor",
            "missing-local-as",
            "missing-neighbor-as",
        }
        verified = [
            item for item in checks
            if item["gao_rexford_violation"]
        ]
        unresolved = [
            item for item in checks
            if item["ingress_relationship"] in unresolved_names
            or item["export_relationship"] in unresolved_names
        ]

        flags = []
        if scenario["type"] == "leak" and not verified:
            flags.append(
                "no_verified_valley_free_violation_in_caida"
            )
        if unresolved:
            flags.append("event_relationship_missing_from_caida")

        secondary_targets = {
            str(stage["exporter"]): sorted(
                int(asn) for asn in stage["targets"]
            )
            for stage in scenario.get("secondary_exports", [])
        }

        type1_audit = None
        if forged_origin is not None:
            adjacency = relationship(
                as_graph,
                int(config.root_asn),
                int(forged_origin),
            )
            type1_audit = {
                "attacker_as": int(config.root_asn),
                "forged_origin_as": int(forged_origin),
                "legal_origin_as": scenario.get("victim_as"),
                "caida_relationship": adjacency,
                "present_in_caida": adjacency != "not-neighbor",
            }
            if adjacency != "not-neighbor":
                flags.append("type1_adjacency_present_in_caida")

        topology_audit["root_as"] = int(config.root_asn)
        topology_audit["causal_validation"] = {
            "validator": "clean_historical_caida_topology",
            "rib_topology_overlay_used": False,
            "relationship_overrides_used": False,
            "observed_export_tree_required": False,
            "observed_export_tree_injected": False,
            "required_asns": sorted(required_asns),
            "missing_required_asns": [],
            "export_relationship_checks": checks,
            "verified_valley_free_violation_count": len(verified),
            "unresolved_relationship_count": len(unresolved),
            "quality_flags": flags,
            "type1_forged_adjacency": type1_audit,
        }
        topology_audit["event_relationship_verification"] = {
            "all_verified": not unresolved,
            "customer_provider": [],
            "peer": [],
        }
        topology_audit["event_constraints"] = {
            "observed_first_hop_anchors": [],
            "customer_provider_overrides": [],
            "peer_overrides": [],
            "export_targets": secondary_targets,
            "observed_export_tree_verified": False,
            "observed_export_tree_injected": False,
            "validation_semantics": (
                "full observed export tree deliberately disabled; "
                "only explicitly modeled causal secondary exports remain"
            ),
        }

    module.validate_topology = causal_validate_topology

def configure_module(
    module: Any,
    scenario: dict[str, Any],
    variant: str,
) -> None:
    event_type = scenario["type"]

    module_type = {
        "hijack": "hijack",
        "leak": "leak",
        "recovery": "recovery",
    }[event_type]

    module.CONFIG = replace(
        module.CONFIG,
        anomaly_type=module_type,
        root_asn=int(scenario["root_as"]),
        victim_asn=scenario.get("victim_as"),
    )
    if scenario.get("forged_origin_as") is not None:
        if not hasattr(module, "is_forged_origin_hijack"):
            raise RuntimeError(
                "Type-1 scenario requires a replay that implements "
                "forged-origin observation and announcement hooks"
            )
        module.HIJACK_FORM = "forged-origin"
        module.FORGED_ORIGIN_ASN = int(scenario["forged_origin_as"])
    elif hasattr(module, "HIJACK_FORM"):
        module.HIJACK_FORM = "origin"
    install_causal_topology_validator(module, scenario)

    # Never alter the historical CAIDA topology with event RIB edges.
    if hasattr(module, "EVENT_CP_OVERRIDES"):
        module.EVENT_CP_OVERRIDES = frozenset()
    if hasattr(module, "EVENT_PEER_OVERRIDES"):
        module.EVENT_PEER_OVERRIDES = frozenset()
    if hasattr(module, "EVENT_ATTACK_FIRST_HOPS"):
        module.EVENT_ATTACK_FIRST_HOPS = ()

    secondary = (
        scenario.get("secondary_exports", [])
        if event_type == "leak" and variant == "case"
        else []
    )
    secondary_targets = {
        int(stage["exporter"]): frozenset(
            int(asn) for asn in stage["targets"]
        )
        for stage in secondary
    }

    if hasattr(module, "EVENT_EXPORT_TARGETS"):
        module.EVENT_EXPORT_TARGETS = secondary_targets
    if hasattr(module, "EVENT_FORCE_EXPORT_TREE"):
        module.EVENT_FORCE_EXPORT_TREE = bool(secondary_targets)

    if event_type == "leak":
        if variant == "case":
            install_exact_leak_policy(module, scenario)
            if not secondary and hasattr(module, "make_event_export_policy"):
                module.make_event_export_policy = ordinary_bgp_policy
        else:
            install_valley_free_policy(module)
    elif variant == "counterfactual":
        install_origin_removal(module)

    if event_type != "leak" and hasattr(module, "make_event_export_policy"):
        module.make_event_export_policy = ordinary_bgp_policy


def output_directory(arguments: list[str]) -> Path:
    index = arguments.index("--output-dir")
    return Path(arguments[index + 1]).resolve()


def evaluation_digest(output_dir: Path) -> str | None:
    path = output_dir / "resolved_event_inputs.json"
    if not path.exists():
        return None

    resolved = load_json(path)
    value = {
        "observed_paths": resolved.get("observed_paths", []),
        "validation_split": resolved.get("validation_split", {}),
        "observation_selection": resolved.get("observation_selection", {}),
    }
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_no_other_routes(
    output_dir: Path,
    scenario: dict[str, Any],
    *,
    allow_legal_origin: bool = False,
) -> dict[str, Any]:
    document = load_json(output_dir / "simulation_complete.json")
    announcement_audit = document.get("announcement_audit", {})
    root_as = int(scenario["root_as"])
    allowed = {root_as}
    if allow_legal_origin and scenario.get("victim_as") is not None:
        allowed.add(int(scenario["victim_as"]))
    unexpected = []

    for item in announcement_audit.get("announcements", []):
        item_type = str(item.get("type", ""))
        seed_as = item.get("seed_as")
        if "not_seeded" in item_type:
            continue
        if seed_as is not None and int(seed_as) not in allowed:
            unexpected.append(item)

    simulation = document.get("simulation", {})
    forced_helpers = [
        key
        for key in (
            "calibration_route_anchor_count",
            "hijack_calibration_stage_used",
            "calibration_stage_anchors_used",
            "calibration_stage_forced_export_policy_used",
            "pre_rib_export_tree_used",
        )
        if simulation.get(key)
    ]

    if unexpected:
        raise RuntimeError(
            f"Unexpected non-event announcements: {unexpected}"
        )
    if forced_helpers:
        raise RuntimeError(
            "Event-calibrated export helpers remain enabled: "
            + ", ".join(forced_helpers)
        )

    return {
        "no_other_route_injected": True,
        "rib_topology_overlay_disabled": not allow_legal_origin,
        "relationship_overrides_disabled": True,
        "forced_stage_helpers_disabled": True,
        "legal_origin_allowed": allow_legal_origin,
    }


def annotate_outputs(
    output_dir: Path,
    event_id: str,
    variant: str,
    signature: str,
    audit: dict[str, Any],
    *,
    experiment_mode: str = "causal",
) -> None:
    reproduction = experiment_mode == "reproduction"
    annotation = {
        "event_id": event_id,
        "variant": variant,
        "run_signature": signature,
        "metric": PRIMARY_METRIC,
        "delta_definition": "M_case - M_counterfactual",
        "experiment_mode": experiment_mode,
        "topology": (
            "event-date CAIDA snapshot with covering-prefix pre-rib overlay "
            "and attacker observed first-hop customer links"
            if reproduction
            else "event-date CAIDA snapshot without RIB overlay"
        ),
        "legal_route_mode": "prefix-aware" if reproduction else "withdrawn",
        "path_source": "local-rib",
        "audit": audit,
    }

    for filename in (
        "simulation_complete.json",
        "similarity_vs_real_rib.json",
        "propagation_paths.json",
    ):
        path = output_dir / filename
        if not path.exists():
            continue
        document = load_json(path)
        document["causal_replay"] = annotation

        if filename == "similarity_vs_real_rib.json":
            quality = document.setdefault("evaluation_quality", {})
            flags = quality.setdefault("quality_flags", [])
            for flag in (
                "event_calibrated_causal_reconstruction",
                "no_other_legal_route_injected",
            ):
                if reproduction:
                    continue
                if flag not in flags:
                    flags.append(flag)
            if reproduction:
                for flag in (
                    "reproduction_consistency_case",
                    "covering_and_exact_prefix_aware",
                ):
                    if flag not in flags:
                        flags.append(flag)

        save_json(path, document)


def worker_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--variant", choices=("case", "counterfactual"))
    parser.add_argument("--replay-script", type=Path, required=True)
    parser.add_argument("--run-signature", required=True)
    parser.add_argument(
        "--experiment-mode",
        choices=("causal", "reproduction"),
        default="causal",
    )
    args, replay_arguments = parser.parse_known_args(argv)

    scenario = SCENARIOS[args.event_id]
    script = args.replay_script.resolve()
    module = import_replay(script)
    configure_module(module, scenario, args.variant)

    if args.experiment_mode == "causal":
        set_option(replay_arguments, "--topology-overlay-mode", "none")
        set_option(replay_arguments, "--legal-route-mode", "withdrawn")
        set_option(replay_arguments, "--path-source", "local-rib")
    else:
        set_option(replay_arguments, "--topology-overlay-mode", "pre-rib")
        set_option(replay_arguments, "--overlay-relationship-mode", "infer")
        set_option(replay_arguments, "--legal-route-mode", "prefix-aware")
        set_option(replay_arguments, "--path-source", "local-rib")

    source = script.read_text(encoding="utf-8")
    disable_event_helpers(replay_arguments, source)

    output_dir = output_directory(replay_arguments)
    sys.argv = [script.name, *replay_arguments]
    module.run_cli(module.CONFIG)

    audit = validate_no_other_routes(
        output_dir,
        scenario,
        allow_legal_origin=args.experiment_mode == "reproduction",
    )
    annotate_outputs(
        output_dir,
        args.event_id,
        args.variant,
        args.run_signature,
        audit,
        experiment_mode=args.experiment_mode,
    )
    return 0


def read_metrics(output_dir: Path) -> dict[str, Any]:
    path = output_dir / "similarity_vs_real_rib.json"
    if not path.exists():
        return {
            "available": False,
            "score": None,
            "quality_flags": ["missing_similarity_file"],
        }

    document = load_json(path)
    score = document.get("similarity", {}).get(PRIMARY_METRIC)
    quality = document.get("evaluation_quality", {})
    coverage = document.get("coverage", {})
    return {
        "available": score is not None,
        "score": score,
        "quality_flags": quality.get("quality_flags", []),
        "digest": evaluation_digest(output_dir),
        "first_hop_coverage": coverage.get("observed_first_hop_coverage"),
        "exact_match_rate": coverage.get("exact_observed_path_match_rate"),
        "receiver_coverage": coverage.get("observed_receiver_coverage"),
    }


def signature(
    script: Path,
    event_id: str,
    variant: str,
    arguments: list[str],
) -> str:
    value = {
        "driver": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "replay": hashlib.sha256(script.read_bytes()).hexdigest(),
        "scenario": SCENARIOS[event_id],
        "variant": variant,
        "arguments": arguments,
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True).encode()
    ).hexdigest()


def run_variant(
    args: argparse.Namespace,
    event_id: str,
    variant: str,
) -> dict[str, Any]:
    script = args.scripts_dir.resolve() / f"replay_{event_id}.py"
    output_dir = args.output_root.resolve() / event_id / variant

    experiment_mode = getattr(args, "experiment_mode", "causal")
    if experiment_mode == "reproduction":
        overlay_mode = "pre-rib"
        legal_mode = "prefix-aware"
    else:
        overlay_mode = "none"
        legal_mode = "withdrawn"

    replay_arguments = [
        "--events-root", str(args.events_root.resolve()),
        "--output-dir", str(output_dir),
        "--observation-mode", args.observation_mode,
        "--validation-mode", args.validation_mode,
        "--calibration-fraction", str(args.calibration_fraction),
        "--minimum-holdout-pairs", str(args.minimum_holdout_pairs),
        "--topology-overlay-mode", overlay_mode,
        "--overlay-relationship-mode", "infer",
        "--legal-route-mode", legal_mode,
        "--path-source", "local-rib",
        "--leak-target-mode", "event",
    ]

    source = script.read_text(encoding="utf-8")
    disable_event_helpers(replay_arguments, source)
    if args.caida_cache_dir:
        replay_arguments += [
            "--caida-cache-dir",
            str(args.caida_cache_dir.resolve()),
        ]
    if args.caida_file:
        replay_arguments += ["--caida-file", str(args.caida_file.resolve())]

    run_signature = signature(
        script,
        event_id,
        variant,
        replay_arguments,
    )
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        "--event-id", event_id,
        "--variant", variant,
        "--replay-script", str(script),
        "--run-signature", run_signature,
        "--experiment-mode", experiment_mode,
        *replay_arguments,
    ]

    print(f"[+] {event_id}: {variant}")
    if args.dry_run:
        print("    " + " ".join(command))
        return {"available": False, "score": None, "digest": None}

    reusable = False
    complete_path = output_dir / "simulation_complete.json"
    if args.reuse and complete_path.exists():
        annotation = load_json(complete_path).get("causal_replay", {})
        reusable = annotation.get("run_signature") == run_signature

    if not reusable:
        output_dir.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            command,
            cwd=script.parent,
            text=True,
            capture_output=True,
            check=False,
        )
        (output_dir / "run.log").write_text(
            completed.stdout + "\n" + completed.stderr,
            encoding="utf-8",
        )
        if completed.returncode:
            if args.fail_fast:
                raise RuntimeError(
                    f"{event_id}/{variant} failed:\n"
                    + (completed.stderr or completed.stdout)[-6000:]
                )
            return {
                "available": False,
                "score": None,
                "digest": None,
                "error": completed.stderr or completed.stdout,
            }

    return read_metrics(output_dir)


def mean(values: list[float]) -> float | None:
    return statistics.mean(values) if values else None


def parent_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scripts-dir", type=Path, default=Path("."))
    parser.add_argument("--events-root", type=Path, default=Path("dudata"))
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("results_causal"),
    )
    parser.add_argument("--caida-cache-dir", type=Path)
    parser.add_argument("--caida-file", type=Path)
    parser.add_argument("--event", action="append", default=[])
    parser.add_argument(
        "--observation-mode",
        choices=("receiver-last", "peak", "final", "all-updates"),
        default="receiver-last",
    )
    parser.add_argument(
        "--validation-mode",
        choices=("receiver-holdout", "all"),
        default="all",
    )
    parser.add_argument("--calibration-fraction", type=float, default=0.25)
    parser.add_argument("--minimum-holdout-pairs", type=int, default=10)
    parser.add_argument(
        "--experiment-mode",
        choices=("causal", "reproduction"),
        default="causal",
        help=(
            "causal keeps a clean CAIDA topology and withdrawn legal origin. "
            "reproduction overlays covering-prefix pre-rib edges and the "
            "attacker's observed first hop, and seeds legal origin by prefix."
        ),
    )
    parser.add_argument("--reuse", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    event_ids = args.event or sorted(SCENARIOS)
    rows = []

    for event_id in event_ids:
        scenario = SCENARIOS[event_id]

        if scenario["type"] == "unconfirmed":
            rows.append({
                "event_id": event_id,
                "event_type": "unconfirmed",
                "root_as": scenario.get("root_as"),
                "victim_as": scenario.get("victim_as"),
                "case_m": None,
                "counterfactual_m": None,
                "delta_m": None,
                "paired_evaluation": False,
                "quality_flags": scenario["flags"],
            })
            print(f"[!] {event_id}: excluded, anomaly cause unconfirmed")
            continue

        case = run_variant(args, event_id, "case")
        counterfactual = run_variant(
            args,
            event_id,
            "counterfactual",
        )

        paired = (
            case.get("digest") is not None
            and case.get("digest") == counterfactual.get("digest")
        )
        case_m = case.get("score")
        counterfactual_m = counterfactual.get("score")
        delta_m = (
            float(case_m) - float(counterfactual_m)
            if paired
            and case_m is not None
            and counterfactual_m is not None
            else None
        )

        flags = list(scenario.get("flags", []))
        flags.extend(case.get("quality_flags", []))
        if not paired:
            flags.append("case_counterfactual_evaluation_mismatch")

        rows.append({
            "event_id": event_id,
            "event_type": scenario["type"],
            "root_as": scenario["root_as"],
            "victim_as": scenario.get("victim_as"),
            "case_m": case_m,
            "counterfactual_m": counterfactual_m,
            "delta_m": delta_m,
            "paired_evaluation": paired,
            "case_first_hop_coverage": case.get("first_hop_coverage"),
            "case_exact_match_rate": case.get("exact_match_rate"),
            "case_receiver_coverage": case.get("receiver_coverage"),
            "quality_flags": sorted(set(flags)),
        })

    if args.dry_run:
        return 0

    args.output_root.mkdir(parents=True, exist_ok=True)
    csv_path = args.output_root / "causal_event_results.csv"

    fields = [
        "event_id",
        "event_type",
        "root_as",
        "victim_as",
        "case_m",
        "counterfactual_m",
        "delta_m",
        "paired_evaluation",
        "case_first_hop_coverage",
        "case_exact_match_rate",
        "case_receiver_coverage",
        "quality_flags",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            serialized = {key: row.get(key) for key in fields}
            serialized["quality_flags"] = "|".join(
                row.get("quality_flags", [])
            )
            writer.writerow(serialized)

    aggregates = {}
    for event_type in ("hijack", "leak", "recovery"):
        selected = [
            row for row in rows
            if row["event_type"] == event_type
            and row["delta_m"] is not None
        ]
        deltas = [float(row["delta_m"]) for row in selected]
        aggregates[event_type] = {
            "paired_event_count": len(selected),
            "mean_case_m": mean(
                [float(row["case_m"]) for row in selected]
            ),
            "mean_counterfactual_m": mean(
                [float(row["counterfactual_m"]) for row in selected]
            ),
            "mean_delta_m": mean(deltas),
            "median_delta_m": (
                statistics.median(deltas) if deltas else None
            ),
            "positive_delta_fraction": (
                sum(value > 0 for value in deltas) / len(deltas)
                if deltas else None
            ),
        }

    summary = {
        "primary_metric": PRIMARY_METRIC,
        "delta_definition": "M_case - M_counterfactual",
        "experiment_constraints": {
            "topology": "event-date CAIDA snapshot",
            "rib_topology_overlay": False,
            "relationship_overrides": False,
            "other_legal_routes_injected": False,
            "path_source": "local-rib",
            "leak_counterfactual_policy": "Gao-Rexford valley-free export",
        },
        "event_count": len(rows),
        "event_rows": rows,
        "aggregate_results": aggregates,
    }
    summary_path = args.output_root / "causal_summary.json"
    save_json(summary_path, summary)

    print(f"[+] Saved: {csv_path}")
    print(f"[+] Saved: {summary_path}")
    return 0


if __name__ == "__main__":
    if "--worker" in sys.argv[1:]:
        raise SystemExit(worker_main(sys.argv[1:]))
    raise SystemExit(parent_main(sys.argv[1:]))