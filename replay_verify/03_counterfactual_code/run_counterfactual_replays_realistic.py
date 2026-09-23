#!/usr/bin/env python3
"""Realistic counterfactual replay with the original causal Case fixed.

Case:
- Uses run_causal_replays.py without changing its simulation.
- Uses validation-mode=all, topology-overlay-mode=none,
  legal-route-mode=withdrawn, and path-source=local-rib.
- Excludes the four unconfirmed events defined by the causal driver.

Counterfactual:
- Removes the anomalous origin for hijack/recovery events.
- Restores Gao-Rexford export for leak events.
- Retains only legal origins verified before the event.
- Uses the same observations and primary metric as Case.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import sys
from pathlib import Path
from typing import Any, Sequence

import run_causal_replays as base


BASELINE_VERSION = 7
PRIMARY_METRIC = base.PRIMARY_METRIC


def before_origin_counts(
    resolved: dict[str, Any],
) -> dict[str, int]:
    return {
        str(asn): int(count)
        for asn, count in (
            resolved.get("origin_audit", {})
            .get("before_unique_path_origins", {})
            .items()
        )
    }


def baseline_specifications(
    config: Any,
    resolved: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Return one pre-event legal route per anomalous prefix."""

    counts = before_origin_counts(resolved)
    anomalous_prefixes = [
        str(prefix)
        for prefix in resolved.get("anomalous_prefixes", [])
    ]
    specifications: dict[str, dict[str, Any]] = {}

    if config.anomaly_type == "hijack":
        if config.victim_asn is None:
            return specifications

        origin_as = int(config.victim_asn)
        if counts.get(str(origin_as), 0) <= 0:
            return specifications

        victim_prefixes = (
            resolved.get("hijack", {})
            .get("victim_prefix_by_anomalous_prefix", {})
        )

        for anomalous_prefix in anomalous_prefixes:
            route_prefix = str(
                victim_prefixes.get(
                    anomalous_prefix,
                    anomalous_prefix,
                )
            )
            specifications[anomalous_prefix] = {
                "anomalous_prefix": anomalous_prefix,
                "route_prefix": route_prefix,
                "origin_as": origin_as,
                "source": "rib_before_incident.csv",
                "before_path_count": counts[str(origin_as)],
                "covering_prefix_fallback": (
                    route_prefix != anomalous_prefix
                ),
                "hijack_form": resolved.get("hijack", {}).get(
                    "hijack_form"
                ),
                "type1_forged_origin_as": resolved.get(
                    "hijack", {}
                ).get("forged_origin_as"),
            }

    elif config.anomaly_type == "recovery":
        if config.victim_asn is None:
            return specifications

        origin_as = int(config.victim_asn)
        if counts.get(str(origin_as), 0) <= 0:
            return specifications

        for anomalous_prefix in anomalous_prefixes:
            specifications[anomalous_prefix] = {
                "anomalous_prefix": anomalous_prefix,
                "route_prefix": anomalous_prefix,
                "origin_as": origin_as,
                "source": "rib_before_incident.csv",
                "before_path_count": counts[str(origin_as)],
                "covering_prefix_fallback": False,
            }

    elif config.anomaly_type == "leak":
        route_leak = resolved.get("route_leak", {})

        for anomalous_prefix in anomalous_prefixes:
            details = route_leak.get(anomalous_prefix, {})
            origin_as = details.get("origin_as")

            if origin_as is None:
                continue

            origin_as = int(origin_as)
            if counts.get(str(origin_as), 0) <= 0:
                continue

            specifications[anomalous_prefix] = {
                "anomalous_prefix": anomalous_prefix,
                "route_prefix": anomalous_prefix,
                "origin_as": origin_as,
                "source": "rib_before_incident.csv",
                "before_path_count": counts[str(origin_as)],
                "covering_prefix_fallback": False,
            }

    return specifications


def install_pre_event_legal_baseline(
    module: Any,
    scenario: dict[str, Any],
) -> None:
    """Retain only the corrected event route and legal baseline."""

    original = module.build_announcements

    def build_counterfactual(
        config: Any,
        resolved: dict[str, Any],
        as_graph: Any,
        **kwargs: Any,
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        from bgpy.shared.enums import Relationships, Timestamps
        from bgpy.simulation_engine import Announcement

        specifications = baseline_specifications(
            config,
            resolved,
        )
        anomalous_prefixes = {
            str(prefix)
            for prefix in resolved.get(
                "anomalous_prefixes",
                [],
            )
        }
        complete = (
            bool(anomalous_prefixes)
            and set(specifications) == anomalous_prefixes
        )

        # The native replay constructs its legal origin when possible.
        kwargs["legal_route_mode"] = "always"

        announcements, audit = original(
            config,
            resolved,
            as_graph,
            **kwargs,
        )

        root_as = int(config.root_asn)
        keep_corrected_root = scenario["type"] == "leak"

        legal_keys = {
            (
                str(specification["route_prefix"]),
                int(specification["origin_as"]),
            )
            for specification in specifications.values()
        }

        retained: list[Any] = []

        for announcement in announcements:
            seed_as = int(announcement.seed_asn)
            key = (
                str(announcement.prefix),
                seed_as,
            )

            if keep_corrected_root and seed_as == root_as:
                retained.append(announcement)
            elif key in legal_keys:
                retained.append(announcement)

        existing = {
            (
                str(announcement.prefix),
                int(announcement.seed_asn),
            )
            for announcement in retained
        }
        inserted: list[dict[str, Any]] = []

        for specification in specifications.values():
            key = (
                str(specification["route_prefix"]),
                int(specification["origin_as"]),
            )
            if key in existing:
                continue

            origin_as = int(specification["origin_as"])
            retained.append(
                Announcement(
                    prefix=str(specification["route_prefix"]),
                    as_path=(origin_as,),
                    seed_asn=origin_as,
                    next_hop_asn=origin_as,
                    recv_relationship=Relationships.ORIGIN,
                    timestamp=Timestamps.VICTIM.value,
                )
            )
            existing.add(key)
            inserted.append({
                "prefix": str(
                    specification["route_prefix"]
                ),
                "anomalous_prefix": str(
                    specification["anomalous_prefix"]
                ),
                "seed_as": origin_as,
                "type": (
                    "counterfactual_pre_event_legal_origin"
                ),
                "source": "rib_before_incident.csv",
            })

        retained_announcements = [
            {
                "prefix": str(announcement.prefix),
                "seed_as": int(announcement.seed_asn),
            }
            for announcement in retained
        ]

        baseline = {
            "version": BASELINE_VERSION,
            "available": complete,
            "complete_prefix_coverage": complete,
            "specification_count": len(specifications),
            "required_prefix_count": len(
                anomalous_prefixes
            ),
            "specifications": list(
                specifications.values()
            ),
            "inserted_announcement_count": len(
                inserted
            ),
            "retained_announcements": (
                retained_announcements
            ),
            "corrected_root_retained": (
                keep_corrected_root
            ),
            "removed_anomalous_root": (
                not keep_corrected_root
            ),
            "post_event_evaluation_paths_used": False,
            "topology_overlay_added": False,
        }

        audit.setdefault(
            "announcements",
            [],
        ).extend(inserted)

        audit["counterfactual_legal_baseline"] = (
            baseline
        )
        audit["counterfactual_intervention"] = {
            "name": (
                "gao_rexford_export_restored"
                if keep_corrected_root
                else "anomalous_origin_removed"
            ),
            "root_as": root_as,
            "pre_event_legal_baseline": baseline,
        }

        return tuple(retained), audit

    module.build_announcements = build_counterfactual


def install_baseline_path_extractor(
    module: Any,
) -> None:
    """Extract selected legal paths for the original destination."""

    def extract_baseline_paths(
        config: Any,
        resolved: dict[str, Any],
        engine: Any,
        *,
        leak_target_mode: Any,
        path_source: str,
    ) -> dict[str, Any]:
        del leak_target_mode

        if path_source != "local-rib":
            raise RuntimeError(
                "The original causal Case requires "
                "--path-source local-rib"
            )

        specifications = baseline_specifications(
            config,
            resolved,
        )
        required_prefixes = [
            str(prefix)
            for prefix in resolved.get(
                "anomalous_prefixes",
                [],
            )
        ]

        prefix_results: dict[str, Any] = {}
        selected_by_prefix: dict[str, int] = {}

        for anomalous_prefix in required_prefixes:
            specification = specifications.get(
                anomalous_prefix
            )
            simulated_paths: list[dict[str, Any]] = []

            if specification is not None:
                route_prefix = str(
                    specification["route_prefix"]
                )
                origin_as = int(
                    specification["origin_as"]
                )

                for receiver_as, as_obj in sorted(
                    engine.as_graph.as_dict.items()
                ):
                    announcement = (
                        as_obj.policy.local_rib.get(
                            route_prefix
                        )
                    )
                    if announcement is None:
                        continue

                    announcement_origin = int(
                        getattr(
                            announcement,
                            "origin",
                            announcement.as_path[-1],
                        )
                    )
                    if announcement_origin != origin_as:
                        continue

                    full_path = [
                        int(asn)
                        for asn in reversed(
                            announcement.as_path
                        )
                    ]
                    if origin_as not in full_path:
                        continue

                    origin_index = full_path.index(
                        origin_as
                    )
                    propagation_path = full_path[
                        origin_index:
                    ]

                    if (
                        not propagation_path
                        or propagation_path[0] != origin_as
                        or int(receiver_as) == origin_as
                    ):
                        continue

                    simulated_paths.append({
                        "prefix": anomalous_prefix,
                        "route_prefix": route_prefix,
                        "receiver_as": int(receiver_as),
                        "as_path_view": [
                            int(asn)
                            for asn
                            in announcement.as_path
                        ],
                        "full_propagation_path": (
                            full_path
                        ),
                        "anomalous_propagation_path": (
                            propagation_path
                        ),
                        "first_hop_after_root": (
                            propagation_path[1]
                            if len(propagation_path) > 1
                            else None
                        ),
                        "first_hop_allowed_by_event_constraint": True,
                        "event_constraint_available": False,
                        "path_source": path_source,
                        "counterfactual_origin_as": (
                            origin_as
                        ),
                        "counterfactual_route_prefix": (
                            route_prefix
                        ),
                        "counterfactual_path_role": (
                            "pre_event_legal_baseline"
                        ),
                    })

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

            selected_by_prefix[anomalous_prefix] = (
                len(simulated_paths)
            )
            root_as = int(config.root_asn)
            via_root_count = sum(
                root_as in path
                for path in path_lists
            )

            prefix_results[anomalous_prefix] = {
                "summary": {
                    "reachable_as_count": len(
                        simulated_paths
                    ),
                    "selected_route_via_root_count": (
                        via_root_count
                    ),
                    "selected_route_via_legal_origin_count": (
                        len(simulated_paths)
                    ),
                    "anomalous_receiver_count": len(
                        simulated_paths
                    ),
                    "anomalous_node_count": len(nodes),
                    "anomalous_edge_count": len(edges),
                    "counterfactual_baseline_available": (
                        specification is not None
                        and bool(simulated_paths)
                    ),
                },
                "paths": simulated_paths,
                "nodes": sorted(nodes),
                "edges": [
                    {
                        "src": int(source),
                        "dst": int(destination),
                    }
                    for source, destination
                    in sorted(edges)
                ],
            }

        complete = (
            bool(required_prefixes)
            and set(specifications)
            == set(required_prefixes)
            and all(
                selected_by_prefix.get(prefix, 0) > 0
                for prefix in required_prefixes
            )
        )

        return {
            "prefixes": prefix_results,
            "root_advertisements": [],
            "leak_target_mode": "not_applicable",
            "path_source": "local-rib",
            "path_selection": (
                "final_selected_pre_event_legal_route"
            ),
            "counterfactual_baseline": {
                "version": BASELINE_VERSION,
                "available": complete,
                "complete_prefix_coverage": complete,
                "specification_count": len(
                    specifications
                ),
                "required_prefix_count": len(
                    required_prefixes
                ),
                "selected_route_count": sum(
                    selected_by_prefix.values()
                ),
                "selected_route_count_by_prefix": (
                    selected_by_prefix
                ),
                "source": "rib_before_incident.csv",
                "covering_prefix_fallback_enabled": True,
                "post_event_evaluation_paths_used": False,
            },
        }

    module.extract_simulation_paths = (
        extract_baseline_paths
    )


def configure_counterfactual(
    module: Any,
    scenario: dict[str, Any],
) -> None:
    # This installs origin removal or Gao-Rexford restoration.
    base.configure_module(
        module,
        scenario,
        "counterfactual",
    )

    # This retains only the verified pre-event legal baseline.
    install_pre_event_legal_baseline(
        module,
        scenario,
    )
    install_baseline_path_extractor(module)


def validate_counterfactual(
    output_dir: Path,
    scenario: dict[str, Any],
) -> dict[str, Any]:
    document = base.load_json(
        output_dir / "simulation_complete.json"
    )

    simulation = document.get("simulation", {})
    baseline = simulation.get(
        "counterfactual_baseline",
        {},
    )
    announcement_baseline = (
        document.get("announcement_audit", {})
        .get("counterfactual_legal_baseline", {})
    )

    allowed_seed_asns = {
        int(specification["origin_as"])
        for specification
        in announcement_baseline.get(
            "specifications",
            [],
        )
    }

    if scenario["type"] == "leak":
        allowed_seed_asns.add(
            int(scenario["root_as"])
        )

    unexpected = [
        item
        for item
        in announcement_baseline.get(
            "retained_announcements",
            [],
        )
        if int(item["seed_as"])
        not in allowed_seed_asns
    ]

    if unexpected:
        raise RuntimeError(
            "Unexpected counterfactual announcements: "
            f"{unexpected}"
        )

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

    if forced_helpers:
        raise RuntimeError(
            "Event-calibrated export helpers remain enabled: "
            + ", ".join(forced_helpers)
        )

    return {
        "pre_event_legal_baseline": baseline,
        "baseline_available": bool(
            baseline.get("available")
        ),
        "allowed_seed_asns": sorted(
            allowed_seed_asns
        ),
        "rib_topology_overlay_disabled": True,
        "relationship_overrides_disabled": True,
        "forced_stage_helpers_disabled": True,
        "post_event_evaluation_paths_used": False,
    }


def annotate_counterfactual(
    output_dir: Path,
    event_id: str,
    signature: str,
    audit: dict[str, Any],
) -> None:
    baseline = audit.get(
        "pre_event_legal_baseline",
        {},
    )
    available = bool(baseline.get("available"))

    annotation = {
        "event_id": event_id,
        "variant": "counterfactual",
        "run_signature": signature,
        "metric": PRIMARY_METRIC,
        "delta_definition": (
            "M_case - M_counterfactual"
        ),
        "topology": (
            "event-date CAIDA snapshot without RIB overlay"
        ),
        "legal_route_mode": "always",
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

        document = base.load_json(path)
        document["causal_replay"] = annotation
        document["counterfactual_experiment"] = {
            "counterfactual_baseline": baseline,
            "intervention_validated": available,
        }

        if filename == "similarity_vs_real_rib.json":
            quality = document.setdefault(
                "evaluation_quality",
                {},
            )
            flags = quality.setdefault(
                "quality_flags",
                [],
            )

            for flag in (
                "pre_event_counterfactual_baseline",
                "counterfactual_longest_prefix_match_enabled",
                "counterfactual_post_event_paths_not_used",
                "single_full_selected_route_metric",
            ):
                if flag not in flags:
                    flags.append(flag)

            quality["counterfactual_baseline"] = (
                baseline
            )

            if not available:
                document["available"] = False
                document.setdefault(
                    "similarity",
                    {},
                )[PRIMARY_METRIC] = None

                unavailable_flag = (
                    "counterfactual_baseline_unavailable"
                )
                if unavailable_flag not in flags:
                    flags.append(unavailable_flag)

        base.save_json(path, document)


def worker_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        add_help=False
    )
    parser.add_argument(
        "--worker",
        action="store_true",
    )
    parser.add_argument(
        "--event-id",
        required=True,
    )
    parser.add_argument(
        "--variant",
        choices=("case", "counterfactual"),
        required=True,
    )
    parser.add_argument(
        "--replay-script",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--run-signature",
        required=True,
    )

    args, replay_arguments = parser.parse_known_args(
        list(argv)
    )

    scenario = base.SCENARIOS[args.event_id]
    script = args.replay_script.resolve()
    module = base.import_replay(script)

    if args.variant == "case":
        # This is the original screenshot Case configuration.
        base.configure_module(
            module,
            scenario,
            "case",
        )
        legal_route_mode = "withdrawn"
    else:
        configure_counterfactual(
            module,
            scenario,
        )
        legal_route_mode = "always"

    base.set_option(
        replay_arguments,
        "--topology-overlay-mode",
        "none",
    )
    base.set_option(
        replay_arguments,
        "--legal-route-mode",
        legal_route_mode,
    )
    base.set_option(
        replay_arguments,
        "--path-source",
        "local-rib",
    )

    source = script.read_text(encoding="utf-8")
    base.disable_event_helpers(
        replay_arguments,
        source,
    )

    output_dir = base.output_directory(
        replay_arguments
    )

    sys.argv = [
        script.name,
        *replay_arguments,
    ]
    module.run_cli(module.CONFIG)

    if args.variant == "case":
        audit = base.validate_no_other_routes(
            output_dir,
            scenario,
        )
        base.annotate_outputs(
            output_dir,
            args.event_id,
            "case",
            args.run_signature,
            audit,
        )
    else:
        audit = validate_counterfactual(
            output_dir,
            scenario,
        )
        annotate_counterfactual(
            output_dir,
            args.event_id,
            args.run_signature,
            audit,
        )

    return 0


def argument_value(
    arguments: Sequence[str],
    option: str,
    default: str,
) -> str:
    values = list(arguments)

    try:
        index = values.index(option)
    except ValueError:
        return default

    if index + 1 >= len(values):
        raise RuntimeError(
            f"Missing value for {option}"
        )

    return str(values[index + 1])


def remove_custom_option(
    arguments: list[str],
    option: str,
) -> str | None:
    if option not in arguments:
        return None

    index = arguments.index(option)
    if index + 1 >= len(arguments):
        raise RuntimeError(
            f"Missing value for {option}"
        )

    value = arguments[index + 1]
    del arguments[index:index + 2]
    return value


def find_summary(root: Path) -> Path:
    for name in (
        "causal_summary.json",
        "counterfactual_summary.json",
    ):
        candidate = root / name
        if candidate.exists():
            return candidate

    raise RuntimeError(
        f"No summary JSON found under {root}"
    )


def assert_case_unchanged(
    new_root: Path,
    reference_root: Path,
    tolerance: float,
) -> None:
    new_summary = base.load_json(
        find_summary(new_root)
    )
    reference_summary = base.load_json(
        find_summary(reference_root)
    )

    new_rows = {
        str(row["event_id"]): row
        for row in new_summary.get(
            "event_rows",
            [],
        )
        if row.get("event_type") != "unconfirmed"
    }
    reference_rows = {
        str(row["event_id"]): row
        for row in reference_summary.get(
            "event_rows",
            [],
        )
        if row.get("event_type") != "unconfirmed"
    }

    mismatches: list[str] = []

    # A smoke run may contain only a subset of reference events.
    for event_id, new_row in new_rows.items():
        reference_row = reference_rows.get(
            event_id
        )

        if reference_row is None:
            mismatches.append(
                f"{event_id}: missing reference Case"
            )
            continue

        new_score = new_row.get("case_m")
        reference_score = reference_row.get(
            "case_m"
        )

        if (
            new_score is None
            or reference_score is None
            or abs(
                float(new_score)
                - float(reference_score)
            ) > tolerance
        ):
            mismatches.append(
                f"{event_id}: "
                f"new={new_score}, "
                f"reference={reference_score}"
            )

        new_digest = base.evaluation_digest(
            new_root / event_id / "case"
        )
        reference_digest = base.evaluation_digest(
            reference_root / event_id / "case"
        )

        if (
            new_digest is None
            or reference_digest is None
            or new_digest != reference_digest
        ):
            mismatches.append(
                f"{event_id}: evaluation digest changed"
            )

    if mismatches:
        raise RuntimeError(
            "Case regression check failed:\n"
            + "\n".join(mismatches)
        )


def enrich_summary(
    output_root: Path,
) -> None:
    causal_path = (
        output_root / "causal_summary.json"
    )
    summary = base.load_json(causal_path)

    for row in summary.get("event_rows", []):
        if row.get("event_type") == "unconfirmed":
            continue

        event_id = str(row["event_id"])
        metrics_path = (
            output_root
            / event_id
            / "counterfactual"
            / "similarity_vs_real_rib.json"
        )

        if not metrics_path.exists():
            continue

        metrics = base.load_json(metrics_path)
        quality = metrics.get(
            "evaluation_quality",
            {},
        )
        baseline = quality.get(
            "counterfactual_baseline",
            {},
        )

        row[
            "counterfactual_baseline_available"
        ] = bool(baseline.get("available"))

        row[
            "counterfactual_receiver_coverage"
        ] = (
            metrics.get("coverage", {})
            .get("observed_receiver_coverage")
        )

        row["quality_flags"] = sorted(
            set(
                list(row.get("quality_flags", []))
                + list(
                    quality.get(
                        "quality_flags",
                        [],
                    )
                )
            )
        )

    summary["counterfactual_baseline"] = {
        "version": BASELINE_VERSION,
        "source": "rib_before_incident.csv",
        "legal_origin_must_be_pre_event_verified": True,
        "covering_prefix_fallback": True,
        "post_event_evaluation_paths_used": False,
        "case_construction_changed": False,
        "case_driver": "run_causal_replays.py",
        "primary_metric": PRIMARY_METRIC,
    }

    base.save_json(causal_path, summary)
    base.save_json(
        output_root
        / "counterfactual_summary.json",
        summary,
    )

    fields = [
        "event_id",
        "event_type",
        "root_as",
        "victim_as",
        "case_m",
        "counterfactual_m",
        "delta_m",
        "paired_evaluation",
        "counterfactual_baseline_available",
        "counterfactual_receiver_coverage",
        "quality_flags",
    ]

    csv_path = (
        output_root / "causal_event_results.csv"
    )

    with csv_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
        )
        writer.writeheader()

        for row in summary.get(
            "event_rows",
            [],
        ):
            serialized = {
                key: row.get(key)
                for key in fields
            }
            serialized["quality_flags"] = "|".join(
                row.get("quality_flags", [])
            )
            writer.writerow(serialized)

    shutil.copyfile(
        csv_path,
        output_root
        / "counterfactual_event_results.csv",
    )


def main(argv: Sequence[str]) -> int:
    arguments = list(argv)

    if "--worker" in arguments:
        return worker_main(arguments)

    reference_value = remove_custom_option(
        arguments,
        "--case-reference-root",
    )
    tolerance_value = remove_custom_option(
        arguments,
        "--case-tolerance",
    )

    tolerance = (
        float(tolerance_value)
        if tolerance_value is not None
        else 1e-12
    )

    validation_mode = argument_value(
        arguments,
        "--validation-mode",
        "all",
    )

    if validation_mode != "all":
        raise RuntimeError(
            "The screenshot Case used "
            "--validation-mode all; changing it "
            "would change M_case"
        )

    if (
        reference_value is None
        and "--dry-run" not in arguments
    ):
        raise RuntimeError(
            "--case-reference-root is required "
            "to guarantee the original M_case"
        )

    # base.run_variant must launch this patched entry point.
    base.__file__ = str(
        Path(__file__).resolve()
    )

    result = base.parent_main(arguments)

    if "--dry-run" in arguments:
        return result

    output_root = Path(
        argument_value(
            arguments,
            "--output-root",
            "results_causal",
        )
    ).resolve()

    enrich_summary(output_root)

    assert reference_value is not None
    assert_case_unchanged(
        output_root,
        Path(reference_value).resolve(),
        tolerance,
    )

    print(
        "[+] Original Case regression check passed: "
        f"tolerance={tolerance}"
    )
    print(
        "[+] Saved: "
        + str(
            output_root
            / "counterfactual_event_results.csv"
        )
    )
    print(
        "[+] Saved: "
        + str(
            output_root
            / "counterfactual_summary.json"
        )
    )

    return result


if __name__ == "__main__":
    raise SystemExit(
        main(sys.argv[1:])
    )