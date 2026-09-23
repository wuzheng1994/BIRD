#!/usr/bin/env python3
"""Write root_cause_report.json from deterministic evidence.

High-confidence outage / Type-1 / leak reports are materialized without an
LLM. Ambiguous or ownership-conflict cases use a single ChatTongyi call on a
compact JSON summary (no CSV or paths.json).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

SKILL_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SKILL_DIR.parents[1]
if str(SKILL_DIR) not in sys.path:
    sys.path.insert(0, str(SKILL_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from extended_rca import (  # noqa: E402
    as_number,
    build_outage_report,
    build_type1_report,
)


CLASSIFICATION_RULES = """
Classify in this order: route_outage → type_1_hijack (E|1 / S|1) → prefix_hijack (E|0 / S|0) → route_leak → other.
Type-1 (... A V): attacker is penultimate AS A, not origin V. S|1 covering-origin change is not automatic Type-0.
Prefix hijack only if exact-prefix origin is unauthorized, or S|1 is rejected because V is unauthorized for the covering space.
Route leak only if origin is unchanged AND relationship_validation.conclusion is route_leak_candidate. Copy leak fields from that JSON only.
Missing CAIDA relationships (code 2) are uncertainty, not proof of hijack or leak.
Return a single JSON object: prefix, start_time, end_time, anomaly_type, root_cause, description.
root_cause must be a JSON object with type-specific fields, never a string.
For type_1_hijack or prefix_hijack include attacker_as and victim_as.
For route_leak include leaking_as and leak_type.
Do not invent ASNs, paths, or SQL results. If unsure, use anomaly_type other and list evidence_limitations.
""".strip()


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def dump_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def compact_candidate(candidate: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    if not candidate:
        return None
    skip = {"supporting_vps", "anomalous_paths", "score_record_indexes"}
    compact = {key: value for key, value in candidate.items() if key not in skip}
    compact["anomalous_path_count"] = len(candidate.get("anomalous_paths") or [])
    compact["supporting_vp_count"] = candidate.get("supporting_vp_count")
    return compact


def compact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    type1 = evidence.get("type_1_hijack") or {}
    outage = evidence.get("route_outage") or {}
    return {
        "classification": evidence.get("classification"),
        "input_summary": evidence.get("input_summary"),
        "route_outage": {
            "detected": outage.get("detected"),
            "available": outage.get("available"),
            "confidence": outage.get("confidence"),
        },
        "type_1_hijack": {
            "detected": type1.get("detected"),
            "ambiguous_with_route_leak": type1.get("ambiguous_with_route_leak"),
            "best_candidate": compact_candidate(type1.get("best_candidate")),
            "origin_changed_record_count": type1.get("origin_changed_record_count"),
            "same_origin_record_count": type1.get("same_origin_record_count"),
        },
    }


def compact_validation(validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "conclusion": validation.get("conclusion"),
        "path_relationships": validation.get("path_relationships"),
        "abnormal_triplet_count": validation.get("abnormal_triplet_count"),
        "route_leak_candidates": validation.get("route_leak_candidates") or [],
        "update_path": validation.get("update_path"),
        "relationship_table": validation.get("relationship_table"),
    }


def compact_ownership(ownership: dict[str, Any]) -> dict[str, Any]:
    hits = [
        query
        for query in ownership.get("queries") or []
        if query.get("asns")
    ]
    return {
        "table": ownership.get("table"),
        "network_address": ownership.get("network_address"),
        "observed_origin_as": ownership.get("observed_origin_as"),
        "legitimate_asns": ownership.get("legitimate_asns"),
        "claimed_origin_authorized": ownership.get("claimed_origin_authorized"),
        "hits": hits[:8],
    }


def origin_unchanged(evidence: dict[str, Any], validation: dict[str, Any]) -> bool:
    type1 = evidence.get("type_1_hijack") or {}
    if type1.get("origin_changed_record_count"):
        return False
    if type1.get("same_origin_record_count"):
        return True
    path = str(validation.get("update_path") or "")
    return bool(path)


def type1_victim_authorized(
    type1: dict[str, Any], ownership: dict[str, Any]
) -> Any:
    """Authorize Type-1 claimed origin V via pfx2as or historical origin."""
    best = type1.get("best_candidate") or {}
    if best.get("claimed_origin_seen_in_baseline") or best.get("origin_unchanged"):
        return True
    victim = str(best.get("victim_as") or "")
    if not victim:
        return ownership.get("claimed_origin_authorized")
    legitimate = {str(item) for item in (ownership.get("legitimate_asns") or [])}
    if victim in legitimate:
        return True
    observed = str(ownership.get("observed_origin_as") or "")
    if observed == victim:
        return ownership.get("claimed_origin_authorized")
    return False


def needs_llm(
    evidence: dict[str, Any],
    validation: dict[str, Any],
    ownership: dict[str, Any],
) -> bool:
    recommendation = (evidence.get("classification") or {}).get(
        "recommended_anomaly_type"
    )
    type1 = evidence.get("type_1_hijack") or {}
    outage = evidence.get("route_outage") or {}
    authorized = ownership.get("claimed_origin_authorized")
    if outage.get("detected"):
        return False
    if recommendation == "ambiguous" or type1.get("ambiguous_with_route_leak"):
        return True
    if type1.get("detected") and type1_victim_authorized(type1, ownership) is False:
        return True
    if recommendation == "defer_existing_route_leak_or_other":
        leak = validation.get("conclusion") == "route_leak_candidate"
        if leak and origin_unchanged(evidence, validation):
            return False
        return True
    if recommendation == "prefix_hijack" and authorized is not False:
        return True
    return False


def build_leak_report(
    evidence: dict[str, Any],
    validation: dict[str, Any],
) -> dict[str, Any]:
    candidates = validation.get("route_leak_candidates") or []
    if not candidates:
        raise ValueError("no route_leak_candidates in relationship_validation.json")
    top = candidates[0]
    triplets = [" ".join(item.get("triplet") or []) for item in candidates]
    return {
        "prefix": evidence.get("prefix"),
        "start_time": evidence.get("start_time"),
        "end_time": evidence.get("end_time"),
        "anomaly_type": "route_leak",
        "root_cause": {
            "leaking_as": as_number(top.get("leaking_as")),
            "leak_type": top.get("leak_type_label") or top.get("leak_type"),
            "abnormal_triplets": triplets,
            "leak_candidates": candidates,
            "path_relationships": validation.get("path_relationships"),
        },
        "description": (
            f"AS {top.get('leaking_as')} leaked traffic "
            f"({top.get('leak_type_label') or top.get('leak_type')}) "
            f"in triplet {' '.join(top.get('triplet') or [])}."
        ),
    }


def build_prefix_hijack_report(
    evidence: dict[str, Any],
    ownership: dict[str, Any],
) -> dict[str, Any]:
    attacker = ownership.get("observed_origin_as")
    victims = ownership.get("legitimate_asns") or []
    victim = victims[0] if victims else None
    return {
        "prefix": evidence.get("prefix"),
        "start_time": evidence.get("start_time"),
        "end_time": evidence.get("end_time"),
        "anomaly_type": "prefix_hijack",
        "root_cause": {
            "attacker_as": as_number(attacker),
            "victim_as": as_number(victim),
            "network_address": ownership.get("network_address"),
        },
        "description": (
            f"AS {attacker} announced {evidence.get('prefix')}. "
            f"The legitimate origin is AS {victim}."
        ),
    }


def build_other_report(
    evidence: dict[str, Any],
    validation: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    return {
        "prefix": evidence.get("prefix"),
        "start_time": evidence.get("start_time"),
        "end_time": evidence.get("end_time"),
        "anomaly_type": "other",
        "root_cause": {
            "update_path": validation.get("update_path"),
            "path_relationships": validation.get("path_relationships"),
            "confidence": "low",
            "evidence_limitations": [reason],
        },
        "description": reason,
    }


def deterministic_report(
    evidence: dict[str, Any],
    validation: dict[str, Any],
    ownership: dict[str, Any],
) -> Optional[dict[str, Any]]:
    recommendation = (evidence.get("classification") or {}).get(
        "recommended_anomaly_type"
    )
    type1 = evidence.get("type_1_hijack") or {}
    outage = evidence.get("route_outage") or {}
    authorized = ownership.get("claimed_origin_authorized")

    if outage.get("detected"):
        return build_outage_report(evidence)
    if type1.get("detected") and not type1.get("ambiguous_with_route_leak"):
        if type1_victim_authorized(type1, ownership) is False:
            return None
        return build_type1_report(evidence)
    if recommendation == "prefix_hijack" and authorized is False:
        return build_prefix_hijack_report(evidence, ownership)
    if (
        recommendation == "defer_existing_route_leak_or_other"
        and validation.get("conclusion") == "route_leak_candidate"
        and origin_unchanged(evidence, validation)
    ):
        return build_leak_report(evidence, validation)
    return None


def coerce_root_cause_object(
    report: dict[str, Any],
    evidence: dict[str, Any],
    validation: dict[str, Any],
    ownership: dict[str, Any],
) -> dict[str, Any]:
    """Keep LLM narrative, but always materialize root_cause as an object."""
    root = report.get("root_cause")
    narrative = ""
    if not isinstance(root, dict):
        narrative = str(root).strip() if root else ""
        root = {}

    template = None
    try:
        template = deterministic_report(evidence, validation, ownership)
    except Exception:
        template = None
    if template and isinstance(template.get("root_cause"), dict):
        for key, value in template["root_cause"].items():
            root.setdefault(key, value)

    type1 = (evidence.get("type_1_hijack") or {}).get("best_candidate") or {}
    if report.get("anomaly_type") in {"type_1_hijack", "prefix_hijack"}:
        root.setdefault("attacker_as", as_number(type1.get("attacker_as")))
        root.setdefault("victim_as", as_number(type1.get("victim_as")))
        if type1.get("hijack_subtype"):
            root.setdefault("hijack_subtype", type1.get("hijack_subtype"))
        if report.get("anomaly_type") == "prefix_hijack":
            root.setdefault("attacker_as", as_number(ownership.get("observed_origin_as")))
            victims = ownership.get("legitimate_asns") or []
            if victims:
                root.setdefault("victim_as", as_number(victims[0]))
    if report.get("anomaly_type") == "route_leak":
        candidates = validation.get("route_leak_candidates") or []
        if candidates:
            root.setdefault("leaking_as", as_number(candidates[0].get("leaking_as")))
            root.setdefault(
                "leak_type",
                candidates[0].get("leak_type_label") or candidates[0].get("leak_type"),
            )
    if report.get("anomaly_type") == "other":
        root.setdefault("origin_as", as_number(ownership.get("observed_origin_as")))
        root.setdefault("update_path", validation.get("update_path"))

    if narrative:
        root.setdefault("llm_summary", narrative)
        if not report.get("description"):
            report["description"] = narrative

    if root.get("attacker_as") is None:
        root.pop("attacker_as", None)
    if root.get("victim_as") is None:
        root.pop("victim_as", None)

    report["root_cause"] = root
    return report


def parse_llm_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", stripped, re.DOTALL)
    if fenced:
        stripped = fenced.group(1)
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("LLM response did not contain a JSON object")
    payload = json.loads(stripped[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("LLM JSON is not an object")
    return payload


def llm_report(
    evidence: dict[str, Any],
    validation: dict[str, Any],
    ownership: dict[str, Any],
    retrieve_context: str = "",
) -> dict[str, Any]:
    from llm_provider import llms, token_tracer

    token_tracer.set_stage("step_5_root_cause")
    payload = {
        "rules": CLASSIFICATION_RULES,
        "evidence": compact_evidence(evidence),
        "relationship_validation": compact_validation(validation),
        "ownership": compact_ownership(ownership),
    }
    if retrieve_context:
        payload["reference_case"] = retrieve_context[:2000]
    prompt = (
        "Produce root_cause_report.json from this summary only. "
        "Do not request more files.\n\n"
        + json.dumps(payload, ensure_ascii=False)
    )
    response = llms.invoke(prompt)
    content = getattr(response, "content", None) or str(response)
    return parse_llm_json(content)


def finalize(
    project_root: Path,
    event_name: str,
    retrieve_context: str = "",
    force_llm: bool = False,
) -> dict[str, Any]:
    event_dir = project_root / "data" / "events" / event_name
    evidence = load_json(event_dir / "root_cause_evidence.json", {})
    validation = load_json(event_dir / "relationship_validation.json", {})
    ownership = load_json(event_dir / "ownership.json", {})
    event_meta = load_json(project_root / "event.json", {})
    if event_meta.get("event_name") == event_name:
        evidence.setdefault("prefix", event_meta.get("prefix"))
        evidence.setdefault("start_time", event_meta.get("start_time"))
        evidence.setdefault("end_time", event_meta.get("end_time"))

    used_llm = False
    if force_llm or needs_llm(evidence, validation, ownership):
        try:
            report = llm_report(evidence, validation, ownership, retrieve_context)
            used_llm = True
        except Exception as exc:
            report = build_other_report(
                evidence,
                validation,
                f"LLM finalize failed ({exc}); conserved as other.",
            )
            used_llm = True
    else:
        report = deterministic_report(evidence, validation, ownership)
        if report is None:
            report = build_other_report(
                evidence,
                validation,
                "Insufficient deterministic evidence for a named anomaly type.",
            )

    report["prefix"] = report.get("prefix") or evidence.get("prefix")
    report["start_time"] = report.get("start_time") or evidence.get("start_time")
    report["end_time"] = report.get("end_time") or evidence.get("end_time")
    report = coerce_root_cause_object(report, evidence, validation, ownership)
    rels = validation.get("path_relationships")
    root_cause = report.get("root_cause")
    if rels is not None and isinstance(root_cause, dict):
        root_cause.setdefault("path_relationships", rels)

    output = event_dir / "root_cause_report.json"
    dump_json(output, report)
    print(f"Saved root cause report to {output}")
    print(f"anomaly_type={report.get('anomaly_type')} llm={used_llm}")

    try:
        from llm_provider import token_tracer

        token_path = event_dir / "token_usage_report.json"
        token_tracer.write_report(token_path)
        summary = {
            "input_tokens": sum(call.get("input_tokens", 0) for call in token_tracer.calls),
            "output_tokens": sum(call.get("output_tokens", 0) for call in token_tracer.calls),
            "total_tokens": sum(call.get("total_tokens", 0) for call in token_tracer.calls),
        }
        print(
            f"token_usage input={summary['input_tokens']} "
            f"output={summary['output_tokens']} "
            f"total={summary['total_tokens']} "
            f"calls={len(token_tracer.calls)}"
        )
        print(f"Token report saved to {token_path}")
    except Exception as exc:
        print(f"[token] skipped: {exc}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Finalize root_cause_report.json from evidence JSONs"
    )
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--project-root", default=None)
    parser.add_argument("--retrieve-context", default="")
    parser.add_argument("--force-llm", action="store_true")
    args = parser.parse_args()
    project_root = (
        Path(args.project_root).resolve()
        if args.project_root
        else PROJECT_ROOT
    )
    finalize(
        project_root,
        args.event_name,
        retrieve_context=args.retrieve_context,
        force_llm=args.force_llm,
    )


if __name__ == "__main__":
    main()
