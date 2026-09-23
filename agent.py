#!/usr/bin/env python3
"""Script-first BGP RCA runner. LLM is used only for ambiguous root-cause cases."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional


_root = Path(__file__).resolve().parent
_skills = _root / "skills"

stage_durations: dict[str, float] = {}
_tracer: Any = None


class _NullTracer:
    def reset(self) -> None:
        return None

    def set_stage(self, stage: str) -> None:
        return None

    def write_report(self, path: Path) -> None:
        dump_json(
            Path(path),
            {
                "summary": {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                },
                "by_stage": {},
                "calls": [],
            },
        )


def load_tracer():
    try:
        from llm_provider import token_tracer

        return token_tracer
    except Exception:
        return _NullTracer()


def dump_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def event_name_from_start(start_time: str) -> str:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(start_time, fmt).strftime("%Y%m%d_%H%M")
        except ValueError:
            continue
    raise ValueError(f"cannot parse start_time: {start_time!r}")


def timed(stage_name: str, fn: Callable[[], Any]) -> Any:
    if _tracer is not None:
        _tracer.set_stage(stage_name)
    start = time.perf_counter()
    try:
        return fn()
    finally:
        elapsed = time.perf_counter() - start
        stage_durations[stage_name] = round(elapsed, 2)
        print(f"[{stage_name}] finished in {elapsed:.2f}s")


def run_python(script: Path, extra_args: Optional[list[str]] = None) -> None:
    cmd = [sys.executable, str(script), *(extra_args or [])]
    result = subprocess.run(cmd, cwd=str(_root))
    if result.returncode != 0:
        raise RuntimeError(f"{script.name} exited with {result.returncode}")


def write_event(prefix: str, start_time: str, end_time: str, event_name: str) -> Path:
    event_dir = _root / "data" / "events" / event_name
    event_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "prefix": prefix,
        "start_time": start_time,
        "end_time": end_time,
        "event_name": event_name,
    }
    dump_json(_root / "event.json", payload)
    print(f"Wrote event.json and {event_dir}")
    return event_dir


FORCE_RERUN_FILES = (
    "history_rib.csv",
    "rib_before_incident.csv",
    "rib_after_incident.csv",
    "paths.json",
    "score.json",
    "root_cause_evidence.json",
    "relationship_validation.json",
    "ownership.json",
    "root_cause_report.json",
    "token_usage_report.json",
    "token_usage_step_5a.json",
    "token_usage_step_5d.json",
)

PIPELINE_STAGES = (
    "step_1_create_event",
    "step_2_data_process",
    "step_3_detect_path_change",
    "step_4_path_score",
    "step_5_root_cause",
    "step_5a_retrieve",
    "step_5d_archive_case",
    "step_6_propagation",
    "step_7_replay_verify",
)


def clear_event_outputs(event_dir: Path) -> None:
    event_dir.mkdir(parents=True, exist_ok=True)
    removed = []
    for name in FORCE_RERUN_FILES:
        path = event_dir / name
        if path.exists():
            path.unlink()
            removed.append(name)
    if removed:
        print(f"[force] removed {', '.join(removed)}")
    else:
        print("[force] no existing step outputs to remove")


def merge_token_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    calls: list[dict[str, Any]] = []
    for report in reports:
        if isinstance(report, dict):
            calls.extend(report.get("calls") or [])
    by_stage: dict[str, dict[str, int]] = {
        stage: {"calls": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
        for stage in PIPELINE_STAGES
    }
    for call in calls:
        stage = str(call.get("stage") or "planning")
        if stage not in by_stage:
            by_stage[stage] = {
                "calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
            }
        by_stage[stage]["calls"] += 1
        by_stage[stage]["input_tokens"] += int(call.get("input_tokens") or 0)
        by_stage[stage]["output_tokens"] += int(call.get("output_tokens") or 0)
        by_stage[stage]["total_tokens"] += int(call.get("total_tokens") or 0)
    summary = {
        "input_tokens": sum(item["input_tokens"] for item in by_stage.values()),
        "output_tokens": sum(item["output_tokens"] for item in by_stage.values()),
        "total_tokens": sum(item["total_tokens"] for item in by_stage.values()),
    }
    return {"summary": summary, "by_stage": by_stage, "calls": calls}


def csvs_ready(event_dir: Path) -> bool:
    names = ("history_rib.csv", "rib_before_incident.csv", "rib_after_incident.csv")
    return all((event_dir / name).exists() for name in names)


def optional_retrieve(event_name: str, token_report: Optional[Path] = None) -> str:
    scores = load_json(_root / "data" / "events" / event_name / "score.json", [])
    event = load_json(_root / "event.json", {})
    year = str(event.get("start_time") or "")[:4]
    prefix = event.get("prefix") or ""
    path = ""
    if isinstance(scores, list) and scores:
        path = str(scores[0].get("update_path") or "")
    if not (year.isdigit() and prefix and path):
        print("[retrieve] skipped: missing year, prefix, or update_path")
        return ""
    cmd = [
        sys.executable,
        str(_skills / "root-cause-analysis" / "retrieve.py"),
        "--year",
        year,
        "--prefix",
        prefix,
        "--anomaly-path",
        path,
        "-k",
        "1",
    ]
    if token_report is not None:
        cmd.extend(["--token-report", str(token_report)])
    result = subprocess.run(cmd, cwd=str(_root), capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[retrieve] failed: {result.stderr.strip() or result.stdout.strip()}")
        return ""
    return (result.stdout or "").strip()


def replay_modes(args: argparse.Namespace) -> list[str]:
    modes = []
    if args.replay:
        modes.append("replay")
    if args.causal:
        modes.append("causal")
    if args.counterfactual:
        modes.append("counterfactual")
    if args.verify:
        modes.append("verify")
    if args.replay_only and not modes:
        modes.append("replay")
    return modes


def run_replay_verify(event_name: str, args: argparse.Namespace) -> None:
    modes = replay_modes(args)
    if not modes:
        return
    extra = ["--event-name", event_name, "--project-root", str(_root)]
    for mode in modes:
        extra.extend(["--mode", mode])
    extra.extend(["--path-source", args.path_source])
    if args.dry_run:
        extra.append("--dry-run")
    run_python(_root / "replay_verify" / "invoke.py", extra)


def resolve_event_args(args: argparse.Namespace) -> dict[str, str]:
    existing = load_json(_root / "event.json", {})
    prefix = args.prefix or existing.get("prefix")
    start_time = args.start_time or existing.get("start_time")
    end_time = args.end_time or existing.get("end_time")
    if not prefix or not start_time or not end_time:
        raise SystemExit(
            "prefix, start_time, and end_time are required "
            "(via flags or existing event.json)"
        )
    event_name = args.event_name or existing.get("event_name")
    if not event_name:
        event_name = event_name_from_start(start_time)
    return {
        "prefix": str(prefix),
        "start_time": str(start_time),
        "end_time": str(end_time),
        "event_name": str(event_name),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the BGP RCA pipeline with scripts first; LLM only if needed"
    )
    parser.add_argument("--prefix")
    parser.add_argument("--start-time")
    parser.add_argument("--end-time")
    parser.add_argument("--event-name")
    parser.add_argument(
        "--archive",
        action="store_true",
        help="Index root_cause_report.json into Chroma (Step 5d)",
    )
    parser.add_argument(
        "--retrieve",
        action="store_true",
        help="Fetch one Chroma reference case before finalize (optional)",
    )
    parser.add_argument(
        "--skip-propagation",
        action="store_true",
        help="Do not run Step 6",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Delete existing step outputs and rerun Steps 1–5 from scratch",
    )
    parser.add_argument(
        "--cursor-transcript",
        help="Cursor agent transcript jsonl; merge session tokens with llm_provider",
    )
    parser.add_argument(
        "--replay",
        action="store_true",
        help="After RCA, run the BGPy structural replay for this event",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="After RCA, run wrong-attribution (misattribution) verify",
    )
    parser.add_argument(
        "--causal",
        action="store_true",
        help="After RCA, run paired causal Case/counterfactual tracing",
    )
    parser.add_argument(
        "--counterfactual",
        action="store_true",
        help="After RCA, run the counterfactual replay driver",
    )
    parser.add_argument(
        "--replay-only",
        action="store_true",
        help="Skip RCA/propagation; only run --replay/--verify/--causal/--counterfactual",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Pass --dry-run to BGPy replay/verify (no CAIDA/BGPy load)",
    )
    parser.add_argument(
        "--path-source",
        choices=("local-rib", "received-envelope"),
        default="received-envelope",
        help="BGPy path extraction mode for replay/counterfactual",
    )
    return parser.parse_args()


def main() -> None:
    global _tracer
    args = parse_args()
    _tracer = load_tracer()
    _tracer.reset()

    if args.replay_only:
        event_name = args.event_name
        if not event_name:
            existing = load_json(_root / "event.json", {})
            event_name = existing.get("event_name")
        if not event_name:
            raise SystemExit("--replay-only requires --event-name (or an existing event.json)")
        timed(
            "step_7_replay_verify",
            lambda: run_replay_verify(str(event_name), args),
        )
        dump_json(
            _root / "stage_durations_report.json",
            {
                "stage_durations_seconds": stage_durations,
                "total_duration_seconds": round(sum(stage_durations.values()), 2),
            },
        )
        return

    event = resolve_event_args(args)
    event_name = event["event_name"]
    event_dir = _root / "data" / "events" / event_name
    extra_root = ["--event-name", event_name, "--project-root", str(_root)]
    token_5a = event_dir / "token_usage_step_5a.json"
    token_5d = event_dir / "token_usage_step_5d.json"

    if args.force:
        timed("step_0_clear_outputs", lambda: clear_event_outputs(event_dir))

    timed(
        "step_1_create_event",
        lambda: write_event(
            event["prefix"], event["start_time"], event["end_time"], event_name
        ),
    )

    def step_2() -> None:
        if not args.force and csvs_ready(event_dir):
            print("[data-process] CSV files exist, skipping")
            return
        run_python(_skills / "data-process" / "history_rib.py")
        run_python(_skills / "data-process" / "rib_before_incident.py")
        run_python(_skills / "data-process" / "rib_after_incident.py")

    timed("step_2_data_process", step_2)
    timed(
        "step_3_detect_path_change",
        lambda: run_python(_skills / "detect-path-change" / "detect_change.py"),
    )
    timed(
        "step_4_path_score",
        lambda: run_python(_skills / "path-score" / "path_score.py"),
    )

    retrieve_context = [""]

    def step_5_extractors() -> None:
        rca = _skills / "root-cause-analysis"
        run_python(rca / "extended_rca.py", extra_root)
        run_python(rca / "validate_relationships.py", extra_root)
        run_python(rca / "lookup_ownership.py", extra_root)

    timed("step_5_extractors", step_5_extractors)
    if args.retrieve:
        timed(
            "step_5a_retrieve",
            lambda: retrieve_context.__setitem__(
                0, optional_retrieve(event_name, token_5a)
            ),
        )
    else:
        print("[step_5a] skipped (pass --retrieve to query Chroma)")

    def step_5_finalize() -> None:
        finalize_args = list(extra_root)
        if retrieve_context[0]:
            finalize_args.extend(["--retrieve-context", retrieve_context[0]])
        finalize_args.append("--force-llm")
        run_python(_skills / "root-cause-analysis" / "finalize_report.py", finalize_args)

    timed("step_5_root_cause", step_5_finalize)

    if args.archive:
        timed(
            "step_5d_archive_case",
            lambda: run_python(
                _skills / "case-update" / "case_update.py",
                ["--token-report", str(token_5d)],
            ),
        )
    else:
        print("[step_5d] skipped (pass --archive to index Chroma)")

    if args.skip_propagation:
        print("[step_6] skipped")
    else:
        def step_6() -> None:
            try:
                run_python(
                    _skills / "propagation-analysis" / "propagation-analysis.py",
                    extra_root,
                )
            except RuntimeError as exc:
                print(f"[step_6] propagation analysis failed: {exc}")

        timed("step_6_propagation", step_6)

    if replay_modes(args):
        timed(
            "step_7_replay_verify",
            lambda: run_replay_verify(event_name, args),
        )

    dest = _root / "token_usage_report.json"
    merged = merge_token_reports(
        [
            load_json(event_dir / "token_usage_report.json", {}),
            load_json(token_5a, {}),
            load_json(token_5d, {}),
        ]
    )
    dump_json(event_dir / "token_usage_report.json", merged)
    dump_json(dest, merged)
    dump_json(
        _root / "stage_durations_report.json",
        {
            "stage_durations_seconds": stage_durations,
            "total_duration_seconds": round(sum(stage_durations.values()), 2),
        },
    )
    print(f"Token report saved to: {_root / 'token_usage_report.json'}")
    print(f"Duration report saved to: {_root / 'stage_durations_report.json'}")

    if args.cursor_transcript:
        from combine_token_reports import write_combined_report

        combined_paths = [
            _root / "combined_token_report.json",
            event_dir / "combined_token_report.json",
        ]
        write_combined_report(
            transcript=Path(args.cursor_transcript),
            provider_report=dest,
            agents_md=_root / "AGENTS.md",
            outputs=combined_paths,
        )
        print(f"Combined report saved to: {_root / 'combined_token_report.json'}")


if __name__ == "__main__":
    main()
