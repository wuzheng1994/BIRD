#!/usr/bin/env python3
"""Dispatch BGPy replay / causal / counterfactual / misattribution runs.

Called by ``agent.py`` with event-name only. Scripts and RIB files stay on disk.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


REPLAY_ROOT = Path(__file__).resolve().parent
SCRIPTS_DIR = REPLAY_ROOT / "02_reproduction_code"
BUNDLE_EVENTS = REPLAY_ROOT / "01_24_anomaly_events" / "events"
CAIDA_CACHE = REPLAY_ROOT / "01_24_anomaly_events" / "caida_cache"
CAUSAL_DRIVER = REPLAY_ROOT / "04_error_tracing_code" / "run_causal_replays.py"
VERIFY_DRIVER = REPLAY_ROOT / "04_error_tracing_code" / "run_misattribution_replays.py"
COUNTERFACTUAL_DRIVER = (
    REPLAY_ROOT / "03_counterfactual_code" / "run_counterfactual_replays.py"
)
OUTPUTS = REPLAY_ROOT / "outputs"

EVENT_ALIASES = {
    "20160416_fp": "7-20160416_fp",
    "20220203_0209": "20220203_fp",
    "20220817_1939": "20220817_fp",
}

CSV_NAMES = (
    "history_rib.csv",
    "rib_before_incident.csv",
    "rib_after_incident.csv",
)


def replay_scripts() -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    for path in sorted(SCRIPTS_DIR.glob("replay_*.py")):
        mapping[path.stem.removeprefix("replay_")] = path
    return mapping


def resolve_event_id(event_name: str) -> str:
    scripts = replay_scripts()
    if event_name in scripts:
        return event_name
    alias = EVENT_ALIASES.get(event_name)
    if alias and alias in scripts:
        return alias
    available = ", ".join(sorted(scripts))
    raise FileNotFoundError(
        f"no replay script for {event_name!r}. available: {available}"
    )


def choose_events_root(project_root: Path, event_id: str) -> Path:
    local_dir = project_root / "data" / "events" / event_id
    if all((local_dir / name).is_file() for name in CSV_NAMES):
        return project_root / "data" / "events"
    bundled = BUNDLE_EVENTS / event_id
    if bundled.is_dir():
        return BUNDLE_EVENTS
    raise FileNotFoundError(
        f"no RIB inputs for {event_id}: looked in {local_dir} and {bundled}"
    )


def run_cmd(script: Path, extra: list[str]) -> None:
    cmd = [sys.executable, str(script), *extra]
    result = subprocess.run(cmd, cwd=str(REPLAY_ROOT))
    if result.returncode != 0:
        raise RuntimeError(f"{script.name} exited with {result.returncode}")


def common_paths(project_root: Path, event_id: str) -> dict[str, str]:
    events_root = choose_events_root(project_root, event_id)
    return {
        "event_id": event_id,
        "scripts_dir": str(SCRIPTS_DIR),
        "events_root": str(events_root),
        "caida_cache": str(CAIDA_CACHE),
        "replay_script": str(replay_scripts()[event_id]),
    }


def run_replay(
    project_root: Path,
    event_id: str,
    *,
    dry_run: bool,
    path_source: str,
) -> Path:
    paths = common_paths(project_root, event_id)
    output_dir = OUTPUTS / "reproduction" / event_id
    args = [
        "--events-root",
        paths["events_root"],
        "--caida-cache-dir",
        paths["caida_cache"],
        "--output-dir",
        str(output_dir),
        "--path-source",
        path_source,
    ]
    if dry_run:
        args.append("--dry-run")
    run_cmd(Path(paths["replay_script"]), args)
    return output_dir


def run_driver(
    script: Path,
    project_root: Path,
    event_id: str,
    output_root: Path,
    *,
    dry_run: bool,
    extra: list[str] | None = None,
) -> Path:
    paths = common_paths(project_root, event_id)
    args = [
        "--scripts-dir",
        paths["scripts_dir"],
        "--events-root",
        paths["events_root"],
        "--caida-cache-dir",
        paths["caida_cache"],
        "--output-root",
        str(output_root),
        "--event",
        event_id,
        *(extra or []),
    ]
    if dry_run:
        args.append("--dry-run")
    run_cmd(script, args)
    return output_root


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run BGPy replay or attribution verify for one event"
    )
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--project-root", default=None)
    parser.add_argument(
        "--mode",
        action="append",
        choices=("replay", "causal", "counterfactual", "verify"),
        default=[],
        help="May be repeated. Default: replay",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--path-source",
        choices=("local-rib", "received-envelope"),
        default="received-envelope",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_root = (
        Path(args.project_root).resolve()
        if args.project_root
        else REPLAY_ROOT.parent
    )
    event_id = resolve_event_id(args.event_name)
    modes = args.mode or ["replay"]
    print(f"[replay_verify] event={event_id} modes={','.join(modes)}")

    if "replay" in modes:
        dest = run_replay(
            project_root,
            event_id,
            dry_run=args.dry_run,
            path_source=args.path_source,
        )
        print(f"[replay_verify] replay output: {dest}")
    if "causal" in modes:
        dest = run_driver(
            CAUSAL_DRIVER,
            project_root,
            event_id,
            OUTPUTS / "causal",
            dry_run=args.dry_run,
            extra=["--validation-mode", "all"],
        )
        print(f"[replay_verify] causal output: {dest}")
    if "counterfactual" in modes:
        dest = run_driver(
            COUNTERFACTUAL_DRIVER,
            project_root,
            event_id,
            OUTPUTS / "counterfactual",
            dry_run=args.dry_run,
            extra=["--path-source", args.path_source],
        )
        print(f"[replay_verify] counterfactual output: {dest}")
    if "verify" in modes:
        dest = run_driver(
            VERIFY_DRIVER,
            project_root,
            event_id,
            OUTPUTS / "misattribution",
            dry_run=args.dry_run,
            extra=["--causal-driver", str(CAUSAL_DRIVER)],
        )
        print(f"[replay_verify] verify output: {dest}")


if __name__ == "__main__":
    main()
