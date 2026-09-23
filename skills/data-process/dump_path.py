"""Resolve the local event_new dump directory for data-process scripts."""

from __future__ import annotations

import os
from pathlib import Path

def _event_new_root() -> Path:
    override = (os.environ.get("RCA_DUMP_ROOT") or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / "data" / "ribs"


def dump_event_name(event_name: str) -> str:
    override = (os.environ.get("RCA_DUMP_EVENT") or "").strip()
    return override or str(event_name)


def dump_dir(event_name: str) -> Path:
    return _event_new_root() / dump_event_name(event_name)
