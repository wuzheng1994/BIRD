#!/usr/bin/env python3
"""Merge Cursor-session token estimates with llm_provider API usage."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

_root = Path(__file__).resolve().parent

CURSOR_STAGES = (
    "cursor_orchestration",
    "cursor_launch",
    "cursor_wrapup",
    "cursor_other",
)

_WRAPUP_MARKERS = (
    "token_usage_report",
    "stage_durations_report",
    "combined_token_report",
    "combine_token_reports",
    "token_usage_step_",
)
_ORCH_PATH_MARKERS = (
    "event.json",
    "agents.md",
    "history_rib",
    "rib_before_incident",
    "rib_after_incident",
    "event_new",
    "/data/embs/",
)
_WRAPUP_QUERY_MARKERS = (
    "各阶段的token",
    "测量各阶段的时间",
    "统计起来",
    "记录一下token",
    "cursor侧的token",
)
_OTHER_QUERY_MARKERS = (
    "不花费token",
    "读取skills",
    "skill.md",
    "通过agents.md",
    "通过@agents.md",
    "cursor会参与",
    "cursor参与哪些",
    "工具的调用",
)

_encoding = None


def count_tokens(text: str) -> int:
    if not text:
        return 0
    global _encoding
    if _encoding is None:
        import tiktoken

        _encoding = tiktoken.get_encoding("cl100k_base")
    return len(_encoding.encode(text))


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def dump_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def _part_text(part: Any) -> str:
    if isinstance(part, str):
        return part
    if not isinstance(part, dict):
        return str(part)
    kind = part.get("type")
    if kind == "text":
        return str(part.get("text") or "")
    if kind == "tool_use":
        return json.dumps(
            {"name": part.get("name"), "input": part.get("input")},
            ensure_ascii=False,
            separators=(",", ":"),
        )
    return json.dumps(part, ensure_ascii=False, separators=(",", ":"))


def message_text(record: dict[str, Any]) -> str:
    message = record.get("message") or {}
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(_part_text(part) for part in content)
    if content is None:
        return ""
    return json.dumps(content, ensure_ascii=False, separators=(",", ":"))


def load_transcript_records(path: Path) -> list[dict[str, Any]]:
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("role") in {"user", "assistant"}:
            records.append(obj)
    return records


def _tool_uses(record: dict[str, Any]) -> Iterable[dict[str, Any]]:
    content = (record.get("message") or {}).get("content")
    if not isinstance(content, list):
        return
    for part in content:
        if isinstance(part, dict) and part.get("type") == "tool_use":
            yield part


def _tool_blob(record: dict[str, Any]) -> str:
    chunks = []
    for part in _tool_uses(record):
        name = str(part.get("name") or "")
        payload = part.get("input") or {}
        chunks.append(name)
        if isinstance(payload, dict):
            for key in ("command", "path", "target_directory", "pattern"):
                value = payload.get(key)
                if value:
                    chunks.append(str(value))
        else:
            chunks.append(str(payload))
    return "\n".join(chunks)


def empty_stage_usage() -> dict[str, int]:
    return {"calls": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0}


def classify_cursor_stage(record: dict[str, Any], current_user: str) -> str:
    """Map one Cursor generation to the outer-agent stage it belongs to.

    Cursor does not run Steps 1–6 internally. It only orchestrates, launches
    agent.py, checks artifacts, or answers questions about the pipeline.
    Launch > wrapup > orchestration > other.
    """
    tools = _tool_blob(record).lower()
    user = current_user.lower()

    if "agent.py" in tools and "combine_token_reports" not in tools:
        return "cursor_launch"
    if any(marker in tools for marker in _WRAPUP_MARKERS):
        return "cursor_wrapup"
    if any(marker in tools for marker in _ORCH_PATH_MARKERS):
        return "cursor_orchestration"
    if any(marker in user for marker in _WRAPUP_QUERY_MARKERS):
        return "cursor_wrapup"
    if any(marker in user for marker in _OTHER_QUERY_MARKERS):
        return "cursor_other"
    if "event.json" in user or "测量各阶段" in user or "使用agent.py" in user:
        return "cursor_orchestration" if tools else "cursor_wrapup"
    return "cursor_other"


def estimate_cursor_usage(
    transcript_path: Path,
    agents_md_path: Path,
) -> dict[str, Any]:
    """Replay the transcript as successive model calls.

    Each assistant record is treated as one Cursor generation. Input is
    AGENTS.md (always-applied workspace rule) plus prior user/assistant
    messages. Tool *results* are not stored in the jsonl, so this is a
    lower bound and excludes Cursor's system prompt and tool schemas.
    """
    agents_md = agents_md_path.read_text(encoding="utf-8") if agents_md_path.exists() else ""
    agents_tokens = count_tokens(agents_md)
    records = load_transcript_records(transcript_path)

    history_parts: list[str] = []
    input_tokens = 0
    output_tokens = 0
    generations = 0
    user_turns = 0
    current_user = ""
    by_stage = {stage: empty_stage_usage() for stage in CURSOR_STAGES}

    for record in records:
        role = record.get("role")
        text = message_text(record)
        if role == "user":
            user_turns += 1
            current_user = text
            history_parts.append(text)
            continue
        generations += 1
        history_tokens = count_tokens("\n".join(history_parts))
        inp = agents_tokens + history_tokens
        out = count_tokens(text)
        input_tokens += inp
        output_tokens += out
        stage = classify_cursor_stage(record, current_user)
        bucket = by_stage[stage]
        bucket["calls"] += 1
        bucket["input_tokens"] += inp
        bucket["output_tokens"] += out
        bucket["total_tokens"] += inp + out
        history_parts.append(text)

    return {
        "source": "cursor_session_estimate",
        "method": "cl100k_base replay; AGENTS.md injected on every assistant call",
        "excludes": [
            "cursor_system_prompt",
            "tool_schemas",
            "tool_results_not_in_transcript",
        ],
        "transcript": str(transcript_path),
        "agents_md_tokens": agents_tokens,
        "user_turns": user_turns,
        "generations": generations,
        "summary": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        },
        "by_stage": by_stage,
    }


def provider_summary(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary") or {}
    return {
        "source": "llm_provider",
        "summary": {
            "input_tokens": int(summary.get("input_tokens") or 0),
            "output_tokens": int(summary.get("output_tokens") or 0),
            "total_tokens": int(summary.get("total_tokens") or 0),
        },
        "by_stage": report.get("by_stage") or {},
        "calls": report.get("calls") or [],
    }


def combine(cursor: dict[str, Any], provider: dict[str, Any]) -> dict[str, Any]:
    c = cursor["summary"]
    p = provider["summary"]
    combined = {
        "input_tokens": c["input_tokens"] + p["input_tokens"],
        "output_tokens": c["output_tokens"] + p["output_tokens"],
        "total_tokens": c["total_tokens"] + p["total_tokens"],
    }
    return {
        "combined": combined,
        "by_source": {
            "cursor": cursor,
            "llm_provider": provider,
        },
    }


def write_combined_report(
    *,
    transcript: Path,
    provider_report: Path,
    agents_md: Path,
    outputs: list[Path],
) -> dict[str, Any]:
    cursor = estimate_cursor_usage(transcript, agents_md)
    provider = provider_summary(load_json(provider_report, {}))
    report = combine(cursor, provider)
    for path in outputs:
        dump_json(path, report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Combine Cursor session token estimates with llm_provider usage"
    )
    parser.add_argument("--transcript", required=True, type=Path)
    parser.add_argument(
        "--provider-report",
        type=Path,
        default=_root / "token_usage_report.json",
    )
    parser.add_argument("--agents-md", type=Path, default=_root / "AGENTS.md")
    parser.add_argument("--event-name")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    outputs = [_root / "combined_token_report.json"]
    if args.output:
        outputs.append(args.output)
    if args.event_name:
        outputs.append(
            _root / "data" / "events" / args.event_name / "combined_token_report.json"
        )
    # De-duplicate while keeping order
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in outputs:
        resolved = path.resolve()
        if resolved not in seen:
            unique.append(path)
            seen.add(resolved)

    report = write_combined_report(
        transcript=args.transcript.resolve(),
        provider_report=args.provider_report.resolve(),
        agents_md=args.agents_md.resolve(),
        outputs=unique,
    )
    combined = report["combined"]
    cursor = report["by_source"]["cursor"]["summary"]
    provider = report["by_source"]["llm_provider"]["summary"]
    print(
        "combined "
        f"input={combined['input_tokens']} "
        f"output={combined['output_tokens']} "
        f"total={combined['total_tokens']}"
    )
    print(
        "cursor "
        f"input={cursor['input_tokens']} "
        f"output={cursor['output_tokens']} "
        f"total={cursor['total_tokens']}"
    )
    print(
        "llm_provider "
        f"input={provider['input_tokens']} "
        f"output={provider['output_tokens']} "
        f"total={provider['total_tokens']}"
    )
    cursor_stages = report["by_source"]["cursor"].get("by_stage") or {}
    for stage in CURSOR_STAGES:
        item = cursor_stages.get(stage) or empty_stage_usage()
        print(
            f"[{stage}] calls={item['calls']} "
            f"input={item['input_tokens']} "
            f"output={item['output_tokens']} "
            f"total={item['total_tokens']}"
        )
    for path in unique:
        print(f"Combined report saved to: {path}")


if __name__ == "__main__":
    main()
