# BGP Anomaly Analysis Agent

## Overview

Performs root cause analysis and anomaly propagation analysis on a BGP
anomaly using a multi-step skill pipeline.

**Invoke tools with parameters. Do not carry routing data in the prompt.**
The only inputs an agent or caller should supply are the event parameters
below. Scripts read CSVs, `paths.json`, `score.json`, and the database from
disk. Never paste RIB/UPDATE rows, AS-path tables, SQL results, or the
contents of `paths.json` / `score.json` into the conversation.

The recommended entry point is one command:

```bash
python <PROJECT_ROOT>/agent.py \
 --prefix "<prefix>" \
 --start-time "<start_time>" \
 --end-time "<end_time>"
```

Optional flags: `--event-name <YYYYMMDD_HHmm>`, `--retrieve`, `--archive`,
`--skip-propagation`, `--replay`, `--verify`, `--causal`,
`--counterfactual`, `--replay-only`, `--dry-run`. `agent.py` writes
`event.json`, runs Steps 1–4 and 6 as local scripts, and materializes
`root_cause_report.json` from deterministic evidence. Pass `--replay`
or `--verify` to call `replay_verify/invoke.py` with the event name
only (no RIB/UPDATE payload). The LLM is invoked at most once, and
only when Type-1/leak evidence is ambiguous, prefix ownership conflicts
with S|1, or no named type can be decided. Do not use a deep agent with
all skills and the SQL toolkit to schedule these steps.

If a step must be run individually, call that skill's script with CLI
flags (or rely on `event.json` already written by Step 1). Do not load the
underlying files into context to "help" the script.

## Path Configuration

| Variable         | Path            |
|------------------|-----------------|
| Project Root     | repository root |
| Skills Directory | `skills/`       |

> **Note:** Replace `<PROJECT_ROOT>` with the cloned repository root and
> `<SKILLS_DIR>` with `<PROJECT_ROOT>/skills` when executing commands.

## Invocation Contract

| Parameter    | Type   | Description                                | Example                 |
|--------------|--------|--------------------------------------------|-------------------------|
| `prefix`     | string | IP prefix related to the BGP anomaly       | `"92.62.251.0/24"`      |
| `start_time` | string | Anomaly event start time                   | `"2026-03-19 09:32:14"` |
| `end_time`   | string | Anomaly event end time                     | `"2026-03-19 11:05:17"` |
| `event_name` | string | Optional folder id; default `YYYYMMDD_HHmm` from `start_time` | `"20260319_0932"` |

Allowed in the prompt: the four parameters above, plus optional flags
(`--retrieve`, `--archive`, `--skip-propagation`, `--replay`, `--verify`,
`--causal`, `--counterfactual`, `--replay-only`, `--dry-run`).

Not allowed in the prompt or tool arguments: CSV excerpts, RIB/UPDATE
dumps, `paths.json` / `score.json` bodies, AS-path lists, `bgp.db` query
results, or hand-copied ownership/relationship tables. Those stay on disk
under `data/events/<event_name>/`. After a step finishes, check only that
the expected output file exists (and optionally its size or a one-line
status). Read `root_cause_report.json` or `propagation_report.json` only
when the user asks for a summary.

Do not query `rel_*` or `pfx2as_*` with SQL. Scripts write
`relationship_validation.json` and `ownership.json`; those files are the
only sources for relationships and prefix ownership.

## Workflow

Follow these steps **in order**. Prefer `python agent.py` with the
parameters above. If stepping manually, create a dedicated task for each
step, invoke the listed command, and complete it before moving on.

### Step 1 — Create Event Folder

Write event parameters via `agent.py` or a four-field `event.json`. Do not
embed routing data.

```bash
python <PROJECT_ROOT>/agent.py \
  --prefix "<prefix>" \
  --start-time "<start_time>" \
  --end-time "<end_time>"
```

If only creating the folder (skipping the rest of the pipeline):

```bash
mkdir -p <PROJECT_ROOT>/data/events/<YYYYMMDD_HHmm>
```

Then write `event.json` in the project root with **only** these keys:

```json
{
  "prefix": "<prefix>",
  "start_time": "<start_time>",
  "end_time": "<end_time>",
  "event_name": "<YYYYMMDD_HHmm>"
}
```

- Folder name format: `[start_datetime]` = `YYYYMMDD_HHmm`
- If the folder already exists, skip folder creation
- Subsequent scripts read this file; do not re-pass prefix/times as data
  payloads

### Step 2 — Process Routing Data

Use the `data-process` skill. Scripts take no data payload; they read
`event.json` and write CSVs into the event folder.

```bash
python <SKILLS_DIR>/data-process/history_rib.py
python <SKILLS_DIR>/data-process/rib_before_incident.py
python <SKILLS_DIR>/data-process/rib_after_incident.py
```

Outputs (do not open or paste these):

1. `history_rib.csv` — historical RIB snapshots for the prefix
2. `rib_before_incident.csv` — routing data before the anomaly
3. `rib_after_incident.csv` — routing data after the anomaly

If all three CSV files already exist in the event folder, skip this step.

### Step 3 — Detect Path Changes

```bash
python <SKILLS_DIR>/detect-path-change/detect_change.py
```

The script loads the two CSVs from disk, matches prefixes (exact first,
then supernet), and writes `paths.json`. Do not read the CSVs or
`paths.json` into context.

### Step 4 — Calculate Difference Score

```bash
python <SKILLS_DIR>/path-score/path_score.py
```

The script scores `paths.json` on disk (DTW), deduplicates, sorts, and
writes the top `k` records to `score.json`. Do not paste path pairs or
scores into the prompt.

### Step 5 — Root Cause Analysis

Always run the extractors, then `finalize_report.py`. Pass only
`--event-name` and `--project-root`. Do not classify by inspecting CSVs or
`paths.json`.

```bash
python <SKILLS_DIR>/root-cause-analysis/extended_rca.py \
  --event-name <YYYYMMDD_HHmm> \
  --project-root <PROJECT_ROOT>
python <SKILLS_DIR>/root-cause-analysis/validate_relationships.py \
  --event-name <YYYYMMDD_HHmm> \
  --project-root <PROJECT_ROOT>
python <SKILLS_DIR>/root-cause-analysis/lookup_ownership.py \
  --event-name <YYYYMMDD_HHmm> \
  --project-root <PROJECT_ROOT>
python <SKILLS_DIR>/root-cause-analysis/finalize_report.py \
  --event-name <YYYYMMDD_HHmm> \
  --project-root <PROJECT_ROOT>
```

`extended_rca.py` writes `root_cause_evidence.json`.
`validate_relationships.py` writes `relationship_validation.json` (the
**only** source for `path_relationships` and valley-free triplets).
`lookup_ownership.py` writes `ownership.json` (the **only** source for
prefix ownership). `finalize_report.py` writes `root_cause_report.json`.
The validator is leak evidence only, not a standalone classifier.

**Step 5a — Retrieve Reference Cases (optional)**: Skip by default. With
`python agent.py --retrieve`, `retrieve.py` is called with `-k 1`. If
invoking it directly, pass only year, prefix, and the anomalous path
string from `score.json` (do not attach the score file):

```bash
python <SKILLS_DIR>/root-cause-analysis/retrieve.py \
  --year <YYYY> \
  --prefix "<prefix>" \
  --anomaly-path "<update_path>" \
  -k 1
```

**Step 5b — Classification order** (implemented by `finalize_report.py`;
do not re-implement by reading raw files): type-1 hijack →
prefix hijack → route leak → other.

- Type-1 (`... A V`) takes precedence over a covering-vs-more-specific
  origin mismatch: a novel penultimate AS `A` adjacent to claimed origin
  `V` with multi-VP support is `type_1_hijack` (`E|1` same prefix, `S|1`
  new more-specific). Attacker is `A`, not `V`.
- An exact-prefix origin change (E|0), or a more-specific originated by
  an unauthorized AS after S|1 is rejected (S|0), is `prefix_hijack`
  even if the update path also contains abnormal triplets.
- Only when the origin AS is unchanged **and** the validation conclusion
  is `route_leak_candidate`, classify as `route_leak` and take
  `leaking_as`, `leak_type`, `leak_candidates`, and `abnormal_triplets`
  from `relationship_validation.json`.
- Otherwise `route_outage` or `other`. Leak-specific fields apply only
  to `route_leak` events.

**Step 5c — Generate Report**: `finalize_report.py` writes
high-confidence `route_outage`, `type_1_hijack`, `prefix_hijack`, and
`route_leak` reports without an LLM. An LLM is used only for ambiguous or
unresolved cases, and only sees a compact JSON summary (not CSVs or
`paths.json`). Do not feed extra evidence into that call.

**Step 5d — Archive Root Cause Report (optional)**: Skip by default.
`python agent.py --archive` or:

```bash
python <SKILLS_DIR>/case-update/case_update.py
```

The script reads `event.json` and indexes `root_cause_report.json` into
Chroma by year. Do not pass the report body as an argument.

### Step 6 — Propagation Analysis

```bash
python <SKILLS_DIR>/propagation-analysis/propagation-analysis.py \
  --event-name <YYYYMMDD_HHmm> \
  --project-root <PROJECT_ROOT>
```

The script reads `root_cause_report.json` and post-event routing files
from disk and writes `propagation_report.json`. Do not paste those files
into the prompt.

If the standard script fails for `other` events (no `leaking_as` or
`attacker_as`), run `create_propagation_report.py` the same way — still
parameters only, no data payload.

### Step 7 — Replay / verify (optional)

Use `agent.py` flags or call the dispatcher with `--event-name` only:

```bash
python <PROJECT_ROOT>/agent.py --event-name <YYYYMMDD_HHmm> --replay-only --dry-run
python <PROJECT_ROOT>/agent.py --event-name <YYYYMMDD_HHmm> --replay-only --verify --dry-run
python <PROJECT_ROOT>/replay_verify/invoke.py \
  --event-name <YYYYMMDD_HHmm> \
  --project-root <PROJECT_ROOT> \
  --mode replay --mode verify \
  --dry-run
```

`--replay` runs the matching `replay_<event>.py`. `--verify` runs
wrong-attribution. `--causal` and `--counterfactual` run the paired
drivers. Prefer `--dry-run` first. Do not paste RIB rows, simulated
paths, or similarity JSON into the prompt.

## After a Run

Artifacts live under `<PROJECT_ROOT>/data/events/<event_name>/`. Confirm
exit codes and that the expected files exist. Summarize from
`root_cause_report.json` (and `propagation_report.json` if present) only
when asked. Do not dump intermediate data files back to the user unless
they request a specific file.

To merge Cursor-session tokens (AGENTS.md + transcript replay) with
`llm_provider` DashScope usage:

```bash
python <PROJECT_ROOT>/combine_token_reports.py \
  --event-name <YYYYMMDD_HHmm> \
  --transcript <cursor-transcript.jsonl>
```

Or pass `--cursor-transcript <cursor-transcript.jsonl>` to `agent.py`.
The merge writes `combined_token_report.json` and splits Cursor tokens
into `cursor_orchestration`, `cursor_launch`, `cursor_wrapup`, and
`cursor_other`. Do not paste the transcript body into the prompt.
