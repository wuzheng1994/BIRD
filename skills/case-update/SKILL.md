---
name: case-update
description: Runs the `case-update` skill to archive `root_cause_report.json` into the Chroma vector store, grouped by year. Call this skill after `root-cause-analysis` completes.
---

# Case Update Skill

Archives a BGP root cause analysis report by indexing it into a year-grouped
Chroma vector collection.

## When to Use

Call this skill **after** `root-cause-analysis` finishes generating
`root_cause_report.json`.

## Input Parameters

| Parameter | Type | Source | Description |
|-----------|------|--------|-------------|
| `event_name` | string | `event.json` → `event_name` | Derived from the event's start datetime (e.g. `20260319_0932`) |

No explicit parameters are passed; the script reads `event.json` directly.

## Steps

### Step 1: Read `event.json`

From the project root, load `event.json`. Extract the `event_name` field, then
build the report path as:

```
data/events/<event_name>/root_cause_report.json
```

### Step 2: Add Report to Chroma Collection

Run `case_update.py` (the `__main__` block). 

## Usage

```bash
python <SKILLS_DIR>/case-update/case_update.py
```

