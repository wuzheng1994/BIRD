---
name: detect-path-change
description: Based on the routing data before and after the BGP anomaly event, identify the changes in AS paths. 
---

# Detect Path Change Skill

Detects AS (Autonomous System) path changes before and after a BGP anomaly event.

## Required files

Required files in `<PROJECT_ROOT>/data/events/<YYYYMMDD_HHmm>/`:

| File                      | Description                             |
|---------------------------|-----------------------------------------|
| `rib_before_incident.csv` | Routing data before the anomaly event   |
| `rib_after_incident.csv`  | Routing data after the anomaly event    |

## Output

Generates `paths.json` in `<PROJECT_ROOT>/data/events/<YYYYMMDD_HHmm>/`:

| Field         | Description                                        |
|---------------|----------------------------------------------------|
| `rib_prefix`  | IP prefix (before the event)                       |
| `upd_prefix`  | IP prefix (after the event)                        |
| `prefix_relation` | `exact` or `more_specific` (update vs baseline) |
| `rib_path`    | AS path from RIB and UPDATE (before the event)     |
| `update_path` | AS path from UPDATE (after the event)              |

## Steps

### Detect AS Path Changes

Obtain the AS paths before and after the incident based on the prefix and peer AS:

```bash
python <SKILLS_DIR>/detect-path-change/detect_change.py
```

The script performs the following:

1. Loads `rib_before_incident.csv` and `rib_after_incident.csv`
2. For each prefix/peer combination, compares the AS paths. Exact prefix
   matches are preferred; otherwise the longest covering supernet is used.
3. Labels each pair with `prefix_relation` (`exact` or `more_specific`).
4. Outputs all path pairs (changed and unchanged) to `paths.json`

## Output Format

Example `paths.json` entry:

```json
{
  "rib_prefix": "44.224.0.0/11",
  "upd_prefix": "44.235.216.0/24",
  "prefix_relation": "more_specific",
  "rib_path": "34854 1299 16509",
  "update_path": "34854 1299 209243 14618"
}
```

## Notes

- The script uses prefix matching (exact match first, then longest covering supernet)
- `prefix_relation` is `exact` when the prefixes are equal and `more_specific` when the update is a subnet of the baseline prefix
- Paths are normalized by splitting on whitespace
- Use this output with `path-score` skill to calculate difference scores