---
name: path-score
description: Calculate a difference score for each AS path change record based on Dynamic Time Warping (DTW) distance using AS embedding vectors. The score quantifies how different the pre-event and post-event AS paths are, enabling prioritization of the most significant anomalies. 
---

# Path Score Skill

Calculates a difference score for AS path changes using Dynamic Time Warping (DTW) with AS embedding vectors.

## Required files:

| File                      | Location                                              | Description                    |
|---------------------------|-------------------------------------------------------|--------------------------------|
| `paths.json`              | `<PROJECT_ROOT>/data/events/<YYYYMMDD_HHmm>/`        | AS path change data             |
| `<YYYYMMDD_HHmm>.pkl`     | `<PROJECT_ROOT>/data/embs/`                          | AS embedding vectors (pickle)   |

## Output

Generates `score.json` in `<PROJECT_ROOT>/data/events/<YYYYMMDD_HHmm>/`:

| Field         | Type   | Description                                        |
|---------------|--------|----------------------------------------------------|
| `rib_prefix`  | string | IP prefix (before the event)                       |
| `upd_prefix`  | string | IP prefix (after the event)                        |
| `prefix_relation` | string | `exact` or `more_specific`                         |
| `rib_path`    | string | Original AS path (before the event)                |
| `update_path` | string | New AS path (after the event)                      |
| `score`       | float  | DTW distance score (higher = more different)       |

The script returns the top `k` records with the highest scores as a JSON array.

## Steps

### Calculate Difference Scores

```bash
python <SKILLS_DIR>/path-score/path_score.py
```

The script performs the following:

1. Loads AS embedding vectors from the pickle file
2. Reads all path change records from `paths.json`
3. For each record, calculates DTW distance between `rib_path` and `update_path`
4. Deduplicates records by the full set of fields (`rib_prefix`, `upd_prefix`, `prefix_relation`, `rib_path`, `update_path`, `score`)
5. Sorts by more-specific first, then longest update prefix, then origin-mismatch, then DTW score descending, and saves the top `k` records to `score.json`

## Output Format

Example `score.json` — a JSON array of top-k records (highest scores first):

```json
[
  {
    "rib_prefix": "192.168.1.0/24",
    "upd_prefix": "192.168.1.0/24",
    "rib_path": "65001 65002 65003",
    "update_path": "65001 65004 65005 65003",
    "score": 0.8472
  },
  {
    "rib_prefix": "10.0.0.0/16",
    "upd_prefix": "10.0.0.0/16",
    "rib_path": "64512 64513 64514",
    "update_path": "64512 64515 64514",
    "score": 0.7231
  }
]
```



