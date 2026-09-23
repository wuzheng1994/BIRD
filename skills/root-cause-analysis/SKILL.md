---
name: root-cause-analysis
description: Classify and trace BGP prefix hijacks, route leaks, route outages, and Type-1 hijacks (E|1 exact-prefix and S|1 subprefix forged-origin) using path changes, multi-VP withdrawals, historical baselines, and routing metadata.
---

# Root Cause Analysis Skill

Analyzes BGP anomalies using type-specific, evidence-first strategies. Supported
types are `prefix_hijack`, `type_1_hijack`, `route_leak`, `route_outage`, and
`other`. Type-1 includes exact-prefix `E|1` and subprefix `S|1`.

## Required Files

| File | Location | Description |
|------|----------|-------------|
| `score.json` | `<PROJECT_ROOT>/data/events/<YYYYMMDD_HHmm>/` | Highest scored path change record from `path-score` skill |
| `event.json` | `<PROJECT_ROOT>/` | Event parameters (prefix, start_time, end_time, event_name) |
| `bgp.db` | `<PROJECT_ROOT>/data/` | Database containing prefix-to-AS mappings and AS business relationships |
| `rib_before_incident.csv` | Event directory | Pre-event paths used for origin, adjacency, and outage visibility baselines |
| `rib_history.csv` or `history_rib.csv` | Event directory | Historical paths used to determine whether an AS adjacency is novel |
| `rib_after_incident.csv` | Event directory | Post-event announcements and VP support for anomalous paths |
| `withdrawals.csv` | Event directory, optional | Upstream-supplied withdrawal observations required for route-outage analysis |
| `relationship_validation.json` | Event directory, generated | Direction-normalized AS relationship validation for the selected update path |
| `ownership.json` | Event directory, generated | Prefix ownership from `lookup_ownership.py` (`pfx2as_*`, network address only) |

`withdrawals.csv` requires `timestamp,prefix,peer_asn` and may include
`collector,peer_ip,previous_as_path,recovered_as_path`. This skill does not
collect withdrawals. If the file is absent, route-outage evidence is
unavailable rather than negative.

## Output

Generates `root_cause_report.json` in `<PROJECT_ROOT>/data/events/<YYYYMMDD_HHmm>/`.

| Field | Type | Description |
|-------|------|-------------|
| `prefix` | string | IP prefix |
| `anomaly_type` | string | `prefix_hijack`, `type_1_hijack`, `route_leak`, `route_outage`, or `other` |
| `root_cause` | object | Root cause details (varies by anomaly type) |
| `description` | string | Human-readable analysis description |

## Steps

### Step 1: Read Score Data

Read the highest-scored record from `score.json`:

```json
{
  "rib_prefix": "192.168.1.0/24",
  "upd_prefix": "192.168.1.0/24",
  "rib_path": "65001 65002 65003",
  "update_path": "65001 65004 65005 65003",
  "score": 0.8472
}
```

### Step 1a: Extract Extended Evidence

Always run the deterministic evidence extractor before final classification:

```bash
python <SKILLS_DIR>/root-cause-analysis/extended_rca.py \
  --event-name <YYYYMMDD_HHmm> \
  --project-root <PROJECT_ROOT>
```

This generates `root_cause_evidence.json`. It identifies route-outage and
Type-1 candidates (`E|1` and `S|1`) but does not replace ownership,
relationship, or operator validation. A more-specific whose covering origin
differs is **not** automatically a prefix hijack: evaluate S|1 first. When
Type-1 and leak-shaped insertions coexist, the recommendation is `ambiguous`;
keep both candidates and prefer `other` or low-confidence reporting instead of
forced classification.

Optional report materializers in `extended_rca.py`:

- `build_outage_report(evidence)` for validated `route_outage`
- `build_type1_report(evidence)` for validated `type_1_hijack`

These helpers produce Case Template JSON whose `root_cause` fields remain
scalar/list-compatible with `case-update`.

### Step 2: Retrieve Reference Cases (optional)

Skip by default. With `python agent.py --retrieve` (or an explicit `retrieve.py`
call, `-k 1`), fetch one similar historical case from Chroma. Retrieval is
optional context, not required for classification.

**Command**:

```bash
python <SKILLS_DIR>/root-cause-analysis/retrieve.py \
    --year <year> \
    --prefix "<prefix>" \
    --anomaly-path "<anomaly_path>"
```

| Argument | Value Source | Example |
|----------|--------------|---------|
| `--year` / `-y` | Year extracted from `event_name` (YYYY from `YYYYMMDD_HHmm`) | `2015` |
| `--prefix` / `-p` | `rib_prefix` from the selected score record | `172.81.128.0/21` |
| `--anomaly-path` / `-ap` | `update_path` from the selected score record | `29608 5511 6762` |

### Step 3: Determine Anomaly Type and Perform Analysis

Analyze the path and withdrawal evidence in this conservative order:

1. **Type-1 Hijack**: a novel AS `A` appears immediately to the left of claimed
   origin `V` (`... A V`) with independent VP support.
   - **E|1**: exact prefix, origin unchanged, novel `A-V` vs same-prefix history.
   - **S|1**: new more-specific compared with a covering prefix; covering origin
     may differ from `V`. Attacker is still `A`, not `V`.
2. **Prefix Hijack**: exact-prefix origin change to an unauthorized AS (E|0), or
   a more-specific originated by an unauthorized AS after S|1 has been rejected
   (S|0).
3. **Route Leak**: the origin remains unchanged and an intermediate AS creates
   a validated valley-free relationship violation.
4. **Other**: the evidence does not satisfy any validated type.

`root_cause_evidence.json` is candidate evidence, not final truth. If Type-1
and route-leak evidence conflict, retain both explanations and report low
confidence or `other`; do not silently force one class. If S|1 is recommended
but ownership validation shows `V` is unauthorized for the covering space,
reclassify as `prefix_hijack` (S|0) with attacker = origin.

#### For Prefix Hijack (use `prefix_hijack.md` reference):

1. Extract network address from the IP prefix (e.g. `172.81.128.0/21` → `172.81.128.0`)
2. Extract the origin AS (last AS in the AS path) from `update_path`
3. Read `ownership.json` (from `lookup_ownership.py`) for the legitimate AS.
   Do not query `pfx2as_*` with SQL. The lookup uses the network address
   without the prefix length (e.g. `172.81.128.0`, never `172.81.128.0/21`).
4. If observed origin AS ≠ legitimate origin AS, a hijack has occurred
5. Observed origin AS = attacker, legitimate AS = victim

**Validation**: If the observed origin AS equals the legitimate AS, ordinary
origin hijack is rejected, but Type-1 and route-leak analysis must still run.
A covering-prefix origin that differs from a more-specific origin is S|1
evidence, not automatic Type-0, until ownership shows `V` is unauthorized.

#### For Type-1 Hijack (use `type_1_hijack.md` reference):

1. Collapse consecutive prepends in normal and anomalous paths.
2. Read `prefix_relation` (`exact` vs `more_specific`) from the score record.
3. Extract `A = update_path[-2]` and `V = update_path[-1]`.
4. For E|1, require unchanged origin and `A != rib_path[-2]`.
5. For S|1, require a covering baseline prefix; origin change vs the covering
   prefix is expected. Attacker = `A`, victim = `V`.
6. Confirm the adjacency `A-V` is absent from historical and pre-event paths
   of origin `V`, including covering-prefix paths.
7. Require at least two distinct VP identities supporting `... A V`.
8. Query AS relationships and check whether a legitimate upstream change,
   authorized deaggregation, or route leak better explains the observation.
9. If `V` is not a legitimate origin for the covering space, reclassify as
   prefix hijack (S|0 / E|0).

**Validation**: A penultimate-AS change or a new more-specific by itself is
insufficient. Missing ownership, historical-adjacency, covering-prefix,
relationship, or multi-VP evidence lowers confidence and may require
classification as `other`.

#### For Route Leak (use `route_leak.md` reference):

1. **Run the deterministic relationship validator first**:

   ```bash
   python <SKILLS_DIR>/root-cause-analysis/validate_relationships.py \
     --event-name <YYYYMMDD_HHmm> \
     --project-root <PROJECT_ROOT>
   ```

   This writes `relationship_validation.json` into the event directory with
   the correct `relationship_table` (resolved from the event month, falling
   back to the most recent earlier table), direction-normalized
   `path_relationships`, and the valley-free triplet analysis. Do not hand-query
   `bgp.db` for relationships: manual SQL has caused wrong-month table
   selection and direction-sensitive misses that mark existing pairs as
   missing (`2`).
2. Extract all consecutive AS triplets from the `update_path`, traversing from
   right to left, and read the corresponding pairs from
   `relationship_validation.json` instead of re-querying the database.
3. Detect abnormal relationship patterns: `(-1, 1)`, `(-1, 0)`, `(0, 1)`, `(0, 0)`
4. The middle AS in abnormal triplets is the leaking AS

**Validation**: If no abnormal triplets are found:
1. Reclassify this event as `anomaly_type = "other"`
2. Traverse the highest-scored `update_path` from left to right (from ingress
   towards origin) and use `path_relationships` from `relationship_validation.json`
3. Record the full sequence of path relationships in `root_cause.path_relationships` (e.g., `[1, 2, -1]`), where:
   - `1`: Customer-to-Provider (c2p)
   - `-1`: Provider-to-Customer (p2c)
   - `0`: Peer-to-Peer (p2p)
   - `2`: Missing / Unknown relationship in `bgp.db` (unobserved in topology data)

#### For Route Outage (use `route_outage.md` reference):

1. Read `route_outage` evidence from `root_cause_evidence.json`.
2. Verify at least two previously visible VPs withdrew the prefix.
3. Verify the affected-baseline VP ratio, synchronization ratio, and immediate
   alternative-path ratio satisfy the documented thresholds.
4. Set `affected_origin_as` from the dominant last-known origin.
5. Set `suspected_failure_as` only when the last-known paths provide one
   unique common internal candidate; otherwise leave it null.
6. Report recovery and duration when observed. Missing recovery means
   right-censored duration.

**Validation**: Withdrawals establish control-plane loss, not confirmed
data-plane failure. Never invent a trigger AS because Withdrawal messages do
not contain AS_PATH.

### Step 4: Generate Report

Run `finalize_report.py`. High-confidence outage / Type-1 / leak / unauthorized
origin hijack reports are written without an LLM. Ambiguous cases use one LLM
call on a compact JSON summary (no CSVs or `paths.json`).

Create `root_cause_report.json` following the Case Template format. **Must strictly follow the Case Template**.

Populate `anomaly_type` from the classification in Step 3, and populate
`path_relationships` directly from `relationship_validation.json` so the
report matches the deterministic validation output. Leak-specific fields
(`leaking_as`, `leak_type`, `leak_candidates`, `abnormal_triplets`) must be
populated from `relationship_validation.json` **only when** `anomaly_type` is
`route_leak`. For other anomaly types, use the type-specific `root_cause`
fields shown in the examples below (e.g., `attacker_as`/`victim_as` for
hijacks, `affected_origin_as`/`suspected_failure_as` for outages) and do not
include leak-only fields. Then use the `case-update` skill to archive the
report.

Every report for a new type must include `confidence` and
`evidence_limitations` inside `root_cause`. The `case-update` serializer accepts
these scalar/list fields without schema changes.

## Example Output

### Prefix Hijack Report

```json
{
  "prefix": "64.233.161.0/24",
  "start_time": "2024-01-01 12:00:00",
  "end_time": "2024-01-01 12:30:00",
  "anomaly_type": "prefix_hijack",
  "root_cause": {
    "attacker_as": 65004,
    "victim_as": 65001,
    "network_address": "64.233.161.0"
  },
  "description": "AS 65004 hijacked prefix 64.233.161.0/24. The legitimate origin is AS 65001, but AS 65004 is announcing this prefix."
}
```

### Route Leak Report

```json
{
  "prefix": "192.168.1.0/24",
  "start_time": "2024-01-01 12:00:00",
  "end_time": "2024-01-01 12:30:00",
  "anomaly_type": "route_leak",
  "root_cause": {
    "leaking_as": 65004,
    "leak_type": "p2p_to_p2p",
    "abnormal_triplets": ["65001 65004 65005"]
},
  "description": "AS 65004 leaked traffic from a peer (AS 65001) to another peer (AS 65005), violating AS relationship constraints."
}
```

### Type-1 Hijack Report

```json
{
  "prefix": "203.0.113.0/24",
  "start_time": "2026-01-01 00:00:00",
  "end_time": "2026-01-01 00:20:00",
  "anomaly_type": "type_1_hijack",
  "root_cause": {
    "attacker_as": 65066,
    "victim_as": 65001,
    "hijack_subtype": "E|1",
    "forged_adjacency": [65066, 65001],
    "normal_predecessors": [64500],
    "origin_unchanged": true,
    "novel_adjacency": true,
    "supporting_vp_count": 4,
    "confidence": "high",
    "evidence_limitations": []
  },
  "description": "AS 65066 newly appeared immediately before legitimate origin AS 65001 across four VPs."
}
```

### Route Outage Report

```json
{
  "prefix": "203.0.113.0/24",
  "start_time": "2026-01-01 00:00:00",
  "end_time": "2026-01-01 00:30:00",
  "anomaly_type": "route_outage",
  "root_cause": {
    "affected_origin_as": 65001,
    "suspected_failure_as": null,
    "attribution_scope": "affected_origin_only",
    "withdrawal_ratio": 0.8,
    "synchronization_ratio": 0.875,
    "alternative_path_ratio": 0.0625,
    "outage_start_timestamp": 1767225600,
    "recovery_timestamp": 1767226500,
    "duration_seconds": 900,
    "confidence": "high",
    "evidence_limitations": [
      "Withdrawals do not expose the triggering AS",
      "No data-plane reachability measurements were supplied"
    ]
  },
  "description": "Most baseline VPs synchronously withdrew the prefix with few immediate alternatives."
}
```

### Other Report

```json
{
  "prefix": "192.168.1.0/24",
  "anomaly_type": "other",
  "root_cause": {
    "update_path": "65001 65002 65003 65004",
    "path_relationships": [1, 2, -1]
  },
  "description": "No definitive anomaly detected. The AS path relationships are [1, 2, -1], which do not match validated patterns of route_leak, prefix_hijack, type_1_hijack, or route_outage."
}
```

## References

- Prefix hijack analysis: `<SKILLS_DIR>/root-cause-analysis/references/prefix_hijack.md`
- Route leak analysis: `<SKILLS_DIR>/root-cause-analysis/references/route_leak.md`
- Type-1 hijack analysis: `<SKILLS_DIR>/root-cause-analysis/references/type_1_hijack.md`
- Route outage analysis: `<SKILLS_DIR>/root-cause-analysis/references/route_outage.md`
