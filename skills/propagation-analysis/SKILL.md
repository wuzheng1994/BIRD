---
name: propagation-analysis
description: Analyze how a BGP anomaly (route leak or prefix hijack) propagated through the internet by examining post-event AS paths. Identifies key transit ASes, propagation patterns, path inflation, and impact scope.
---

# Propagation Analysis Skill

## References

Required files in `<PROJECT_ROOT>/data/events/<YYYYMMDD_HHmm>/`:

| File | Description |
|---|---|
| `root_cause_report.json` | Output from `root-cause-analysis`; supplies anomaly type and root AS |
| `rib_after_incident.csv` | Timestamped post-event UPDATE observations |
| `rib_before_incident.csv` | Pre-event RIB paths used for path-inflation and normal baseline analysis |
| `rib_history.csv` or `history_rib.csv` | Historical normal RIB paths; both names are supported |
| `paths.json` | Paired RIB/UPDATE paths from `detect-path-change` |

For a route leak, `root_cause.leaking_as` is required. For a prefix hijack
or Type-1 hijack, `root_cause.attacker_as` (or `root_cause.hijacker_as`) is
required. Type-1 uses the forged penultimate AS `A` as the propagation root.

## Output

Generates `propagation_report.json` in the event folder with the original
top-level fields: `prefix`, `start_time`, `end_time`, `anomaly_type`,
`propagation_analysis`, `impact_assessment`, and `recommendations`.

`leak_start_time` is emitted for route leaks and `hijack_start_time` for
prefix hijacks when timestamped root-containing observations exist.

### Existing `propagation_analysis` fields

Both anomaly types contain:

| Field | Description |
|---|---|
| `key_transit_asns` | Important ASes on observed root-to-observer paths |
| `transit_as_descriptions` | AS descriptions; empty when no metadata is supplied |
| `observed_peer_asns` | Terminal ASes observing the anomaly paths |
| `propagation_patterns` | Distinct observed propagation patterns and their support |
| `propagation_timeline` | Timestamped root-containing post-event observations |
| `path_inflation_analysis` | Path length comparison before and after the incident |
| `geographic_analysis` | Location/coverage information; unavailable fields are explicit |

For `route_leak`, it also contains `leaking_as`, `leaked_to`,
`direct_upstream`, and `leak_direction`. For `prefix_hijack` and
`type_1_hijack`, it contains `hijacker_as`, `direct_upstream`, and
`hijack_type` (Type-1 prefers `hijack_subtype` such as `E|1` / `S|1`).

### Added Bayesian fields

| Field | Description |
|---|---|
| `data_summary` | Path-pair count, raw and deduplicated root-related UPDATE counts, and normal-baseline count |
| `propagation_edge_probabilities` | Conditional Beta posterior and posterior mean for every observed root-to-observer edge |
| `propagation_path_ranking` | Ranked complete UPDATE paths that actually occur in `paths.json` |

Each item in `propagation_edge_probabilities.edges` has `from_as`, `to_as`,
`posterior`, `propagation_probability`, `edge_update_count`, and
`source_update_count`. It uses the posterior:

```text
Beta(1 + edge_update_count,
     1 + source_update_count - edge_update_count)
```

Each item in `propagation_path_ranking.paths` has the original `update_path`,
the root-to-observer `propagation_path`, `path_probability` (geometric mean of
connecting-edge probabilities), per-hop edge probabilities, rank, leak-specificity
score, minimum edge probability, and raw UPDATE support.
`propagation_path_ranking.max_path_probability` is the maximum of those
geometric means; `max_paths` lists every observed path that attains it.

## Steps

1. Read `root_cause_report.json` to identify the anomaly type and confirmed
   root AS.
2. Read `rib_after_incident.csv` to identify key transit ASes, propagation
   patterns, propagation timeline, and observed scope.
3. Compare pre-event and root-containing post-event paths for path inflation,
   then produce impact assessment and recommendations.
4. Select `paths.json` UPDATE paths containing the root AS. Deduplicate
   Bayesian samples by `(upd_prefix, update_path)`; raw duplicates provide
   frequency support only.
5. Reverse the root-containing part of every observed AS_PATH into
   root-to-observer direction and calculate propagation-edge posteriors.
6. Build the normal baseline from historical RIB paths, pre-event RIB paths,
   and paired `rib_path` values. The baseline is not automatically filtered
   by root AS; its provenance must be validated as pre-event/normal data.
7. Rank only complete observed UPDATE paths. Path probability is the geometric
   mean of connecting-edge propagation probabilities along the root-to-observer
   chain. Rank by that value descending (the reported path probability is the
   maximum). Leak-specificity (sum of log leak-to-normal Beta posterior-mean
   ratios on novel edges) is retained as a secondary field, not the primary rank.

DTW scores are not propagation evidence. Graph edges are never recombined to
create a path that does not appear in `paths.json`.

## Execution

The agent must run the script during the propagation-analysis stage rather
than construct the JSON report freehand:

```bash
python <SKILLS_DIR>/propagation-analysis/propagation_analysis.py \
  --event-name <YYYYMMDD_HHmm> \
  --project-root <PROJECT_ROOT>
```
