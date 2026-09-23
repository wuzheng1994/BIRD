# BGPy Historical Anomaly Replay Bundle

This repository contains a curated, auditable replay pipeline for 24 historical
BGP anomaly events. It combines standalone event replays with a paired
counterfactual driver built on BGPy and Gao--Rexford commercial routing.

The release bundle is intentionally narrower than the working research tree.
It includes the selected replay code, event inputs, local CAIDA relationship
snapshots, and the BGPy runtime. Generated results, figures, exploratory
scripts, IDE files, and temporary data are excluded.

## What the bundle provides

- 24 self-contained `replay_<event-id>.py` programs.
- A paired experiment driver, `run_counterfactual_replays.py`.
- Deterministic receiver/prefix calibration and held-out evaluation.
- Event-local, immutable topology overlays; cached CAIDA files are not edited.
- Audited anomaly-removal, mechanism-specificity, and topology ablations.
- Normalized and raw path similarity, receiver coverage, and quality flags.
- Script and artifact SHA-256 checksums for provenance.

The primary metric is:

```text
similarity.mean_observed_path_similarity_including_uncovered
```

Uncovered observed receivers contribute zero to this coverage-adjusted metric.
The paired effect is reported as `Delta M = M_case - M_counterfactual`.

## Bundle layout

```text
bgpy-historical-replay-24/
|-- README.md
|-- LICENSE.txt
|-- pyproject.toml
|-- requirements.txt
|-- bundle_manifest.json
|-- SHA256SUMS
|-- run_counterfactual_replays.py
|-- replay_<event-id>.py       # 24 selected standalone replays
|-- bgpy/                      # local BGPy source
|-- dudata/
|   |-- event.xlsx
|   |-- anomaly-event-info.csv
|   `-- <event-id>/            # per-event RIB and audit inputs
|-- data/caida_cache/          # 15 historical CAIDA snapshots
`-- tools/build_replay_bundle.py
```

`bundle_manifest.json` is the authoritative list of selected replay scripts.
Do not mix them with historical copies from other directories.

## Requirements

- Python 3.10 or newer.
- Enough memory to load an Internet-scale CAIDA AS graph.
- Graphviz only if diagram rendering is required.

Create an isolated environment and install the local package:

```bash
python -m venv .venv
```

Linux or macOS:

```bash
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

The archive already contains the event inputs and CAIDA cache. Network access
is not required when the matching cached snapshot is present.

## Validate before running

Verify the release files:

Linux or macOS:

```bash
sha256sum --check SHA256SUMS
```

PowerShell:

```powershell
Get-Content SHA256SUMS | ForEach-Object {
    $expected, $path = $_ -split '  ', 2
    $actual = (Get-FileHash -Algorithm SHA256 $path).Hash.ToLower()
    if ($actual -ne $expected) { throw "Checksum mismatch: $path" }
}
```

Resolve one event without loading BGPy or CAIDA:

```bash
python replay_20241030_1316.py \
  --events-root dudata \
  --output-dir results/20241030_1316-dry-run \
  --dry-run
```

Preview the paired commands for the same event:

```bash
python run_counterfactual_replays.py \
  --event 20241030_1316 \
  --path-source received-envelope \
  --dry-run
```

## Run a single replay

```bash
python replay_20241030_1316.py \
  --events-root dudata \
  --caida-cache-dir data/caida_cache \
  --output-dir results/20241030_1316 \
  --path-source received-envelope
```

Important replay controls include:

| Option | Default | Purpose |
|---|---|---|
| `--observation-mode` | `receiver-last` | Selects the observed event state. |
| `--validation-mode` | `receiver-holdout` | Keeps calibration and evaluation receivers disjoint when possible. |
| `--calibration-fraction` | `0.25` | Sets the per-prefix calibration share. |
| `--minimum-holdout-pairs` | `10` | Enables holdout only when enough receiver/prefix pairs exist. |
| `--topology-overlay-mode` | event-specific audited default | Controls RIB-derived, in-memory topology edges. |
| `--overlay-relationship-mode` | `infer` | Infers safe relationship directions or falls back to peers. |
| `--path-source` | event-specific audited default | Chooses final local-RIB paths or the received abnormal-path envelope. |
| `--legal-route-mode` | event-specific audited default | Models whether the legitimate route is present. |
| `--leak-target-mode` | event-specific audited default | Controls route-leak export scope. |

Use an explicit `--path-source` in reported experiments. The
`received-envelope` mode evaluates abnormal candidates retained in local RIBs
and RIBs-In; `local-rib` is the stricter final-route-only ablation.

Each single-event run writes:

- `resolved_event_inputs.json`: selected observations, split, prefixes, and
  topology candidates.
- `simulation_complete.json`: topology, announcement, convergence, and full
  simulation audit.
- `propagation_paths.json`: compact paths, nodes, and edges.
- `similarity_vs_real_rib.json`: similarity, coverage, counts, and quality
  flags.

## Run paired counterfactual experiments

Run the full 24-event experiment:

```bash
python run_counterfactual_replays.py \
  --scripts-dir . \
  --events-root dudata \
  --caida-cache-dir data/caida_cache \
  --output-root results_counterfactual \
  --path-source received-envelope
```

Run selected events by repeating `--event`:

```bash
python run_counterfactual_replays.py \
  --event 20241030_1316 \
  --event 20251120_2147 \
  --path-source received-envelope
```

The driver launches every variant in an isolated subprocess and records the
replay script path and SHA-256. It computes a digest of the actual evaluation
paths and only reports a paired delta when the case and counterfactual digests
match.

Depending on the event type, variants include:

- `case`: the audited event reconstruction.
- `cf_origin_removed`: removes the configured anomalous or recovered origin.
- `cf_leak_removed`: replaces event-only leak export with policy-compliant
  Gao--Rexford export.
- `cf_legal_always` and `cf_legal_withdrawn`: legal-route state ablations.
- `cf_scope_relationship` and `cf_scope_all`: leak-scope ablations.
- `cf_topology_only`: disables RIB-derived topology input.

The output root contains per-event variant directories plus:

- `counterfactual_event_results.csv`: one row per event and variant.
- `counterfactual_summary.json`: configuration, paired deltas, aggregate
  bootstrap intervals, failures, and evaluation mismatches.

Use `--reuse` to reuse an existing result only when its stored run signature is
still valid. Use `--force-variant <name>` with `--reuse` to rerun a specific
variant.

## Method notes

### Observation selection

`receiver-last` keeps the last anomalous route for each receiver/prefix pair and
avoids treating transient path exploration as independent observations.
`peak`, `final`, and the legacy `all-updates` mode are available as ablations.

### Held-out evaluation

Events with enough observations are split deterministically by SHA-256 within
each prefix. Calibration receivers may determine leak targets and optional
topology overlays; evaluation receivers are used only for scoring. Small events
fall back to all observations and receive explicit overlap quality flags.

### Topology handling

The base CAIDA relationship file and cached graph remain unchanged. Missing
RIB-observed adjacencies are added only to a new per-event in-memory graph and
are recorded in the topology audit. Inferred relationships are sensitivity
assumptions, not CAIDA facts.

### Path normalization

The normalized score removes consecutive AS prepending and RFC 6996 private
ASNs. The raw numeric path score is retained for audit and ablation.

## Known data limitation

The `20251114_1950` after-event RIB has no comparable announcements. Its
simulation can still run, but real-path similarity remains unavailable until
the event observations are recollected.

## Build a clean release archive

From the repository root:

```bash
python tools/build_replay_bundle.py
```

This creates:

```text
dist/bgpy-historical-replay-24/
dist/bgpy-historical-replay-24.zip
```

Use `--code-only` to omit the event inputs and CAIDA cache. The build validates
the selection manifest before copying any replay and writes a deterministic ZIP
with a complete `SHA256SUMS` file.

## License

The BGPy source is distributed under the MIT License. See `LICENSE.txt`.
