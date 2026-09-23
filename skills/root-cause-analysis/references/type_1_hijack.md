---
name: type-1-hijack-analysis
description: Analyze Type-1 path hijacks, including exact-prefix E|1 and subprefix S|1 forged-origin cases.
---

# Type-1 Hijack Analysis

## Definition

A Type-1 hijack is a forged-origin path of the form:

```text
Anomalous path: ... A V
```

`V` is the claimed origin (rightmost AS). `A` is a newly observed AS immediately
to its left. The suspected attacker is `A`; the victim is `V`. Consecutive
prepending is collapsed (`... A A A V` → `... A V`).

There are two prefix-dimension subtypes:

### E|1 — exact prefix

```text
Normal path:    ... U V     on prefix P
Anomalous path: ... A V     on the same prefix P
```

The origin `V` is unchanged. Legitimate neighbors of `V` on `P` remain visible
as `... U V` while the forged adjacency `A-V` appears. Detect E|1 from the
same-prefix historical neighbor baseline.

### S|1 — more-specific / subprefix

```text
Normal path:    ... U       on covering prefix C (e.g. 44.224.0.0/11 origin 16509)
Anomalous path: ... A V     on new more-specific P (e.g. 44.235.216.0/24, 209243 14618)
```

The more-specific did not exist (or was not the baseline) before the event.
The covering origin may differ from `V`. Do not treat that origin change as
Type-0: the attacker is still the novel penultimate AS `A`, not `V`.

Celer Bridge (2022-08-17) and KLAYswap (2022-02) are S|1. There is usually no
same-prefix path `... X V` to compare; the legitimate control plane lives on
the covering prefix.

This differs from:

- Type-0 / prefix hijack (`E|0` or `S|0`): the attacker is the origin.
- Route leak: an existing route is exported against policy, typically with the
  old predecessor of `V` retained.

## Required evidence

A positive classification requires all of the following:

1. `A` is immediately adjacent to claimed origin `V` (`... A V`).
2. Prefix ownership (or same-organization / historical origin) confirms that
   `V` is a plausible legitimate origin for E|1, or for the covering space in
   S|1. If `V` is unauthorized, reclassify as prefix hijack (S|0 / E|0).
3. The adjacency `A-V` is absent from the historical and pre-event baseline of
   origin `V` (including covering-prefix paths for S|1).
4. At least two VPs observe paths containing the same `A-V` adjacency.
5. The observations occur within the event interval.
6. For S|1 only: the update prefix is a more-specific of a covering baseline
   prefix. Empty pre-event RIB for the more-specific is expected, not a
   collection failure, provided the covering prefix is present.

The deterministic evidence extractor checks path shape, prefix relation,
adjacency novelty, and VP support. The root-cause-analysis skill must validate
prefix ownership before producing the final report.

## Analysis procedure

### Step 1 — Normalize paths

Collapse consecutive AS prepends and reject empty or one-hop paths.

### Step 2 — Classify prefix relation

Compare `rib_prefix` and `upd_prefix`:

- `exact` → evaluate E|1. If origins differ, this is an ordinary origin-hijack
  candidate (E|0), not Type-1.
- `more_specific` → evaluate S|1. Covering origin ≠ claimed origin does **not**
  by itself make the event Type-0.
- Same origin, same predecessor, more-specific → legitimate deaggregation, not
  Type-1.

### Step 3 — Extract strict adjacency

```text
candidate attacker = update_path[-2]
claimed origin V   = update_path[-1]
covering origin    = rib_path[-1]          # S|1 baseline
```

The candidate is valid only when `A != V`.

### Step 4 — Check adjacency novelty

Build historical predecessors of origin `V` from `rib_history.csv` /
`history_rib.csv` and `rib_before_incident.csv`, including covering prefixes.
Reject high-confidence Type-1 classification if `A` is already a normal
predecessor of `V`. CAIDA `rel_*` missing values are not novelty evidence.

### Step 5 — Check VP support

Match anomalous paths against post-event observations. Require at least two
distinct `(collector, peer_asn, peer_ip)` VP identities.

### Step 6 — Check competing explanations

Query AS relationships for `A-V` and nearby triplets.

- A known provider/customer adjacency may indicate a legitimate upstream change.
- A valley-free violation away from the origin may support route leak.
- Missing relationship data is uncertainty, not proof of hijacking.
- For S|1, if ownership validation shows `V` is unauthorized, report
  `prefix_hijack` (S|0) with attacker = origin, not Type-1.

If Type-1 and route-leak evidence are both strong, report the result as
ambiguous or low confidence and retain both evidence sets.

## Counterexamples

Do not classify the following as Type-1:

- Exact prefix `... U V` changes to `... U X`: origin change, E|0 candidate.
- More-specific originated by an unauthorized AS with no plausible victim
  origin `V`: S|0 prefix hijack; attacker is the origin.
- `... U V` changes to another historically common `... A V`.
- A single VP observes `... A V` once without independent support.
- An AS is inserted in the middle of the path but is not immediately adjacent
  to `V`.
- The same `A-V` adjacency is common in historical RIB data.
- A more-specific that keeps covering origin `V` and the same predecessor `U`.

## Report schema

```json
{
  "prefix": "44.235.216.0/24",
  "start_time": "2022-08-17 19:39:00",
  "end_time": "2022-08-17 21:00:00",
  "anomaly_type": "type_1_hijack",
  "root_cause": {
    "attacker_as": 209243,
    "victim_as": 14618,
    "hijack_subtype": "S|1",
    "forged_adjacency": [209243, 14618],
    "covering_prefix": "44.224.0.0/11",
    "covering_origin_as": 16509,
    "announced_prefix": "44.235.216.0/24",
    "prefix_relation": "more_specific",
    "normal_predecessors": [],
    "origin_unchanged": false,
    "novel_adjacency": true,
    "supporting_vp_count": 4,
    "confidence": "high",
    "evidence_limitations": []
  },
  "description": "AS 209243 newly appeared immediately before origin AS 14618 on more-specific 44.235.216.0/24 compared against covering 44.224.0.0/11 origin AS 16509."
}
```

For E|1, set `hijack_subtype` to `"E|1"`, `origin_unchanged` to true, and omit
or leave covering fields empty.

## Mandatory limitations

The report must not state that Type-1 is proven solely because the penultimate
AS changed, or solely because a more-specific appeared. It must disclose missing
prefix ownership, relationship, historical adjacency, covering-prefix, or
independent VP evidence. Attacker attribution is the penultimate AS `A`, never
the claimed origin `V` when the path is `... A V`.
