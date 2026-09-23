# Prefix Hijack Analysis

## Overview

A prefix hijack occurs when an AS announces a prefix that it does not legitimately own, causing traffic to be redirected to the attacker instead of the legitimate owner. This can result in traffic interception, service disruption, or data theft.

**Key characteristic**: The origin/destination AS in the AS path changes to a different AS, meaning traffic will be routed to a different destination than the legitimate owner.

## Instructions

### Step 1: Extract Network Address and Origin AS

Extract the network address from the IP prefix (`rib_prefix`), then extract the origin AS from the AS path (`rib_path`).

**Network address extraction**:
- Remove the prefix length from the IP prefix
- Example: `64.233.161.0/24` → network address: `64.233.161.0`

**Origin AS extraction**:
- The origin AS is the last AS in the AS path
- Example: AS path `65001 65002 65003` → origin AS: `65003`

### Step 2: Query Prefix-to-AS Mapping

Run the deterministic ownership lookup. Do **not** query `pfx2as_*` with ad-hoc SQL.

```bash
python <SKILLS_DIR>/root-cause-analysis/lookup_ownership.py \
  --event-name <YYYYMMDD_HHmm> \
  --project-root <PROJECT_ROOT>
```

Use `ownership.json` in the event folder as the **only** source for prefix
ownership. The script selects the nearest `pfx2as_YYYYMMDD` table (event day
or the most recent earlier table), queries the network address **without**
`/len`, then supernet addresses longest-first.

| Field in `ownership.json` | Description |
|---------------------------|-------------|
| `table` | Resolved `pfx2as_YYYYMMDD` table |
| `network_address` | Event prefix with mask stripped |
| `observed_origin_as` | Origin of the top `score.json` update path |
| `legitimate_asns` | ASNs returned for exact/supernet hits |
| `claimed_origin_authorized` | `true` / `false` / `null` (unknown if no rows) |
| `queries` | Addresses actually queried and their ASN lists |

### Step 3: Detect Anomalies

Compare the observed origin AS with the legitimate owner AS:

| Condition | Result |
|-----------|--------|
| Observed AS = Legitimate AS | Normal routing |
| Observed AS ≠ Legitimate AS | **Prefix hijack detected** |

**Hijack roles**:
| Role | Definition |
|------|------------|
| **Attacker AS** | For Type-0 (`E|0` / `S|0`): the origin AS of the updated path. Do **not** use this attribution when the path is Type-1 (`... A V`); then the attacker is the penultimate AS `A`. |
| **Victim AS** | The legitimate owner of the prefix (from database) |

A more-specific whose origin differs from the covering prefix is **not** automatically Type-0. Evaluate Type-1 S|1 first (`type_1_hijack.md`). Only if the claimed origin is unauthorized should the event be classified as `prefix_hijack` (S|0).

### Example

**Input**:
- IP prefix: `64.233.161.0/24`
- AS path: `65001 65002 65004`
- Origin AS: `65004`

**Ownership lookup** (`ownership.json`):
- Network address `64.233.161.0` in the nearest `pfx2as_YYYYMMDD` table
- Result: `legitimate_asns` = `["65001"]`, `claimed_origin_authorized` = `false`

**Detection**:
- The origin AS of the updated announcement path (`65004`) ≠ Legitimate AS (`65001`) → **Hijack detected**

**Result**:
- Attacker AS: `65004`
- Victim AS: `65001`
- AS 65004 is announcing prefix 64.233.161.0/24 which legitimately belongs to AS 65001
