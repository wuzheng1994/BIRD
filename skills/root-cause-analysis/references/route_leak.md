---
name: leak-analysis
description: Use this skill to perform a root-cause analysis of a route leak incident.
---

# Route Leak Analysis

## Overview

A route leak occurs when an AS announces prefixes it received from a provider or peer to another provider or peer, violating the Valley-Free routing principle. This causes traffic to flow through unexpected ASes, potentially causing congestion or enabling traffic interception.

**Key characteristic**: The destination/origin AS (last AS in path) remains unchanged, but unexpected transit ASes are inserted in the middle of the path.

## Instructions

### Step 1: Extract AS Triplets

Extract all consecutive AS triplets from the AS path (`update_path`), **traversing from right to left** (closest to the destination first). For a path like `AS1 AS2 AS3 AS4`, the triplets are:
- (AS2, AS3, AS4)  ← checked first (closest to origin/destination)
- (AS1, AS2, AS3)

> **Note:** The leaking AS **cannot** be the first AS (origin) or the last AS (next-hop) in the AS path. It must be an intermediate AS in the path.

### Step 2: Query AS Business Relationships

Use database-related tools (`query_sql_database_tool`,`info_sql_database_tool`,`list_sql_database_tool`,`query_sql_checker_tool`) to query the commercial relationships of all AS pairs in the triplets.

**Table naming convention**: `{table}_{YYYYMM}`
- Example: If start time is `2026-03-19 10:00:00`, the table name is `rel_202603`
- Read the start date from `event.json` to determine the correct table name

> **Fallback**: If the specified table (`rel_{YYYYMM}`) does not exist, query the available tables and use the one with the **most recent date** that is **less than or equal to** the start date. If no such table exists, use the **most recent available table**.

| Field | Description | Values |
|-------|-------------|--------|
| `as1` | First AS number | String |
| `as2` | Second AS number | String |
| `rel` | Relationship | -1 (p2c), 1 (c2p), 0 (p2p) |

**Relationship codes**:
| Code | Relationship | Description |
|------|--------------|-------------|
| `-1` | Provider-to-Customer (p2c) | Provider announces customer routes |
| `1` | Customer-to-Provider (c2p) | Customer announces provider routes |
| `0` | Peer-to-Peer (p2p) | Peers exchange mutual traffic |

**Example query**:
For triplet `(18734, 28548, 14178)`:
1. Query relationship between AS18734 and AS28548 → result: `-1`
2. Query relationship between AS28548 and AS14178 → result: `1`
3. Pair: `(-1, 1)`

### Step 3: Detect Anomalies

Find triplets with abnormal business relationship pairs:

| Pair | Type | Description |
|------|------|-------------|
| `(-1, 1)` | Provider-to-Provider leak | Transit provider leaks to another provider |
| `(-1, 0)` | Provider-to-Peer leak | Provider leaks routes to a peer |
| `(0, 1)` | Peer-to-Provider leak | Peer leaks routes to their provider |
| `(0, 0)` | Peer-to-Peer leak | Peer leaks routes to another peer |

**Normal patterns** (valley-free):
- `(1, -1)` - Customer → Provider → Customer (correct)
- `(0, -1)` - Peer → Customer (correct)
- `(1, 0)` - Customer → Peer (correct)
- `(1, 1)` - Customer → Provider → Peer (acceptable)

### Example

**Input**:
- IP prefix: `192.168.1.0/24`
- AS path: `65001 65004 65005 65003`

**Triplets**:
- `(65004, 65005, 65003)` - relationship pair: `(p2p, p2c) = (0, -1)` → normal
- `(65001, 65004, 65005)` - relationship pair: `(p2p, p2p) = (0, 0)` → **ABNORMAL**

**Result**: AS 65004 leaked routes from peer AS 65001 to peer AS 65005.
