---
name: data-process
description: Obtain and process the routing data related to the BGP anomaly event. This is the first step in analyzing a BGP anomaly event. The routing data includes historical RIB data, UPDATES data before the anomaly event, and UPDATES data after the anomaly event.
---

# Data Process Skill

Processes historical RIB and UPDATES data for BGP anomaly analysis.

## Output

Generates the following CSV files in `<PROJECT_ROOT>/data/events/<YYYYMMDD_HHmm>/`:

| File                       | Description                                  |
|----------------------------|----------------------------------------------|
| `rib_history.csv`          | Historical RIB data for the prefix           |
| `rib_before_incident.csv`  | RIB and UPDATE data before the anomaly event |
| `rib_after_incident.csv`   | UPDATE data after the anomaly event          |


The scripts collect covering prefixes with two BGPStream passes
(`prefix more P` and `prefix less P`; BGPStream does not support `or`).
Covering routes are required for S|1 (subprefix Type-1) baselines. If the
three CSV files already exist they are not overwritten; delete them before
re-collecting with the updated filter.

## Steps

### Step 1: Extract Historical RIB Data

Extracts historical BGP routing information (RIB snapshots) for the specified prefix.

```bash
python <SKILLS_DIR>/data-process/history_rib.py

### Step 2: Extract Routing Data Before the Anomaly

Extracts RIB and UPDATE data from the time period before the anomaly start time.

```bash
python <SKILLS_DIR>/data-process/rib_before_incident.py
```

### Step 3: Extract Routing Data After the Anomaly

Extracts UPDATE data from the time period after the anomaly end time.

```bash
python <SKILLS_DIR>/data-process/rib_after_incident.py 
```