# Data layout

These directories are placeholders. Large routing dumps, CAIDA tables, and
per-event artifacts are **not** shipped with the code.

| Path | Used by | Contents |
|------|---------|----------|
| `data/bgp.db` | `lookup_ownership.py`, `validate_relationships.py` | SQLite with `pfx2as_*` and `rel_*` tables. Build with `python init_bgp_db.py` after placing CAIDA files in `data/pfx2as/` and `data/rel/`. |
| `data/embs/<event_name>.pkl` | `path_score.py` | BGP2VEC AS embeddings for DTW scoring. Train with `python bgp2vec.py --rib-path ... --model-path data/embs/<event_name>.pkl`. |
| `data/ribs/<event_name>/rib/` | `history_rib.py`, `rib_before_incident.py` | Local RIB dumps (`bview.YYYYMMDD.HHMM`). Override root with `RCA_DUMP_ROOT`. |
| `data/ribs/<event_name>/update/` | `rib_after_incident.py` | Local UPDATE dumps. |
| `data/events/<event_name>/` | full pipeline | Per-event CSVs and reports written by `agent.py`. |
| `data/chroma/` | `retrieve.py`, `case_update.py` | Optional Chroma case index (`--retrieve` / `--archive`). |
