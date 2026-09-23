# BIRD

**BIRD**（BGP Incident Root-cause Detection）是一套脚本优先的 BGP 异常溯源与传播分析流水线。给定前缀与时间窗，它从本地 RIB/UPDATE 转储中提取路径变化，用 DTW + AS 嵌入打分，再按确定性规则生成根因报告；仅在证据歧义时调用一次 LLM。传播阶段对观测到的 root→observer 路径估计链路后验概率。

BIRD is a script-first pipeline for BGP anomaly root-cause and propagation analysis. Most events are classified without an LLM.

## Pipeline

```
prefix, start_time, end_time
        │
        ▼
 Step 1  event.json + data/events/<event_name>/
        │
        ▼
 Step 2  data-process          → history_rib.csv
                                 rib_before_incident.csv
                                 rib_after_incident.csv
        │
        ▼
 Step 3  detect-path-change    → paths.json
        │
        ▼
 Step 4  path-score (DTW)      → score.json
        │
        ▼
 Step 5  RCA extractors        → root_cause_evidence.json
                                 relationship_validation.json
                                 ownership.json
         finalize_report.py    → root_cause_report.json
        │
        ▼
 Step 6  propagation-analysis  → propagation_report.json
```

Optional flags: `--retrieve` (Chroma 参考案例)、`--archive`（把报告写入向量库）、`--skip-propagation`。

分类顺序（由 `finalize_report.py` 实现，不要手读 CSV 重做）：

1. Type-1 hijack（`... A V`，攻击者是倒数第二跳 `A`）
2. Prefix hijack（精确前缀源 AS 变化，或未授权更具体前缀）
3. Route leak（源 AS 不变，且关系校验为 `route_leak_candidate`）
4. Route outage / other

## Repository layout

```
BIRD_code/
├── agent.py                         # 主入口：串联 Step 1–6
├── config.py                        # 从 .env 读取 DASHSCOPE_API_KEY
├── llm_provider.py                  # DashScope ChatTongyi + embedding（歧义分类 / 检索）
├── combine_token_reports.py         # 可选：合并 Cursor transcript 与 API token
├── bgp2vec.py                       # 训练 AS 嵌入，供 path-score 使用
├── init_bgp_db.py                   # 从 CAIDA pfx2as / rel 文件建 SQLite
├── create_simple_propagation_report.py
├── AGENTS.md                        # 给 Agent 用的调用约定（不要把路由数据贴进 prompt）
├── requirements.txt
├── skills/
│   ├── data-process/                # 从本地 dump 抽 RIB / UPDATE
│   ├── detect-path-change/          # 事件前后 AS_PATH 配对
│   ├── path-score/                  # DTW 路径差分数
│   ├── root-cause-analysis/         # 溯源证据、关系校验、所有权、定稿
│   ├── case-update/                 # 可选：Chroma 归档
│   └── propagation-analysis/        # 观测路径上的边后验与路径排序
├── tests/
├── data/                            # 占位目录；数据库与大规模事件产物不随代码提交
└── replay_verify/                   # BGPy 历史事件 replay / 反事实 / 错误归因验证
```

RCA 流水线的 `data/events/`、`bgp.db`、嵌入 `.pkl`、Chroma 索引需自行准备，见 [data/README.md](data/README.md)。Replay 验证的事件输入在 [replay_verify/](replay_verify/README.md)（不含 CAIDA 缓存）。

## Requirements

- Python 3.10+
- [libbgpstream](https://bgpstream.caida.org/docs/install/pybgpstream)（`pybgpstream` 的系统依赖）
- 阿里云百炼 / DashScope API Key（仅在需要 LLM 或 `--retrieve` / `--archive` 时）

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pybgpstream   # 需先安装 libbgpstream-dev / libwandio-dev
cp .env.example .env      # 填入 DASHSCOPE_API_KEY
```

## Data you must provide

| File | Purpose |
|------|---------|
| `data/bgp.db` | 前缀所有权 `pfx2as_*` 与 AS 关系 `rel_*`。将 CAIDA 文件放到 `data/pfx2as/`、`data/rel/` 后运行 `python init_bgp_db.py`。 |
| `data/embs/<event_name>.pkl` | DTW 用的 AS 向量。`python bgp2vec.py --rib-path <rib.txt> --model-path data/embs/<event_name>.pkl` |
| `data/ribs/<event_name>/rib/` 与 `.../update/` | 本地 BGP dump。也可用环境变量 `RCA_DUMP_ROOT` 指向已有 dump 根目录。 |

`path-score` 会读取 `data/embs/<event_name>.pkl`。没有该文件时无法写出 `score.json`。

## Usage

```bash
python agent.py \
  --prefix "208.65.152.0/22" \
  --start-time "2008-02-24 18:00:00" \
  --end-time "2008-02-24 22:00:00"
```

可选参数：

| Flag | Meaning |
|------|---------|
| `--event-name YYYYMMDD_HHmm` | 事件目录名；默认由 `start_time` 生成 |
| `--force` | 删除该事件已有步骤产物后重跑 |
| `--retrieve` | 定稿前从 Chroma 取 1 条参考案例 |
| `--archive` | 把 `root_cause_report.json` 写入 Chroma |
| `--skip-propagation` | 跳过传播分析 |
| `--replay` | RCA 之后跑对应事件的 BGPy 结构 replay |
| `--verify` | RCA 之后跑错误归因（misattribution）验证 |
| `--causal` | RCA 之后跑因果 Case / counterfactual |
| `--counterfactual` | RCA 之后跑反事实对照 |
| `--replay-only` | 跳过 RCA，只跑上面的 replay/verify |
| `--dry-run` | 传给 BGPy：只解析输入，不加载拓扑 |
| `--cursor-transcript path.jsonl` | 合并 Cursor 会话 token 统计 |

单步运行（需已有 `event.json`）：

```bash
python skills/data-process/history_rib.py
python skills/data-process/rib_before_incident.py
python skills/data-process/rib_after_incident.py
python skills/detect-path-change/detect_change.py
python skills/path-score/path_score.py
python skills/root-cause-analysis/extended_rca.py --event-name <id> --project-root .
python skills/root-cause-analysis/validate_relationships.py --event-name <id> --project-root .
python skills/root-cause-analysis/lookup_ownership.py --event-name <id> --project-root .
python skills/root-cause-analysis/finalize_report.py --event-name <id> --project-root .
python skills/propagation-analysis/propagation-analysis.py --event-name <id> --project-root .
python replay_verify/invoke.py --event-name <id> --mode replay --dry-run
```

Agent 调度约定见 [AGENTS.md](AGENTS.md)：只传前缀与时间，不要把 RIB/UPDATE 或 `paths.json` 贴进对话。

## Outputs

每个事件写在 `data/events/<event_name>/`：

| File | Description |
|------|-------------|
| `event.json` | 输入参数 |
| `history_rib.csv` / `rib_before_incident.csv` / `rib_after_incident.csv` | 抽取出的路由观测 |
| `paths.json` | 事件前后路径对 |
| `score.json` | DTW 排序后的 top-k 路径差 |
| `root_cause_evidence.json` | 溯源抽取器原始证据 |
| `relationship_validation.json` | 谷底无关三元组 / leak 证据（关系的唯一来源） |
| `ownership.json` | 前缀所有权（所有权的唯一来源） |
| `root_cause_report.json` | 溯源报告 |
| `propagation_report.json` | 传播边后验与路径排序 |

对 `other` 类型且标准传播脚本因缺少 `leaking_as` / `attacker_as` 失败时，可改跑 `create_simple_propagation_report.py`。

## Tests

```bash
python -m unittest discover -s skills/data-process/tests -p "test_*.py"
python -m unittest discover -s skills/detect-path-change/tests -p "test_*.py"
python -m unittest discover -s skills/root-cause-analysis/tests -p "test_*.py"
python -m unittest tests/test_validate_relationships.py
```

## Replay / verify

`agent.py` 在 RCA 之后（或 `--replay-only`）调用 `replay_verify/invoke.py`，只传事件名：

```bash
python agent.py --event-name 20241030_1316 --replay-only --dry-run
python agent.py --event-name 20241030_1316 --replay --verify --dry-run
```

优先使用 `data/events/<id>/` 里已抽出的 CSV；没有则回退到 `replay_verify/01_24_anomaly_events/events/`。直接跑驱动见 [replay_verify/README.md](replay_verify/README.md)：

```bash
cd replay_verify
python -m pip install -e 02_reproduction_code
python 02_reproduction_code/replay_20241030_1316.py \
  --events-root 01_24_anomaly_events/events \
  --caida-cache-dir 01_24_anomaly_events/caida_cache \
  --output-dir outputs/reproduction/20241030_1316-dry-run \
  --dry-run
```

因果对照与错误归因分别由 `04_error_tracing_code/run_causal_replays.py` 和 `run_misattribution_replays.py` 驱动。CAIDA 快照需放到 `replay_verify/01_24_anomaly_events/caida_cache/`。

## Notes for publishing

- 不要提交 `.env`、`data/bgp.db`、事件 CSV、嵌入 pickle 或 Chroma 目录。
- `llm_provider.py` 只从环境变量读密钥；没有 `DASHSCOPE_API_KEY` 时，确定性定稿仍可运行，LLM 回退会失败。
- 本目录是从运行时仓库抽出的骨干代码，不含 `experiments/` 与大规模 `data/events/` 产物。

## License

本项目采用 [MIT License](LICENSE)。内嵌的 BGPy 运行时见 [replay_verify/02_reproduction_code/LICENSE.txt](replay_verify/02_reproduction_code/LICENSE.txt)（MIT, Copyright 2020 Justin Furuness）。CAIDA 关系数据、RouteViews/RIPE RIB 转储等第三方数据仍受其各自许可约束，不随本仓库再授权。
