# Replay and verify

BGPy 历史异常 **replay / verify** 代码，对应原 `bgpy_24_events` 交付包的第 2–4 部分：单事件复现、反事实对照、因果根因与错误归因实验。

所有命令默认在本目录 `replay_verify/` 下执行。仓库根的 `agent.py` 也会调用本目录的 `invoke.py`：

```bash
python agent.py --event-name 20241030_1316 --replay-only --dry-run
python agent.py --event-name 20241030_1316 --replay --verify --dry-run
```

## Layout

```text
replay_verify/
|-- README.md
|-- 01_24_anomaly_events/
|   |-- event.xlsx
|   |-- anomaly-event-info.csv
|   |-- events/<event-id>/          # 事件 RIB / UPDATE 输入
|   `-- caida_cache/                # 需自行放入 CAIDA 快照（未随仓库提交）
|-- 02_reproduction_code/
|   |-- bgpy/                       # 本地 BGPy 运行时（MIT, Justin Furuness 等）
|   `-- replay_<event-id>.py
|-- 03_counterfactual_code/
|   |-- run_counterfactual_replays.py
|   `-- run_counterfactual_replays_realistic.py
`-- 04_error_tracing_code/
    |-- run_causal_replays.py
    |-- run_misattribution_replays.py
    `-- plot_misattribution_cdfs.py
```

仿真输出写到 `replay_verify/outputs/`（已加入 gitignore）。

## Install

Python 3.10+。在仓库根或本目录创建环境后，以可编辑方式安装本地 BGPy：

```bash
cd replay_verify
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e 02_reproduction_code
```

## CAIDA snapshots

完整仿真需要事件日期对应的 AS 关系图，放到：

```text
01_24_anomaly_events/caida_cache/
```

文件名形如 `CAIDAASGraphCollector_YYYY.MM.01.txt`。仓库不附带这些快照（约 134MB）。无缓存时，replay 会尝试按 BGPy 逻辑下载 CAIDA serial-2 文件。

## Validate one event (no simulation)

```bash
python 02_reproduction_code/replay_20241030_1316.py \
  --events-root 01_24_anomaly_events/events \
  --caida-cache-dir 01_24_anomaly_events/caida_cache \
  --output-dir outputs/reproduction/20241030_1316-dry-run \
  --dry-run
```

## Reproduce one event

```bash
python 02_reproduction_code/replay_20241030_1316.py \
  --events-root 01_24_anomaly_events/events \
  --caida-cache-dir 01_24_anomaly_events/caida_cache \
  --output-dir outputs/reproduction/20241030_1316 \
  --path-source received-envelope
```

产物：`resolved_event_inputs.json`、`simulation_complete.json`、`propagation_paths.json`、`similarity_vs_real_rib.json`。

主指标为覆盖调整后的路径相似度（未覆盖观测接收者计 0）：

```text
similarity.mean_observed_path_similarity_including_uncovered
```

## Counterfactual

```bash
python 03_counterfactual_code/run_counterfactual_replays.py \
  --scripts-dir 02_reproduction_code \
  --events-root 01_24_anomaly_events/events \
  --caida-cache-dir 01_24_anomaly_events/caida_cache \
  --output-root outputs/counterfactual \
  --event 20241030_1316 \
  --path-source received-envelope \
  --dry-run
```

基于预事件合法源的 realistic 对照：

```bash
PYTHONPATH=04_error_tracing_code \
python 03_counterfactual_code/run_counterfactual_replays_realistic.py \
  --scripts-dir 02_reproduction_code \
  --events-root 01_24_anomaly_events/events \
  --caida-cache-dir 01_24_anomaly_events/caida_cache \
  --output-root outputs/counterfactual-realistic \
  --event 20241030_1316 \
  --validation-mode all \
  --dry-run
```

完整跑时去掉 `--dry-run`，并可提供因果 Case 对照目录：`--case-reference-root outputs/causal`。

`Delta M = M_case - M_counterfactual`，仅在两侧 evaluation digest 一致时报告。

## Causal root tracing

```bash
python 04_error_tracing_code/run_causal_replays.py \
  --scripts-dir 02_reproduction_code \
  --events-root 01_24_anomaly_events/events \
  --caida-cache-dir 01_24_anomaly_events/caida_cache \
  --output-root outputs/causal \
  --event 20241030_1316 \
  --validation-mode all \
  --dry-run
```

## Wrong-attribution (verify)

```bash
python 04_error_tracing_code/run_misattribution_replays.py \
  --scripts-dir 02_reproduction_code \
  --events-root 01_24_anomaly_events/events \
  --caida-cache-dir 01_24_anomaly_events/caida_cache \
  --causal-driver 04_error_tracing_code/run_causal_replays.py \
  --output-root outputs/misattribution \
  --event 20241030_1316 \
  --dry-run
```

去掉 `--dry-run` 后会写出归因分数、CDF 与 `attribution_summary.json`。可用 `plot_misattribution_cdfs.py` 绘图。

## Notes

- `20251114_1950` 事后 RIB 为空，真实路径相似度不可用。
- RIB 导出的拓扑边是事件局部敏感性假设，不是 CAIDA 事实。
- 本地 `bgpy/` 按 [MIT License](02_reproduction_code/LICENSE.txt) 分发（Copyright 2020 Justin Furuness）。
