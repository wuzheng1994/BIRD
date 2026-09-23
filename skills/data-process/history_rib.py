from datetime import datetime, timedelta, timezone
from pathlib import Path
import csv
import sys
import pybgpstream
from tqdm import tqdm
import json
import re
from itertools import groupby

_skill_dir = Path(__file__).resolve().parent
if str(_skill_dir) not in sys.path:
    sys.path.insert(0, str(_skill_dir))
from prefix_filter import bgpstream_prefix_filters
from dump_path import dump_dir

_root = Path(__file__).resolve().parents[2]

'''
def extract_history_rib(prefix: str, start_time: str, event_name: str):
    _event_dir = _root / "data" / "events" / event_name
    output_file = _event_dir / "history_rib.csv"

    if output_file.exists():
        print(f"[history_rib] Output already exists, skipping: {output_file}")
        return

    start = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
    from_time = (start - timedelta(hours=16)).strftime("%Y-%m-%d %H:%M:%S")
    until_time = (start - timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")

    stream = pybgpstream.BGPStream(
        from_time=from_time,
        until_time=until_time,
        collectors=["rrc00"],
        record_type="ribs",
        filter=bgpstream_prefix_filter(prefix)
    )

    _rib_dir = _root / "data" / "cache" / event_name / "rib"
    _rib_dir.mkdir(parents=True, exist_ok=True)

    stream.set_data_interface_option("broker", "cache-dir", str(_rib_dir))

    rows = []

    for rec in tqdm(stream.records()):
        for elem in rec:
            if str(elem.type) == "R":
                peer = str(elem.peer_asn)
                if "as-path" in elem.fields and "prefix" in elem.fields:
                    hops = [k for k, g in groupby(elem.fields['as-path'].split(" "))]
                    as_path = " ".join(hops)
                    rows.append({
                        "prefix": elem.fields["prefix"],
                        "peer_asn": peer,
                        "as_path": as_path,
                    })

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["prefix", "peer_asn", "as_path"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} rows to {output_file}")    
'''

def extract_history_rib(prefix: str, start_time: str, event_name: str):
    _event_dir = _root / "data" / "events" / event_name
    _event_dir.mkdir(parents=True, exist_ok=True)  # 顺便确保输出目录存在
    output_file = _event_dir / "history_rib.csv"

    if output_file.exists():
        print(f"[history_rib] Output already exists, skipping: {output_file}")
        return

    # 事件时间按 UTC 解析（BGP 数据时间戳为 UTC epoch）
    start_ts = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
    # 严格对齐旧版的"16~8 小时窗口"：只处理快照时间在 [start-16h, start-8h) 内的 RIB 文件
    from_ts = start_ts - timedelta(hours=16).total_seconds()
    until_ts = start_ts - timedelta(hours=8).total_seconds()

    # ---------- 数据来源：本地 RIB 目录 ----------
    rib_dir = dump_dir(event_name) / "rib"
    if not rib_dir.exists():
        print(f"[history_rib] RIB directory not found: {rib_dir}")
        return

    rib_files = sorted([f for f in rib_dir.iterdir() if f.is_file()])
    if not rib_files:
        print(f"[history_rib] No RIB files found in {rib_dir}")
        return

    # 从文件名解析 RIB 快照时间 (bview.YYYYMMDD.HHMM)，并筛选落在窗口内的文件
    rib_file_pattern = re.compile(r"(\d{8})\.(\d{4})")
    matched_files = []
    for f in rib_files:
        m = rib_file_pattern.search(f.name)
        if not m:
            print(f"[history_rib] Cannot parse time from filename, skipping: {f.name}")
            continue
        yyyymmdd, hhmm = m.group(1), m.group(2)
        ts = datetime(int(yyyymmdd[:4]), int(yyyymmdd[4:6]), int(yyyymmdd[6:8]),
                      int(hhmm[:2]), int(hhmm[2:4]), tzinfo=timezone.utc).timestamp()
        if from_ts <= ts < until_ts:
            matched_files.append((ts, f))
        else:
            print(f"[history_rib] RIB file outside window, skipping: {f.name}")

    if not matched_files:
        print(f"[history_rib] No RIB files within [{datetime.fromtimestamp(from_ts, tz=timezone.utc)}"
              f" , {datetime.fromtimestamp(until_ts, tz=timezone.utc)}) window")
        # Local _fp dumps often keep only the window-start RIB, not an 8-16h lookback.
        fallback = []
        for f in rib_files:
            m = rib_file_pattern.search(f.name)
            if not m:
                continue
            yyyymmdd, hhmm = m.group(1), m.group(2)
            ts = datetime(int(yyyymmdd[:4]), int(yyyymmdd[4:6]), int(yyyymmdd[6:8]),
                          int(hhmm[:2]), int(hhmm[2:4]), tzinfo=timezone.utc).timestamp()
            if ts <= start_ts:
                fallback.append((ts, f))
        if fallback:
            latest_ts = max(t for t, _ in fallback)
            matched_files = [(t, f) for t, f in fallback if t == latest_ts]
            print(f"[history_rib] Falling back to latest RIB at or before start: "
                  f"{matched_files[0][1].name}")

    rows = []
    for ts, rib_file in tqdm(matched_files, desc="Processing RIB files"):
        print(f"Reading RIB file: {rib_file.name}")
        for filt in bgpstream_prefix_filters(prefix):
            stream = pybgpstream.BGPStream(
                data_interface="singlefile",
                filter=filt,
            )
            stream.set_data_interface_option("singlefile", "rib-file", str(rib_file))

            for rec in stream.records():
                for elem in rec:
                    if str(elem.type) == "R":
                        peer = str(elem.peer_asn)
                        if "as-path" in elem.fields and "prefix" in elem.fields:
                            hops = [k for k, g in groupby(elem.fields['as-path'].split(" "))]
                            as_path = " ".join(hops)
                            rows.append({
                                "prefix": elem.fields["prefix"],
                                "peer_asn": peer,
                                "as_path": as_path,
                            })

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["prefix", "peer_asn", "as_path"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} rows to {output_file}")

if __name__ == "__main__":
    event_json = _root / "event.json"
    with open(event_json, 'r') as file:
        data = json.load(file)

    prefix = data.get("prefix")
    start_time = data.get("start_time")
    end_time = data.get("end_time")
    event_name = data.get("event_name")
    extract_history_rib(prefix, start_time, event_name)