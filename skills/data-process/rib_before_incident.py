from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import sys
import pybgpstream
from tqdm import tqdm
import pandas as pd
from itertools import groupby

_skill_dir = Path(__file__).resolve().parent
if str(_skill_dir) not in sys.path:
    sys.path.insert(0, str(_skill_dir))
from prefix_filter import bgpstream_prefix_filters
from dump_path import dump_dir

_root = Path(__file__).resolve().parents[2]

'''
def rib_before_incident(prefix: str, start_time: str, event_name: str):
    _event_dir = _root / "data" / "events" / event_name
    output_file = _event_dir / "rib_before_incident.csv"

    if output_file.exists():
        print(f"[rib_before_incident] Output already exists, skipping: {output_file}")
        return

    start = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
    from_time = (start - timedelta(hours=6)).strftime("%Y-%m-%d %H:%M:%S")

    stream = pybgpstream.BGPStream(
        from_time=from_time,
        until_time=start_time,
        collectors=["rrc00"],
        record_type="updates",
        filter=bgpstream_prefix_filter(prefix)
    )

    _upd_dir = _root / "data" / "cache" / event_name / "updates"
    _upd_dir.mkdir(parents=True, exist_ok=True)

    stream.set_data_interface_option("broker", "cache-dir", str(_upd_dir))

    history_rib_file = _event_dir / "history_rib.csv"
    rows = []

    try:
        if not history_rib_file.exists():
            raise FileNotFoundError(f"Required file not found: {history_rib_file}")

        history_rib_df = pd.read_csv(history_rib_file, dtype=str)
    except Exception as e:
        raise RuntimeError(f"Failed to load history RIB CSV: {e}") from e

    for rec in tqdm(stream.records()):
        for elem in rec:
            if str(elem.type) == "A":
                peer = str(elem.peer_asn)
                if "as-path" in elem.fields and "prefix" in elem.fields:
                    hops = [k for k, g in groupby(elem.fields['as-path'].split(" "))]
                    as_path = " ".join(hops)
                    rows.append({
                        "prefix": elem.fields["prefix"],
                        "peer_asn": peer,
                        "as_path": as_path,
                    })
    before_df = pd.DataFrame(rows, columns=["prefix", "peer_asn", "as_path"])

    merged_df = pd.concat([history_rib_df, before_df], ignore_index=True)
    merged_df = merged_df.drop_duplicates()

    merged_df.to_csv(output_file, index=False, encoding="utf-8")

    print(f"Saved {len(merged_df)} rows to {output_file}")
'''

def rib_before_incident(prefix: str, start_time: str, event_name: str):
    _event_dir = _root / "data" / "events" / event_name
    _event_dir.mkdir(parents=True, exist_ok=True)
    output_file = _event_dir / "rib_before_incident.csv"

    if output_file.exists():
        print(f"[rib_before_incident] Output already exists, skipping: {output_file}")
        return

    # 事件时间按 UTC 解析（BGP 数据时间戳为 UTC epoch）
    start_ts = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
    # 恢复旧实现的"前 6 小时"窗口：只保留 [start-6h, start) 内的 UPDATE 记录
    from_ts = start_ts - timedelta(hours=6).total_seconds()

    upd_dir = dump_dir(event_name) / "updates"
    if not upd_dir.exists():
        print(f"[rib_before_incident] Updates directory not found: {upd_dir}")
        return

    upd_files = sorted([str(f) for f in upd_dir.iterdir() if f.is_file()])
    if not upd_files:
        print(f"[rib_before_incident] No updates files found in {upd_dir}")
        return

    print(f"Found {len(upd_files)} update file(s) in {upd_dir}")

    history_rib_file = _event_dir / "history_rib.csv"
    rows = []

    try:
        if not history_rib_file.exists():
            raise FileNotFoundError(f"Required file not found: {history_rib_file}")

        history_rib_df = pd.read_csv(history_rib_file, dtype=str)
    except Exception as e:
        raise RuntimeError(f"Failed to load history RIB CSV: {e}") from e

    # 循环遍历离线更新文件
    for upd_file in tqdm(upd_files, desc="Processing Updates"):
        for filt in bgpstream_prefix_filters(prefix):
            stream = pybgpstream.BGPStream(
                data_interface="singlefile",
                filter=filt,
            )
            stream.set_data_interface_option("singlefile", "upd-file", upd_file)

            for rec in stream.records():
                for elem in rec:
                    if str(elem.type) == "A":
                        t = float(elem.time)
                        if t < from_ts or t >= start_ts:
                            continue
                        peer = str(elem.peer_asn)
                        if "as-path" in elem.fields and "prefix" in elem.fields:
                            hops = [k for k, g in groupby(elem.fields['as-path'].split(" "))]
                            as_path = " ".join(hops)
                            rows.append({
                                "prefix": elem.fields["prefix"],
                                "peer_asn": peer,
                                "as_path": as_path,
                            })

    before_df = pd.DataFrame(rows, columns=["prefix", "peer_asn", "as_path"])

    merged_df = pd.concat([history_rib_df, before_df], ignore_index=True)
    merged_df = merged_df.drop_duplicates()

    merged_df.to_csv(output_file, index=False, encoding="utf-8")

    print(f"Saved {len(merged_df)} rows to {output_file}")

    
if __name__ == "__main__":
    event_json = _root / "event.json"
    with open(event_json, 'r') as file:
        data = json.load(file)

    prefix = data.get("prefix")
    start_time = data.get("start_time")
    end_time = data.get("end_time")
    event_name = data.get("event_name")
    rib_before_incident(prefix, start_time, event_name)
