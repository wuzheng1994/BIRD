from datetime import datetime, timedelta, timezone
from pathlib import Path
import csv
import sys
import pybgpstream
from tqdm import tqdm
import json
from itertools import groupby

_skill_dir = Path(__file__).resolve().parent
if str(_skill_dir) not in sys.path:
    sys.path.insert(0, str(_skill_dir))
from prefix_filter import bgpstream_prefix_filters
from dump_path import dump_dir

_root = Path(__file__).resolve().parents[2]

'''
def rib_after_incident(prefix: str, start_time: str, end_time: str, event_name: str):
    _event_dir = _root / "data" / "events" / event_name
    output_file = _event_dir / "rib_after_incident.csv"

    if output_file.exists():
        print(f"[rib_after_incident] Output already exists, skipping: {output_file}")
        return

    stream = pybgpstream.BGPStream(
        from_time=start_time,
        until_time=end_time,
        collectors=["rrc00"],
        record_type="updates",
        filter=bgpstream_prefix_filter(prefix)
    )

    _upd_dir = _root / "data" / "cache" / event_name / "updates"
    _upd_dir.mkdir(parents=True, exist_ok=True)

    stream.set_data_interface_option("broker", "cache-dir", str(_upd_dir))

    rows = []

    for rec in tqdm(stream.records()):
        for elem in rec:
            if str(elem.type) == "A":
                timestamp = int(elem.time)
                peer = str(elem.peer_asn)
                if "as-path" in elem.fields and "prefix" in elem.fields:
                    hops = [k for k, g in groupby(elem.fields['as-path'].split(" "))]
                    as_path = " ".join(hops)
                    rows.append({
                        "timestamp": timestamp,
                        "prefix": elem.fields["prefix"],
                        "peer_asn": peer,
                        "as_path": as_path,
                    })

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "prefix", "peer_asn", "as_path"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} rows to {output_file}")
'''

def rib_after_incident(prefix: str, start_time: str, end_time: str, event_name: str):
    _event_dir = _root / "data" / "events" / event_name
    _event_dir.mkdir(parents=True, exist_ok=True)
    output_file = _event_dir / "rib_after_incident.csv"

    if output_file.exists():
        print(f"[rib_after_incident] Output already exists, skipping: {output_file}")
        return

    # 只保留异常开始时间至结束时间之间（start_time <= t < end_time）的 UPDATE 记录
    # 事件时间按 UTC 解析（BGP 数据时间戳为 UTC epoch）
    start_ts = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
    end_ts = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).timestamp()

    # ---------- 读取 updates 目录下所有文件 ----------
    upd_dir = dump_dir(event_name) / "updates"
    if not upd_dir.exists():
        print(f"[rib_after_incident] Updates directory not found: {upd_dir}")
        return

    upd_files = sorted([str(f) for f in upd_dir.iterdir() if f.is_file()])
    if not upd_files:
        print(f"[rib_after_incident] No updates files found in {upd_dir}")
        return

    print(f"Found {len(upd_files)} update file(s) in {upd_dir}")

    rows = []

    # 循环遍历 120 个离线更新文件
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
                        timestamp = int(elem.time)
                        if timestamp < start_ts or timestamp >= end_ts:
                            continue
                        peer = str(elem.peer_asn)
                        if "as-path" in elem.fields and "prefix" in elem.fields:
                            hops = [k for k, g in groupby(elem.fields['as-path'].split(" "))]
                            as_path = " ".join(hops)
                            rows.append({
                                "timestamp": timestamp,
                                "prefix": elem.fields["prefix"],
                                "peer_asn": peer,
                                "as_path": as_path,
                            })

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "prefix", "peer_asn", "as_path"])
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
    rib_after_incident(prefix, start_time, end_time, event_name)
