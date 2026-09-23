import json
import os
import pickle
from typing import List, Dict, Optional
import numpy as np
from pathlib import Path

_root = Path(__file__).resolve().parents[2]


def load_embeddings(path: str) -> Optional[Dict[str, np.ndarray]]:
    if not os.path.exists(path):
        print(f"Embedding file not found: {path}")
        return None
    with open(path, "rb") as f:
        return pickle.load(f)


def emb_distance(a: str, b: str, em_dict: Dict[str, np.ndarray]) -> float:
    vec_a = em_dict.get(a)
    vec_b = em_dict.get(b)
    if vec_a is None or vec_b is None:
        return float("nan")
    denom = np.linalg.norm(vec_a) * np.linalg.norm(vec_b)
    if denom == 0:
        return 1.0
    return 1.0 - np.dot(vec_a, vec_b) / denom


def dtw_distance(path_a: List[str], path_b: List[str], em_dict: Dict[str, np.ndarray]) -> Optional[float]:
    if path_a == path_b:
        return 0.0
    la, lb = len(path_a), len(path_b)
    if la == 0 or lb == 0:
        return float("nan")
    DTW = np.full((la + 1, lb + 1), np.inf)
    DTW[0, 0] = 0.0
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = emb_distance(path_a[i-1], path_b[j-1], em_dict)
            if np.isnan(cost):
                return None
            DTW[i, j] = cost + min(DTW[i-1, j], DTW[i, j-1], DTW[i-1, j-1])
    i, j = la, lb
    steps = 0
    while i > 0 and j > 0:
        steps += 1
        options = [DTW[i-1, j-1], DTW[i-1, j], DTW[i, j-1]]
        move = int(np.argmin(options))
        if move == 0:
            i -= 1; j -= 1
        elif move == 1:
            i -= 1
        else:
            j -= 1
    return float(DTW[la, lb] / steps) if steps > 0 else float("nan")


def _origin(path: str) -> str:
    tokens = [tok for tok in str(path or "").split() if tok]
    return tokens[-1] if tokens else ""


def _prefixlen(prefix: str) -> int:
    text = str(prefix or "")
    if "/" not in text:
        return 0
    try:
        return int(text.rsplit("/", 1)[-1])
    except ValueError:
        return 0


def _sort_key(result: Dict) -> tuple:
    """Prefer the longest more-specific update, then origin mismatch, then DTW.

    S|1 attacks announce a new longest prefix. Ranking origin mismatch before
    prefix length would promote a legitimate intermediate covering prefix
    (for example Kakao /23 vs Dreamline /17) over the actual /24 attack.
    """
    more_specific = 1 if result.get("prefix_relation") == "more_specific" else 0
    origin_mismatch = 1 if _origin(result.get("rib_path")) != _origin(result.get("update_path")) else 0
    return (
        more_specific,
        _prefixlen(result.get("upd_prefix")),
        origin_mismatch,
        result["score"],
    )


def score(event_name: str, k: int = 1):
    _event_dir = _root / "data" / "events" / event_name
    emb_path = _root / "data" / "embs" / f"{event_name}.pkl"
    paths_json = _event_dir / "paths.json"
    score_json = _event_dir / "score.json"

    if not os.path.exists(paths_json):
        print(f"Input JSON not found: {paths_json}")
        return

    em = load_embeddings(emb_path)
    with open(paths_json, 'r', encoding='utf-8') as f:
        records = json.load(f)

    results = []
    for r in records:
        rib_path = r.get("rib_path", "")
        upd_path = r.get("update_path", "")
        rib_list = [tok for tok in rib_path.split() if tok]
        upd_list = [tok for tok in upd_path.split() if tok]

        dtw = None
        if em is not None:
            dtw_val = dtw_distance(rib_list, upd_list, em)
            if dtw_val is not None:
                dtw = float(dtw_val)

        if dtw is not None:
            out = {
                "rib_prefix": r.get("rib_prefix"),
                "upd_prefix": r.get("upd_prefix"),
                "prefix_relation": r.get("prefix_relation"),
                "rib_path": rib_path,
                "update_path": upd_path,
                "score": dtw
            }
            results.append(out)

    unique_results = {}
    for result in results:
        key = (
            result["rib_prefix"],
            result["upd_prefix"],
            result.get("prefix_relation"),
            result["rib_path"],
            result["update_path"],
            result["score"],
        )
        if key not in unique_results:
            unique_results[key] = result

    deduplicated_results = list(unique_results.values())
    sorted_results = sorted(deduplicated_results, key=_sort_key, reverse=True)
    top_k_results = sorted_results[:k]

    if top_k_results:
        os.makedirs(os.path.dirname(score_json), exist_ok=True)
        with open(score_json, 'w', encoding='utf-8') as f:
            json.dump(top_k_results, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    event_json = _root / "event.json"
    with open(event_json, 'r') as file:
        data = json.load(file)

    event_name = data.get("event_name")

    k = 10
    score(event_name, k)
