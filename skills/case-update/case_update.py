import argparse
import json
import sys
from pathlib import Path

from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document

_root = Path(__file__).resolve().parents[2]
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from llm_provider import get_embeddings, token_tracer

DATA_DIR = _root / "data"
CASE_DIR = DATA_DIR / "case"
CHROMA_DIR = DATA_DIR / "chroma"


def _embedding():
    return get_embeddings()


def load_cases(year: str = "2015") -> list[dict]:
    """Load BGP anomaly cases from a year-specific JSONL file."""
    case_file = CASE_DIR / "by_year" / f"{year}.jsonl"
    cases = []
    with open(case_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def case_to_document(case: dict) -> Document:
    """Convert a BGP anomaly case dict into a LangChain Document.

    The page_content is a human-readable summary combining all key fields.
    Metadata stores flattened structured fields for Chroma compatibility.
    """
    rc = case.get("root_cause", {})
    page_content = (
        f"Anomaly type: {case.get('anomaly_type', 'unknown')}. "
        f"IP prefix: {case.get('prefix', 'N/A')}. "
        f"Start time: {case.get('start_time', 'N/A')}. "
        f"End time: {case.get('end_time', 'N/A')}. "
        f"Description: {case.get('description', 'N/A')}"
    )

    metadata = {
        "prefix": case.get("prefix", ""),
        "start_time": case.get("start_time", ""),
        "end_time": case.get("end_time", ""),
        "anomaly_type": case.get("anomaly_type", ""),
        "description": case.get("description", ""),
    }
    for k, v in rc.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            metadata[f"rc_{k}"] = v
        elif isinstance(v, list):
            if not v:
                metadata[f"rc_{k}"] = ""
            # Check if it's a nested list (like relationship_pairs)
            elif isinstance(v[0], list):
                # Convert nested list to string representation
                metadata[f"rc_{k}"] = str(v)
            else:
                # Check if list contains dictionaries or complex objects
                if v and isinstance(v[0], dict):
                    # Convert list of dictionaries to string representation
                    metadata[f"rc_{k}"] = str(v)
                else:
                    # Simple list - keep as is if all elements are same type
                    metadata[f"rc_{k}"] = v
        else:
            metadata[f"rc_{k}"] = str(v)
    return Document(page_content=page_content, metadata=metadata)


def build_year_collection(year: str = "2015") -> Chroma:
    """Build (or rebuild) a Chroma collection for the given year.

    Each JSON line in the year file becomes one document.  The collection
    is persisted under ``data/chroma/<year>/``.
    """
    cases = load_cases(year)
    documents = [case_to_document(c) for c in cases]

    persist_dir = str(CHROMA_DIR / year)
    Chroma.from_documents(
        documents=documents,
        embedding=_embedding(),
        persist_directory=persist_dir,
        collection_name=year,
    )
    print(f"[vector_db] Indexed {len(documents)} documents into '{year}' collection at {persist_dir}")
    return load_year_collection(year)


def load_year_collection(year: str = "2015") -> Chroma:
    """Load an existing Chroma collection for the given year."""
    persist_dir = str(CHROMA_DIR / year)
    return Chroma(
        collection_name=year,
        embedding_function=_embedding(),
        persist_directory=persist_dir,
    )


def add_report_to_collection(report_path: str | Path) -> None:
    """Add a single root_cause_report.json to its corresponding year's Chroma collection.

    Args:
        report_path: Path to the root_cause_report.json file.
                     The year is inferred from the ``start_time`` field.
                     The report is added to ``data/chroma/<year>/`` and persisted.
    """
    report_path = Path(report_path)
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    start_time = report.get("start_time", "")
    year = start_time[:4] if start_time else "unknown"
    doc = case_to_document(report)

    db = load_year_collection(year)
    # Idempotent upsert: remove any previously archived documents for the same
    # event (same prefix and start_time) before adding the updated report.
    stale = db.get(
        where={
            "$and": [
                {"prefix": {"$eq": report.get("prefix", "")}},
                {"start_time": {"$eq": start_time}},
            ]
        }
    )
    stale_ids = stale.get("ids") or []
    if stale_ids:
        db.delete(ids=stale_ids)
        print(
            f"[case_update] Removed {len(stale_ids)} stale document(s) for "
            f"prefix {report.get('prefix', '')} at {start_time}"
        )
    db.add_documents([doc])
    print(f"[case_update] Added report to '{year}' collection: {report_path.name}")


def rebuild_year_collection(year: str = "2015", rebuild: bool = False) -> None:
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)

    if rebuild:
        db = build_year_collection(year)
        print(f"[vector_db] Collection '{year}' rebuilt. "
              f"Total docs: {db._collection.count()}")
    else:
        db = load_year_collection(year)


def main() -> None:
    parser = argparse.ArgumentParser(description="Archive root_cause_report.json into Chroma")
    parser.add_argument("--token-report", default="", help="Write embedding token usage JSON here")
    args = parser.parse_args()

    token_tracer.reset()
    token_tracer.set_stage("step_5d_archive_case")

    event_json = _root / "event.json"
    with open(event_json, "r", encoding="utf-8") as file:
        data = json.load(file)

    event_name = data.get("event_name")
    report_path = f"data/events/{event_name}/root_cause_report.json"
    add_report_to_collection(report_path)
    if args.token_report:
        token_tracer.write_report(Path(args.token_report))


if __name__ == "__main__":
    main()
