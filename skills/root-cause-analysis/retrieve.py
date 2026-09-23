import argparse
import json
import sys
from pathlib import Path

from langchain_community.vectorstores import Chroma

_root = Path(__file__).resolve().parents[2]
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from llm_provider import get_embeddings, token_tracer

DATA_DIR = _root / "data"
CHROMA_DIR = DATA_DIR / "chroma"


def load_year_collection(year: str = "2015") -> Chroma:
    """Load an existing Chroma collection for the given year."""
    persist_dir = str(CHROMA_DIR / year)
    return Chroma(
        collection_name=year,
        embedding_function=get_embeddings(),
        persist_directory=persist_dir,
    )


def query_similar(db: Chroma, query: str, k: int = 3) -> str:
    retriever = db.as_retriever(search_kwargs={"k": k})
    context_docs = retriever.invoke(query)
    context = ""
    counter = 0
    for doc in context_docs:
        counter += 1
        context += (
            f"[Reference Case {counter}]: Reference Case：{doc.page_content} "
            f"| Reference metadata：{doc.metadata}\n"
        )
    return context


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Retrieve similar BGP anomaly cases from Chroma vector store."
    )
    parser.add_argument("--year", "-y", required=True, help="Collection year, e.g. 2015")
    parser.add_argument("--prefix", "-p", required=True, help="IP prefix, e.g. 172.81.128.0/21")
    parser.add_argument(
        "--anomaly-path",
        "-ap",
        required=True,
        help="BGP AS path, e.g. '29608 5511 6762'",
    )
    parser.add_argument("-k", type=int, default=1, help="Number of reference cases to return")
    parser.add_argument("--token-report", default="", help="Write embedding token usage JSON here")
    args = parser.parse_args()

    token_tracer.reset()
    token_tracer.set_stage("step_5a_retrieve")
    query = f"prefix: {args.prefix} anomaly_path: {args.anomaly_path}"
    db = load_year_collection(args.year)
    print(query_similar(db, query, k=args.k))
    if args.token_report:
        token_tracer.write_report(Path(args.token_report))
