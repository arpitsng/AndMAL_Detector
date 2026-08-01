"""
RAG Knowledge Base — Case-Based Retrieval for LAMD Tier 1 Analysis
=====================================================================
Builds a searchable index of previously-labeled CFG function slices
(from data/train.csv + extracted_cfgs/) and retrieves the most similar
known examples for a new CFG slice at inference time.

Why this helps:
  The LLM currently judges each function slice "cold" — with no sense
  of what malicious vs. benign usage of a given API has looked like
  before. By retrieving the K most similar labeled slices (by embedding
  similarity) and showing them as reference cases, Tier 1 gets grounded,
  concrete precedent instead of guessing from first principles alone.
  This mirrors the case-based reasoning step used in AppPoet.

Build the index (run once, or whenever extracted_cfgs/ changes):
  python src_python/rag.py --build

Test retrieval directly:
  python src_python/rag.py --query "sendTextMessage premium number"

Environment:
  Requires: sentence-transformers, faiss-cpu (see requirements.txt)
"""

import argparse
import hashlib
import pickle
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CFG_DIR = PROJECT_ROOT / "extracted_cfgs"
TRAIN_CSV = PROJECT_ROOT / "data" / "train.csv"
RAG_DIR = PROJECT_ROOT / "rag_store"
RAG_DIR.mkdir(exist_ok=True)

EMBEDDING_MODEL = "all-MiniLM-L6-v2"   # local, no API key required
MAX_SNIPPET_CHARS = 1500                # truncate before embedding/display

# Same framework-noise filter used in 4_llm_inference.py, kept in sync so
# the knowledge base reflects the same "interesting" functions the
# pipeline actually reasons over.
FRAMEWORK_PREFIXES = (
    'android.', 'androidx.', 'java.', 'javax.',
    'com.google.ads.', 'com.google.android.gms.',
    'com.google.firebase.', 'com.facebook.',
    'org.apache.', 'dalvik.'
)
SENSITIVE_APIS = (
    'dexclassloader', 'loadclass', 'forname', 'newinstance',
    'load', 'loadlibrary', 'exec', 'getmethod'
)


@dataclass
class CfgSlice:
    function_name: str
    suspicious_api: str
    raw_text: str


@dataclass
class RagExample:
    sha256: str
    family: str
    label: str          # "MALWARE" or "BENIGN"
    function_name: str
    suspicious_api: str
    snippet: str         # truncated raw CFG text shown to the LLM
    score: float = 0.0   # similarity score, filled in at retrieval time


# =============================================================================
#  Lightweight CFG parsing (mirrors 4_llm_inference.py's parse_cfg_file)
# =============================================================================

def parse_cfg_file(cfg_path: Path) -> list[CfgSlice]:
    text = cfg_path.read_text(encoding="utf-8")
    if text.strip() == "NO_SUSPICIOUS_APIS_FOUND":
        return []

    slices = []
    blocks = re.split(r"=== FUNCTION:", text)
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        lines = block.split("\n")
        func_name = lines[0].strip().rstrip("=").strip()

        suspicious_api = ""
        body_lines = []
        for line in lines[1:]:
            line = line.strip()
            if line.startswith("SUSPICIOUS_API:"):
                suspicious_api = line.split(":", 1)[1].strip()
            elif line.startswith("NODE ") or line.startswith("EDGE:"):
                body_lines.append(line)
            elif line.startswith("=== END FUNCTION"):
                break

        raw_text = f"=== FUNCTION: {func_name} ===\nSUSPICIOUS_API: {suspicious_api}\n"
        raw_text += "\n".join(body_lines)
        slices.append(CfgSlice(func_name, suspicious_api, raw_text))
    return slices


def _is_framework_noise(func_name: str, api: str) -> bool:
    api_lower = api.lower()
    if any(sec in api_lower for sec in SENSITIVE_APIS):
        return False
    return func_name.startswith(FRAMEWORK_PREFIXES)


# =============================================================================
#  Build the index
# =============================================================================

def build_index() -> None:
    import faiss
    from sentence_transformers import SentenceTransformer

    if not TRAIN_CSV.is_file():
        print(f"[ERROR] {TRAIN_CSV} not found.", file=sys.stderr)
        sys.exit(1)
    if not CFG_DIR.is_dir():
        print(f"[ERROR] {CFG_DIR} not found. Run 2_extract_cfg.py first.", file=sys.stderr)
        sys.exit(1)

    df = pd.read_csv(TRAIN_CSV, usecols=["sha256", "family", "label"],
                      dtype={"sha256": str, "family": str, "label": float})
    df["sha256"] = df["sha256"].str.strip().str.lower()
    df.dropna(subset=["sha256"], inplace=True)
    df.drop_duplicates(subset=["sha256"], inplace=True)

    examples: list[RagExample] = []
    seen_hashes = set()

    print(f"[INFO] Scanning {len(df)} labeled samples for CFG files...")
    matched = 0
    for _, row in df.iterrows():
        sha256 = row["sha256"]
        cfg_path = CFG_DIR / f"{sha256}_cfg.txt"
        if not cfg_path.is_file():
            continue
        matched += 1

        label = "MALWARE" if row["label"] == 1.0 else "BENIGN"
        family = str(row.get("family", "")).strip()

        for s in parse_cfg_file(cfg_path):
            if not s.suspicious_api:
                continue
            if _is_framework_noise(s.function_name, s.suspicious_api):
                continue

            dedup_hash = hashlib.md5(s.raw_text.encode("utf-8")).hexdigest()
            if dedup_hash in seen_hashes:
                continue
            seen_hashes.add(dedup_hash)

            examples.append(RagExample(
                sha256=sha256,
                family=family,
                label=label,
                function_name=s.function_name,
                suspicious_api=s.suspicious_api,
                snippet=s.raw_text[:MAX_SNIPPET_CHARS],
            ))

    if not examples:
        print("[ERROR] No usable CFG slices found. Nothing to index.", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] {matched} CFG files matched labels -> {len(examples)} indexable function slices.")
    print(f"[INFO] Loading embedding model '{EMBEDDING_MODEL}'...")
    model = SentenceTransformer(EMBEDDING_MODEL)

    print("[INFO] Embedding slices (this may take a minute)...")
    texts = [e.snippet for e in examples]
    vectors = model.encode(texts, show_progress_bar=True, convert_to_numpy=True).astype("float32")
    faiss.normalize_L2(vectors)

    index = faiss.IndexFlatIP(vectors.shape[1])
    index.add(vectors)

    faiss.write_index(index, str(RAG_DIR / "faiss.index"))
    with open(RAG_DIR / "examples.pkl", "wb") as f:
        pickle.dump(examples, f)

    mal = sum(1 for e in examples if e.label == "MALWARE")
    ben = len(examples) - mal
    print(f"[OK] Index built: {len(examples)} slices ({mal} from malware, {ben} from benign samples).")
    print(f"[OK] Saved to {RAG_DIR}/")


# =============================================================================
#  Retrieval (used by 4_llm_inference.py)
# =============================================================================

_model = None
_index = None
_examples: list[RagExample] | None = None


def _lazy_load():
    global _model, _index, _examples
    if _examples is None:
        index_path = RAG_DIR / "faiss.index"
        examples_path = RAG_DIR / "examples.pkl"
        if not index_path.exists() or not examples_path.exists():
            raise FileNotFoundError(
                "RAG index not found. Run `python src_python/rag.py --build` first."
            )
        import faiss
        _index = faiss.read_index(str(index_path))
        with open(examples_path, "rb") as f:
            _examples = pickle.load(f)
    if _model is None:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(EMBEDDING_MODEL)


def retrieve_similar(
    query_text: str, k: int = 3, exclude_sha256: str | None = None
) -> list[RagExample]:
    """
    Returns the top-k most similar labeled CFG slices to query_text.

    exclude_sha256 filters out results from the same APK being analyzed,
    which matters during evaluation — without it, the model could retrieve
    its own answer key when running RAG over the training set itself.
    """
    import faiss

    _lazy_load()
    query_vec = _model.encode([query_text[:MAX_SNIPPET_CHARS]], convert_to_numpy=True).astype("float32")
    faiss.normalize_L2(query_vec)

    # Over-fetch a bit so we still have k results after excluding same-APK matches.
    search_k = k + 10 if exclude_sha256 else k
    scores, indices = _index.search(query_vec, search_k)

    results = []
    for score, idx in zip(scores[0], indices[0]):
        if idx == -1:
            continue
        ex = _examples[idx]
        if exclude_sha256 and ex.sha256 == exclude_sha256:
            continue
        ex_copy = RagExample(**{**ex.__dict__, "score": float(score)})
        results.append(ex_copy)
        if len(results) >= k:
            break
    return results


def format_examples_for_prompt(examples: list[RagExample]) -> str:
    """Formats retrieved examples into a block for insertion into the Tier 1 prompt."""
    if not examples:
        return ""
    parts = []
    for i, ex in enumerate(examples, 1):
        family_note = f", family: {ex.family}" if ex.label == "MALWARE" and ex.family else ""
        parts.append(
            f"--- Reference Case {i} (known label: {ex.label}{family_note}, "
            f"similarity: {ex.score:.2f}) ---\n"
            f"Suspicious API: {ex.suspicious_api}\n"
            f"{ex.snippet[:600]}"
        )
    return "\n\n".join(parts)


# =============================================================================
#  CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Build or query the RAG knowledge base.")
    parser.add_argument("--build", action="store_true", help="Build the index from data/train.csv + extracted_cfgs/")
    parser.add_argument("--query", type=str, default=None, help="Test retrieval with a free-text query")
    parser.add_argument("--k", type=int, default=3, help="Number of results for --query")
    args = parser.parse_args()

    if args.build:
        build_index()
    elif args.query:
        results = retrieve_similar(args.query, k=args.k)
        if not results:
            print("No results. Did you run --build first?")
            return
        print(format_examples_for_prompt(results))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
