"""
RAG Utilities — Shared helpers for the LAMD RAG pipeline
=========================================================
Provides:
  - CFG file parser (reuses FunctionSlice logic from 4_llm_inference.py)
  - Local sentence-transformer embedding wrapper (all-MiniLM-L6-v2)
  - Qdrant Cloud client factory
  - Common constants (collection name, vector dim, Top-K)
  - RAG prompt builder

Used by:
  6_build_rag_kb.py  — builds the knowledge base
  7_rag_query.py     — queries and predicts
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Allow running from project root or src_python/
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# =============================================================================
#  Constants
# =============================================================================

COLLECTION_NAME = "lamd_cfg_kb"
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"  # via fastembed ONNX, 384-dim
VECTOR_DIM      = 384
TOP_K           = 5                     # retrieved neighbours per query
BATCH_SIZE      = 64                    # embedding batch size


# =============================================================================
#  Data classes
# =============================================================================

@dataclass
class FunctionSlice:
    """One sliced CFG block parsed from a _cfg.txt file."""
    function_name:  str
    suspicious_api: str
    nodes:          list[str] = field(default_factory=list)
    edges:          list[str] = field(default_factory=list)
    raw_text:       str = ""


@dataclass
class RetrievedExample:
    """A single retrieved document from Qdrant, with its metadata."""
    sha256:         str
    function_name:  str
    suspicious_api: str
    label:          str    # "MALWARE" or "BENIGN"
    family:         str
    raw_text:       str
    score:          float  # cosine similarity


# =============================================================================
#  CFG Parser  (mirrors parse_cfg_file from 4_llm_inference.py)
# =============================================================================

def parse_cfg_file(cfg_path: Path) -> list[FunctionSlice]:
    """
    Parses a _cfg.txt file produced by the Soot slicer into a list of
    FunctionSlice objects (one per === FUNCTION: ... === END FUNCTION === block).
    """
    text = cfg_path.read_text(encoding="utf-8", errors="replace")

    if text.strip() in ("NO_SUSPICIOUS_APIS_FOUND", ""):
        return []

    slices: list[FunctionSlice] = []
    blocks = re.split(r"=== FUNCTION:", text)

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        lines = block.split("\n")
        func_name = lines[0].strip().rstrip("=").strip()

        suspicious_api = ""
        nodes: list[str] = []
        edges: list[str] = []
        raw_lines: list[str] = []

        for line in lines[1:]:
            line_s = line.strip()
            if line_s.startswith("SUSPICIOUS_API:"):
                suspicious_api = line_s.split(":", 1)[1].strip()
            elif line_s.startswith("NODE "):
                nodes.append(line_s)
                raw_lines.append(line_s)
            elif line_s.startswith("EDGE:"):
                edges.append(line_s)
                raw_lines.append(line_s)
            elif line_s.startswith("=== END FUNCTION"):
                break

        raw_text = (
            f"=== FUNCTION: {func_name} ===\n"
            f"SUSPICIOUS_API: {suspicious_api}\n"
            + "\n".join(raw_lines)
            + "\n=== END FUNCTION ===\n"
        )

        slices.append(FunctionSlice(
            function_name=func_name,
            suspicious_api=suspicious_api,
            nodes=nodes,
            edges=edges,
            raw_text=raw_text,
        ))

    return slices


def load_cfg_for_sha256(sha256: str) -> list[FunctionSlice]:
    """
    Resolve a SHA256 hash to its _cfg.txt file and parse it.
    Raises FileNotFoundError if no CFG file exists for this hash.
    """
    cfg_dir = PROJECT_ROOT / "extracted_cfgs"

    # Accept both full hash and short prefix
    matches = list(cfg_dir.glob(f"{sha256}*_cfg.txt"))
    if not matches:
        candidate = cfg_dir / f"{sha256}_cfg.txt"
        if candidate.exists():
            matches = [candidate]

    if not matches:
        raise FileNotFoundError(
            f"No CFG file found for SHA256 '{sha256}' in {cfg_dir}"
        )
    return parse_cfg_file(matches[0])


# =============================================================================
#  Embedding Model (local CPU — no API key needed)
# =============================================================================

class EmbeddingModel:
    """
    Wrapper around fastembed (ONNX-based, no PyTorch needed).
    Uses sentence-transformers/all-MiniLM-L6-v2 via ONNX runtime.
    Downloads the model (~90 MB) once; cached in ~/.cache/fastembed.
    Works on Windows without any CUDA/VC++ runtime dependencies.
    """

    def __init__(self, model_name: str = EMBEDDING_MODEL):
        try:
            from fastembed import TextEmbedding
        except ImportError as e:
            print(
                f"[ERROR] fastembed not installed or failed to import: {e}\n"
                "  Run: pip install fastembed",
                file=sys.stderr,
            )
            sys.exit(1)

        print(f"  Loading embedding model '{model_name}' (fastembed/ONNX) …", flush=True)
        self._model = TextEmbedding(model_name=model_name)
        self._model_name = model_name

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Embed a list of strings. Returns list of 384-dim float vectors."""
        # fastembed returns a generator — materialise to list
        return [vec.tolist() for vec in self._model.embed(texts, batch_size=BATCH_SIZE)]

    def embed_one(self, text: str) -> list[float]:
        """Convenience wrapper: embed a single string."""
        return self.embed([text])[0]


# =============================================================================
#  Qdrant Cloud Client Factory
# =============================================================================

def get_qdrant_client():
    """
    Creates and returns a QdrantClient configured from .env.
    Requires QDRANT_URL and QDRANT_API_KEY.
    """
    try:
        from qdrant_client import QdrantClient
    except ImportError:
        print(
            "[ERROR] qdrant-client not installed.\n"
            "  Run: pip install qdrant-client",
            file=sys.stderr,
        )
        sys.exit(1)

    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")

    url     = os.environ.get("QDRANT_URL", "").strip()
    api_key = os.environ.get("QDRANT_API_KEY", "").strip()

    if not url or not api_key:
        print(
            "[ERROR] QDRANT_URL and QDRANT_API_KEY must be set in .env\n"
            "\n"
            "  Sign up free at: https://cloud.qdrant.io\n"
            "  Then add to your .env:\n"
            "    QDRANT_URL=https://<cluster-id>.qdrant.io\n"
            "    QDRANT_API_KEY=<your-api-key>",
            file=sys.stderr,
        )
        sys.exit(1)

    client = QdrantClient(url=url, api_key=api_key, timeout=60)
    return client


def ensure_collection_exists(client) -> None:
    """
    Creates the Qdrant collection 'lamd_cfg_kb' if it doesn't exist yet.
    Uses cosine distance on 384-dim vectors (matching all-MiniLM-L6-v2 output).
    """
    from qdrant_client.http.models import Distance, VectorParams

    existing = {c.name for c in client.get_collections().collections}
    if COLLECTION_NAME not in existing:
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=VECTOR_DIM, distance=Distance.COSINE),
        )
        print(f"  [OK] Created Qdrant collection '{COLLECTION_NAME}'")
    else:
        info = client.get_collection(COLLECTION_NAME)
        count = info.points_count or 0
        print(f"  [OK] Collection '{COLLECTION_NAME}' exists ({count:,} points) -- will upsert")

    # Always ensure the sha256 payload index exists (needed for filters)
    ensure_sha256_index(client)


def ensure_sha256_index(client) -> None:
    """
    Creates a keyword payload index on 'sha256' if it doesn't exist yet.
    Required by Qdrant for filtering by sha256 during retrieval.
    """
    from qdrant_client import models

    try:
        collection_info = client.get_collection(COLLECTION_NAME)
        existing_indexes = collection_info.payload_schema or {}
        if "sha256" not in existing_indexes:
            client.create_payload_index(
                collection_name=COLLECTION_NAME,
                field_name="sha256",
                field_schema=models.PayloadSchemaType.KEYWORD,
            )
            print(f"  [OK] Created payload index on 'sha256'")
    except Exception as e:
        # Non-fatal: queries will still work, just without sha256 self-exclusion
        print(f"  [WARN] Could not create sha256 index: {e}", file=sys.stderr)



# =============================================================================
#  RAG Prompt Builder
# =============================================================================

RAG_SYSTEM = (
    "You are a cybersecurity expert specializing in Android malware analysis. "
    "You are provided with retrieved similar CFG examples from a knowledge base "
    "(each with a known MALWARE/BENIGN label) and a new input to classify. "
    "Use the examples as few-shot context to make a more accurate, grounded prediction. "
    "CRITICAL: The retrieved examples are ground truth. If the most similar retrieved examples "
    "are overwhelmingly MALWARE, you must strongly lean towards classifying the input as MALWARE, "
    "and similarly for BENIGN."
)


def build_rag_prompt(
    query_input: str,
    examples:    list[RetrievedExample],
    query_mode:  str,   # "cfg", "sha256", or "text"
) -> str:
    """
    Builds the RAG-augmented prompt for the LLM.

    Injects Top-K retrieved examples with their labels as few-shot context,
    then appends the query input for the model to classify.
    """
    lines: list[str] = []

    # ── Retrieved few-shot examples ──────────────────────────────────────────
    malware_count = sum(1 for e in examples if e.label == "MALWARE")
    benign_count  = len(examples) - malware_count

    lines.append(
        f"=== RETRIEVED SIMILAR EXAMPLES FROM KNOWLEDGE BASE "
        f"({malware_count} MALWARE, {benign_count} BENIGN) ==="
    )
    lines.append("")

    for i, ex in enumerate(examples, 1):
        lines.append(f"── Example {i} (similarity: {ex.score:.3f}) ──")
        lines.append(f"  Label         : {ex.label}")
        lines.append(f"  Family        : {ex.family}")
        lines.append(f"  Function      : {ex.function_name}")
        lines.append(f"  Suspicious API: {ex.suspicious_api}")
        lines.append("  CFG Slice:")
        # Truncate very long slices to save context tokens
        snippet = ex.raw_text[:600]
        if len(ex.raw_text) > 600:
            snippet += "\n  ... [truncated]"
        for sl in snippet.splitlines():
            lines.append(f"    {sl}")
        lines.append("")

    # ── New query ─────────────────────────────────────────────────────────────
    lines.append("=== NEW INPUT TO CLASSIFY ===")
    lines.append("")

    if query_mode == "text":
        lines.append("Analyst description (no CFG available):")
        lines.append(query_input)
    else:
        lines.append("Control Flow Graph extracted from Android APK:")
        # Cap at ~4000 chars to stay within typical context limits
        cfg_snippet = query_input[:4000]
        if len(query_input) > 4000:
            cfg_snippet += "\n... [truncated] ..."
        lines.append(cfg_snippet)

    lines.append("")
    lines.append(
        "Based on the retrieved examples above AND your analysis of the new input,\n"
        "provide your final assessment in this exact format:\n"
        "\n"
        "=== FINAL APPLICATION ANALYSIS ===\n"
        "\n"
        "**Final Prediction:**\n"
        "<MALWARE or BENIGN>\n"
        "\n"
        "**Application Purpose:**\n"
        "<1-2 sentence description of what the app appears to do>\n"
        "\n"
        "**Indicators of Compromise:**\n"
        "<numbered list of specific suspicious behaviors, or 'None detected'>\n"
        "\n"
        "**Retrieved Examples Influence:**\n"
        "<Which example numbers influenced your decision most, and why>\n"
        "\n"
        "**Final Conclusion:**\n"
        "<2-3 sentence overall assessment with confidence level>"
    )

    return "\n".join(lines)
