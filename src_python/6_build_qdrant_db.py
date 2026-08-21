"""
Build Qdrant Cloud Vector Database for RAG Pipeline — v2 (Hybrid Embeddings)

ARCHITECTURE CHANGE FROM v1:
  v1: 1 APK  = 1 vector  (truncated 3K chars of concatenated CFG text)
  v2: 1 FUNCTION SLICE = 1 vector (hybrid: semantic + graph-structural)

Each function slice from a CFG file becomes an independent Qdrant vector with:
  - Semantic component (384 dims): bge-small-en embedding of a LINEARIZED
    execution path (e.g. "getSystemService → cast(LocationManager) → branch →
    getLastKnownLocation") instead of raw Jimple IR.
  - Graph-structural component (25 dims): normalized numeric features extracted
    directly from NODE/EDGE topology (node count, edge density, branching,
    cycles, node-type histogram, API-category one-hot).

WHY THIS MATTERS:
  1. No benign dilution — a malicious sendTextMessage in obfuscated a.b.c gets
     its own vector instead of being drowned by 200 benign SDK functions.
  2. No truncation — individual slices are 5-30 lines, fitting entirely within
     the embedding model's 512-token window.
  3. Graph awareness — two functions using the same API but with different data
     flows (log locally vs. encrypt & exfiltrate) get DIFFERENT embeddings.
  4. Stratified retrieval at query time — Qdrant filter by ground_truth ensures
     the LLM always sees both malware AND benign reference examples regardless
     of class imbalance in the database.

Usage:
  python src_python/6_build_qdrant_db.py
"""

import importlib.util
import math
import os
import re
import sys
import uuid

# Configure HuggingFace mirror endpoint before importing fastembed/huggingface_hub
os.environ["HF_ENDPOINT"] = os.environ.get("HF_ENDPOINT", "https://hf-mirror.com")

import numpy as np
import pandas as pd
from collections import defaultdict
from pathlib import Path
from dotenv import load_dotenv
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from fastembed import TextEmbedding
from tqdm import tqdm

# --- Configuration ---
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_ROOT / "data" / "train.csv"
CFG_DIR = PROJECT_ROOT / "extracted_cfgs"
COLLECTION_NAME = "lamd_cfgs"

# Hybrid vector: 384 (semantic via bge-small-en) + 25 (graph-structural) = 409
SEMANTIC_DIM = 384
GRAPH_DIM = 25
HYBRID_DIM = SEMANTIC_DIM + GRAPH_DIM  # 409

# 4_llm_inference.py can't be `import`ed normally (filename starts with a
# digit) — load it by path so we reuse its exact parse_cfg_file /
# preprocess_slices logic instead of drifting a second copy of it here.
_infer_spec = importlib.util.spec_from_file_location(
    "infer_mod", Path(__file__).resolve().parent / "4_llm_inference.py"
)
_infer_mod = importlib.util.module_from_spec(_infer_spec)
_infer_spec.loader.exec_module(_infer_mod)
parse_cfg_file = _infer_mod.parse_cfg_file
preprocess_slices = _infer_mod.preprocess_slices


# =============================================================================
#  Graph Feature Extraction
# =============================================================================

# API categories for one-hot encoding (10 categories)
API_CATEGORIES = {
    "reflection": {"forname", "newinstance", "getdeclaredmethod", "getdeclaredfield",
                   "getmethod", "invoke", "load", "loadlibrary"},
    "telephony": {"getdeviceid", "getsubscriberid", "getline1number", "getimei",
                  "getmeid", "getsimoperator", "getsimserialnumber", "getandroidid"},
    "location": {"getlastknownlocation", "requestlocationupdates"},
    "sms": {"sendtextmessage", "sendmultiparttextmessage", "senddatamessage"},
    "network": {"openconnection", "connect", "getoutputstream", "getactivenetworkinfo",
                "getmacaddress", "getconnectioninfo"},
    "storage": {"openfileoutput", "openfileinput", "getexternalstoragedirectory",
                "getexternalfilesdir"},
    "crypto": {"dofinal", "update"},
    "exec": {"exec"},
    "content_resolver": {"query"},
    "dynamic_loading": {"dexclassloader", "loadclass"},
}
API_CATEGORY_ORDER = list(API_CATEGORIES.keys())

# Node statement types for histogram (8 categories)
NODE_TYPE_PATTERNS = [
    ("invoke", re.compile(r"(virtual|static|special|interface)invoke", re.IGNORECASE)),
    ("assign", re.compile(r"\$\w+\s*=\s*(?!@)", re.IGNORECASE)),
    ("identity", re.compile(r":=\s*@(this|parameter|caughtexception)", re.IGNORECASE)),
    ("if_branch", re.compile(r"\bif\b\s+\$", re.IGNORECASE)),
    ("return", re.compile(r"\breturn\b", re.IGNORECASE)),
    ("cast", re.compile(r"\(\s*[a-zA-Z][\w.]*\)\s*\$", re.IGNORECASE)),
    ("goto", re.compile(r"\bgoto\b", re.IGNORECASE)),
]
NODE_TYPE_ORDER = [n[0] for n in NODE_TYPE_PATTERNS] + ["other"]


def _classify_api(api_name: str) -> str:
    """Classify a suspicious API into one of the 10 predefined categories."""
    api_lower = api_name.lower()
    for cat_name, api_set in API_CATEGORIES.items():
        if api_lower in api_set:
            return cat_name
    return "other"


def _classify_node(node_text: str) -> str:
    """Classify a NODE line into one of 8 statement type categories."""
    for type_name, pattern in NODE_TYPE_PATTERNS:
        if pattern.search(node_text):
            return type_name
    return "other"


def _parse_edges(edges: list[str]) -> dict[int, list[int]]:
    """Parse EDGE lines into an adjacency list {src: [dst1, dst2, ...]}."""
    adj = defaultdict(list)
    for edge_line in edges:
        match = re.search(r"EDGE:\s*(\d+)\s*->\s*(\d+)", edge_line)
        if match:
            src, dst = int(match.group(1)), int(match.group(2))
            adj[src].append(dst)
    return dict(adj)


def _has_cycle(adj: dict[int, list[int]], all_nodes: set[int]) -> bool:
    """Detect if the directed graph has a cycle using DFS."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in all_nodes}

    def dfs(u):
        color[u] = GRAY
        for v in adj.get(u, []):
            if color.get(v, WHITE) == GRAY:
                return True
            if color.get(v, WHITE) == WHITE and dfs(v):
                return True
        color[u] = BLACK
        return False

    return any(dfs(n) for n in all_nodes if color[n] == WHITE)


def _longest_path(adj: dict[int, list[int]], all_nodes: set[int]) -> int:
    """Find the longest simple path length in a DAG (or use DFS for small graphs)."""
    if not all_nodes:
        return 0
    best = 0
    for start in all_nodes:
        stack = [(start, 1, {start})]
        while stack:
            node, depth, visited = stack.pop()
            best = max(best, depth)
            for neighbor in adj.get(node, []):
                if neighbor not in visited:
                    stack.append((neighbor, depth + 1, visited | {neighbor}))
    return best


def extract_graph_features(func_slice) -> list[float]:
    """
    Extract 25 normalized graph-structural features from a FunctionSlice.

    Returns a list of 25 floats in [0, 1].

    Features (25 total):
      [0]  num_nodes (normalized by log)
      [1]  num_edges (normalized by log)
      [2]  edge_density (edges / max_possible_edges)
      [3]  max_out_degree (normalized by log)
      [4]  has_branch (binary: any node with out-degree > 1)
      [5]  has_cycle (binary)
      [6]  chain_length (longest path, normalized by log)
      [7..14]  node_type_histogram (8 categories, normalized to sum=1)
      [15..24] api_category_one_hot (10 categories)
    """
    nodes = func_slice.nodes
    edges = func_slice.edges
    num_nodes = len(nodes)
    num_edges = len(edges)

    # Parse adjacency
    adj = _parse_edges(edges)
    all_node_ids = set()
    for node_line in nodes:
        match = re.match(r"NODE\s+(\d+):", node_line)
        if match:
            all_node_ids.add(int(match.group(1)))

    # Topology features (7)
    max_possible_edges = num_nodes * (num_nodes - 1) if num_nodes > 1 else 1
    edge_density = num_edges / max_possible_edges if max_possible_edges > 0 else 0.0

    out_degrees = [len(adj.get(n, [])) for n in all_node_ids] if all_node_ids else [0]
    max_out_degree = max(out_degrees) if out_degrees else 0
    has_branch = 1.0 if max_out_degree > 1 else 0.0

    cycle = 1.0 if all_node_ids and _has_cycle(adj, all_node_ids) else 0.0

    chain_len = _longest_path(adj, all_node_ids) if all_node_ids else 0

    def log_norm(x, scale=50.0):
        return min(1.0, math.log1p(x) / math.log1p(scale))

    topology = [
        log_norm(num_nodes, 50),
        log_norm(num_edges, 100),
        min(1.0, edge_density),
        log_norm(max_out_degree, 10),
        has_branch,
        cycle,
        log_norm(chain_len, 30),
    ]

    # Node type histogram (8 categories, normalized)
    type_counts = {t: 0 for t in NODE_TYPE_ORDER}
    for node_line in nodes:
        node_type = _classify_node(node_line)
        type_counts[node_type] += 1
    total_types = sum(type_counts.values()) or 1
    node_hist = [type_counts[t] / total_types for t in NODE_TYPE_ORDER]

    # API category one-hot (10 categories)
    api_cat = _classify_api(func_slice.suspicious_api)
    api_onehot = [1.0 if cat == api_cat else 0.0 for cat in API_CATEGORY_ORDER]

    features = topology + node_hist + api_onehot
    assert len(features) == GRAPH_DIM, f"Expected {GRAPH_DIM} features, got {len(features)}"
    return features


# =============================================================================
#  Linearized Execution Path Construction
# =============================================================================

_INVOKE_RE = re.compile(r"<[\w.]+:\s+[\w.\[\]]+\s+([\w<>]+)\(")
_CAST_RE = re.compile(r"\((\w[\w.]*)\)\s*\$")
_PARAM_RE = re.compile(r":=\s*@(this|parameter\d+):\s*([\w.]+)")
_IF_RE = re.compile(r"\bif\b")
_RETURN_RE = re.compile(r"\breturn\b")


def linearize_slice(func_slice) -> str:
    """
    Convert a FunctionSlice into a linearized execution path string suitable
    for text embedding.

    Instead of raw Jimple IR (meaningless to an NLP embedding model), this
    produces a compact, human-readable sequence like:

        "FUNC: com.example.Tracker.run | API: getDeviceId |
         PATH: param(Context) -> getSystemService -> cast(TelephonyManager) ->
         getDeviceId -> encrypt -> openConnection -> getOutputStream"

    This captures:
      - The package/class context (obfuscated vs. named SDK)
      - The suspicious API being tracked
      - The ordered data-flow chain (source -> transform -> sink)
    """
    func_name = func_slice.function_name
    api_name = func_slice.suspicious_api

    node_map = {}  # node_id -> description

    for node_line in func_slice.nodes:
        match = re.match(r"NODE\s+(\d+):\s*(.*)", node_line)
        if not match:
            continue
        node_id = int(match.group(1))
        content = match.group(2).strip()

        desc = None

        # Parameter / identity
        param_match = _PARAM_RE.search(content)
        if param_match:
            param_type = param_match.group(2).split(".")[-1]
            desc = f"param({param_type})"

        # Invoke
        if desc is None:
            invoke_match = _INVOKE_RE.search(content)
            if invoke_match:
                method = invoke_match.group(1)
                desc = method

        # Cast
        if desc is None:
            cast_match = _CAST_RE.search(content)
            if cast_match:
                cast_type = cast_match.group(1).split(".")[-1]
                desc = f"cast({cast_type})"

        # If branch
        if desc is None and _IF_RE.search(content):
            desc = "branch"

        # Return
        if desc is None and _RETURN_RE.search(content):
            desc = "return"

        # Fallback
        if desc is None:
            desc = "assign"

        node_map[node_id] = desc

    # Follow edge order to build the path
    adj = _parse_edges(func_slice.edges)
    all_ids = sorted(node_map.keys())

    if adj and all_ids:
        has_incoming = set()
        for targets in adj.values():
            has_incoming.update(targets)
        roots = [n for n in all_ids if n not in has_incoming]
        if not roots:
            roots = [all_ids[0]]

        visited = set()
        path_descs = []
        queue = list(roots)
        while queue:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            if node in node_map:
                path_descs.append(node_map[node])
            for child in adj.get(node, []):
                if child not in visited:
                    queue.append(child)

        for nid in all_ids:
            if nid not in visited and nid in node_map:
                path_descs.append(node_map[nid])
    else:
        path_descs = [node_map[nid] for nid in all_ids]

    # Deduplicate consecutive identical steps
    deduped = []
    for d in path_descs:
        if not deduped or deduped[-1] != d:
            deduped.append(d)

    path_str = " -> ".join(deduped) if deduped else "unknown"

    return f"FUNC: {func_name} | API: {api_name} | PATH: {path_str}"


# =============================================================================
#  Main
# =============================================================================

def main():
    print("=" * 60)
    print("  LAMD RAG DB Builder v2 - Hybrid Function-Level Embeddings")
    print("=" * 60)

    # 1. Load credentials
    load_dotenv()
    qdrant_url = os.environ.get("QDRANT_URL")
    qdrant_api_key = os.environ.get("QDRANT_API_KEY")

    if not qdrant_url or not qdrant_api_key:
        print("[ERROR] QDRANT_URL or QDRANT_API_KEY is missing in .env")
        sys.exit(1)

    qdrant_port = int(os.environ.get("QDRANT_PORT", "443"))
    print(f"[INFO] Connecting to Qdrant Cloud (port {qdrant_port})...")
    client = QdrantClient(
        url=qdrant_url,
        api_key=qdrant_api_key,
        port=qdrant_port,
        timeout=60,
    )

    # 2. Initialize FastEmbed locally
    print("[INFO] Loading FastEmbed model (BAAI/bge-small-en) locally...")
    model_dir = PROJECT_ROOT / "fastembed_models" / "bge-small-en"
    if (model_dir / "fast-bge-small-en").is_dir():
        model_dir = model_dir / "fast-bge-small-en"

    kwargs = {
        "model_name": "BAAI/bge-small-en",
        "providers": ["CUDAExecutionProvider", "CPUExecutionProvider"],
    }
    if model_dir.is_dir() and any(model_dir.glob("*.onnx")):
        kwargs["specific_model_path"] = str(model_dir)
        print(f"[INFO] Using local offline model at: {model_dir}")
    else:
        print("[INFO] Using cached FastEmbed model")

    embedding_model = TextEmbedding(**kwargs)

    # 3. Delete old collection & create new with hybrid dimensions
    collections = client.get_collections().collections
    for coll in collections:
        if coll.name == COLLECTION_NAME:
            print(f"[INFO] Deleting old collection '{COLLECTION_NAME}'...")
            client.delete_collection(collection_name=COLLECTION_NAME)
            break

    print(f"[INFO] Creating collection '{COLLECTION_NAME}' (dim={HYBRID_DIM}, "
          f"hybrid: {SEMANTIC_DIM} semantic + {GRAPH_DIM} graph)...")
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=HYBRID_DIM, distance=Distance.COSINE),
    )

    # 4. Load ground-truth labels
    print(f"[INFO] Loading dataset from {DATA_FILE}")
    if not DATA_FILE.exists():
        print(f"[ERROR] Cannot find {DATA_FILE}")
        sys.exit(1)

    df = pd.read_csv(DATA_FILE)
    df["sha256"] = df["sha256"].str.strip().str.lower()

    label_lookup = {}
    for _, row in df.iterrows():
        sha = str(row.get("sha256", "")).strip().lower()
        label_lookup[sha] = {
            "label": int(row.get("label", 0)),
            "family": str(row.get("family", "benign")).strip(),
        }

    # 5. Process ALL CFGs — function-level chunking
    cfg_files = sorted(CFG_DIR.glob("*_cfg.txt"))
    print(f"[INFO] Found {len(cfg_files)} CFG files in {CFG_DIR}")

    documents = []
    graph_feats = []
    metadata_list = []
    ids = []

    stats = {
        "apks_processed": 0,
        "apks_skipped_empty": 0,
        "apks_skipped_no_label": 0,
        "apks_all_filtered": 0,
        "functions_total": 0,
        "functions_malware": 0,
        "functions_benign": 0,
    }

    for cfg_path in tqdm(cfg_files, desc="Processing CFGs"):
        sha256 = cfg_path.stem.replace("_cfg", "").lower()

        cfg_text = cfg_path.read_text(encoding="utf-8")
        if cfg_text.strip() == "NO_SUSPICIOUS_APIS_FOUND" or len(cfg_text.strip()) < 50:
            stats["apks_skipped_empty"] += 1
            continue

        info = label_lookup.get(sha256)
        if info is None:
            stats["apks_skipped_no_label"] += 1
            continue

        ground_truth = "MALWARE" if info["label"] == 1 else "BENIGN"
        family = info["family"]

        raw_slices = parse_cfg_file(cfg_path)
        filtered_slices, _, _ = preprocess_slices(raw_slices)

        if not filtered_slices:
            stats["apks_all_filtered"] += 1
            continue

        stats["apks_processed"] += 1

        for slice_obj in filtered_slices:
            linearized = linearize_slice(slice_obj)
            gf = extract_graph_features(slice_obj)

            unique_key = f"{sha256}:{slice_obj.function_name}:{slice_obj.suspicious_api}"
            point_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, unique_key))

            documents.append(linearized)
            graph_feats.append(gf)
            metadata_list.append({
                "sha256": sha256,
                "function_name": slice_obj.function_name,
                "suspicious_api": slice_obj.suspicious_api,
                "ground_truth": ground_truth,
                "family": family,
                "cfg_preview": slice_obj.raw_text[:500],
                "linearized_path": linearized,
            })
            ids.append(point_id)

            if ground_truth == "MALWARE":
                stats["functions_malware"] += 1
            else:
                stats["functions_benign"] += 1
            stats["functions_total"] += 1

    print(f"\n[INFO] {stats['functions_total']} function-level vectors to embed "
          f"(from {stats['apks_processed']} APKs)")
    print(f"[INFO] Malware functions: {stats['functions_malware']} | "
          f"Benign functions: {stats['functions_benign']}")
    print(f"[INFO] Skipped APKs: {stats['apks_skipped_empty']} empty/no-API, "
          f"{stats['apks_skipped_no_label']} no label, "
          f"{stats['apks_all_filtered']} fully-filtered")

    if not documents:
        print("[ERROR] No documents to embed!")
        sys.exit(1)

    # 6. Compute semantic embeddings
    print(f"\n[INFO] Computing semantic embeddings for {len(documents)} function slices...")
    print(f"       (this may take a while - {len(documents)} slices vs old {stats['apks_processed']} APKs)")
    semantic_embeddings = list(embedding_model.embed(documents, batch_size=64))

    # 7. Build hybrid vectors: concat(semantic[384], graph[25]) = 409
    print(f"[INFO] Building hybrid vectors ({SEMANTIC_DIM} semantic + {GRAPH_DIM} graph = {HYBRID_DIM} dims)...")
    graph_feats_np = np.array(graph_feats, dtype=np.float32)

    hybrid_vectors = []
    for i in range(len(documents)):
        sem = np.array(semantic_embeddings[i], dtype=np.float32)
        gf = graph_feats_np[i]
        gf_norm = np.linalg.norm(gf)
        if gf_norm > 0:
            gf = gf / gf_norm
        hybrid = np.concatenate([sem, gf])
        hybrid_vectors.append(hybrid.tolist())

    # 8. Upload to Qdrant
    points = [
        PointStruct(id=ids[i], vector=hybrid_vectors[i], payload=metadata_list[i])
        for i in range(len(documents))
    ]

    print(f"\n[INFO] Uploading {len(points)} hybrid vectors to Qdrant Cloud...")

    batch_size = 100
    for i in tqdm(range(0, len(points), batch_size)):
        batch = points[i : i + batch_size]
        client.upsert(
            collection_name=COLLECTION_NAME,
            points=batch,
        )

    # Summary
    print(f"\n{'=' * 70}")
    print(f"  RAG Database v2 Successfully Populated (Hybrid Embeddings)!")
    print(f"{'=' * 70}")
    print(f"  Collection    : {COLLECTION_NAME}")
    print(f"  Vector Dim    : {HYBRID_DIM} (semantic {SEMANTIC_DIM} + graph {GRAPH_DIM})")
    print(f"  Total Vectors : {len(points):,}")
    print(f"  From APKs     : {stats['apks_processed']:,}")
    print(f"  |-- Malware fn : {stats['functions_malware']:,}")
    print(f"  +-- Benign fn  : {stats['functions_benign']:,}")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
