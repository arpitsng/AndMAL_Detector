"""
Build LOCAL FAISS Vector Database for RAG Pipeline (No Cloud Required)
======================================================================
Reads the precomputed hybrid vectors from the existing Qdrant cache
(data/rag_cache/hybrid_vectors_cache.pkl) and builds a local FAISS
index + metadata sidecar.

Output:
  data/rag_local/faiss_index.bin      -- FAISS IndexFlatIP (cosine via normalized vectors)
  data/rag_local/metadata.pkl         -- list[dict] aligned with FAISS row ids
  data/rag_local/label_indices.pkl    -- {"MALWARE": [...], "BENIGN": [...]} row id lists

Usage:
  python src_python/6_build_local_db.py
  python src_python/6_build_local_db.py --recreate   # force rebuild
"""

import argparse
import os
import pickle
import sys
import time
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CACHE_FILE = PROJECT_ROOT / "data" / "rag_cache" / "hybrid_vectors_cache.pkl"
LOCAL_DB_DIR = PROJECT_ROOT / "data" / "rag_local"
FAISS_INDEX_PATH = LOCAL_DB_DIR / "faiss_index.bin"
METADATA_PATH = LOCAL_DB_DIR / "metadata.pkl"
LABEL_INDEX_PATH = LOCAL_DB_DIR / "label_indices.pkl"

HYBRID_DIM = 409  # 384 semantic + 25 graph


def main():
    parser = argparse.ArgumentParser(description="Build local FAISS RAG database from cache")
    parser.add_argument("--recreate", action="store_true", help="Force rebuild even if index exists")
    args = parser.parse_args()

    print("=" * 70)
    print("  LAMD Local FAISS RAG DB Builder")
    print("  (Zero cloud dependency -- runs entirely on your machine)")
    print("=" * 70)

    # Check if already built
    if FAISS_INDEX_PATH.is_file() and not args.recreate:
        print(f"\n[INFO] Local FAISS index already exists at: {FAISS_INDEX_PATH}")
        print(f"[INFO] Use --recreate to force rebuild.")
        # Quick stats
        import faiss
        idx = faiss.read_index(str(FAISS_INDEX_PATH))
        with open(METADATA_PATH, "rb") as f:
            meta = pickle.load(f)
        with open(LABEL_INDEX_PATH, "rb") as f:
            labels = pickle.load(f)
        print(f"\n  Total Vectors : {idx.ntotal:,}")
        print(f"  Dimensions    : {idx.d}")
        print(f"  MALWARE       : {len(labels['MALWARE']):,}")
        print(f"  BENIGN        : {len(labels['BENIGN']):,}")
        print(f"  Index Size    : {FAISS_INDEX_PATH.stat().st_size / 1024**2:.1f} MB")
        print("=" * 70)
        return

    # 1. Load precomputed cache
    if not CACHE_FILE.is_file():
        print(f"[ERROR] Cache file not found: {CACHE_FILE}")
        print("[ERROR] Run 6_build_qdrant_db.py first (or place the cache file).")
        sys.exit(1)

    print(f"\n[1/4] Loading precomputed vectors from: {CACHE_FILE}")
    t0 = time.time()
    with open(CACHE_FILE, "rb") as f:
        cache = pickle.load(f)
    elapsed = time.time() - t0
    print(f"      Loaded in {elapsed:.1f}s")

    hybrid_vectors = cache["hybrid_vectors"]
    metadata_list = cache["metadata_list"]
    n = len(hybrid_vectors)
    print(f"      Total vectors: {n:,} x {HYBRID_DIM}d")

    # 2. Convert to numpy and L2-normalize for cosine similarity via inner product
    print(f"\n[2/4] Converting to numpy and L2-normalizing for cosine similarity...")
    t0 = time.time()
    vectors_np = np.array(hybrid_vectors, dtype=np.float32)
    # L2 normalize so inner product == cosine similarity
    norms = np.linalg.norm(vectors_np, axis=1, keepdims=True)
    norms[norms == 0] = 1.0  # avoid div by zero
    vectors_np = vectors_np / norms
    elapsed = time.time() - t0
    print(f"      Normalized {n:,} vectors in {elapsed:.1f}s")
    print(f"      Array shape: {vectors_np.shape}, dtype: {vectors_np.dtype}")
    print(f"      Memory: {vectors_np.nbytes / 1024**3:.2f} GB")

    # 3. Build FAISS index (IndexFlatIP for exact cosine via normalized vectors)
    print(f"\n[3/4] Building FAISS IndexFlatIP (exact cosine search)...")
    import faiss
    t0 = time.time()
    index = faiss.IndexFlatIP(HYBRID_DIM)  # Inner Product on normalized vectors = cosine
    index.add(vectors_np)
    elapsed = time.time() - t0
    print(f"      Added {index.ntotal:,} vectors in {elapsed:.1f}s")

    # 4. Build label indices for stratified retrieval
    print(f"\n[4/4] Building stratified label indices and saving to disk...")
    t0 = time.time()
    label_indices = {"MALWARE": [], "BENIGN": []}
    for i, meta in enumerate(metadata_list):
        gt = meta.get("ground_truth", "BENIGN")
        if gt in label_indices:
            label_indices[gt].append(i)
    label_indices["MALWARE"] = np.array(label_indices["MALWARE"], dtype=np.int64)
    label_indices["BENIGN"] = np.array(label_indices["BENIGN"], dtype=np.int64)

    # Save everything
    LOCAL_DB_DIR.mkdir(parents=True, exist_ok=True)

    faiss.write_index(index, str(FAISS_INDEX_PATH))
    with open(METADATA_PATH, "wb") as f:
        pickle.dump(metadata_list, f, protocol=pickle.HIGHEST_PROTOCOL)
    with open(LABEL_INDEX_PATH, "wb") as f:
        pickle.dump(label_indices, f, protocol=pickle.HIGHEST_PROTOCOL)

    elapsed = time.time() - t0

    idx_size = FAISS_INDEX_PATH.stat().st_size / 1024**2
    meta_size = METADATA_PATH.stat().st_size / 1024**2

    print(f"      Saved in {elapsed:.1f}s")
    print(f"\n{'=' * 70}")
    print(f"  LOCAL FAISS RAG DATABASE BUILT SUCCESSFULLY!")
    print(f"{'=' * 70}")
    print(f"  Total Vectors   : {index.ntotal:,}")
    print(f"  Dimensions      : {HYBRID_DIM}")
    print(f"  MALWARE vectors : {len(label_indices['MALWARE']):,}")
    print(f"  BENIGN vectors  : {len(label_indices['BENIGN']):,}")
    print(f"  Index file      : {FAISS_INDEX_PATH} ({idx_size:.1f} MB)")
    print(f"  Metadata file   : {METADATA_PATH} ({meta_size:.1f} MB)")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
