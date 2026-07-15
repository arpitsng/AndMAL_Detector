"""
LAMD Pipeline — Step 6: Build RAG Knowledge Base
=================================================
One-time script that indexes all extracted CFG files into a Qdrant Cloud
vector collection for retrieval-augmented generation.

What it does:
  1. Reads data/train.csv to get ground-truth labels (MALWARE/BENIGN)
     and malware family names for each SHA256.
  2. Scans extracted_cfgs/ for *_cfg.txt files whose SHA256 appears in
     the training split (avoids test-set leakage).
  3. Parses each file into per-function FunctionSlice objects.
  4. Embeds all slices locally using all-MiniLM-L6-v2 (CPU, free).
  5. Upserts vectors + metadata into Qdrant Cloud collection 'lamd_cfg_kb'.

Usage:
  python src_python/6_build_rag_kb.py

  # Force re-index (delete collection and rebuild from scratch)
  python src_python/6_build_rag_kb.py --reset

Requirements (add to .env):
  QDRANT_URL=https://<cluster-id>.qdrant.io
  QDRANT_API_KEY=<your-api-key>
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid
from pathlib import Path

import pandas as pd
from tqdm import tqdm

# Allow running from project root or src_python/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src_python"))

from rag_utils import (
    BATCH_SIZE,
    COLLECTION_NAME,
    EmbeddingModel,
    FunctionSlice,
    ensure_collection_exists,
    get_qdrant_client,
    parse_cfg_file,
)

# =============================================================================
#  Paths
# =============================================================================

TRAIN_CSV = PROJECT_ROOT / "data" / "train.csv"
CFG_DIR   = PROJECT_ROOT / "extracted_cfgs"


# =============================================================================
#  Load label map from train.csv
# =============================================================================

def load_label_map(csv_path: Path) -> dict[str, dict]:
    """
    Returns a dict mapping sha256 (lowercase) → {'label': 'MALWARE'|'BENIGN', 'family': str}.
    Handles both numeric labels (0.0/1.0) and string labels (benign/malware).
    """
    df = pd.read_csv(csv_path)

    # Normalise column names (handle potential whitespace)
    df.columns = [c.strip().lower() for c in df.columns]

    # sha256 column
    sha_col = "sha256" if "sha256" in df.columns else df.columns[0]

    # label / family columns — train.csv uses 'label' (0.0=benign, 1.0=malware)
    label_col  = next((c for c in df.columns if c == "label" or "class" in c), None)
    family_col = next((c for c in df.columns if "family" in c), None)

    label_map: dict[str, dict] = {}
    for _, row in df.iterrows():
        # SHA256 is uppercase in CSV — normalise to lowercase for filename matching
        sha = str(row[sha_col]).strip().lower()
        family = str(row[family_col]).strip() if family_col else "unknown"

        # Resolve label — numeric (0.0/1.0) or string (benign/malware)
        if label_col:
            raw = str(row[label_col]).strip().lower()
            try:
                numeric = float(raw)
                label = "MALWARE" if numeric >= 1.0 else "BENIGN"
            except ValueError:
                if "malware" in raw or raw == "1":
                    label = "MALWARE"
                elif "benign" in raw or raw == "0":
                    label = "BENIGN"
                else:
                    label = raw.upper()
        else:
            label = "UNKNOWN"

        label_map[sha] = {"label": label, "family": family}

    return label_map


# =============================================================================
#  Build upsert payloads
# =============================================================================

def collect_slices(
    cfg_dir: Path,
    label_map: dict[str, dict],
) -> list[dict]:
    """
    Walk all *_cfg.txt files in cfg_dir, parse per-function slices,
    and return a list of dicts ready for Qdrant upsert.

    Only processes files whose SHA256 is present in label_map (training set).
    """
    records: list[dict] = []
    skipped_no_label = 0
    skipped_no_slices = 0

    cfg_files = sorted(cfg_dir.glob("*_cfg.txt"))
    print(f"\n  Found {len(cfg_files):,} CFG files in {cfg_dir.name}/")

    for cfg_path in tqdm(cfg_files, desc="  Parsing CFGs", unit="file"):
        # Extract SHA256 from filename: <sha256>_cfg.txt
        sha256 = cfg_path.name.replace("_cfg.txt", "").lower()

        # Only index training-set entries (avoids test leakage)
        if sha256 not in label_map:
            skipped_no_label += 1
            continue

        meta = label_map[sha256]
        slices = parse_cfg_file(cfg_path)

        if not slices:
            skipped_no_slices += 1
            continue

        for sl in slices:
            records.append({
                # Stable deterministic ID from sha256 + function name
                "id":            str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{sha256}::{sl.function_name}")),
                "sha256":        sha256,
                "function_name": sl.function_name,
                "suspicious_api": sl.suspicious_api,
                "label":         meta["label"],
                "family":        meta["family"],
                "raw_text":      sl.raw_text,
                # Text to embed: function name + API + full slice
                "embed_text":    f"API: {sl.suspicious_api}\nFunction: {sl.function_name}\n{sl.raw_text}",
            })

    print(f"\n  Slices collected : {len(records):,}")
    print(f"  Skipped (no label in train.csv): {skipped_no_label:,}")
    print(f"  Skipped (empty CFG)            : {skipped_no_slices:,}")
    return records


# =============================================================================
#  Upsert to Qdrant Cloud
# =============================================================================

def upsert_to_qdrant(
    client,
    records:     list[dict],
    embedder:    EmbeddingModel,
    batch_size:  int = BATCH_SIZE,
) -> None:
    """
    Embeds records in batches and upserts them into Qdrant.
    Uses deterministic UUIDs so re-runs are idempotent.
    """
    from qdrant_client.http.models import PointStruct

    total = len(records)
    print(f"\n  Upserting {total:,} vectors to Qdrant Cloud …")

    start = time.time()
    upserted = 0

    for batch_start in tqdm(range(0, total, batch_size), desc="  Upserting", unit="batch"):
        batch = records[batch_start : batch_start + batch_size]

        # Embed
        texts    = [r["embed_text"] for r in batch]
        vectors  = embedder.embed(texts)

        # Build Qdrant points
        points = [
            PointStruct(
                id=r["id"],
                vector=vec,
                payload={
                    "sha256":         r["sha256"],
                    "function_name":  r["function_name"],
                    "suspicious_api": r["suspicious_api"],
                    "label":          r["label"],
                    "family":         r["family"],
                    "raw_text":       r["raw_text"],
                },
            )
            for r, vec in zip(batch, vectors)
        ]

        client.upsert(collection_name=COLLECTION_NAME, points=points)
        upserted += len(points)

    elapsed = time.time() - start
    print(f"\n  [OK] Upserted {upserted:,} points in {elapsed:.1f}s")


# =============================================================================
#  Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the LAMD RAG knowledge base in Qdrant Cloud."
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete the existing Qdrant collection and rebuild from scratch.",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  LAMD — Step 6: Build RAG Knowledge Base")
    print("=" * 60)

    # ── 1. Load labels ────────────────────────────────────────────────────────
    print(f"\n[1/5] Loading label map from {TRAIN_CSV.name} …")
    if not TRAIN_CSV.exists():
        print(f"[ERROR] {TRAIN_CSV} not found.", file=sys.stderr)
        sys.exit(1)
    label_map = load_label_map(TRAIN_CSV)
    malware_n = sum(1 for v in label_map.values() if v["label"] == "MALWARE")
    benign_n  = len(label_map) - malware_n
    print(f"  Train set: {len(label_map):,} samples  ({malware_n:,} MALWARE, {benign_n:,} BENIGN)")

    # ── 2. Connect to Qdrant Cloud ────────────────────────────────────────────
    print("\n[2/5] Connecting to Qdrant Cloud …")
    client = get_qdrant_client()

    if args.reset:
        existing = {c.name for c in client.get_collections().collections}
        if COLLECTION_NAME in existing:
            print(f"  --reset: Deleting collection '{COLLECTION_NAME}' …")
            client.delete_collection(COLLECTION_NAME)

    ensure_collection_exists(client)

    # ── 3. Parse CFG files ────────────────────────────────────────────────────
    print("\n[3/5] Parsing CFG files …")
    records = collect_slices(CFG_DIR, label_map)

    if not records:
        print("[WARN] No records to index. Check extracted_cfgs/ and train.csv.")
        sys.exit(0)

    label_dist: dict[str, int] = {}
    for r in records:
        label_dist[r["label"]] = label_dist.get(r["label"], 0) + 1
    print("  Label distribution in KB:")
    for lbl, cnt in sorted(label_dist.items()):
        print(f"    {lbl}: {cnt:,} slices")

    # ── 4. Load embedding model ───────────────────────────────────────────────
    print("\n[4/5] Loading local embedding model …")
    embedder = EmbeddingModel()

    # ── 5. Upsert to Qdrant ───────────────────────────────────────────────────
    print("\n[5/5] Embedding + upserting to Qdrant Cloud …")
    upsert_to_qdrant(client, records, embedder)

    # ── Final summary ─────────────────────────────────────────────────────────
    info  = client.get_collection(COLLECTION_NAME)
    total = info.points_count or 0
    print("\n" + "=" * 60)
    print("  [OK] Knowledge Base Built Successfully")
    print(f"  Collection : {COLLECTION_NAME}")
    print(f"  Total docs : {total:,}")
    print("=" * 60)
    print("\nNext step:")
    print("  python src_python/7_rag_query.py --sha256 <hash>")
    print("  python src_python/7_rag_query.py --cfg extracted_cfgs/<file>_cfg.txt")
    print("  python src_python/7_rag_query.py --text 'app sends SMS to premium numbers'")


if __name__ == "__main__":
    main()
