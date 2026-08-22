"""
LAMD Phase 3 — Pure RAG Classification (Vector Similarity Without LLM)
======================================================================
Classifies Android APKs using ONLY the 1.9M-vector FAISS knowledge base.
Performs k-NN nearest-neighbor similarity search on hybrid function embeddings
(384d semantic + 25d graph structure) to determine if an APK is MALWARE or BENIGN.

Zero LLM calls, zero cloud dependencies, instant high-throughput inference.

Usage:
  # Run 100 APKs from test_1.csv
  python src_python/7_rag_only_inference.py --csv data/test_1.csv --cfg-dir test_extracted_cfgs --limit 100

  # Run with custom output and k-neighbors
  python src_python/7_rag_only_inference.py --csv data/test_1.csv --cfg-dir test_extracted_cfgs --limit 100 -k 7 --output results/predictions_rag_100.jsonl
"""

import argparse
import importlib.util
import json
import os
import pickle
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src_python"))

from console_ui import (
    console, banner, section, ok, fail, warn, info,
    sample_result_line, sample_skip_line, sample_error_line,
    make_progress,
)

# Paths
LOCAL_DB_DIR = PROJECT_ROOT / "data" / "rag_local"
FAISS_INDEX_PATH = LOCAL_DB_DIR / "faiss_index.bin"
METADATA_PATH = LOCAL_DB_DIR / "metadata.pkl"
RESULTS_DIR = PROJECT_ROOT / "results"
TRAIN_CSV = PROJECT_ROOT / "data" / "train.csv"
CFG_DIR = PROJECT_ROOT / "extracted_cfgs"


@dataclass
class FunctionSlice:
    function_name: str
    suspicious_api: str
    nodes: list[str] = field(default_factory=list)
    edges: list[str] = field(default_factory=list)
    raw_text: str = ""


# Lazy load 6_build_qdrant_db for feature extraction
_rag_hybrid_mod = None

def get_hybrid_mod():
    global _rag_hybrid_mod
    if _rag_hybrid_mod is None:
        spec = importlib.util.spec_from_file_location(
            "rag_mod", Path(__file__).resolve().parent / "6_build_qdrant_db.py"
        )
        _rag_hybrid_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_rag_hybrid_mod)
    return _rag_hybrid_mod


def parse_cfg_file(cfg_path: Path) -> list[FunctionSlice]:
    text = cfg_path.read_text(encoding="utf-8")
    if text.startswith("=== SLICER_VERSION:"):
        first_newline = text.find("\n")
        text = text[first_newline + 1:] if first_newline != -1 else ""

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
        nodes = []
        edges = []
        raw_lines = []

        for line in lines[1:]:
            line = line.strip()
            if line.startswith("SUSPICIOUS_API:"):
                suspicious_api = line.split(":", 1)[1].strip()
            elif line.startswith("NODE "):
                nodes.append(line)
                raw_lines.append(line)
            elif line.startswith("EDGE:"):
                edges.append(line)
                raw_lines.append(line)
            elif line.startswith("=== END FUNCTION"):
                break

        raw_text = f"=== FUNCTION: {func_name} ===\n"
        raw_text += f"SUSPICIOUS_API: {suspicious_api}\n"
        raw_text += "\n".join(raw_lines)
        raw_text += "\n=== END FUNCTION ===\n"

        slices.append(FunctionSlice(
            function_name=func_name,
            suspicious_api=suspicious_api,
            nodes=nodes,
            edges=edges,
            raw_text=raw_text,
        ))

    return slices


def deduplicate_slices(slices: list[FunctionSlice]) -> list[FunctionSlice]:
    seen = set()
    unique = []
    for s in slices:
        key = (s.function_name, s.suspicious_api, len(s.nodes), len(s.edges))
        if key not in seen:
            seen.add(key)
            unique.append(s)
    return unique


def build_hybrid_vector(func_slice: FunctionSlice, embed_model) -> list[float]:
    rag_mod = get_hybrid_mod()
    linearized = rag_mod.linearize_slice(func_slice)
    graph_feats = rag_mod.extract_graph_features(func_slice)

    sem = list(embed_model.embed([linearized]))[0]
    sem = np.array(sem, dtype=np.float32)
    gf = np.array(graph_feats, dtype=np.float32)
    gf_norm = np.linalg.norm(gf)
    if gf_norm > 0:
        gf = gf / gf_norm

    vec = np.concatenate([sem, gf])
    v_norm = np.linalg.norm(vec)
    if v_norm > 0:
        vec = vec / v_norm
    return vec.tolist()


def classify_apk_rag_only(
    slices: list[FunctionSlice],
    faiss_index,
    metadata_list: list[dict],
    embed_model,
    k: int = 5,
    max_query_slices: int = 20,
    similarity_threshold: float = 0.70,
) -> dict:
    """
    Performs k-NN vector classification across the APK's function slices.
    """
    if not slices:
        return {
            "prediction": "BENIGN",
            "confidence": "LOW",
            "score": 0.0,
            "malware_votes": 0,
            "benign_votes": 0,
            "top_family": "none",
            "analysis": "No suspicious API slices found in CFG. Classified as BENIGN."
        }

    # Prioritize functions calling highest-risk APIs first
    def slice_priority(s: FunctionSlice):
        api = s.suspicious_api.lower()
        if any(x in api for x in ["dexclassloader", "loadclass", "sendtextmessage", "getdeviceid", "getsubscriberid", "exec"]):
            return 0
        if any(x in api for x in ["getlastknownlocation", "requestlocationupdates", "startrecording", "getinstalledpackages"]):
            return 1
        return 2

    sorted_slices = sorted(slices, key=slice_priority)[:max_query_slices]

    malware_weight = 0.0
    benign_weight = 0.0
    malware_votes = 0
    benign_votes = 0
    family_counter = Counter()
    match_details = []

    for s in sorted_slices:
        try:
            vec = build_hybrid_vector(s, embed_model)
            q_vec = np.array([vec], dtype=np.float32)

            scores, indices = faiss_index.search(q_vec, k)

            for score, idx in zip(scores[0], indices[0]):
                if idx < 0 or score < similarity_threshold:
                    continue
                hit_meta = metadata_list[idx]
                gt = hit_meta.get("ground_truth", "BENIGN")
                fam = hit_meta.get("family", "unknown")
                weight = float(score) ** 2  # emphasize high-similarity matches

                if gt == "MALWARE":
                    malware_weight += weight
                    malware_votes += 1
                    if fam and fam.lower() not in ("unknown", "benign"):
                        family_counter[fam] += weight
                else:
                    benign_weight += weight
                    benign_votes += 1

                match_details.append({
                    "query_func": s.function_name,
                    "query_api": s.suspicious_api,
                    "score": float(score),
                    "ground_truth": gt,
                    "family": fam,
                    "matched_func": hit_meta.get("function_name", ""),
                })
        except Exception:
            continue

    total_weight = malware_weight + benign_weight
    if total_weight > 0:
        malware_ratio = malware_weight / total_weight
    else:
        malware_ratio = 0.0

    # Decision rule: Pure majority weighted ratio
    # If >= 50% of the weighted similarity belongs to malware -> MALWARE, else BENIGN
    if malware_ratio >= 0.50:
        prediction = "MALWARE"
        confidence = "HIGH" if malware_ratio >= 0.70 else "MEDIUM"
    else:
        prediction = "BENIGN"
        confidence = "HIGH" if malware_ratio <= 0.30 else "MEDIUM"

    top_family = family_counter.most_common(1)[0][0] if family_counter else "unknown"

    # Format structured analysis summary
    analysis_lines = [
        f"PREDICTION: {prediction}",
        f"CONFIDENCE: {confidence}",
        f"RAG_METRICS: MalwareWeight={malware_weight:.2f}, BenignWeight={benign_weight:.2f}, MalwareRatio={malware_ratio:.1%}",
        f"VOTES: {malware_votes} MALWARE vs {benign_votes} BENIGN (k={k}, evaluated {len(sorted_slices)} functions)",
        f"TOP_FAMILY: {top_family}",
        "\nTOP_NEAREST_NEIGHBOR_MATCHES:"
    ]
    # Sort matches by score descending
    match_details.sort(key=lambda x: x["score"], reverse=True)
    for m in match_details[:8]:
        analysis_lines.append(
            f"  - [{m['ground_truth']} | {m['family']}] Sim: {m['score']:.3f} | Query: {m['query_func']} ({m['query_api']})"
        )

    analysis_text = "\n".join(analysis_lines)

    return {
        "prediction": prediction,
        "confidence": confidence,
        "score": malware_ratio,
        "malware_votes": malware_votes,
        "benign_votes": benign_votes,
        "top_family": top_family,
        "analysis": analysis_text,
    }


def main():
    parser = argparse.ArgumentParser(description="LAMD Phase 3: Pure RAG Vector Similarity Classification")
    parser.add_argument("--csv", type=Path, default=TRAIN_CSV, help="CSV file with sha256 + labels")
    parser.add_argument("--cfg-dir", type=Path, default=CFG_DIR, help="Directory with extracted CFGs")
    parser.add_argument("--offset", type=int, default=0, help="Skip the first N samples")
    parser.add_argument("--limit", type=int, default=100, help="Process only N samples (default: 100)")
    parser.add_argument("-k", type=int, default=5, help="Number of nearest neighbors per function slice (default: 5)")
    parser.add_argument("--max-slices", type=int, default=20, help="Max function slices to query per APK (default: 20)")
    parser.add_argument("--output", type=Path, default=None, help="Custom output path for predictions")
    parser.add_argument("--resume", action="store_true", help="Resume and skip already processed APKs")
    args = parser.parse_args()

    # Verify FAISS DB files
    if not FAISS_INDEX_PATH.is_file() or not METADATA_PATH.is_file():
        fail(f"Local FAISS database not found at: {LOCAL_DB_DIR}")
        console.print("  Run  python src_python/6_build_local_db.py  first.")
        sys.exit(1)

    csv_path = args.csv if args.csv.is_absolute() else (PROJECT_ROOT / args.csv).resolve()
    cfg_dir = args.cfg_dir if args.cfg_dir.is_absolute() else (PROJECT_ROOT / args.cfg_dir).resolve()

    info_lines = [
        "Mode    : PURE RAG (Vector k-NN, Zero LLM)",
        f"CSV     : {csv_path.name}",
        f"CFG Dir : {cfg_dir.name}",
        f"Limit   : {args.limit}",
        f"k-NN    : {args.k}",
    ]
    if args.offset > 0:
        info_lines.append(f"Offset  : {args.offset}")
    banner("LAMD Pure RAG Vector Classifier", info_lines)
    console.print()

    # Load FAISS index & metadata
    info("Loading 1.9M vector FAISS index and embedding model into memory...")
    import faiss
    from fastembed import TextEmbedding

    t0 = time.time()
    faiss_index = faiss.read_index(str(FAISS_INDEX_PATH))
    with open(METADATA_PATH, "rb") as f:
        metadata_list = pickle.load(f)

    model_dir = PROJECT_ROOT / "fastembed_models" / "bge-small-en"
    if (model_dir / "fast-bge-small-en").is_dir():
        model_dir = model_dir / "fast-bge-small-en"

    kwargs = {
        "model_name": "BAAI/bge-small-en",
        "providers": ["CUDAExecutionProvider", "CPUExecutionProvider"]
    }
    if model_dir.is_dir() and any(model_dir.glob("*.onnx")):
        kwargs["specific_model_path"] = str(model_dir)

    embed_model = TextEmbedding(**kwargs)
    ok(f"FAISS index loaded ({faiss_index.ntotal:,} vectors) in {time.time() - t0:.1f}s.")
    console.print()

    # Load dataset CSV
    if not csv_path.is_file():
        fail(f"CSV file not found: {csv_path}")
        sys.exit(1)

    df = pd.read_csv(csv_path, usecols=["sha256", "family", "label"], dtype={"sha256": str, "family": str, "label": float})
    df["sha256"] = df["sha256"].str.strip().str.lower()
    df.dropna(subset=["sha256"], inplace=True)
    df.drop_duplicates(subset=["sha256"], inplace=True)

    if args.offset > 0:
        df = df.iloc[args.offset:]
    if args.limit:
        df = df.head(args.limit)

    info(f"{len(df)} sample(s) queued for evaluation.")

    # Output file setup
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = args.output or (RESULTS_DIR / f"predictions_rag_only_{csv_path.stem}.jsonl")

    already_done = set()
    results = []
    if args.resume and output_path.is_file():
        with open(output_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        rec = json.loads(line.strip())
                        already_done.add(rec["sha256"])
                        results.append(rec)
                    except Exception:
                        pass
        info(f"Resuming: {len(already_done)} already done, skipping.")

    total = len(df)
    run_start = time.time()

    with make_progress() as progress:
        task = progress.add_task("Classifying APKs (Pure RAG)", total=total)
        for idx, row in df.iterrows():
            sha256 = row["sha256"]
            sha_short = sha256[:20]
            i = len(results) + 1

            if sha256 in already_done:
                sample_skip_line(i, total, sha_short, "already done")
                progress.advance(task)
                continue

            cfg_path = cfg_dir / f"{sha256}_cfg.txt"
            if not cfg_path.is_file():
                # Check default extracted_cfgs directory as fallback
                fallback_cfg = CFG_DIR / f"{sha256}_cfg.txt"
                if fallback_cfg.is_file():
                    cfg_path = fallback_cfg
                else:
                    sample_skip_line(i, total, sha_short, "no CFG found")
                    progress.advance(task)
                    continue

            t_start = time.time()
            slices = parse_cfg_file(cfg_path)
            slices = deduplicate_slices(slices)

            rag_res = classify_apk_rag_only(
                slices=slices,
                faiss_index=faiss_index,
                metadata_list=metadata_list,
                embed_model=embed_model,
                k=args.k,
                max_query_slices=args.max_slices,
            )
            elapsed = time.time() - t_start

            record = {
                "sha256": sha256,
                "prediction": rag_res["prediction"],
                "confidence": rag_res["confidence"],
                "score": rag_res["score"],
                "malware_votes": rag_res["malware_votes"],
                "benign_votes": rag_res["benign_votes"],
                "top_family": rag_res["top_family"],
                "analysis": rag_res["analysis"],
                "elapsed_sec": round(elapsed, 3),
            }
            results.append(record)

            # Append to output file in real-time
            with open(output_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

            gt_label = "MALWARE" if row.get("label") == 1.0 else ("BENIGN" if row.get("label") == 0.0 else None)

            sample_result_line(
                i, total, sha_short,
                rag_res["prediction"],
                gt_label,
                elapsed,
            )
            progress.advance(task)

    console.print()
    total_time = time.time() - run_start
    ok(f"Completed {len(results)} samples in {total_time:.1f}s ({total_time/max(len(results),1):.2f}s per APK).")
    ok(f"Predictions saved to: {output_path}")

    # Run quick evaluation summary
    mal_pred = sum(1 for r in results if r["prediction"] == "MALWARE")
    ben_pred = sum(1 for r in results if r["prediction"] == "BENIGN")
    console.print(f"    Predictions: [bold red]{mal_pred} MALWARE[/bold red]  |  [bold green]{ben_pred} BENIGN[/bold green]")


if __name__ == "__main__":
    main()
