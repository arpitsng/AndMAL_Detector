"""
LAMD Pipeline — End-to-End Orchestrator (Extract + Analyze)
===========================================================
Given a single SHA256 hash or a CSV file:
1. Extract CFG (download APK -> run Slicer -> clean up).
2. Run RAG query for malware analysis.

Usage:
  python src_python/8_full_pipeline.py --sha256 <HASH>
  python src_python/8_full_pipeline.py --csv <PATH> [--limit N]
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src_python"))

import importlib
extract_cfg = importlib.import_module("2_extract_cfg")
rag_query = importlib.import_module("7_rag_query")
from rag_utils import EmbeddingModel, ensure_sha256_index, get_qdrant_client

def process_single(sha256, api_key, client, embedder, llm, gt_map, top_k):
    sha256 = sha256.strip().lower()
    
    import subprocess
    import requests

    # 1. Extraction
    cfg_path = extract_cfg.CFG_DIR / f"{sha256}_cfg.txt"
    if not cfg_path.is_file() or cfg_path.stat().st_size == 0:
        print(f"\n[Extract] CFG not found for {sha256}. Extracting...")
        apk_path = extract_cfg.APK_DIR / f"{sha256}.apk"
        try:
            print(f"  Downloading APK...")
            extract_cfg.download_apk(sha256, api_key)
            print(f"  Running Soot Slicer...")
            extract_cfg.run_slicer(apk_path, cfg_path)
        except requests.exceptions.RequestException as e:
            print(f"  [ERROR] Download failed: {e}", file=sys.stderr)
            return None
        except subprocess.TimeoutExpired:
            print(f"  [WARN] Soot analysis timed out. (Common for large/obfuscated APKs)", file=sys.stderr)
            return None
        except subprocess.CalledProcessError as e:
            print(f"  [WARN] Soot failed with exit code {e.returncode}. (Common for obfuscated malware)", file=sys.stderr)
            if e.stderr:
                (extract_cfg.CFG_DIR / f"{sha256}_error.log").write_text(e.stderr, encoding="utf-8")
            return None
        except Exception as e:
            print(f"  [ERROR] Unexpected extraction error: {e}", file=sys.stderr)
            return None
        finally:
            extract_cfg.safe_delete(apk_path)
        
        if not cfg_path.is_file() or cfg_path.stat().st_size == 0:
            print("  [ERROR] Soot failed to produce a valid CFG.")
            return None
    else:
        print(f"\n[Extract] CFG already exists for {sha256}. Skipping extraction.")
        
    # 2. Analysis
    print(f"\n[Analyze] Running RAG analysis for {sha256}...")
    try:
        result = rag_query.analyse_one(
            query_mode="sha256", 
            query_value=sha256, 
            client=client, 
            embedder=embedder, 
            llm=llm, 
            top_k=top_k, 
            ground_truth_map=gt_map
        )
        return result
    except Exception as e:
        print(f"  [ERROR] Analysis failed: {e}", file=sys.stderr)
        return None

def main():
    parser = argparse.ArgumentParser(description="End-to-End LAMD Pipeline (Extract -> Analyze)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sha256", help="Analyze a single SHA256 hash")
    group.add_argument("--csv", help="Analyze multiple SHA256 hashes from a CSV")
    parser.add_argument("--limit", type=int, default=None, help="Max number of APKs to process (for --csv)")
    parser.add_argument("--top-k", type=int, default=rag_query.TOP_K, help="Number of retrieved neighbours")
    parser.add_argument("--output", default=str(rag_query.OUTPUT_FILE), help="Output JSONL file")
    args = parser.parse_args()

    print("=" * 60)
    print("  LAMD — End-to-End Orchestrator (Extract + Analyze)")
    print("=" * 60)

    # 1. Init API Keys
    try:
        api_key = extract_cfg.load_api_key()
    except SystemExit:
        sys.exit(1)

    # 2. Init AI components
    print("\n[Init] Loading embedding model …")
    embedder = EmbeddingModel()
    print("[Init] Connecting to Qdrant Cloud …")
    client = get_qdrant_client()
    ensure_sha256_index(client)
    print("[Init] Loading LLM backend …")
    try:
        llm = rag_query.create_llm()
        backend_name = "Gemini" if "Gemini" in type(llm).__name__ else "Groq"
        print(f"  [OK] Initialized {backend_name} backend with {len(llm.api_keys)} key(s)")
    except SystemExit:
        sys.exit(1)

    # 3. Load GT Map
    gt_map = {}
    for csv in [rag_query.TRAIN_CSV, rag_query.TEST_CSV]:
        if csv.exists():
            gt_map.update(rag_query.load_ground_truth(csv))

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # 4. Prepare targets
    targets = []
    if args.sha256:
        targets.append(args.sha256)
        write_mode = "w"
    elif args.csv:
        csv_path = Path(args.csv)
        if not csv_path.exists():
            print(f"[ERROR] CSV not found: {csv_path}", file=sys.stderr)
            sys.exit(1)
            
        df = pd.read_csv(csv_path)
        df.columns = [c.strip().lower() for c in df.columns]
        sha_col = "sha256" if "sha256" in df.columns else df.columns[0]
        targets = df[sha_col].astype(str).str.strip().str.lower().tolist()
        
        if args.limit:
            targets = targets[:args.limit]
            
        print(f"\n  Batch mode: {len(targets)} APKs from {csv_path.name}")
        write_mode = "w"

    correct = 0
    total = 0

    with open(output_path, write_mode, encoding="utf-8") as f:
        for idx, sha256 in enumerate(targets, 1):
            if len(targets) > 1:
                print(f"\n{'-'*60}")
                print(f"[{idx}/{len(targets)}] Processing {sha256}...")
                
            result = process_single(
                sha256=sha256, 
                api_key=api_key, 
                client=client, 
                embedder=embedder, 
                llm=llm, 
                gt_map=gt_map, 
                top_k=args.top_k
            )
            
            if result:
                f.write(json.dumps(result, ensure_ascii=True) + "\n")
                f.flush()
                
                if result.get("ground_truth") and result["ground_truth"] != "UNKNOWN":
                    total += 1
                    if result["prediction"] == result["ground_truth"]:
                        correct += 1

    print(f"\n{'='*60}")
    print(f"  Pipeline complete: {len(targets)} requests")
    print(f"  Results saved → {output_path}")
    if total > 0:
        acc = correct / total * 100
        print(f"  Quick accuracy: {correct}/{total} = {acc:.1f}%")
        print(f"  Run full evaluation:")
        print(f"    python src_python/5_evaluate.py --predictions {output_path}")
    print("=" * 60)

if __name__ == "__main__":
    main()
