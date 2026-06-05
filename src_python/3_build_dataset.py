"""
LAMD Pipeline — Step 3: Build the JSONL Training Dataset
=========================================================
Final step of LAMD Phase 1. Merges the extracted Sliced CFG text files
with the ground-truth labels from the CSV to produce the instruction-tuning
dataset consumed by the LLM in Phase 2.

Each JSONL record has three fields:
  instruction  — fixed prompt telling the LLM what to do
  input        — the Sliced CFG text produced by the Soot backward slicer
  output       — the ground-truth verdict (MALWARE/BENIGN + family)

Ground truth source:
  The train.csv already contains  label  (0.0 = benign, 1.0 = malware)
  and  family  (e.g. "airpush", "dowgin", "benign").
  No separate log files are needed.

Output format — one JSON object per line (JSONL):
  {"instruction": "...", "input": "<CFG text>", "output": "<verdict>"}

Usage:
  python src_python/3_build_dataset.py [--csv PATH] [--output PATH]

  --csv PATH     Override the default CSV (useful for test/validation sets).
  --output PATH  Override the default output JSONL path.

Resume safety:
  The script opens the JSONL in APPEND mode. If it crashes mid-run, restart
  it — already-written records are preserved and the loop continues from
  where it left off (because each hash is checked against what is already
  in the CSV, not the JSONL).
  NOTE: If you want a clean rebuild, delete the JSONL file first.
"""

import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd

# =============================================================================
#  Paths
# =============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAIN_CSV    = PROJECT_ROOT / "data" / "train.csv"
CFG_DIR      = PROJECT_ROOT / "extracted_cfgs"
OUTPUT_JSONL = PROJECT_ROOT / "lamd_training_dataset.jsonl"

# The instruction text prepended to every LLM input record.
# Keep this IDENTICAL across all records for consistent fine-tuning.
INSTRUCTION = (
    "Analyze this control flow graph and determine if it is MALWARE or BENIGN."
)


# =============================================================================
#  Load CSV and build a hash → verdict lookup table
# =============================================================================

def load_ground_truth(csv_path: Path) -> dict:
    """
    Reads the training CSV and returns a dict mapping each lowercase SHA-256
    hash to its human-readable verdict string.

    Verdict format:
      "MALWARE (family: <family_name>)"   for malicious samples
      "BENIGN"                            for clean samples

    Args:
        csv_path: Path to the CSV file (e.g. data/train.csv).

    Returns:
        dict { sha256_lowercase: verdict_string }
    """
    if not csv_path.is_file():
        print(f"[ERROR] CSV not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Loading ground truth from: {csv_path.name}")
    df = pd.read_csv(
        csv_path,
        usecols=["sha256", "family", "label"],
        dtype={"sha256": str, "family": str, "label": float},
    )

    df["sha256"] = df["sha256"].str.strip().str.lower()
    df.dropna(subset=["sha256"], inplace=True)
    df.drop_duplicates(subset=["sha256"], inplace=True)

    lookup = {}
    for _, row in df.iterrows():
        sha256 = row["sha256"]
        if row["label"] == 1.0:
            lookup[sha256] = f"MALWARE (family: {str(row['family']).strip()})"
        else:
            lookup[sha256] = "BENIGN"

    print(f"[INFO] Ground truth loaded for {len(lookup)} sample(s).")
    return lookup


# =============================================================================
#  Build one training record
# =============================================================================

def build_record(cfg_text: str, verdict: str) -> dict:
    """
    Constructs the instruction-tuning dict for a single sample.

    Args:
        cfg_text: raw text of the Sliced CFG file.
        verdict:  ground-truth string (e.g. "MALWARE (family: dowgin)").

    Returns:
        dict ready for json.dumps().
    """
    return {
        "instruction": INSTRUCTION,
        "input":       cfg_text.strip(),
        "output":      verdict,
    }


# =============================================================================
#  Main assembly loop
# =============================================================================

def main(csv_path: Path, output_path: Path) -> None:
    print("=" * 65)
    print("  LAMD Phase 1 — Step 3: Build Training Dataset")
    print("=" * 65)
    print()

    # ── Validate CFG directory ────────────────────────────────────────────────
    if not CFG_DIR.is_dir():
        print(
            f"[ERROR] CFG directory not found: {CFG_DIR}\n"
            "  Run  python src_python/2_extract_cfg.py  first.",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Load ground truth lookup ──────────────────────────────────────────────
    ground_truth = load_ground_truth(csv_path)
    total_in_csv = len(ground_truth)

    # ── Check existing JSONL ──────────────────────────────────────────────────
    if output_path.is_file():
        existing = sum(1 for _ in output_path.open(encoding="utf-8"))
        print(f"[INFO] {output_path.name} already has {existing} record(s) — appending.")
    else:
        print(f"[INFO] Creating new JSONL: {output_path.name}")
    print()

    # ── Discover extracted CFG files ──────────────────────────────────────────
    # CFG filenames follow the pattern:  {sha256}_cfg.txt
    cfg_files = sorted(CFG_DIR.glob("*_cfg.txt"))
    total_cfgs = len(cfg_files)
    print(f"[INFO] {total_cfgs} extracted CFG file(s) found in {CFG_DIR.name}/")

    if total_cfgs == 0:
        print(
            "[WARN] No CFG files found. "
            "Run  python src_python/2_extract_cfg.py  first.",
            file=sys.stderr,
        )
        sys.exit(1)

    print()

    # ── Assembly loop ─────────────────────────────────────────────────────────
    written   = 0
    skipped_no_label = 0   # CFG exists but hash not in CSV
    skipped_empty    = 0   # CFG file is empty
    errors           = 0

    run_start = time.time()

    with open(output_path, "a", encoding="utf-8") as jsonl_fh:
        for idx, cfg_path in enumerate(cfg_files, start=1):

            # Progress print every 10 samples (or on the last one)
            if idx % 10 == 0 or idx == total_cfgs:
                print(f"  Processing {idx}/{total_cfgs}...", flush=True)

            # ── Extract hash from filename ─────────────────────────────────────
            # Filename format: {sha256}_cfg.txt  →  stem = "{sha256}_cfg"
            sha256 = cfg_path.stem.replace("_cfg", "")

            # ── Look up ground truth label ─────────────────────────────────────
            verdict = ground_truth.get(sha256)
            if verdict is None:
                skipped_no_label += 1
                continue

            # ── Read the CFG text ──────────────────────────────────────────────
            try:
                cfg_text = cfg_path.read_text(encoding="utf-8")
            except OSError as exc:
                print(f"  [WARN] Cannot read {cfg_path.name}: {exc}")
                errors += 1
                continue

            if not cfg_text.strip():
                skipped_empty += 1
                continue

            # ── Build and write the record ─────────────────────────────────────
            try:
                record = build_record(cfg_text, verdict)
                jsonl_fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                written += 1
            except Exception as exc:
                print(f"  [ERROR] Failed to serialise {sha256[:16]}...: {exc}")
                errors += 1

    # ── Summary ────────────────────────────────────────────────────────────────
    total_elapsed = time.time() - run_start
    print()
    print("=" * 65)
    print("  Dataset Assembly Complete")
    print("=" * 65)
    print(f"  Hashes in CSV             : {total_in_csv}")
    print(f"  CFG files found           : {total_cfgs}")
    print(f"  Records written this run  : {written}")
    print(f"  Skipped (no CSV label)    : {skipped_no_label}")
    print(f"  Skipped (empty CFG)       : {skipped_empty}")
    print(f"  Errors                    : {errors}")
    print(f"  Total time                : {total_elapsed:.1f}s")
    print(f"  Output JSONL              : {output_path}")
    print("=" * 65)

    if written == 0:
        print(
            "\n[WARN] No records were written. Possible causes:\n"
            "  • Step 2 has not been run yet (no CFG files produced).\n"
            f"  • The sha256 values in the CFG filenames don't match the CSV.\n"
            f"  • All CFG files are empty (check for Soot errors)."
        )
        sys.exit(1)

    print(f"\n[✓] {written} training record(s) written to {output_path.name}")


# =============================================================================
#  Entry point
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Assemble the LAMD JSONL training dataset from CFGs and CSV labels."
    )
    parser.add_argument(
        "--csv", type=Path, default=TRAIN_CSV,
        help=f"Path to the training CSV (default: {TRAIN_CSV})"
    )
    parser.add_argument(
        "--output", type=Path, default=OUTPUT_JSONL,
        help=f"Destination JSONL file (default: {OUTPUT_JSONL})"
    )
    args = parser.parse_args()
    main(csv_path=args.csv, output_path=args.output)
