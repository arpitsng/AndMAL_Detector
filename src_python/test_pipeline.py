"""
Quick test script — matches pre-computed malware_logs against train.csv
ground truth to produce a properly labelled predictions file for evaluation.
"""
import json
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR      = PROJECT_ROOT / "lamd" / "malware_logs"
DATA_LOG_DIR = PROJECT_ROOT / "data" / "logs"
TRAIN_CSV    = PROJECT_ROOT / "data" / "train.csv"
TEST_CSV     = PROJECT_ROOT / "data" / "test_1.csv"
RESULTS_DIR  = PROJECT_ROOT / "results"


def parse_prediction(log_path: Path) -> str:
    text = log_path.read_text(encoding="utf-8")
    for line in text.split("\n"):
        upper = line.upper().strip()
        if "MALWARE" in upper and ("PREDICTION" in upper or "FINAL" in upper):
            return "MALWARE"
        if upper.strip("* ").startswith("MALWARE"):
            return "MALWARE"
    return "BENIGN"


def main():
    # Load all CSV labels
    print("[1/4] Loading ground truth from CSV files...")
    dfs = []
    for csv_path in [TRAIN_CSV, TEST_CSV]:
        if csv_path.is_file():
            df = pd.read_csv(csv_path, usecols=["sha256", "family", "label"],
                             dtype={"sha256": str, "family": str, "label": float})
            df["sha256"] = df["sha256"].str.strip().str.lower()
            dfs.append(df)
            print(f"  Loaded {len(df)} rows from {csv_path.name}")

    all_labels = pd.concat(dfs, ignore_index=True).drop_duplicates(subset=["sha256"])
    label_lookup = {}
    for _, row in all_labels.iterrows():
        gt = "MALWARE" if row["label"] == 1.0 else "BENIGN"
        label_lookup[row["sha256"]] = {"ground_truth": gt, "family": str(row["family"]).strip()}

    print(f"  Total ground truth entries: {len(label_lookup)}")

    # Find log files from both directories
    print("\n[2/4] Scanning log directories...")
    log_dirs = []
    for d in [LOG_DIR, DATA_LOG_DIR]:
        if d.is_dir():
            log_dirs.append(d)
            print(f"  Found: {d.name}/ ({len(list(d.glob('*.log')))} files)")

    # Process logs and match with ground truth
    print("\n[3/4] Processing logs and matching with ground truth...")
    results = []
    seen = set()

    for log_dir in log_dirs:
        for log_path in sorted(log_dir.glob("*.log")):
            sha256 = log_path.stem.lower()
            if sha256 in seen:
                continue
            seen.add(sha256)

            prediction = parse_prediction(log_path)
            gt_info = label_lookup.get(sha256, {})

            results.append({
                "sha256": sha256,
                "prediction": prediction,
                "ground_truth": gt_info.get("ground_truth", "UNKNOWN"),
                "family": gt_info.get("family", "unknown"),
                "source": log_dir.name,
            })

    # Filter out samples without ground truth
    labelled = [r for r in results if r["ground_truth"] != "UNKNOWN"]
    unlabelled = [r for r in results if r["ground_truth"] == "UNKNOWN"]

    print(f"  Total unique logs: {len(results)}")
    print(f"  Matched with ground truth: {len(labelled)}")
    print(f"  No ground truth found: {len(unlabelled)}")

    # Write results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = RESULTS_DIR / "predictions_with_gt.jsonl"
    with open(output_path, "w", encoding="utf-8") as f:
        for r in labelled:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"\n[4/4] Written {len(labelled)} labelled predictions to {output_path.name}")

    # Quick summary
    tp = sum(1 for r in labelled if r["prediction"] == "MALWARE" and r["ground_truth"] == "MALWARE")
    fp = sum(1 for r in labelled if r["prediction"] == "MALWARE" and r["ground_truth"] == "BENIGN")
    fn = sum(1 for r in labelled if r["prediction"] == "BENIGN"  and r["ground_truth"] == "MALWARE")
    tn = sum(1 for r in labelled if r["prediction"] == "BENIGN"  and r["ground_truth"] == "BENIGN")

    print(f"\n  Quick Stats:  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    mal_gt = sum(1 for r in labelled if r["ground_truth"] == "MALWARE")
    ben_gt = sum(1 for r in labelled if r["ground_truth"] == "BENIGN")
    print(f"  Ground truth: {mal_gt} MALWARE, {ben_gt} BENIGN")
    print(f"  Predictions:  {tp+fp} MALWARE, {fn+tn} BENIGN")

    print(f"\n  Now run:  python src_python/5_evaluate.py --predictions {output_path}")


if __name__ == "__main__":
    main()
