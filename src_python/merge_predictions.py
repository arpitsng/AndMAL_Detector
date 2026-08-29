"""
Merges newly re-tested predictions into results/predictions_smallest_200.jsonl
and automatically evaluates the updated accuracy, recall, and false positive rate.

Usage:
  venv\\Scripts\\python.exe src_python\\merge_predictions.py
"""
import json, subprocess, sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
main_pred_file = PROJECT_ROOT / "results" / "predictions_smallest_200.jsonl"
retest_pred_file = PROJECT_ROOT / "results" / "predictions_wrong_samples.jsonl"

if not retest_pred_file.is_file():
    print(f"[ERROR] Retest predictions file not found: {retest_pred_file}")
    print("Please run inference first using the command provided.")
    sys.exit(1)

# Load retested predictions
new_preds = {}
with open(retest_pred_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            sha = data.get("sha256")
            if sha:
                new_preds[sha] = data
        except Exception:
            continue

print(f"[INFO] Loaded {len(new_preds)} new predictions from {retest_pred_file.name}")

# Update main predictions file
updated_records = []
replaced_count = 0

with open(main_pred_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            sha = rec.get("sha256")
            if sha in new_preds:
                rec["prediction"] = new_preds[sha]["prediction"]
                if "analysis" in new_preds[sha]:
                    rec["analysis"] = new_preds[sha]["analysis"]
                replaced_count += 1
            updated_records.append(rec)
        except Exception:
            continue

with open(main_pred_file, "w", encoding="utf-8") as f:
    for r in updated_records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

print(f"[OK] Successfully merged {replaced_count} updated predictions into {main_pred_file.name}")
print("\n" + "="*70)
print("RUNNING FINAL EVALUATION")
print("="*70)

# Run evaluation script
eval_script = PROJECT_ROOT / "src_python" / "5_evaluate.py"
subprocess.run([sys.executable, str(eval_script), "--predictions", str(main_pred_file)])
