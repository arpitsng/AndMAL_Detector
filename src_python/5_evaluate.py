"""
LAMD Pipeline — Step 5: Evaluate Predictions
==============================================
Computes classification metrics (F1, Precision, Recall, FPR, FNR) and
generates detailed analysis reports from prediction JSONL files.

Usage:
  python src_python/5_evaluate.py --predictions results/predictions_cfg.jsonl
  python src_python/5_evaluate.py --predictions results/predictions_logs.jsonl

Metrics computed:
  - F1 Score (primary metric, handles class imbalance)
  - Precision, Recall
  - False Positive Rate (FPR) — benign mislabelled as malware
  - False Negative Rate (FNR) — malware mislabelled as benign
  - Confusion Matrix
  - Per-family detection rates (for malware families)
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR  = PROJECT_ROOT / "results"


# =============================================================================
#  Metrics computation
# =============================================================================

def compute_metrics(y_true: list[str], y_pred: list[str]) -> dict:
    """
    Computes binary classification metrics.

    Positive class = MALWARE, Negative class = BENIGN.
    """
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == "MALWARE" and p == "MALWARE")
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == "BENIGN"  and p == "BENIGN")
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == "BENIGN"  and p == "MALWARE")
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == "MALWARE" and p == "BENIGN")

    total = tp + tn + fp + fn
    accuracy  = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall    = tp / (tp + fn) if (tp + fn) else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fpr       = fp / (fp + tn) if (fp + tn) else 0
    fnr       = fn / (fn + tp) if (fn + tp) else 0

    return {
        "total": total,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
    }


def per_family_analysis(records: list[dict]) -> dict[str, dict]:
    """
    Computes detection rate per malware family.

    Only considers records where ground_truth == "MALWARE".
    """
    family_stats: dict[str, dict] = defaultdict(lambda: {"total": 0, "detected": 0})

    for r in records:
        if r.get("ground_truth") != "MALWARE":
            continue

        family = r.get("family", "unknown").strip().lower()
        if not family or family in ("nan", "benign", ""):
            family = "unknown"

        family_stats[family]["total"] += 1
        if r.get("prediction") == "MALWARE":
            family_stats[family]["detected"] += 1

    # Compute detection rate
    result = {}
    for family, stats in sorted(family_stats.items(), key=lambda x: -x[1]["total"]):
        rate = stats["detected"] / stats["total"] if stats["total"] else 0
        result[family] = {
            "total": stats["total"],
            "detected": stats["detected"],
            "missed": stats["total"] - stats["detected"],
            "detection_rate": rate,
        }

    return result


# =============================================================================
#  Report generation
# =============================================================================

def generate_report(
    metrics: dict, family_analysis: dict, records: list[dict], output_path: Path
) -> None:
    """Generates a markdown evaluation report."""
    lines = [
        "# LAMD Evaluation Report",
        "",
        "## Overall Metrics",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| **Total Samples** | {metrics['total']} |",
        f"| **Accuracy** | {metrics['accuracy']*100:.2f}% |",
        f"| **Precision** | {metrics['precision']*100:.2f}% |",
        f"| **Recall** | {metrics['recall']*100:.2f}% |",
        f"| **F1 Score** | {metrics['f1']*100:.2f}% |",
        f"| **FPR** | {metrics['fpr']*100:.2f}% |",
        f"| **FNR** | {metrics['fnr']*100:.2f}% |",
        "",
        "## Confusion Matrix",
        "",
        "| | Predicted BENIGN | Predicted MALWARE |",
        "|---|---|---|",
        f"| **Actual BENIGN** | {metrics['tn']} (TN) | {metrics['fp']} (FP) |",
        f"| **Actual MALWARE** | {metrics['fn']} (FN) | {metrics['tp']} (TP) |",
        "",
    ]

    # Per-family analysis
    if family_analysis:
        lines.extend([
            "## Per-Family Detection Rates",
            "",
            "| Family | Total | Detected | Missed | Rate |",
            "|--------|-------|----------|--------|------|",
        ])
        for family, stats in family_analysis.items():
            rate_pct = f"{stats['detection_rate']*100:.1f}%"
            lines.append(
                f"| {family} | {stats['total']} | {stats['detected']} "
                f"| {stats['missed']} | {rate_pct} |"
            )
        lines.append("")

    # False positives (benign labelled as malware)
    fp_records = [r for r in records
                  if r.get("ground_truth") == "BENIGN" and r.get("prediction") == "MALWARE"]
    if fp_records:
        lines.extend([
            "## False Positives (Benign → Malware)",
            "",
            f"Total: {len(fp_records)} sample(s)",
            "",
        ])
        for r in fp_records[:10]:  # show first 10
            lines.append(f"- `{r['sha256'][:32]}...`")
        if len(fp_records) > 10:
            lines.append(f"- ... and {len(fp_records) - 10} more")
        lines.append("")

    # False negatives (malware labelled as benign)
    fn_records = [r for r in records
                  if r.get("ground_truth") == "MALWARE" and r.get("prediction") == "BENIGN"]
    if fn_records:
        lines.extend([
            "## False Negatives (Malware → Benign)",
            "",
            f"Total: {len(fn_records)} sample(s)",
            "",
        ])
        for r in fn_records[:10]:
            family = r.get("family", "unknown")
            lines.append(f"- `{r['sha256'][:32]}...` (family: {family})")
        if len(fn_records) > 10:
            lines.append(f"- ... and {len(fn_records) - 10} more")
        lines.append("")

    # LAMD paper comparison
    lines.extend([
        "## LAMD Paper Benchmark Comparison",
        "",
        "| Model | F1 | FPR | FNR |",
        "|-------|-----|-----|-----|",
        f"| **This Run** | **{metrics['f1']*100:.2f}%** | **{metrics['fpr']*100:.2f}%** | **{metrics['fnr']*100:.2f}%** |",
        "| LAMD (paper) | 90.24% | 1.26% | 8.44% |",
        "| Drebin | 81.33% | 0.40% | 24.21% |",
        "| DeepDrebin | 71.92% | 0.62% | 34.12% |",
        "| Malscan | 66.37% | 0.73% | 46.83% |",
        "",
    ])

    report_text = "\n".join(lines)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_text, encoding="utf-8")


# =============================================================================
#  Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate LAMD prediction results."
    )
    parser.add_argument(
        "--predictions", type=Path, required=True,
        help="Path to the predictions JSONL file."
    )
    parser.add_argument(
        "--report", type=Path, default=None,
        help="Output path for the markdown report (default: results/eval_report.md)."
    )
    args = parser.parse_args()

    pred_path = args.predictions
    if not pred_path.is_file():
        print(f"[ERROR] Predictions file not found: {pred_path}", file=sys.stderr)
        sys.exit(1)

    # ── Load predictions ──────────────────────────────────────────────────────
    print(f"[INFO] Loading predictions from: {pred_path.name}")
    records = []
    with open(pred_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    print(f"[INFO] {len(records)} prediction(s) loaded.")

    # ── Check if ground truth is available ────────────────────────────────────
    has_gt = all("ground_truth" in r for r in records)
    if not has_gt:
        print("[WARN] No ground_truth field found. Showing prediction distribution only.")
        preds = Counter(r.get("prediction", "UNKNOWN") for r in records)
        print(f"\n  Predictions: {dict(preds)}")
        print(f"  Total: {len(records)}")
        return

    # ── Compute metrics ───────────────────────────────────────────────────────
    y_true = [r["ground_truth"] for r in records]
    y_pred = [r["prediction"] for r in records]

    metrics = compute_metrics(y_true, y_pred)
    family_analysis = per_family_analysis(records)

    # ── Print results ─────────────────────────────────────────────────────────
    print()
    print("=" * 65)
    print("  LAMD Evaluation Results")
    print("=" * 65)
    print()
    print(f"  Total Samples  : {metrics['total']}")
    print(f"  Accuracy       : {metrics['accuracy']*100:.2f}%")
    print(f"  Precision      : {metrics['precision']*100:.2f}%")
    print(f"  Recall         : {metrics['recall']*100:.2f}%")
    print(f"  F1 Score       : {metrics['f1']*100:.2f}%")
    print(f"  FPR            : {metrics['fpr']*100:.2f}%")
    print(f"  FNR            : {metrics['fnr']*100:.2f}%")
    print()
    print("  Confusion Matrix:")
    print(f"    TP={metrics['tp']}  FN={metrics['fn']}")
    print(f"    FP={metrics['fp']}  TN={metrics['tn']}")
    print()

    if family_analysis:
        print("  Per-Family Detection Rates:")
        for family, stats in list(family_analysis.items())[:15]:
            rate = stats["detection_rate"] * 100
            bar = "█" * int(rate / 5) + "░" * (20 - int(rate / 5))
            print(f"    {family:<20s} {bar} {rate:5.1f}% "
                  f"({stats['detected']}/{stats['total']})")
        if len(family_analysis) > 15:
            print(f"    ... and {len(family_analysis) - 15} more families")
        print()

    # ── Generate report ───────────────────────────────────────────────────────
    report_path = args.report or (RESULTS_DIR / "eval_report.md")
    generate_report(metrics, family_analysis, records, report_path)
    print(f"  Full report saved to: {report_path}")
    print("=" * 65)


if __name__ == "__main__":
    main()
