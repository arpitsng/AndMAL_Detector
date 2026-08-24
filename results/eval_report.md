# LAMD Evaluation Report

## Overall Metrics

| Metric | Value |
|--------|-------|
| **Total Samples** | 58 |
| **Accuracy** | 96.55% |
| **Precision** | 0.00% |
| **Recall** | 0.00% |
| **F1 Score** | 0.00% |
| **FPR** | 0.00% |
| **FNR** | 100.00% |

## Confusion Matrix

| | Predicted BENIGN | Predicted MALWARE |
|---|---|---|
| **Actual BENIGN** | 56 (TN) | 0 (FP) |
| **Actual MALWARE** | 2 (FN) | 0 (TP) |

## Per-Family Detection Rates

| Family | Total | Detected | Missed | Rate |
|--------|-------|----------|--------|------|
| dnotua | 2 | 0 | 2 | 0.0% |

## False Negatives (Malware → Benign)

Total: 2 sample(s)

- `142703321f384e1a46bf90f9ecc3d48f...` (family:  dnotua)
- `d6489fb1ab117b7f655ab95d91a51b5f...` (family:  dnotua)

## LAMD Paper Benchmark Comparison

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| **This Run** | **0.00%** | **0.00%** | **100.00%** |
| LAMD (paper) | 90.24% | 1.26% | 8.44% |
| Drebin | 81.33% | 0.40% | 24.21% |
| DeepDrebin | 71.92% | 0.62% | 34.12% |
| Malscan | 66.37% | 0.73% | 46.83% |
