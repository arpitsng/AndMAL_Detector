# LAMD Evaluation Report

## Overall Metrics

| Metric | Value |
|--------|-------|
| **Total Samples** | 3 |
| **Accuracy** | 33.33% |
| **Precision** | 0.00% |
| **Recall** | 0.00% |
| **F1 Score** | 0.00% |
| **FPR** | 66.67% |
| **FNR** | 0.00% |

## Confusion Matrix

| | Predicted BENIGN | Predicted MALWARE |
|---|---|---|
| **Actual BENIGN** | 1 (TN) | 2 (FP) |
| **Actual MALWARE** | 0 (FN) | 0 (TP) |

## False Positives (Benign → Malware)

Total: 2 sample(s)

- `019b62571b036cebe2e4568f74000e84...`
- `02855d27ac027f0c0a1c1935cc6a402f...`

## LAMD Paper Benchmark Comparison

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| **This Run** | **0.00%** | **66.67%** | **0.00%** |
| LAMD (paper) | 90.24% | 1.26% | 8.44% |
| Drebin | 81.33% | 0.40% | 24.21% |
| DeepDrebin | 71.92% | 0.62% | 34.12% |
| Malscan | 66.37% | 0.73% | 46.83% |
