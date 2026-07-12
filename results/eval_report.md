# LAMD Evaluation Report

## Overall Metrics

| Metric | Value |
|--------|-------|
| **Total Samples** | 10 |
| **Accuracy** | 90.00% |
| **Precision** | 83.33% |
| **Recall** | 100.00% |
| **F1 Score** | 90.91% |
| **FPR** | 20.00% |
| **FNR** | 0.00% |

## Confusion Matrix

| | Predicted BENIGN | Predicted MALWARE |
|---|---|---|
| **Actual BENIGN** | 4 (TN) | 1 (FP) |
| **Actual MALWARE** | 0 (FN) | 5 (TP) |

## Per-Family Detection Rates

| Family | Total | Detected | Missed | Rate |
|--------|-------|----------|--------|------|
| ouow | 1 | 1 | 0 | 100.0% |
| smspay | 1 | 1 | 0 | 100.0% |
| dowgin | 1 | 1 | 0 | 100.0% |
| kuguo | 1 | 1 | 0 | 100.0% |
| igexin | 1 | 1 | 0 | 100.0% |

## False Positives (Benign → Malware)

Total: 1 sample(s)

- `04e95c61e29007905ac6784c1680af6a...`

## LAMD Paper Benchmark Comparison

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| **This Run** | **90.91%** | **20.00%** | **0.00%** |
| LAMD (paper) | 90.24% | 1.26% | 8.44% |
| Drebin | 81.33% | 0.40% | 24.21% |
| DeepDrebin | 71.92% | 0.62% | 34.12% |
| Malscan | 66.37% | 0.73% | 46.83% |
