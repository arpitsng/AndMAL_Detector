# LAMD Evaluation Report

## Overall Metrics

| Metric | Value |
|--------|-------|
| **Total Samples** | 10 |
| **Accuracy** | 80.00% |
| **Precision** | 100.00% |
| **Recall** | 60.00% |
| **F1 Score** | 75.00% |
| **FPR** | 0.00% |
| **FNR** | 40.00% |

## Confusion Matrix

| | Predicted BENIGN | Predicted MALWARE |
|---|---|---|
| **Actual BENIGN** | 5 (TN) | 0 (FP) |
| **Actual MALWARE** | 2 (FN) | 3 (TP) |

## Per-Family Detection Rates

| Family | Total | Detected | Missed | Rate |
|--------|-------|----------|--------|------|
| ouow | 1 | 1 | 0 | 100.0% |
| smspay | 1 | 0 | 1 | 0.0% |
| dowgin | 1 | 0 | 1 | 0.0% |
| kuguo | 1 | 1 | 0 | 100.0% |
| igexin | 1 | 1 | 0 | 100.0% |

## False Negatives (Malware → Benign)

Total: 2 sample(s)

- `292a87235ced592d13ea36891800608a...` (family: smspay)
- `eff9c95689f004ecf37e54a90d25ef39...` (family: dowgin)

## LAMD Paper Benchmark Comparison

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| **This Run** | **75.00%** | **0.00%** | **40.00%** |
| LAMD (paper) | 90.24% | 1.26% | 8.44% |
| Drebin | 81.33% | 0.40% | 24.21% |
| DeepDrebin | 71.92% | 0.62% | 34.12% |
| Malscan | 66.37% | 0.73% | 46.83% |
