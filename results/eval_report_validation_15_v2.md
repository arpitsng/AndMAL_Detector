# LAMD Evaluation Report

## Overall Metrics

| Metric | Value |
|--------|-------|
| **Total Samples** | 15 |
| **Accuracy** | 80.00% |
| **Precision** | 100.00% |
| **Recall** | 62.50% |
| **F1 Score** | 76.92% |
| **FPR** | 0.00% |
| **FNR** | 37.50% |

## Confusion Matrix

| | Predicted BENIGN | Predicted MALWARE |
|---|---|---|
| **Actual BENIGN** | 7 (TN) | 0 (FP) |
| **Actual MALWARE** | 3 (FN) | 5 (TP) |

## Per-Family Detection Rates

| Family | Total | Detected | Missed | Rate |
|--------|-------|----------|--------|------|
| dnotua | 3 | 0 | 3 | 0.0% |
| kuguo | 1 | 1 | 0 | 100.0% |
| dowgin | 1 | 1 | 0 | 100.0% |
| genpua | 1 | 1 | 0 | 100.0% |
| tencentprotect | 1 | 1 | 0 | 100.0% |
| jiagu | 1 | 1 | 0 | 100.0% |

## False Negatives (Malware → Benign)

Total: 3 sample(s)

- `50a440e0b42c8d25714eadde26d89c1c...` (family:  dnotua)
- `42b9ce68aa1c1ace3a96d3b9dc164703...` (family:  dnotua)
- `2930e31085798a592c629093795af552...` (family:  dnotua)

## LAMD Paper Benchmark Comparison

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| **This Run** | **76.92%** | **0.00%** | **37.50%** |
| LAMD (paper) | 90.24% | 1.26% | 8.44% |
| Drebin | 81.33% | 0.40% | 24.21% |
| DeepDrebin | 71.92% | 0.62% | 34.12% |
| Malscan | 66.37% | 0.73% | 46.83% |
