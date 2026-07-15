# LAMD Evaluation Report

## Overall Metrics

| Metric | Value |
|--------|-------|
| **Total Samples** | 18 |
| **Accuracy** | 77.78% |
| **Precision** | 100.00% |
| **Recall** | 60.00% |
| **F1 Score** | 75.00% |
| **FPR** | 0.00% |
| **FNR** | 40.00% |

## Confusion Matrix

| | Predicted BENIGN | Predicted MALWARE |
|---|---|---|
| **Actual BENIGN** | 8 (TN) | 0 (FP) |
| **Actual MALWARE** | 4 (FN) | 6 (TP) |

## Per-Family Detection Rates

| Family | Total | Detected | Missed | Rate |
|--------|-------|----------|--------|------|
| airpush | 3 | 3 | 0 | 100.0% |
| kuguo | 2 | 2 | 0 | 100.0% |
| buzztouch | 1 | 1 | 0 | 100.0% |
| dnotua | 1 | 0 | 1 | 0.0% |
| dowgin | 1 | 0 | 1 | 0.0% |
| anydown | 1 | 0 | 1 | 0.0% |
| feiwo | 1 | 0 | 1 | 0.0% |

## False Negatives (Malware → Benign)

Total: 4 sample(s)

- `36697239cd60917e0fdc992218e7cd64...` (family:  dnotua)
- `ac9af71e91406bfb1666239014f317dc...` (family:  dowgin)
- `87482cb504b8ac201f40b0648f2e4096...` (family:  anydown)
- `63beac3347db71a61e180bb4485b4fc6...` (family:  feiwo)

## LAMD Paper Benchmark Comparison

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| **This Run** | **75.00%** | **0.00%** | **40.00%** |
| LAMD (paper) | 90.24% | 1.26% | 8.44% |
| Drebin | 81.33% | 0.40% | 24.21% |
| DeepDrebin | 71.92% | 0.62% | 34.12% |
| Malscan | 66.37% | 0.73% | 46.83% |
