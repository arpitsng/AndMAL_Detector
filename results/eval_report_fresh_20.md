# LAMD Evaluation Report

## Overall Metrics

| Metric | Value |
|--------|-------|
| **Total Samples** | 20 |
| **Accuracy** | 70.00% |
| **Precision** | 64.29% |
| **Recall** | 90.00% |
| **F1 Score** | 75.00% |
| **FPR** | 50.00% |
| **FNR** | 10.00% |
| **Unparsed (UNKNOWN)** | 0 (excluded from the metrics above, not counted as BENIGN) |

## Confusion Matrix

| | Predicted BENIGN | Predicted MALWARE |
|---|---|---|
| **Actual BENIGN** | 5 (TN) | 5 (FP) |
| **Actual MALWARE** | 1 (FN) | 9 (TP) |

## Per-Family Detection Rates

| Family | Total | Detected | Missed | Rate |
|--------|-------|----------|--------|------|
| geinimi | 2 | 2 | 0 | 100.0% |
| ewind | 2 | 1 | 1 | 50.0% |
| multiverze | 1 | 1 | 0 | 100.0% |
| fakeadblocker | 1 | 1 | 0 | 100.0% |
| tencentprotect | 1 | 1 | 0 | 100.0% |
| commplat | 1 | 1 | 0 | 100.0% |
| svpeng | 1 | 1 | 0 | 100.0% |
| smsreg | 1 | 1 | 0 | 100.0% |

## False Positives (Benign → Malware)

Total: 5 sample(s)

- `85ed56e80c0171612c43029d5ce61ed5...`
- `70dbd9169b30b44f0c02909353273615...`
- `2a3b236a8d38db8495944757389d2d77...`
- `be4e7bdafb2b19f874e9c53a6edd3191...`
- `e730dcd23ad3418fded9ae7e65330ffb...`

## False Negatives (Malware → Benign)

Total: 1 sample(s)

- `cdfbd148130e98026c563dcd843880c3...` (family:  ewind)

## LAMD Paper Benchmark Comparison

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| **This Run** | **75.00%** | **50.00%** | **10.00%** |
| LAMD (paper) | 90.24% | 1.26% | 8.44% |
| Drebin | 81.33% | 0.40% | 24.21% |
| DeepDrebin | 71.92% | 0.62% | 34.12% |
| Malscan | 66.37% | 0.73% | 46.83% |
