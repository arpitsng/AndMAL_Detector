# LAMD Evaluation Report

## Overall Metrics

| Metric | Value |
|--------|-------|
| **Total Samples** | 199 |
| **Accuracy** | 89.45% |
| **Precision** | 64.91% |
| **Recall** | 97.37% |
| **F1 Score** | 77.89% |
| **FPR** | 12.42% |
| **FNR** | 2.63% |
| **Unparsed (UNKNOWN)** | 0 (excluded from the metrics above, not counted as BENIGN) |

## Confusion Matrix

| | Predicted BENIGN | Predicted MALWARE |
|---|---|---|
| **Actual BENIGN** | 141 (TN) | 20 (FP) |
| **Actual MALWARE** | 1 (FN) | 37 (TP) |

## Per-Family Detection Rates

| Family | Total | Detected | Missed | Rate |
|--------|-------|----------|--------|------|
| dnotua | 23 | 23 | 0 | 100.0% |
| fakeadblocker | 4 | 4 | 0 | 100.0% |
| rotexy | 4 | 4 | 0 | 100.0% |
| artemis | 2 | 2 | 0 | 100.0% |
| amaa | 1 | 0 | 1 | 0.0% |
| phishingapp | 1 | 1 | 0 | 100.0% |
| metasploit | 1 | 1 | 0 | 100.0% |
| svpeng | 1 | 1 | 0 | 100.0% |
| tencentprotect | 1 | 1 | 0 | 100.0% |

## False Positives (Benign → Malware)

Total: 20 sample(s)

- `5d02615d1c49d1c39282c188aa46add8...`
- `f12651a9ef37143c641f360b0af1b596...`
- `dc4cdad89f47977eb628f1ed302f54f0...`
- `45b30b655c55dd3c2d1dd7f77c782779...`
- `6fc953acb3e90d89e07cb35226956d14...`
- `83790b92c9f1c7981a7769d0d60c581e...`
- `28793c6bcc658f5030e9e23f4b15e58d...`
- `a56e62bacc7825253bba9e8c42068206...`
- `240424b45ec23ce5c4e9efb4935aab22...`
- `e40d1c6c4121a538469229093f351c52...`
- ... and 10 more

## False Negatives (Malware → Benign)

Total: 1 sample(s)

- `3a690d77f0f1e65ddf1872d99ef3f916...` (family:  amaa)

## LAMD Paper Benchmark Comparison

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| **This Run** | **77.89%** | **12.42%** | **2.63%** |
| LAMD (paper) | 90.24% | 1.26% | 8.44% |
| Drebin | 81.33% | 0.40% | 24.21% |
| DeepDrebin | 71.92% | 0.62% | 34.12% |
| Malscan | 66.37% | 0.73% | 46.83% |
