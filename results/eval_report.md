# LAMD Evaluation Report

## Overall Metrics

| Metric | Value |
|--------|-------|
| **Total Samples** | 133 |
| **Accuracy** | 78.20% |
| **Precision** | 14.71% |
| **Recall** | 100.00% |
| **F1 Score** | 25.64% |
| **FPR** | 22.66% |
| **FNR** | 0.00% |

## Confusion Matrix

| | Predicted BENIGN | Predicted MALWARE |
|---|---|---|
| **Actual BENIGN** | 99 (TN) | 29 (FP) |
| **Actual MALWARE** | 0 (FN) | 5 (TP) |

## Per-Family Detection Rates

| Family | Total | Detected | Missed | Rate |
|--------|-------|----------|--------|------|
| dnotua | 5 | 5 | 0 | 100.0% |

## False Positives (Benign → Malware)

Total: 29 sample(s)

- `dc4cdad89f47977eb628f1ed302f54f0...`
- `f70f7a688736d577b0201cda4f6b9cac...`
- `2342bc12adfe9a36c303f392cfc73477...`
- `80cc211a2c89de2366ec1b556b5de8d2...`
- `c689999b0a2b5b376a2c7394871d6902...`
- `d42b608fd4ab3fd57a83cd4f05429397...`
- `842dd13dda0f4286bcfad53c4674f64f...`
- `655df5bca367dc18c66e0fa6181226b7...`
- `07387f103ddadbaa7f4d1f447506d284...`
- `0a0872ffb06e8f93da11fc18e8de21c1...`
- ... and 19 more

## LAMD Paper Benchmark Comparison

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| **This Run** | **25.64%** | **22.66%** | **0.00%** |
| LAMD (paper) | 90.24% | 1.26% | 8.44% |
| Drebin | 81.33% | 0.40% | 24.21% |
| DeepDrebin | 71.92% | 0.62% | 34.12% |
| Malscan | 66.37% | 0.73% | 46.83% |
