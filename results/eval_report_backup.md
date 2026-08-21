# LAMD Evaluation Report

## Overall Metrics

| Metric | Value |
|--------|-------|
| **Total Samples** | 49 |
| **Accuracy** | 77.55% |
| **Precision** | 57.14% |
| **Recall** | 61.54% |
| **F1 Score** | 59.26% |
| **FPR** | 16.67% |
| **FNR** | 38.46% |

## Confusion Matrix

| | Predicted BENIGN | Predicted MALWARE |
|---|---|---|
| **Actual BENIGN** | 30 (TN) | 6 (FP) |
| **Actual MALWARE** | 5 (FN) | 8 (TP) |

## Per-Family Detection Rates

| Family | Total | Detected | Missed | Rate |
|--------|-------|----------|--------|------|
| gexin | 2 | 1 | 1 | 50.0% |
| datacollector | 2 | 2 | 0 | 100.0% |
| umpay | 1 | 0 | 1 | 0.0% |
| tencentprotect | 1 | 1 | 0 | 100.0% |
| mobby | 1 | 0 | 1 | 0.0% |
| ewind | 1 | 1 | 0 | 100.0% |
| ouow | 1 | 1 | 0 | 100.0% |
| jiagu | 1 | 0 | 1 | 0.0% |
| hiddenad | 1 | 1 | 0 | 100.0% |
| smsreg | 1 | 1 | 0 | 100.0% |
| fakeapp | 1 | 0 | 1 | 0.0% |

## False Positives (Benign → Malware)

Total: 6 sample(s)

- `6c4445a609c71afdf2a4c025344aaa23...`
- `04d9d34a88a16f520fcc1f04349ea260...`
- `a30ce11361090adaac081395bab8b5e9...`
- `bb9153cfd7f215352e7c222a98fc872b...`
- `d0c696f42d8c72c45935ed393b26d940...`
- `389e4837fc12becf636b7b3cf43a8284...`

## False Negatives (Malware → Benign)

Total: 5 sample(s)

- `a5691dbb9e71fa5482111a1c85088363...` (family:  umpay)
- `45147a1482968d8dc14471fff057235d...` (family:  gexin)
- `c47fac9ca0654679f5680e878df2189b...` (family:  mobby)
- `8fa35f05c5a2e1149301c2f6aaae5528...` (family:  jiagu)
- `76bc31138e0c919a90ee8ba61670cf92...` (family:  fakeapp)

## LAMD Paper Benchmark Comparison

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| **This Run** | **59.26%** | **16.67%** | **38.46%** |
| LAMD (paper) | 90.24% | 1.26% | 8.44% |
| Drebin | 81.33% | 0.40% | 24.21% |
| DeepDrebin | 71.92% | 0.62% | 34.12% |
| Malscan | 66.37% | 0.73% | 46.83% |
