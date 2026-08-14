# LAMD Evaluation Report

## Overall Metrics

| Metric | Value |
|--------|-------|
| **Total Samples** | 60 |
| **Accuracy** | 78.33% |
| **Precision** | 61.11% |
| **Recall** | 64.71% |
| **F1 Score** | 62.86% |
| **FPR** | 16.28% |
| **FNR** | 35.29% |

## Confusion Matrix

| | Predicted BENIGN | Predicted MALWARE |
|---|---|---|
| **Actual BENIGN** | 36 (TN) | 7 (FP) |
| **Actual MALWARE** | 6 (FN) | 11 (TP) |

## Per-Family Detection Rates

| Family | Total | Detected | Missed | Rate |
|--------|-------|----------|--------|------|
| tencentprotect | 4 | 4 | 0 | 100.0% |
| gexin | 3 | 0 | 3 | 0.0% |
| smsreg | 2 | 1 | 1 | 50.0% |
| ewind | 2 | 1 | 1 | 50.0% |
| ouow | 2 | 2 | 0 | 100.0% |
| kyfr | 1 | 1 | 0 | 100.0% |
| umpay | 1 | 1 | 0 | 100.0% |
| mobby | 1 | 0 | 1 | 0.0% |
| artemis | 1 | 1 | 0 | 100.0% |

## False Positives (Benign → Malware)

Total: 7 sample(s)

- `1d8711623f2a1a4febcf8228710f1e6a...`
- `04d9d34a88a16f520fcc1f04349ea260...`
- `51aec9d24fdfdca81ebc841ec2ac9907...`
- `d0c696f42d8c72c45935ed393b26d940...`
- `389e4837fc12becf636b7b3cf43a8284...`
- `6fc953acb3e90d89e07cb35226956d14...`
- `d7f3b5452c693b30396c5a4f663cfb4b...`

## False Negatives (Malware → Benign)

Total: 6 sample(s)

- `45147a1482968d8dc14471fff057235d...` (family: gexin)
- `a34dfe68cb6391ddb4aa634308353e4f...` (family: gexin)
- `c47fac9ca0654679f5680e878df2189b...` (family: mobby)
- `181c481d413988035e16c14a89376367...` (family: ewind)
- `79058796590225377c0c478f6c1f46de...` (family: smsreg)
- `1f55015446a5fc98ebb9206097cc88b5...` (family: gexin)

## LAMD Paper Benchmark Comparison

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| **This Run** | **62.86%** | **16.28%** | **35.29%** |
| LAMD (paper) | 90.24% | 1.26% | 8.44% |
| Drebin | 81.33% | 0.40% | 24.21% |
| DeepDrebin | 71.92% | 0.62% | 34.12% |
| Malscan | 66.37% | 0.73% | 46.83% |
