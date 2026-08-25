# LAMD Evaluation Report

## Overall Metrics

| Metric | Value |
|--------|-------|
| **Total Samples** | 80 |
| **Accuracy** | 92.50% |
| **Precision** | 70.59% |
| **Recall** | 92.31% |
| **F1 Score** | 80.00% |
| **FPR** | 7.46% |
| **FNR** | 7.69% |
| **Unparsed (UNKNOWN)** | 0 (excluded from the metrics above, not counted as BENIGN) |

## Confusion Matrix

| | Predicted BENIGN | Predicted MALWARE |
|---|---|---|
| **Actual BENIGN** | 62 (TN) | 5 (FP) |
| **Actual MALWARE** | 1 (FN) | 12 (TP) |

## Per-Family Detection Rates

| Family | Total | Detected | Missed | Rate |
|--------|-------|----------|--------|------|
| fakeadblocker | 4 | 4 | 0 | 100.0% |
| artemis | 2 | 2 | 0 | 100.0% |
| rotexy | 2 | 2 | 0 | 100.0% |
| amaa | 1 | 0 | 1 | 0.0% |
| phishingapp | 1 | 1 | 0 | 100.0% |
| metasploit | 1 | 1 | 0 | 100.0% |
| dnotua | 1 | 1 | 0 | 100.0% |
| svpeng | 1 | 1 | 0 | 100.0% |

## False Positives (Benign → Malware)

Total: 5 sample(s)

- `ce0ce081a24c6b54282cdef365ee2219...`
- `01966ec5eae26bddc15515a8ca428175...`
- `f63c6e191589d439cfcc02b1b1f5f6e1...`
- `204560edb67103c4a7303e2660b5e07b...`
- `5d02615d1c49d1c39282c188aa46add8...`

## False Negatives (Malware → Benign)

Total: 1 sample(s)

- `3a690d77f0f1e65ddf1872d99ef3f916...` (family:  amaa)

## LAMD Paper Benchmark Comparison

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| **This Run** | **80.00%** | **7.46%** | **7.69%** |
| LAMD (paper) | 90.24% | 1.26% | 8.44% |
| Drebin | 81.33% | 0.40% | 24.21% |
| DeepDrebin | 71.92% | 0.62% | 34.12% |
| Malscan | 66.37% | 0.73% | 46.83% |
