# LAMD Evaluation Report

## Overall Metrics

| Metric | Value |
|--------|-------|
| **Total Samples** | 82 |
| **Accuracy** | 63.41% |
| **Precision** | 87.50% |
| **Recall** | 33.33% |
| **F1 Score** | 48.28% |
| **FPR** | 5.00% |
| **FNR** | 66.67% |

## Confusion Matrix

| | Predicted BENIGN | Predicted MALWARE |
|---|---|---|
| **Actual BENIGN** | 38 (TN) | 2 (FP) |
| **Actual MALWARE** | 28 (FN) | 14 (TP) |

## Per-Family Detection Rates

| Family | Total | Detected | Missed | Rate |
|--------|-------|----------|--------|------|
| airpush | 7 | 1 | 6 | 14.3% |
| dowgin | 7 | 5 | 2 | 71.4% |
| dnotua | 4 | 0 | 4 | 0.0% |
| kuguo | 4 | 4 | 0 | 100.0% |
| anydown | 3 | 0 | 3 | 0.0% |
| feiwo | 2 | 2 | 0 | 100.0% |
| revmob | 2 | 0 | 2 | 0.0% |
| tencentprotect | 2 | 0 | 2 | 0.0% |
| unknown | 2 | 0 | 2 | 0.0% |
| buzztouch | 1 | 0 | 1 | 0.0% |
| smsreg | 1 | 0 | 1 | 0.0% |
| gappusin | 1 | 1 | 0 | 100.0% |
| metasploit | 1 | 1 | 0 | 100.0% |
| scamapp | 1 | 0 | 1 | 0.0% |
| deng | 1 | 0 | 1 | 0.0% |
| domob | 1 | 0 | 1 | 0.0% |
| hiddenad | 1 | 0 | 1 | 0.0% |
| ramnit | 1 | 0 | 1 | 0.0% |

## False Positives (Benign → Malware)

Total: 2 sample(s)

- `dc5ba2c3f8e6512a7c310ee05b08b667...`
- `6b8730f0aef2973c3b0a1ed491d83c16...`

## False Negatives (Malware → Benign)

Total: 28 sample(s)

- `db9f7a84ed0da4037532e80eab1ef380...` (family:  buzztouch)
- `36697239cd60917e0fdc992218e7cd64...` (family:  dnotua)
- `06a829b57f391f05aa679c6647992818...` (family:  airpush)
- `ac9af71e91406bfb1666239014f317dc...` (family:  dowgin)
- `244542e4f9cf2ef7c12ec050794f8165...` (family:  airpush)
- `87482cb504b8ac201f40b0648f2e4096...` (family:  anydown)
- `c6dac56eebefe7b6ecf57cbd5984207b...` (family:  dowgin)
- `87d08f2302952a5534b46f6c5b38919f...` (family:  revmob)
- `c7b0232db44382f2f5a3073445c57649...` (family:  tencentprotect)
- `d470fe0af4f3b5660f0cf82a03ed4345...` (family:  smsreg)
- ... and 18 more

## LAMD Paper Benchmark Comparison

| Model | F1 | FPR | FNR |
|-------|-----|-----|-----|
| **This Run** | **48.28%** | **5.00%** | **66.67%** |
| LAMD (paper) | 90.24% | 1.26% | 8.44% |
| Drebin | 81.33% | 0.40% | 24.21% |
| DeepDrebin | 71.92% | 0.62% | 34.12% |
| Malscan | 66.37% | 0.73% | 46.83% |
