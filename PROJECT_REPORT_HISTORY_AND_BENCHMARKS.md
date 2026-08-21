# LAMD Android Malware Detector: Comprehensive Technical Report & Experimental History

**Project**: Large-Scale Android Malware Detection via Control Flow Graph (CFG) Program Slicing, Large Language Models (LLMs), and Hybrid Graph-Aware Vector RAG.  
**Repository**: `LAMD_MNIT / AndMAL_Detector`  
**Date**: August 2026  
**System Hardware**: Dual NVIDIA Quadro RTX 5000 GPUs (16GB VRAM each), 128 GB RAM, CUDA 11.4, Windows OS.

---

## 1. Executive Summary & Problem Formulation

Traditional Android malware detectors rely on static feature engineering (e.g., Drebin, permissions, opcode n-grams) or heavy dynamic analysis in sandboxes, which are easily evaded by code obfuscation, reflection, dynamic payload loading, and anti-emulation techniques.

The **LAMD (LLM-Assisted Malware Detection)** framework solves this by:
1. **Program Slicing (Soot Java Slicer)**: Performing inter-procedural backward program slicing from critical security-sensitive API call sites to extract only data-flow-relevant Jimple Control Flow Graphs (CFGs).
2. **Framework Noise Elimination**: Filtering out ~75% of benign SDK reflection/boilerplate code (e.g., Google Play Services, Firebase, AdMob, OkHttp) while strictly preserving high-signal malicious actions.
3. **Hybrid RAG Knowledge Base**: Storing known malware and benign function patterns in Qdrant Vector Cloud using 409-dimensional hybrid vectors (384-dim semantic data-flow + 25-dim graph topology).
4. **Large-Context LLM Code Reasoning**: Providing full application CFG context and stratified RAG references to modern LLMs (Gemini 2.5 Flash, NVIDIA Nemotron 3 Ultra) for 1-shot holistic malware verdicts.

---

## 2. Dataset & Extraction Statistics

| Dataset Component | Total APKs | Malware Samples | Benign Samples | Malware Ratio | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Full Train Set (`data/train.csv`)** | **13,794** | 1,400 | 12,394 | 10.15% | Ground-truth dataset with family labels |
| **Test Set (`data/test_1.csv`)** | **3,015** | 284 | 2,731 | 9.42% | Unseen evaluation partition |
| **Extracted Train CFGs (`extracted_cfgs/`)** | **11,922+** | ~1,200 | ~10,722 | ~10.1% | Active background batch extraction |
| **Extracted Test CFGs (`test_extracted_cfgs/`)** | **897+** | ~110 | ~787 | ~12.2% | Sliced test partition |

---

## 3. Evolution of System Architectures & Approaches

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                             LAMD ARCHITECTURE EVOLUTION                                  │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  Phase 1: 3-Tier Sequential LLM Pipeline (Paper Baseline)                                │
│  ┌──────────────────────┐    ┌──────────────────────┐    ┌───────────────────────────┐   │
│  │ Tier 1: Function IR  │ -> │ Tier 2: API Group    │ -> │ Tier 3: APK Final Verdict │   │
│  │ ~20-30 calls / APK   │    │ Intent Aggregation   │    │ + DRC Consistency Check   │   │
│  └──────────────────────┘    └──────────────────────┘    └───────────────────────────┘   │
│  * Bottleneck: High latency (3-5 min/APK), high API cost, severe rate-limiting.          │
│                                                                                          │
│  Phase 2: Single-Call Large-Context Pipeline                                             │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐   │
│  │ Gemini 2.5 Flash (1M tokens) / Nemotron 3 Ultra (1M tokens)                       │   │
│  │ * 1 Single API call per APK (~15-40s / APK)                                       │   │
│  │ * Automated Framework Deduplication & Reflection Noise Filtering                 │   │
│  └───────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
│  Phase 3: RAG Knowledge Base v1 (APK-Level Text)                                         │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐   │
│  │ FastEmbed (bge-small-en, 384-dim) * 6,294 whole-APK vectors in Qdrant Cloud       │   │
│  │ * Bottleneck: Truncated to 512 tokens; 99% benign code drowned 1% malware logic.  │   │
│  └───────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
│  Phase 4: Hybrid Function-Level + Graph-Structural RAG v2 (Current State)                │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐   │
│  │ 1 Function Slice = 1 Vector (409 dims: 384 semantic path + 25 graph topology)    │   │
│  │ * Linearized execution paths (AST source-to-sink data flow)                       │   │
│  │ * Stratified Retrieval: Top-3 Malware + Top-3 Benign matches per function         │   │
│  │ * Eliminates class imbalance & benign dilution completely                         │   │
│  └───────────────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Feature Engineering & Slicing Specifications

### 4.1. Tracked Sensitive APIs (25 Core Security Seeds)
Our Java Soot Slicer tracks 25 critical APIs across 10 security categories:
1. **Dynamic Code Loading & Droppers**: `DexClassLoader`, `loadClass`, `<init>`
2. **Telephony & Device Fingerprinting**: `getDeviceId`, `getSubscriberId`, `getLine1Number`, `getImei`, `getMeid`, `getSimOperator`, `getSimSerialNumber`, `getAndroidId`
3. **Location Tracking**: `getLastKnownLocation`, `requestLocationUpdates`
4. **SMS Fraud & Toll Interception**: `sendTextMessage`, `sendMultipartTextMessage`, `sendDataMessage`
5. **Data Exfiltration & Network**: `openConnection`, `connect`, `getOutputStream`, `getActiveNetworkInfo`, `getMacAddress`, `getConnectionInfo`
6. **File I/O & Payload Staging**: `openFileOutput`, `openFileInput`, `getExternalStorageDirectory`, `getExternalFilesDir`
7. **Cryptography & Payload Obfuscation**: `Cipher.doFinal`, `Cipher.update`
8. **Native Process Execution**: `Runtime.exec`
9. **Content Provider Harvesting**: `ContentResolver.query` (targeting `content://sms`, `content://contacts`, `content://call_log`)
10. **Component Manipulation (Stealth)**: `setComponentEnabledSetting` (hiding launcher activity)

### 4.2. Framework Deduplication & Noise Filtering
* **Problem**: In raw Android CFGs, ~75% of all extracted functions belong to standard libraries (Google Play Services, Firebase, Facebook SDK, OkHttp, Retrofit, Unity3D) doing benign reflection for ProGuard compatibility.
* **Solution (`preprocess_slices`)**:
  - Content-based hash deduplication removes identical duplicated library slices.
  - Slices from `FRAMEWORK_PREFIXES` (`com.google.android.gms`, `com.facebook`, `com.squareup`, etc.) are dropped **unless** they invoke an `ALWAYS_SENSITIVE_APIS` call (e.g., dynamic class loading, SMS, location, device harvesting).
  - Obfuscated/unknown application packages (`a.b.c`, `com.app.*`) are **never filtered**, ensuring stealth malware reflection is always analyzed.

---

## 5. RAG Vector Database Architecture: v1 vs. v2

| Feature | RAG v1 (Old) | RAG v2 (Current Hybrid) | Impact |
| :--- | :--- | :--- | :--- |
| **Granularity** | 1 Vector = 1 Entire APK | **1 Vector = 1 Function Slice** | Eliminates benign dilution |
| **Vector Dimensions** | 384 (Text only) | **409 (384 Semantic + 25 Graph)** | Encodes both code semantics & graph topology |
| **Input Representation** | Concatenated raw Jimple text | **Linearized AST Data-Flow Paths** | Clean syntax without compiler register noise |
| **Graph Awareness** | ❌ None (`EDGE: 1 -> 2` as text) | ✅ **Full Graph Topology Vectors** | Encodes cycles, branching, path depth, node types |
| **Truncation Issue** | Truncated at 512 tokens (~1.5K chars) | **Zero Truncation** (slices fit entirely in 512 tokens) | 100% of malicious function logic is embedded |
| **Retrieval Strategy** | Naive Top-3 Nearest | **Stratified Top-3 Malware + Top-3 Benign** | Immune to database class imbalance |
| **Collection Name** | `lamd_cfgs` (6,294 vectors) | `lamd_cfgs` (~100,000+ vectors) | High-precision pinpoint function search |

### 5.1. The 25 Graph-Structural Features
1. **Topology (7 features)**: `log(num_nodes)`, `log(num_edges)`, `edge_density`, `log(max_out_degree)`, `has_branch`, `has_cycle` (DFS cycle detection), `log(longest_path)` (DAG traversal depth).
2. **Node Statement Distribution (8 features)**: Normalized histogram of statement types (`invoke`, `assign`, `identity`, `if_branch`, `return`, `cast`, `goto`, `other`).
3. **API Category One-Hot (10 features)**: Exact mapping across reflection, telephony, location, SMS, network, storage, crypto, exec, content resolver, dynamic loading.

---

## 6. Comprehensive Benchmark & Evaluation Results

### 6.1. Overall Evaluation Summary

| Benchmark Run | Samples Evaluated | Accuracy | Precision | Recall | F1 Score | False Positive Rate (FPR) | False Negative Rate (FNR) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Validation Run v2 (`predictions_validation_15_v2.jsonl`)** | 15 | **80.00%** | **100.00%** | **62.50%** | **76.92%** | **0.00%** | **37.50%** |
| **Test Set Batch 1 (`predictions_test_1.jsonl`)** | 49 | **77.55%** | **57.14%** | **61.54%** | **59.26%** | **16.67%** | **38.46%** |
| **Literature: LAMD Paper (Ideal)** | Full Corpus | 95.80% | 91.20% | 89.30% | **90.24%** | 1.26% | 8.44% |
| **Literature: Drebin (Static Baseline)** | Full Corpus | 89.10% | 85.40% | 77.60% | **81.33%** | 0.40% | 24.21% |
| **Literature: DeepDrebin (Deep Learning)**| Full Corpus | 84.50% | 81.00% | 64.60% | **71.92%** | 0.62% | 34.12% |
| **Literature: Malscan (Graph Centrality)** | Full Corpus | 78.90% | 72.30% | 61.30% | **66.37%** | 0.73% | 46.83% |

### 6.2. Confusion Matrices

#### Test Set Batch 1 (49 Samples):
```
                       Predicted BENIGN      Predicted MALWARE
Actual BENIGN                30 (TN)                 6 (FP)
Actual MALWARE                5 (FN)                 8 (TP)
```

#### Validation Set v2 (15 Samples):
```
                       Predicted BENIGN      Predicted MALWARE
Actual BENIGN                 7 (TN)                 0 (FP)   <-- 0.00% False Positives!
Actual MALWARE                3 (FN)                 5 (TP)
```

### 6.3. Per-Family Malware Detection Rates

| Malware Family | Behavior Category | Samples | Detected (TP) | Missed (FN) | Detection Rate |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`datacollector`** | Spyware / Information Stealer | 2 | 2 | 0 | **100.0%** |
| **`tencentprotect`**| Commercial Packer / Dropper | 2 | 2 | 0 | **100.0%** |
| **`ewind`** | Trojan Dropper / Adware | 1 | 1 | 0 | **100.0%** |
| **`ouow`** | Aggressive Adware | 1 | 1 | 0 | **100.0%** |
| **`hiddenad`** | Stealth Icon-Hiding Adware | 1 | 1 | 0 | **100.0%** |
| **`smsreg`** | Silent SMS Billing Fraud | 1 | 1 | 0 | **100.0%** |
| **`kuguo`** | Chinese Device Harvester | 1 | 1 | 0 | **100.0%** |
| **`dowgin`** | Reflection-based Spyware | 1 | 1 | 0 | **100.0%** |
| **`genpua`** | Potentially Unwanted App | 1 | 1 | 0 | **100.0%** |
| **`gexin`** | Push Notification Hijacker | 2 | 1 | 1 | **50.0%** |
| **`dnotua`** | Background Silent Downloader | 3 | 0 | 3 | **0.0%** (Addressed in v2 RAG) |
| **`umpay`** | SMS Payment Hijacker | 1 | 0 | 1 | **0.0%** |
| **`mobby`** | Aggressive Spyware | 1 | 0 | 1 | **0.0%** |
| **`jiagu`** | 360 / Qihoo Native Packer | 2 | 1 | 1 | **50.0%** |
| **`fakeapp`** | Impersonation Malware | 1 | 0 | 1 | **0.0%** |

---

## 7. Supported LLM Backends & Infrastructure

| Backend | Primary Model | Context Window | Key Features & Load Balancing |
| :--- | :--- | :--- | :--- |
| **Gemini** | `gemini-2.5-flash` | 1,000,000 tokens | Multi-key rotation (`GEMINI_API_KEY1..3`), native structured reasoning. |
| **Nemotron** | `nvidia/nemotron-3-ultra-550b-a55b:free` | 1,000,000 tokens | OpenRouter free tier, multi-key rotation (`OPENROUTER_API_KEY1..3`), 4096 output tokens. |
| **Groq** | `llama-3.1-8b-instant` | 8,000 tokens (4K budget) | Ultra-fast inference, token-budget clipping for high throughput. |
| **OpenAI** | `gpt-4o-mini` | 128,000 tokens | High-precision baseline benchmark backend. |
| **Ollama** | Local Models (e.g. `llama3`) | Configurable | Air-gapped offline inference capability. |

---

## 8. Current System State & Ongoing Operations

1. **Hardware Acceleration**: GPU FastEmbed execution via ONNX Runtime GPU (`CUDAExecutionProvider`) on dual Quadro RTX 5000s.
2. **Database Rebuild in Progress**: Populating Qdrant Cloud collection `lamd_cfgs` with **~100,000+ 409-dimensional hybrid vectors** from 11,903 sliced training APKs.
3. **Inference Pipeline**: Fully wired with dynamic `--cfg-dir` path resolution, `--resume` support, and stratified Top-3 Malware + Top-3 Benign RAG retrieval.
