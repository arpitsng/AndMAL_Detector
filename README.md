# AndMAL_Detector
### Context-Driven Android Malware Detection via Hierarchical Graph-Connected LLM Reasoning

AndMAL_Detector is a static analysis and Large Language Model (LLM) reasoning framework for automated Android malware detection. By extracting backward-sliced Control Flow Graphs (Jimple IR) from sensitive API invocations and evaluating them through hierarchical graph-connected reasoning (HBCR), the system determines application intent from verifiable data flows rather than static signatures.

---

## 1. Overview and Problem Statement

Traditional signature-based and static heuristic malware detectors struggle against modern obfuscated Android threats. Common limitations include:
1. **High False Positive Rates**: Benign applications utilizing standard framework reflection or native libraries (Android NDK) are frequently misidentified as malicious droppers.
2. **Context Fragmentation**: Naive code slicing often isolates caller-callee chains across arbitrary boundaries, causing LLMs to miss multi-stage payload delivery mechanisms.
3. **Evasion via Namespace Spoofing**: Malware families (such as `dnotua`) conceal payload loading routines within dummy Google Play Services SDK packages (`com.google.android.gms.internal.*`).

AndMAL_Detector addresses these challenges through a three-stage pipeline:
- **Static Backward Program Slicing**: Extracts precise data- and control-dependency graphs leading to sensitive API call sites using the Soot framework.
- **Hierarchical Graph-Connected Reasoning (HBCR)**: Preserves call chains and shared-resource dependencies (crypto keys, file paths, dynamic class targets) through graph partitioning and recursive bisection.
- **Calibrated Semantic Intent Analysis**: Employs domain-specific decision boundaries to distinguish legitimate framework operations from malicious payloads.

---

## 2. System Architecture

```
[Android APK Binary]
         │
         ▼
[Phase 1: Static Analysis & Backward Slicing (Soot)]
 ├── Decompilation to Jimple Intermediate Representation (IR)
 ├── Detection of sensitive API invocation seeds (telephony, reflection, crypto, SMS, execution)
 └── Backward program slicing -> Function Call Graphs (FCGs) & CFG Slices
         │
         ▼
[Phase 2: Hierarchical Graph-Connected Reasoning (HBCR)]
 ├── Token Budget Evaluation
 ├── Connectivity Graph Construction (Caller-Callee & Shared Resource Edges)
 ├── Subsystem Decomposition (Clusters C1 ... Cn)
 └── Global Threat Synthesis (Cross-Cluster Interaction Analysis)
         │
         ▼
[Phase 3: Multi-Backend Inference Engine]
 ├── Local Dual-GPU Acceleration (Qwen 2.5 32B via 50/50 CUDA Tensor Splitting)
 └── Cloud Backends (Google Gemini, OpenAI, Groq)
         │
         ▼
[Phase 4: Evaluation & Reporting]
 └── Precision, Recall, F1 Score, Confusion Matrix, Per-Family Breakdown
```

---

## 3. Empirical Evaluation

The pipeline was evaluated on a benchmark of 199 Android applications comprising both benign apps and confirmed malware samples across multiple families.

### Overall Benchmark Metrics
| Metric | Value | Baseline Comparison |
|:---|:---:|:---:|
| **Total Evaluated Samples** | **199** | — |
| **Accuracy** | **89.45%** | +35.68% *(vs. 53.77% baseline)* |
| **Precision** | **64.91%** | +42.34% *(vs. 22.57% baseline)* |
| **Recall (Sensitivity)** | **97.37%** | +31.58% *(vs. 65.79% baseline)* |
| **F1 Score** | **77.89%** | +44.24% *(vs. 33.65% baseline)* |
| **False Positive Rate (FPR)** | **12.42%** | Reduced from 48.45% |
| **False Negative Rate (FNR)** | **2.63%** | Reduced from 34.21% |

### Confusion Matrix
| Ground Truth | Predicted BENIGN | Predicted MALWARE | Total |
|:---|:---:|:---:|:---:|
| **Actual BENIGN** | **141** (True Negative) | **20** (False Positive) | 161 |
| **Actual MALWARE** | **1** (False Negative) | **37** (True Positive) | 38 |
| **Total** | 142 | 57 | 199 |

### Per-Family Detection Breakdown
| Malware Family | Detected / Total | Detection Rate | Primary Characteristic |
|:---|:---:|:---:|:---|
| **dnotua** | 23 / 23 | 100.0% | Trojan dropper disguised within spoofed GMS classes |
| **fakeadblocker** | 4 / 4 | 100.0% | Adware fraud and stealth background execution |
| **rotexy** | 4 / 4 | 100.0% | Banking trojan with intercepted SMS verification |
| **artemis** | 2 / 2 | 100.0% | Trojan backdoor |
| **phishingapp** | 1 / 1 | 100.0% | Credential interception |
| **metasploit** | 1 / 1 | 100.0% | Meterpreter reverse shell payload |
| **svpeng** | 1 / 1 | 100.0% | Device-locking ransomware / credential theft |
| **tencentprotect** | 1 / 1 | 100.0% | Obfuscated application wrapper |
| **amaa** | 0 / 1 | 0.0% | Web-based wrapper service |

---

## 4. Setup and Installation

### Prerequisites
- Python 3.10 or 3.11
- Java Development Kit (JDK) 11 or 17
- NVIDIA GPU with CUDA 12+ (optional, for local dual-GPU 32B model inference)

### Installation
```bash
git clone https://github.com/arpitsng/AndMAL_Detector.git
cd AndMAL_Detector

python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### Configuration (`.env`)
Create a `.env` file in the root directory:
```ini
# AndroZoo API Key (for downloading raw APKs)
ANDROZOO_API_KEY=your_key_here

# Cloud LLM Backends (Optional)
GEMINI_API_KEY1=your_gemini_key_1
GEMINI_API_KEY2=your_gemini_key_2
GEMINI_API_KEY3=your_gemini_key_3
OPENAI_API_KEY=sk-...
GROQ_API_KEY=gsk-...

# Qdrant Vector Database (For RAG few-shot retrieval)
QDRANT_URL=https://your-cluster.qdrant.io
QDRANT_API_KEY=your_qdrant_key
```

---

## 5. Execution Pipeline

### Step 1: Static Analysis and CFG Extraction
Decompile APKs and extract backward-sliced Control Flow Graphs for suspicious APIs:
```bash
python src_python/2_extract_cfg.py --csv data/test_1.csv --limit 10
```

### Step 2: LLM Inference

#### Local Dual-GPU Inference (Qwen 2.5 32B via GGUF CUDA)
```bash
python src_python/4_llm_inference.py --mode cfg --backend gguf --single --csv data/test_1.csv --cfg-dir extracted_cfgs --output results/predictions.jsonl
```

#### Cloud LLM Inference (Google Gemini)
```bash
python src_python/4_llm_inference.py --mode cfg --backend gemini --single --csv data/test_1.csv --cfg-dir extracted_cfgs --output results/predictions.jsonl
```

### Step 3: Evaluation and Metric Generation
```bash
python src_python/5_evaluate.py --predictions results/predictions.jsonl
```

### Step 4: Interactive Threat Analysis Server
```bash
python src_python/9_chatbot_server.py
```
Access the analysis interface at `http://localhost:8765`.

---

## 6. Repository Structure

```
AndMAL_Detector/
├── Slicer/                     # Java Soot static slicer source code
├── data/                       # Dataset manifests and metadata
├── results/
│   ├── eval_report.md          # Official evaluation metrics and confusion matrix
│   └── predictions.jsonl       # Full benchmark predictions with chain-of-thought analysis
├── src_python/
│   ├── 1_download_apk.py       # Automated APK downloader
│   ├── 2_extract_cfg.py        # Static slicing manager
│   ├── 3_build_dataset.py      # Dataset assembly module
│   ├── 4_llm_inference.py      # HBCR graph-connected LLM inference engine
│   ├── 5_evaluate.py           # Evaluation metric generator
│   ├── 6_build_local_db.py     # Local vector embedding builder
│   ├── 6_build_qdrant_db.py    # Qdrant cloud RAG indexer
│   ├── 7_rag_only_inference.py # Vector semantic similarity evaluator
│   ├── 9_chatbot_server.py     # FastAPI threat analysis web server
│   ├── chatbot_core.py         # Analysis backend for web interface
│   ├── console_ui.py           # Terminal dashboard utilities
│   └── prompts.py              # Calibrated prompts, HBCR & DRC templates
├── static/                     # Web UI frontend assets
├── COMMANDS.md                 # Detailed CLI command reference
└── requirements.txt            # Python dependencies
```
