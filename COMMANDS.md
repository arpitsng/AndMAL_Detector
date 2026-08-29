# 📖 AndMAL_Detector — CLI Command Reference

This guide contains the complete list of execution commands for each phase of the Android Malware Detection pipeline.

---

## 1. Environment Setup

```bash
# Clone the repository
git clone https://github.com/arpitsng/AndMAL_Detector.git
cd AndMAL_Detector

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 2. Phase 1: APK Download & Slicing (Static Analysis)

Downloads APKs from AndroZoo, runs the Soot Java Slicer to trace suspicious API calls, and outputs backward-sliced Jimple Control Flow Graphs (CFGs).

```bash
# 1. Download sample APKs from AndroZoo
python src_python/1_download_apk.py --limit 10

# 2. Extract backward-sliced CFGs for a dataset
python src_python/2_extract_cfg.py --csv data/test_1.csv --limit 20

# 3. Process with custom offset and limit
python src_python/2_extract_cfg.py --csv data/train.csv --offset 100 --limit 50
```

---

## 3. Phase 2: Vector Store Indexing (RAG Knowledge Base)

Builds hybrid embeddings (semantic code tokens + graph structure) and indexes them into Qdrant Cloud or a local SQLite vector database for few-shot retrieval.

```bash
# Build local SQLite vector database
python src_python/6_build_local_db.py

# Index into Qdrant Cloud vector cluster
python src_python/6_build_qdrant_db.py
```

---

## 4. Phase 3: LLM Inference

### Option A: Local Dual-GPU Acceleration (Qwen 2.5 32B via GGUF CUDA)
Runs natively inside Python across dual NVIDIA GPUs (`tensor_split=[0.5, 0.5]`):

```bash
# Single-Call HBCR Inference on test samples
python src_python/4_llm_inference.py --mode cfg --backend gguf --single --csv data/test_1.csv --cfg-dir extracted_cfgs --output results/predictions.jsonl

# Resume interrupted inference
python src_python/4_llm_inference.py --mode cfg --backend gguf --single --csv data/test_1.csv --cfg-dir extracted_cfgs --output results/predictions.jsonl --resume
```

### Option B: Cloud API Backends (Gemini / OpenAI / Groq)

```bash
# Google Gemini 2.5 Flash
python src_python/4_llm_inference.py --mode cfg --backend gemini --single --csv data/test_1.csv --cfg-dir extracted_cfgs --output results/predictions.jsonl

# OpenAI GPT-4o-mini
python src_python/4_llm_inference.py --mode cfg --backend openai --single --csv data/test_1.csv --cfg-dir extracted_cfgs --output results/predictions.jsonl

# Groq Llama 3.3 70B
python src_python/4_llm_inference.py --mode cfg --backend groq --single --csv data/test_1.csv --cfg-dir extracted_cfgs --output results/predictions.jsonl
```

### Option C: 3-Tier Step-by-Step Reasoning (Standard LAMD)

```bash
# Multi-tier reasoning: Function-level -> API-level -> App-level
python src_python/4_llm_inference.py --mode cfg --backend gemini --csv data/test_1.csv --limit 10
```

---

## 5. Phase 4: Evaluation & Reporting

Calculates Accuracy, Precision, Recall, F1 Score, False Positive Rate (FPR), False Negative Rate (FNR), and per-family detection breakdowns.

```bash
# Evaluate predictions file and generate Markdown report
python src_python/5_evaluate.py --predictions results/predictions.jsonl
```

---

## 6. Phase 5: Interactive Threat Analysis Chatbot

Launches the local FastAPI web server for inspecting APK verdicts and interactive threat analysis:

```bash
# Start the web server (accessible at http://localhost:8765)
python src_python/9_chatbot_server.py
```

---

## 7. Command Parameters Summary

| Parameter | Options / Type | Description |
| :--- | :--- | :--- |
| `--mode` | `cfg`, `logs`, `direct` | Execution mode (`cfg` for sliced Jimple graphs) |
| `--backend` | `gguf`, `gemini`, `openai`, `groq`, `ollama` | LLM inference backend |
| `--single` | Flag | Enables HBCR graph-connected single-call inference |
| `--csv` | File Path | Input CSV with `sha256`, `label`, `family` columns |
| `--cfg-dir` | Directory Path | Directory containing extracted `*_cfg.txt` files |
| `--output` | File Path | Destination `.jsonl` path for predictions |
| `--offset` | Integer | Number of records to skip from beginning |
| `--limit` | Integer | Maximum number of records to process |
| `--resume` | Flag | Skips samples already present in output file |
