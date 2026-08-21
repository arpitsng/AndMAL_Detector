# LAMD Android Malware Detection — Commands Guide

This document lists all execution commands for every stage of the LAMD pipeline, including data preparation, CFG extraction, RAG indexing, LLM inference, and evaluation.

---

## 1. Environment & Setup

Make sure dependencies are installed and API keys are set in `.env`:

```bash
pip install -r requirements.txt
```

### `.env` File Template:
```ini
# AndroZoo API Key (for downloading APKs)
ANDROZOO_API_KEY=your_androzoo_key_here

# Google Gemini (Supports up to 3 rotating API keys for high throughput)
GEMINI_API_KEY1=your_gemini_key_1
GEMINI_API_KEY2=your_gemini_key_2
GEMINI_API_KEY3=your_gemini_key_3
GEMINI_MODEL=gemini-2.5-flash

# OpenAI / Groq / OpenRouter (Optional alternative backends)
OPENAI_API_KEY=sk-...
GROQ_API_KEY=gsk-...
GROQ_MODEL=llama-3.1-8b-instant
OPENROUTER_API_KEY=sk-or-...

# Qdrant Vector Database (For RAG few-shot retrieval)
QDRANT_URL=https://your-cluster.aws.cloud.qdrant.io
QDRANT_API_KEY=your_qdrant_api_key
```

---

## 2. Phase 1 — APK Download & CFG Extraction

Extracts backward-sliced Control Flow Graphs (CFGs) for suspicious APIs using the Soot Java Slicer. Automatically downloads the APK, slices it, saves the CFG to `extracted_cfgs/{sha256}_cfg.txt`, and deletes the APK to save disk space.

```bash
# Run on full dataset (auto-skips already extracted CFGs)
python src_python/2_extract_cfg.py

# Run on a custom CSV (e.g. split partition)
python src_python/2_extract_cfg.py --csv data/split_laptop1.csv

# Process a slice with offset and limit (e.g. samples 2000 to 2050)
python src_python/2_extract_cfg.py --csv data/train.csv --offset 2000 --limit 50
```

---

## 3. Phase 2 — RAG Knowledge Base Construction (v2 Hybrid)

Builds a function-level Qdrant vector database using **hybrid embeddings** (384-dim semantic + 25-dim graph-structural = 409-dim vectors). Each function slice gets its own vector instead of one per APK, with stratified retrieval (top-3 MALWARE + top-3 BENIGN matches) at query time.

```bash
# Build / rebuild the Qdrant RAG vector database (deletes old, creates new)
python src_python/6_build_qdrant_db.py
```

---

## 4. Phase 3 — LLM Inference

### Mode A: Single-Call RAG Pipeline (Recommended — Fast & Cost Effective)
Leverages large-context LLMs (Gemini 2.5 Flash) and Qdrant RAG vector search to perform classification in **1 API call per APK**.

```bash
# Single-Call with Gemini + RAG (with offset and limit)
python src_python/4_llm_inference.py --mode cfg --backend gemini --csv data/train.csv --offset 2000 --limit 20 --single

# Single-Call with NVIDIA Nemotron via OpenRouter (with 3 rotating keys)
python src_python/4_llm_inference.py --mode cfg --backend nemotron --csv data/test_1.csv --cfg-dir test_extracted_cfgs --offset 15 --limit 50 --single --resume

# Single-Call on test dataset using custom CFG directory (e.g. test_extracted_cfgs)
python src_python/4_llm_inference.py --mode cfg --backend gemini --csv data/test_1.csv --cfg-dir test_extracted_cfgs --offset 0 --limit 15 --single

# Single-Call on a split file with resume support
python src_python/4_llm_inference.py --mode cfg --backend gemini --csv data/split_laptop1.csv --single --resume

# Single-Call with custom CFG dir and custom output file
python src_python/4_llm_inference.py --mode cfg --backend gemini --csv data/test_1.csv --cfg-dir test_extracted_cfgs --single --output results/test_predictions.jsonl
```

---

### Mode B: Full 3-Tier Sequential Pipeline (Standard LAMD Paper)
Executes Tier 1 (Function-level analysis) $\rightarrow$ Tier 2 (API-group intent) $\rightarrow$ Tier 3 (APK-level verdict). Requires ~20–30 API calls per APK.

```bash
# 3-Tier Pipeline with Gemini (Multi-key rotation)
python src_python/4_llm_inference.py --mode cfg --backend gemini --csv data/train.csv --offset 2000 --limit 10

# 3-Tier Pipeline with OpenAI GPT-4o-mini
python src_python/4_llm_inference.py --mode cfg --backend openai --csv data/train.csv --limit 10

# 3-Tier Pipeline with Groq (Free Llama-3.1-8B)
python src_python/4_llm_inference.py --mode cfg --backend groq --csv data/train.csv --limit 10

# Disable Sanity Check (faster)
python src_python/4_llm_inference.py --mode cfg --backend gemini --no-drc --limit 10
```

---

### Mode C: Pre-Computed Malware Logs Mode
Parses existing raw analysis logs in `lamd/malware_logs/`:

```bash
python src_python/4_llm_inference.py --mode logs --offset 0 --limit 100 --output results/predictions_logs.jsonl
```

---

### Mode D: Direct Single-Shot Mode
Directly evaluates truncated CFGs in a single shot without RAG or tier breakdown:

```bash
python src_python/4_llm_inference.py --mode direct --backend gemini --csv data/train.csv --limit 10
```

---

## 5. Phase 4 — Evaluation & Performance Metrics

Computes Accuracy, Precision, Recall, F1 Score, False Positive Rate (FPR), False Negative Rate (FNR), and per-family detection rates.

```bash
# Evaluate predictions from a split run
python src_python/5_evaluate.py --predictions results/predictions_split_laptop1.jsonl

# Evaluate predictions from train/test runs
python src_python/5_evaluate.py --predictions results/predictions_train.jsonl
```

---

## 6. Utilities & Dataset Splitting

```bash
# Create balanced train/test or laptop splits
python src_python/make_balanced_splits.py

# Run quick end-to-end pipeline test
python src_python/test_pipeline.py
```

---

## 7. Command Reference Summary

| Parameter | Options / Type | Description |
|---|---|---|
| `--mode` | `cfg`, `logs`, `direct` | `cfg`: Extracted CFGs, `logs`: Log files, `direct`: Direct prompt |
| `--backend` | `gemini`, `openai`, `groq`, `openrouter`, `ollama` | LLM backend to query |
| `--single` | Flag (Boolean) | Enables 1-call APK inference + Qdrant RAG retrieval |
| `--csv` | File Path (e.g. `data/train.csv`) | CSV file with SHA256 hashes and ground-truth labels |
| `--offset` | Integer (e.g. `2000`) | Skip the first N samples |
| `--limit` | Integer (e.g. `20`) | Number of samples to process |
| `--resume` | Flag (Boolean) | Skips already-analyzed samples in output JSONL |
| `--output` | File Path | Output JSONL file path for predictions |
| `--no-drc` | Flag (Boolean) | Skip consistency check / sanity verification |
