# AndMAL_Detector

**Context-driven Android malware detection powered by LLM reasoning and static code analysis.**

AndMAL_Detector is a research pipeline that classifies Android APKs as malware or benign by combining **Java Soot-based static analysis** with **multi-tier LLM reasoning**, following the LAMD (LLM-Assisted Malware Detection) framework. Instead of relying on fixed signature rules, the system extracts the control-flow context around suspicious API calls and lets an LLM reason over that context the way a security analyst would.

---

## Overview

Traditional malware detectors flag apps based on static rules — "if it sends SMS, flag it." This catches too many legitimate apps and misses malware that hides behind normal-looking APIs. AndMAL_Detector instead:

1. **Extracts the code context** around every suspicious API call in an APK using backward program slicing.
2. **Feeds that context to an LLM** in three escalating tiers of reasoning — function-level, API-level, and whole-app-level — so the verdict is built from evidence rather than a single keyword match.
3. **Grounds the reasoning with retrieval (RAG)**, pulling in similar previously-seen code patterns from a vector store before the LLM makes its final call.

## Pipeline

```
📱 Android APK
      │
      ▼
🔬 Phase 1 — Static Analysis (Soot)
   Decompile → locate suspicious API calls → backward-slice each one → save as a Control Flow Graph (CFG)
      │
      ▼
🧠 Phase 2 — Multi-Tier LLM Reasoning
   Tier 1: Function-level analysis, self-verified with a Data-Reasoning-Consistency (DRC) check
   Tier 2: API-level aggregation across all functions using that API
   Tier 3: APK-level verdict — MALWARE or BENIGN, with justification
      │
      ▼
📊 Phase 3 — Evaluation
   Score predictions against ground truth: precision, recall, F1, confusion matrix
```

The RAG extension sits alongside Phase 2, retrieving semantically similar code slices from a vector store to give the LLM grounded context before it commits to a verdict.

## Key Features

- **Soot-based backward slicing** — decompiles APKs and traces suspicious API calls (`sendTextMessage`, `getDeviceId`, `getLocation`, etc.) back through the code that leads to them, producing a structured Control Flow Graph per suspicious call site.
- **Three-tier LLM reasoning (LAMD framework)** — function → API → APK level analysis, mirroring how a human analyst builds a case from individual clues to a final verdict.
- **Self-verification (DRC check)** — every Tier 1 analysis is independently re-checked by a second LLM pass for factual consistency with the underlying code, reducing hallucinated conclusions.
- **RAG-grounded classification** — a Qdrant Cloud vector store indexed with fast local embeddings retrieves similar historical code patterns, giving the LLM additional grounding beyond the current sample alone.
- **Pluggable LLM backends** — runs on Groq (Llama 3.3 70B) by default, with OpenAI and Gemini also supported.
- **Trained and evaluated on a labeled corpus of 13,000+ Android applications** sourced from AndroZoo, spanning multiple malware families.

## Tech Stack

| Layer | Technology |
|---|---|
| Static analysis | Java, Soot |
| LLM reasoning | Groq (Llama 3.3 70B), OpenAI, Google Gemini |
| Retrieval (RAG) | Qdrant Cloud, FastEmbed |
| Data & evaluation | pandas, scikit-learn, tiktoken |
| Dataset source | AndroZoo |

## Project Structure

```
AndMAL_Detector/
├── Slicer/                 # Java/Soot backward-slicing tool (compiled to slicer-1.0.jar)
├── data/                   # train.csv — labeled app fingerprints (SHA-256 + malware/benign)
├── extracted_cfgs/         # Phase 1 output: per-app Control Flow Graph text files
├── results/                # Phase 2/3 output: predictions and evaluation reports
├── src_python/
│   ├── 2_extract_cfg.py    # Phase 1: download APKs, run the Soot slicer
│   ├── 4_llm_inference.py  # Phase 2: 3-tier LLM reasoning
│   └── 5_evaluate.py       # Phase 3: scoring against ground truth
├── rag_flowchart.md        # RAG extension architecture
├── end_to_end_explanation.md  # Full walkthrough of the pipeline
├── requirements.txt
└── .env.example
```

## Setup

```bash
git clone https://github.com/arpitsng/AndMAL_Detector.git
cd AndMAL_Detector

python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -r requirements.txt
cp .env.example .env           # add your AndroZoo and Groq/OpenAI/Gemini API keys
```

## Usage

```bash
# Phase 1 — extract Control Flow Graphs for the first 5 apps in the dataset
python src_python/2_extract_cfg.py --limit 5

# Phase 2 — run 3-tier LLM inference over the extracted CFGs
python src_python/4_llm_inference.py --mode cfg --backend groq --limit 5

# Phase 3 — evaluate predictions against ground truth
python src_python/5_evaluate.py --predictions results/predictions_cfg.jsonl
```

## Results

Evaluated on the labeled AndroZoo-derived corpus:

- **Precision: 100%** — every sample flagged as malware was in fact malware.
- **F1 Score: 75%** — reflects a deliberately conservative classifier that prioritizes avoiding false positives.
- Retrieval-augmented reasoning (RAG) reduces false positives relative to the base LAMD pipeline by grounding each verdict in similar historical code context rather than the current sample alone.

## Reference

This project implements the **LAMD** framework (LLM-Assisted Malware Detection), extended with a custom Retrieval-Augmented Generation layer for additional grounding.

## Authors

**Arpit Singh** — [GitHub](https://github.com/arpitsng)  &  **Devanshu Garg** — [GitHub](https://github.com/xDevanshu-Garg)
