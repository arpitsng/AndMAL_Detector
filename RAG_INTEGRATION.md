# RAG Integration — Case-Based Retrieval for Tier 1

This adds retrieval-augmented generation to the LAMD pipeline. It's not
document RAG — there's no PDF corpus. Instead it's **case-based retrieval**:
before the LLM judges a function's CFG slice in Tier 1, it's shown the most
similar CFG slices from apps we've *already labeled* (from `data/train.csv`),
along with their known MALWARE/BENIGN verdict.

## Why this helps

Right now Tier 1 judges each function slice cold, with no sense of what
malicious vs. benign usage of a given API has looked like before. Showing it
concrete labeled precedent — "here's a similar `sendTextMessage` call from a
known airpush sample, and here's one from a known-benign app" — gives the
model something to calibrate against instead of guessing from the API name
and code shape alone. This is the same idea behind AppPoet's case-based
reasoning step.

## How it works

```
data/train.csv + extracted_cfgs/*.txt
        |
        v
  rag.py --build   -->  parse CFGs, filter framework noise, dedup
        |                dedup by exact-text hash
        v
  embed each function slice (sentence-transformers, local)
        |
        v
  FAISS index  -->  saved to rag_store/

At inference time (4_llm_inference.py --rag):
  new function slice --> embed --> search FAISS --> top-k similar labeled
  slices --> formatted into Tier 1 prompt as reference cases
```

Retrieval excludes any slice from the same APK being analyzed (`exclude_sha256`),
which matters during evaluation on the training set — otherwise the model
could retrieve its own answer key.

## Usage

1. Install the two new dependencies (already added to `requirements.txt`):
   ```bash
   pip install -r requirements.txt
   ```

2. Build the index once (rerun whenever `extracted_cfgs/` changes):
   ```bash
   python src_python/rag.py --build
   ```
   This scans every labeled sample in `data/train.csv` that has a
   corresponding CFG file, filters out framework/SDK noise the same way
   `4_llm_inference.py` does, and indexes the remaining function slices.

3. Run inference with `--rag`:
   ```bash
   python src_python/4_llm_inference.py --mode cfg --backend groq --rag --rag-k 3 --limit 5
   ```
   `--rag-k` controls how many similar examples are retrieved per function
   slice (default 3). Omit `--rag` to run the pipeline exactly as before —
   nothing changes for existing workflows.

4. Sanity-check retrieval on its own, without running the full pipeline:
   ```bash
   python src_python/rag.py --query "sendTextMessage premium number background"
   ```

## Files touched

| File | Change |
|------|--------|
| `src_python/rag.py` | **New.** Builds the FAISS index, retrieves similar examples, CLI for build/query. |
| `src_python/prompts.py` | Added `TIER1_USER_TEMPLATE_RAG`, a Tier 1 prompt variant with a reference-cases section. Original template untouched. |
| `src_python/4_llm_inference.py` | Added `--rag`/`--rag-k` flags; `run_tier1()` and `analyse_one_apk()` accept optional RAG params; falls back gracefully with a warning if the index hasn't been built. |
| `requirements.txt` | Added `sentence-transformers`, `faiss-cpu`. |
| `.gitignore` | Added `rag_store/` (generated, rebuildable, not source). |

## Notes / next steps

- Building the index downloads the embedding model (~90MB) from Hugging
  Face on first run — needs internet access.
- Retrieval is currently wired into **Tier 1 only** (function-level), since
  that's where the CFG text directly matches what's embedded. Tier 2/3
  could be extended similarly (e.g. retrieving similar *API-level* summaries
  for Tier 2) if you want to take it further.
- The knowledge base is built once from `train.csv`. If you add more labeled
  samples later, just rerun `--build` to refresh it.
- Worth watching for during evaluation: `--rag` will meaningfully increase
  wall-clock time per sample (one extra embedding + FAISS search per
  function slice), though it adds no extra LLM calls.
