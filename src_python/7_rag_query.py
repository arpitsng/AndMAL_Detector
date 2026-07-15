"""
LAMD Pipeline — Step 7: RAG-Augmented Malware Query
====================================================
Query the LAMD knowledge base and get an LLM verdict on whether an
Android application is MALWARE or BENIGN.

Three input modes:
  --sha256  <hash>    Resolve to extracted_cfgs/<hash>_cfg.txt, then analyze
  --cfg     <path>    Use a specific _cfg.txt file directly
  --text    <string>  Use a plain-text description (no CFG file needed)

The script:
  1. Embeds the query (locally, on CPU — no API cost)
  2. Retrieves Top-5 most similar past examples from Qdrant Cloud
  3. Builds a RAG-augmented prompt (retrieved examples + query)
  4. Calls Groq (Llama 3.3 70B, free tier) for the final verdict
  5. Prints and saves the result to results/rag_predictions.jsonl

Usage:
  python src_python/7_rag_query.py --sha256 019b62571b036cebe2e...
  python src_python/7_rag_query.py --cfg extracted_cfgs/019b_cfg.txt
  python src_python/7_rag_query.py --text "app silently sends SMS to premium numbers"

  # Batch-evaluate multiple SHA256s from test CSV
  python src_python/7_rag_query.py --csv data/test_1.csv --limit 20

  # Change number of retrieved neighbours
  python src_python/7_rag_query.py --sha256 <hash> --top-k 3
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv

# Allow running from project root or src_python/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src_python"))

from rag_utils import (
    COLLECTION_NAME,
    TOP_K,
    EmbeddingModel,
    RetrievedExample,
    RAG_SYSTEM,
    build_rag_prompt,
    ensure_sha256_index,
    get_qdrant_client,
    load_cfg_for_sha256,
    parse_cfg_file,
)

# =============================================================================
#  Paths
# =============================================================================

CFG_DIR     = PROJECT_ROOT / "extracted_cfgs"
RESULTS_DIR = PROJECT_ROOT / "results"
TRAIN_CSV   = PROJECT_ROOT / "data" / "train.csv"
TEST_CSV    = PROJECT_ROOT / "data" / "test_1.csv"

RESULTS_DIR.mkdir(exist_ok=True)
OUTPUT_FILE = RESULTS_DIR / "rag_predictions.jsonl"


# =============================================================================
#  Retrieval
# =============================================================================

def retrieve(
    client,
    embedder:   EmbeddingModel,
    query_text: str,
    top_k:      int = TOP_K,
    filter_out_sha256: str | None = None,
) -> list[RetrievedExample]:
    """
    Embed query_text, search Qdrant for top_k nearest neighbours,
    and return RetrievedExample objects.

    filter_out_sha256: exclude results from this APK (prevents self-retrieval
    when the query SHA256 is in the KB).
    """
    from qdrant_client import models

    query_vector = embedder.embed_one(query_text)

    # Optionally exclude the query APK's own entries
    search_filter = None
    if filter_out_sha256:
        search_filter = models.Filter(
            must_not=[
                models.FieldCondition(
                    key="sha256",
                    match=models.MatchValue(value=filter_out_sha256),
                )
            ]
        )

    # qdrant-client >= 1.12 replaced client.search() with client.query_points()
    result = client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        limit=top_k,
        query_filter=search_filter,
        with_payload=True,
    )

    examples: list[RetrievedExample] = []
    for point in result.points:
        p = point.payload or {}
        examples.append(RetrievedExample(
            sha256=p.get("sha256", ""),
            function_name=p.get("function_name", ""),
            suspicious_api=p.get("suspicious_api", ""),
            label=p.get("label", "UNKNOWN"),
            family=p.get("family", "unknown"),
            raw_text=p.get("raw_text", ""),
            score=point.score,
        ))

    return examples


# =============================================================================
#  Groq LLM (free tier, reuses pattern from 4_llm_inference.py)
# =============================================================================

class GroqBackend:
    """Groq API backend using OpenAI-compatible client with key rotation."""

    def __init__(self, api_keys: list[str], model: str = "llama-3.3-70b-versatile"):
        self.api_keys = api_keys
        self.key_index = 0
        self.model = model
        self._init_client()
        print(f"  Loaded {len(api_keys)} Groq API key(s)")

    def _init_client(self):
        from openai import OpenAI
        self.client = OpenAI(
            api_key=self.api_keys[self.key_index],
            base_url="https://api.groq.com/openai/v1",
        )

    def _rotate_key(self) -> bool:
        """Rotate to next key. Returns True if we wrapped around (full cycle)."""
        old_index = self.key_index
        self.key_index = (self.key_index + 1) % len(self.api_keys)
        wrapped = self.key_index <= old_index  # wrapped around
        print(f"\n  [KEY] Rotating to key {self.key_index + 1}/{len(self.api_keys)}", file=sys.stderr)
        self._init_client()
        return wrapped

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        from openai import RateLimitError

        # Total attempts: cycle through all keys up to 3 full cycles
        max_cycles = 3
        base_wait = 30  # seconds to wait after a full rotation cycle fails
        attempts_per_cycle = len(self.api_keys)
        max_retries = attempts_per_cycle * max_cycles
        cycle = 0

        time.sleep(2)  # Base conservative delay

        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user",   "content": user},
                    ],
                    temperature=temperature,
                    max_tokens=2048,
                )
                return response.choices[0].message.content.strip()

            except (RateLimitError, Exception) as e:
                is_rate_limit = isinstance(e, RateLimitError) or "429" in str(e)
                if not is_rate_limit:
                    raise

                if attempt == max_retries - 1:
                    raise  # exhausted all retries

                wrapped = self._rotate_key()
                if wrapped:
                    cycle += 1
                    wait = base_wait * (2 ** (cycle - 1))  # 30s, 60s, 120s
                    print(f"  [WAIT] All {len(self.api_keys)} key(s) rate-limited. "
                          f"Waiting {wait}s before cycle {cycle + 1}/{max_cycles} …",
                          file=sys.stderr)
                    time.sleep(wait)


class GeminiBackend:
    """Gemini API backend using google-generativeai with key rotation."""
    
    def __init__(self, api_keys: list[str], model: str = "gemini-1.5-pro"):
        self.api_keys = api_keys
        self.key_index = 0
        self.model_name = model
        self._init_client()
        
    def _init_client(self):
        import google.generativeai as genai
        # genai module relies on global config, so we configure it with the current key
        genai.configure(api_key=self.api_keys[self.key_index])
        self.client = genai.GenerativeModel(
            model_name=self.model_name,
            generation_config={"temperature": 0.1, "max_output_tokens": 2048}
        )
        
    def _rotate_key(self):
        self.key_index = (self.key_index + 1) % len(self.api_keys)
        print(f"\n  [WARN] Gemini rate limit (429) hit. Rotating to key index {self.key_index} ...", file=sys.stderr)
        self._init_client()

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        from google.api_core.exceptions import ResourceExhausted
        
        max_retries = len(self.api_keys) * 2
        time.sleep(2)
        
        # Override temperature per-call if needed (Gemini supports generation_config here too)
        gen_config = {"temperature": temperature, "max_output_tokens": 2048}
        
        for attempt in range(max_retries):
            try:
                # Gemini doesn't use standard system/user messages the same way, but supports system_instruction
                # However, for simplicity and compatibility across models without system instructions (older geminis), 
                # we just concatenate system + user prompt for basic use. 
                # For gemini-1.5-pro, system_instruction is supported via the GenerativeModel constructor, 
                # but we can also just concat. Let's concatenate for robust basic use.
                prompt = f"{system}\n\n{user}"
                response = self.client.generate_content(
                    prompt, 
                    generation_config=gen_config
                )
                return response.text.strip()
                
            except ResourceExhausted:
                if attempt == max_retries - 1:
                    raise
                self._rotate_key()
            except Exception as e:
                if "429" in str(e) or "quota" in str(e).lower():
                    if attempt == max_retries - 1:
                        raise
                    self._rotate_key()
                else:
                    raise


def create_llm():
    """Load API keys from .env and return a configured backend (Groq or Gemini)."""
    load_dotenv(PROJECT_ROOT / ".env")
    
    backend_choice = os.environ.get("BACKEND", "groq").strip().lower()
    
    if backend_choice == "gemini":
        key_str = os.environ.get("GEMINI_API_KEY", "").strip()
        if not key_str:
            print("[ERROR] GEMINI_API_KEY not set in .env", file=sys.stderr)
            sys.exit(1)
        keys = [k.strip() for k in key_str.split(",") if k.strip()]
        model = os.environ.get("GEMINI_MODEL", "gemini-1.5-pro").strip()
        return GeminiBackend(api_keys=keys, model=model)
    else:
        # Default to Groq
        key_str = os.environ.get("GROQ_API_KEY", "").strip()
        if not key_str:
            print("[ERROR] GROQ_API_KEY not set in .env", file=sys.stderr)
            sys.exit(1)
        keys = [k.strip() for k in key_str.split(",") if k.strip()]
        model = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile").strip()
        return GroqBackend(api_keys=keys, model=model)


# =============================================================================
#  Extract prediction from LLM response
# =============================================================================

def extract_prediction(response: str) -> str:
    """
    Parse 'MALWARE' or 'BENIGN' from the LLM response text.
    Returns 'UNKNOWN' if neither is found.
    """
    # Look for the **Final Prediction:** block first
    for line in response.split("\n"):
        line_up = line.upper().strip()
        if "FINAL PREDICTION" in line_up:
            if "MALWARE" in line_up:
                return "MALWARE"
            if "BENIGN" in line_up:
                return "BENIGN"
        # Also check the very next line after the header
        if line_up in ("MALWARE", "<MALWARE>", "**MALWARE**"):
            return "MALWARE"
        if line_up in ("BENIGN", "<BENIGN>", "**BENIGN**"):
            return "BENIGN"

    # Fallback: count mentions in the full text
    text_up = response.upper()
    m_count = text_up.count("MALWARE")
    b_count = text_up.count("BENIGN")
    if m_count > b_count:
        return "MALWARE"
    if b_count > m_count:
        return "BENIGN"

    return "UNKNOWN"


# =============================================================================
#  Load ground-truth labels from CSV (for evaluation metadata)
# =============================================================================

def load_ground_truth(csv_path: Path) -> dict[str, dict]:
    """Returns sha256 (lowercase) → {'ground_truth': str, 'family': str}.
    Handles numeric labels (0.0=BENIGN, 1.0=MALWARE) and uppercase SHA256."""
    if not csv_path.exists():
        return {}
    df = pd.read_csv(csv_path)
    df.columns = [c.strip().lower() for c in df.columns]

    sha_col    = "sha256" if "sha256" in df.columns else df.columns[0]
    label_col  = next((c for c in df.columns if c == "label" or "class" in c), None)
    family_col = next((c for c in df.columns if "family" in c), None)

    result = {}
    for _, row in df.iterrows():
        # SHA256 is uppercase in CSV — normalise to lowercase
        sha    = str(row[sha_col]).strip().lower()
        family = str(row[family_col]).strip() if family_col else "unknown"

        if label_col:
            raw = str(row[label_col]).strip().lower()
            try:
                numeric = float(raw)
                gt = "MALWARE" if numeric >= 1.0 else "BENIGN"
            except ValueError:
                if "malware" in raw or raw == "1":
                    gt = "MALWARE"
                elif "benign" in raw or raw == "0":
                    gt = "BENIGN"
                else:
                    gt = raw.upper()
        else:
            gt = "UNKNOWN"

        result[sha] = {"ground_truth": gt, "family": family}

    return result


# =============================================================================
#  Single-APK analysis
# =============================================================================

def analyse_one(
    query_mode:  str,        # "cfg", "sha256", "text"
    query_value: str,        # the actual value for the mode
    client,
    embedder:    EmbeddingModel,
    llm:         GroqBackend,
    top_k:       int = TOP_K,
    ground_truth_map: dict | None = None,
) -> dict:
    """
    Run the full RAG pipeline for one query and return a result dict.
    """
    sha256 = ""
    ground_truth = ""
    family = ""

    # ── Prepare query text and sha256 ─────────────────────────────────────────
    if query_mode == "text":
        query_text = query_value
        print(f"\n  Query mode : TEXT")
        print(f"  Input      : \"{query_value[:80]}{'...' if len(query_value)>80 else ''}\"")

    elif query_mode == "sha256":
        sha256 = query_value.strip().lower()
        print(f"\n  Query mode : SHA256")
        print(f"  SHA256     : {sha256}")
        slices = load_cfg_for_sha256(sha256)
        if not slices:
            query_text = f"SHA256: {sha256} — no function slices found in CFG."
        else:
            query_text = "\n".join(sl.raw_text for sl in slices)
            print(f"  Functions  : {len(slices)}")

        if ground_truth_map and sha256 in ground_truth_map:
            meta = ground_truth_map[sha256]
            ground_truth = meta["ground_truth"]
            family = meta["family"]

    elif query_mode == "cfg":
        cfg_path = Path(query_value)
        if not cfg_path.is_absolute():
            cfg_path = PROJECT_ROOT / query_value
        print(f"\n  Query mode : CFG FILE")
        print(f"  Path       : {cfg_path.name}")
        slices = parse_cfg_file(cfg_path)
        sha256 = cfg_path.name.replace("_cfg.txt", "").lower()
        query_text = "\n".join(sl.raw_text for sl in slices) if slices else "Empty CFG."
        print(f"  Functions  : {len(slices)}")

        if ground_truth_map and sha256 in ground_truth_map:
            meta = ground_truth_map[sha256]
            ground_truth = meta["ground_truth"]
            family = meta["family"]

    else:
        raise ValueError(f"Unknown query mode: {query_mode}")

    # ── Retrieve similar examples ─────────────────────────────────────────────
    print(f"  Retrieving top-{top_k} similar examples …", end="", flush=True)
    t0 = time.time()
    examples = retrieve(
        client, embedder, query_text,
        top_k=top_k,
        filter_out_sha256=sha256 or None,
    )
    print(f" done ({time.time()-t0:.1f}s)")

    if examples:
        labels = ", ".join(f"{e.label}({e.score:.2f})" for e in examples)
        print(f"  Retrieved  : {labels}")
    else:
        print("  Retrieved  : [no results — is the KB empty? Run 6_build_rag_kb.py first]")

    # ── Build RAG prompt ──────────────────────────────────────────────────────
    prompt = build_rag_prompt(query_text, examples, query_mode)

    # ── Call LLM ─────────────────────────────────────────────────────────────
    print("  Calling Groq LLM …", end="", flush=True)
    t1 = time.time()
    response = llm.chat(RAG_SYSTEM, prompt)
    print(f" done ({time.time()-t1:.1f}s)")

    prediction = extract_prediction(response)
    print(f"\n  ╔══════════════════════════════╗")
    print(f"  ║  Prediction  : {prediction:<13}   ║")
    if ground_truth:
        correct = "PASS" if prediction == ground_truth else "FAIL"
        print(f"  ║  Ground Truth: {ground_truth:<13}   ║")
        print(f"  ║  Result      : {correct:<13}   ║")
    print(f"  ╚══════════════════════════════╝")

    # ── Build result record ───────────────────────────────────────────────────
    # Sanitize LLM response: strip control chars that can corrupt JSONL output
    safe_response = "".join(
        ch if ch == "\n" or ch == "\t" or (ord(ch) >= 32) else " "
        for ch in response
    )
    result = {
        "sha256":       sha256,
        "query_mode":   query_mode,
        "prediction":   prediction,
        "ground_truth": ground_truth,
        "family":       family,
        "analysis":     safe_response,
        "retrieved": [
            {
                "rank":          i + 1,
                "sha256":        ex.sha256,
                "function_name": ex.function_name,
                "label":         ex.label,
                "family":        ex.family,
                "score":         round(ex.score, 4),
            }
            for i, ex in enumerate(examples)
        ],
    }
    return result


# =============================================================================
#  Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="LAMD RAG Query — classify an Android APK using the CFG knowledge base.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src_python/7_rag_query.py --sha256 019b62571b036cebe2e4568f74000e84eac2130ac4741353af0389092e6f361e
  python src_python/7_rag_query.py --cfg extracted_cfgs/019b62571b_cfg.txt
  python src_python/7_rag_query.py --text "app silently sends SMS to premium numbers"
  python src_python/7_rag_query.py --csv data/test_1.csv --limit 10
        """,
    )

    # Input modes (mutually exclusive for single query)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--sha256", metavar="HASH",
                       help="SHA256 of an APK (must have extracted CFG in extracted_cfgs/)")
    group.add_argument("--cfg",    metavar="PATH",
                       help="Path to a _cfg.txt file")
    group.add_argument("--text",   metavar="TEXT",
                       help="Plain-text description of the app / behaviour")

    # Batch mode
    group.add_argument("--csv",    metavar="PATH",
                       help="CSV file with sha256 + label columns (batch mode)")

    parser.add_argument("--limit",  type=int, default=None,
                        help="Max number of APKs to process in batch mode")
    parser.add_argument("--top-k",  type=int, default=TOP_K,
                        help=f"Number of retrieved neighbours (default: {TOP_K})")
    parser.add_argument("--output", metavar="PATH", default=str(OUTPUT_FILE),
                        help=f"Output JSONL file (default: {OUTPUT_FILE})")
    parser.add_argument("--append", action="store_true",
                        help="Append to output file instead of overwriting")

    args = parser.parse_args()

    # Validate at least one mode is given
    if not any([args.sha256, args.cfg, args.text, args.csv]):
        parser.print_help()
        sys.exit(1)

    print("=" * 60)
    print("  LAMD — Step 7: RAG-Augmented Query")
    print("=" * 60)

    # ── Shared setup ──────────────────────────────────────────────────────────
    print("\n[Init] Loading embedding model …")
    embedder = EmbeddingModel()

    print("[Init] Connecting to Qdrant Cloud …")
    client = get_qdrant_client()
    ensure_sha256_index(client)

    print("[Init] Loading Groq backend …")
    llm = create_llm()

    # Load ground-truth for evaluation metadata (best effort)
    gt_map: dict[str, dict] = {}
    for csv in [TRAIN_CSV, TEST_CSV]:
        gt_map.update(load_ground_truth(csv))

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_mode = "a" if args.append else "w"

    # ── Single query modes ────────────────────────────────────────────────────
    if args.sha256:
        result = analyse_one("sha256", args.sha256, client, embedder, llm, args.top_k, gt_map)
        with open(output_path, write_mode, encoding="utf-8") as f:
            f.write(json.dumps(result, ensure_ascii=True) + "\n")
        print(f"\n  Result saved → {output_path}")

    elif args.cfg:
        result = analyse_one("cfg", args.cfg, client, embedder, llm, args.top_k, gt_map)
        with open(output_path, write_mode, encoding="utf-8") as f:
            f.write(json.dumps(result, ensure_ascii=True) + "\n")
        print(f"\n  Result saved → {output_path}")

    elif args.text:
        result = analyse_one("text", args.text, client, embedder, llm, args.top_k, gt_map)
        with open(output_path, write_mode, encoding="utf-8") as f:
            f.write(json.dumps(result, ensure_ascii=True) + "\n")
        print(f"\n  Result saved → {output_path}")

    # ── Batch mode (CSV) ──────────────────────────────────────────────────────
    elif args.csv:
        csv_path = Path(args.csv)
        if not csv_path.exists():
            print(f"[ERROR] CSV not found: {csv_path}", file=sys.stderr)
            sys.exit(1)

        df = pd.read_csv(csv_path)
        df.columns = [c.strip().lower() for c in df.columns]
        sha_col = "sha256" if "sha256" in df.columns else df.columns[0]
        sha_list = df[sha_col].astype(str).str.strip().str.lower().tolist()

        if args.limit:
            sha_list = sha_list[:args.limit]

        print(f"\n  Batch mode: {len(sha_list)} APKs from {csv_path.name}")
        print(f"  Output    : {output_path}")

        correct = 0
        total   = 0

        with open(output_path, write_mode, encoding="utf-8") as f:
            for idx, sha256 in enumerate(sha_list, 1):
                print(f"\n[{idx}/{len(sha_list)}]", end="")
                try:
                    result = analyse_one("sha256", sha256, client, embedder, llm, args.top_k, gt_map)
                    f.write(json.dumps(result, ensure_ascii=True) + "\n")
                    f.flush()

                    if result["ground_truth"]:
                        total += 1
                        if result["prediction"] == result["ground_truth"]:
                            correct += 1

                except FileNotFoundError as e:
                    print(f"\n  [SKIP] {e}")
                except Exception as e:
                    print(f"\n  [ERROR] {sha256}: {e}", file=sys.stderr)

        print(f"\n{'='*60}")
        print(f"  Batch complete: {len(sha_list)} queries")
        print(f"  Results saved → {output_path}")
        if total > 0:
            acc = correct / total * 100
            print(f"  Quick accuracy: {correct}/{total} = {acc:.1f}%")
        print(f"  Run full evaluation:")
        print(f"    python src_python/5_evaluate.py --predictions {output_path}")
        print("=" * 60)


if __name__ == "__main__":
    main()
