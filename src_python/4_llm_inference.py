"""
LAMD Pipeline — Step 4: Tier-Wise LLM Code Reasoning
======================================================
Implements the full LAMD 3-tier malware detection pipeline:

  Tier 1: Analyse each sliced CFG at function level
  Tier 2: Aggregate function summaries per suspicious API
  Tier 3: Final MALWARE/BENIGN prediction for the APK

Supports multiple LLM backends:
  - OpenAI (GPT-4o-mini — default, as used in the LAMD paper)
  - Google Gemini (Gemini 2.0 Flash)
  - Ollama  (local models like Llama 3, Mistral)

Usage:
  # Run on pre-extracted CFGs (from Step 2)
  python src_python/4_llm_inference.py --mode cfg

  # Run on pre-computed malware logs (existing analysis)
  python src_python/4_llm_inference.py --mode logs

  # Run on test set with evaluation
  python src_python/4_llm_inference.py --mode cfg --csv data/test_1.csv --limit 10

Environment:
  Set your API key in .env:
    OPENAI_API_KEY=sk-...
    or GEMINI_API_KEY=...
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from dataclasses import dataclass, field

import pandas as pd
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv

# Allow running from project root or src_python/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src_python"))

from prompts import (
    TIER1_SYSTEM, TIER1_USER_TEMPLATE,
    TIER2_SYSTEM, TIER2_USER_TEMPLATE,
    TIER3_SYSTEM, TIER3_USER_TEMPLATE,
    DRC_SYSTEM, DRC_USER_TEMPLATE,
    DIRECT_ANALYSIS_SYSTEM, DIRECT_ANALYSIS_TEMPLATE,
    format_api_summaries_for_tier3, classify_api_type,
)

# =============================================================================
#  Paths
# =============================================================================

TRAIN_CSV   = PROJECT_ROOT / "data" / "train.csv"
CFG_DIR     = PROJECT_ROOT / "extracted_cfgs"
LOG_DIR     = PROJECT_ROOT / "lamd" / "malware_logs"
RESULTS_DIR = PROJECT_ROOT / "results"

# =============================================================================
#  Data classes
# =============================================================================

@dataclass
class FunctionSlice:
    """One sliced CFG block parsed from a _cfg.txt file."""
    function_name: str
    suspicious_api: str
    nodes: list[str] = field(default_factory=list)
    edges: list[str] = field(default_factory=list)
    raw_text: str = ""


@dataclass
class Tier1Result:
    """Tier 1 output: function-level behavioral summary."""
    function_name: str
    suspicious_api: str
    summary: str
    risk_level: str = "UNKNOWN"


@dataclass
class Tier2Result:
    """Tier 2 output: API-level intent summary."""
    api_name: str
    api_type: str
    summary: str
    risk_level: str = "UNKNOWN"


@dataclass
class Tier3Result:
    """Tier 3 output: APK-level prediction."""
    sha256: str
    prediction: str  # "MALWARE" or "BENIGN"
    analysis: str    # full text of the analysis
    confidence: str = "UNKNOWN"


# =============================================================================
#  LLM Backend Abstraction
# =============================================================================

class LLMBackend:
    """Abstract interface for LLM API calls."""

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        raise NotImplementedError


class OpenAIBackend(LLMBackend):
    """OpenAI GPT-4o-mini backend (default — as used in LAMD paper)."""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        # pyrefly: ignore [missing-import]
        from openai import OpenAI
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature,
            max_tokens=2048,
        )
        return response.choices[0].message.content.strip()


class OpenRouterBackend(LLMBackend):
    """OpenRouter backend (using OpenAI client compatibility)."""

    def __init__(self, api_key: str, model: str = "openrouter/free"):
        # pyrefly: ignore [import, missing-import]
        from openai import OpenAI
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
        )
        self.model = model

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        import time
        from openai import RateLimitError
        max_retries = 5
        base_wait = 10
        
        # OpenRouter free models have variable rate limits, a small sleep helps.
        time.sleep(2.0)
        
        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=temperature,
                    max_tokens=2048,
                )
                return response.choices[0].message.content.strip()
            except RateLimitError as e:
                if attempt == max_retries - 1:
                    raise
                wait_time = base_wait * (2 ** attempt)
                print(f"\n    [WARN] OpenRouter rate limit hit. Waiting {wait_time}s before retry...", file=sys.stderr, flush=True)
                time.sleep(wait_time)
            except Exception as e:
                if "429" in str(e) or "402" in str(e): # 402 Payment Required
                    if attempt == max_retries - 1:
                        raise
                    wait_time = base_wait * (2 ** attempt)
                    print(f"\n    [WARN] OpenRouter rate limit/payment error. Waiting {wait_time}s before retry...", file=sys.stderr, flush=True)
                    time.sleep(wait_time)
                else:
                    raise


class GroqBackend(LLMBackend):
    """Groq backend (using OpenAI client compatibility)."""

    def __init__(self, api_key: str, model: str = "llama-3.1-8b-instant"):
        # pyrefly: ignore [import, missing-import]
        from openai import OpenAI
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
        )
        self.model = model

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        import time
        # pyrefly: ignore [missing-import]
        from openai import RateLimitError
        max_retries = 5
        base_wait = 10
        
        # Groq free tier for 8b-instant: 131K TPM, 30 RPM.
        # 2s sleep = ~28 RPM, well within limits.
        time.sleep(2)
        
        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=temperature,
                    max_tokens=2048,
                )
                return response.choices[0].message.content.strip()
            except RateLimitError as e:
                if attempt == max_retries - 1:
                    raise
                wait_time = base_wait * (2 ** attempt)
                print(f"\n    [WARN] Groq rate limit hit. Waiting {wait_time}s before retry...", file=sys.stderr, flush=True)
                time.sleep(wait_time)
            except Exception as e:
                if "429" in str(e):
                    if attempt == max_retries - 1:
                        raise
                    wait_time = base_wait * (2 ** attempt)
                    print(f"\n    [WARN] Groq rate limit hit (429). Waiting {wait_time}s before retry...", file=sys.stderr, flush=True)
                    time.sleep(wait_time)
                else:
                    raise


class GeminiBackend(LLMBackend):
    """Google Gemini backend with multi-key rotation to bypass strict rate limits."""

    def __init__(self, api_keys: list[str], model: str = "gemini-2.5-flash"):
        # pyrefly: ignore [missing-import]
        import google.generativeai as genai
        self.api_keys = [k for k in api_keys if k]
        self.current_key_idx = 0
        self.model_name = model
        
        # Configure with the first key initially
        genai.configure(api_key=self.api_keys[self.current_key_idx])
        self.model = genai.GenerativeModel(self.model_name)

    def switch_key(self):
        """Rotate to the next API key in the pool."""
        import google.generativeai as genai
        self.current_key_idx = (self.current_key_idx + 1) % len(self.api_keys)
        genai.configure(api_key=self.api_keys[self.current_key_idx])
        self.model = genai.GenerativeModel(self.model_name)
        print(f"\n    [INFO] Switched to Gemini API Key #{self.current_key_idx + 1}", file=sys.stderr, flush=True)

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        import time
        from google.api_core.exceptions import ResourceExhausted

        max_retries = 15  # Increased so we can cycle through keys multiple times if needed
        base_wait = 15

        # With 3 keys, we have 45 RPM (3 * 15). 
        # A tiny 1-second sleep is enough to prevent hammering the network.
        time.sleep(1.0)

        prompt = f"System: {system}\n\nUser: {user}"
        
        for attempt in range(max_retries):
            try:
                response = self.model.generate_content(
                    prompt,
                    generation_config={"temperature": temperature, "max_output_tokens": 2048},
                )
                try:
                    return response.text.strip()
                except ValueError:
                    # Occurs if Google blocks the response for safety reasons
                    return "RISK_ASSESSMENT: UNKNOWN\nSafety Blocked by Google."
                    
            except ResourceExhausted as e:
                # If we have multiple keys, just switch immediately and retry!
                if len(self.api_keys) > 1:
                    print(f"\n    [WARN] Rate limit hit on Key #{self.current_key_idx + 1}. Rotating to next key...", file=sys.stderr, flush=True)
                    self.switch_key()
                    # If we completed a full cycle of keys, pause slightly to let them cool down
                    if (attempt + 1) % len(self.api_keys) == 0:
                        time.sleep(5.0)
                    continue
                
                # Fallback to sleep if we only have 1 key
                if attempt == max_retries - 1:
                    raise
                wait_time = base_wait * (2 ** attempt)
                print(f"\n    [WARN] Gemini rate limit hit. Waiting {wait_time}s before retry...", file=sys.stderr, flush=True)
                time.sleep(wait_time)
            except Exception as e:
                if "429" in str(e):
                    if len(self.api_keys) > 1:
                        print(f"\n    [WARN] Rate limit (429) hit on Key #{self.current_key_idx + 1}. Rotating to next key...", file=sys.stderr, flush=True)
                        self.switch_key()
                        if (attempt + 1) % len(self.api_keys) == 0:
                            time.sleep(5.0)
                        continue
                    
                    if attempt == max_retries - 1:
                        raise
                    wait_time = base_wait * (2 ** attempt)
                    print(f"\n    [WARN] Gemini rate limit hit (429). Waiting {wait_time}s before retry...", file=sys.stderr, flush=True)
                    time.sleep(wait_time)
                else:
                    raise

        # If we completely exhaust the retry loop without returning
        raise RuntimeError("Exhausted all retries and API keys due to rate limits.")


class OllamaBackend(LLMBackend):
    """Ollama (local) backend for models like Llama 3, Mistral."""

    def __init__(self, model: str = "llama3", host: str = "http://localhost:11434"):
        import requests
        self.model = model
        self.host = host
        self._requests = requests

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        response = self._requests.post(
            f"{self.host}/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "options": {"temperature": temperature},
            },
            timeout=300,
        )
        response.raise_for_status()
        return response.json()["message"]["content"].strip()


def create_backend(backend_name: str) -> LLMBackend:
    """Factory to create the appropriate LLM backend."""
    load_dotenv(PROJECT_ROOT / ".env")

    if backend_name == "openai":
        key = os.environ.get("OPENAI_API_KEY", "").strip()
        if not key:
            print("[ERROR] OPENAI_API_KEY not found in .env", file=sys.stderr)
            sys.exit(1)
        return OpenAIBackend(api_key=key)

    elif backend_name == "openrouter":
        key = os.environ.get("OPENROUTER_API_KEY", "").strip()
        if not key:
            print("[ERROR] OPENROUTER_API_KEY not found in .env", file=sys.stderr)
            sys.exit(1)
        model = os.environ.get("OPENROUTER_MODEL", "openrouter/free").strip()
        print(f"    [INFO] Initialized OpenRouter backend with model: {model}")
        return OpenRouterBackend(api_key=key, model=model)

    elif backend_name == "groq":
        key = os.environ.get("GROQ_API_KEY", "").strip()
        if not key:
            print("[ERROR] GROQ_API_KEY not found in .env", file=sys.stderr)
            sys.exit(1)
        model = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant").strip()
        return GroqBackend(api_key=key, model=model)

    elif backend_name == "gemini":
        keys = [
            os.environ.get("GEMINI_API_KEY1", "").strip(),
            os.environ.get("GEMINI_API_KEY2", "").strip(),
            os.environ.get("GEMINI_API_KEY3", "").strip(),
        ]
        valid_keys = [k for k in keys if k]
        
        if not valid_keys:
            print("[ERROR] No GEMINI_API_KEY1/2/3 found in .env", file=sys.stderr)
            sys.exit(1)
            
        print(f"    [INFO] Initialized Gemini backend with {len(valid_keys)} rotating keys.")
        return GeminiBackend(api_keys=valid_keys)

    elif backend_name == "ollama":
        model = os.environ.get("OLLAMA_MODEL", "llama3").strip()
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").strip()
        return OllamaBackend(model=model, host=host)

    else:
        print(f"[ERROR] Unknown backend: {backend_name}", file=sys.stderr)
        sys.exit(1)


# =============================================================================
#  CFG Parsing
# =============================================================================

def parse_cfg_file(cfg_path: Path) -> list[FunctionSlice]:
    """
    Parses a _cfg.txt file produced by the Soot slicer into a list of
    FunctionSlice objects (one per sliced function).
    """
    text = cfg_path.read_text(encoding="utf-8")

    if text.strip() == "NO_SUSPICIOUS_APIS_FOUND":
        return []

    slices = []
    # Split on function boundaries
    blocks = re.split(r"=== FUNCTION:", text)

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        # Extract function name from the first line
        lines = block.split("\n")
        func_name = lines[0].strip().rstrip("=").strip()

        suspicious_api = ""
        nodes = []
        edges = []
        raw_lines = []

        for line in lines[1:]:
            line = line.strip()
            if line.startswith("SUSPICIOUS_API:"):
                suspicious_api = line.split(":", 1)[1].strip()
            elif line.startswith("NODE "):
                nodes.append(line)
                raw_lines.append(line)
            elif line.startswith("EDGE:"):
                edges.append(line)
                raw_lines.append(line)
            elif line.startswith("=== END FUNCTION"):
                break

        raw_text = f"=== FUNCTION: {func_name} ===\n"
        raw_text += f"SUSPICIOUS_API: {suspicious_api}\n"
        raw_text += "\n".join(raw_lines)
        raw_text += "\n=== END FUNCTION ===\n"

        slices.append(FunctionSlice(
            function_name=func_name,
            suspicious_api=suspicious_api,
            nodes=nodes,
            edges=edges,
            raw_text=raw_text,
        ))

    return slices


# =============================================================================
#  Tier 1 — Function-Level Analysis
# =============================================================================

def run_tier1(llm: LLMBackend, func_slice: FunctionSlice) -> Tier1Result:
    """Analyse a single sliced CFG at function level."""
    # Truncate very large CFGs but allow generous context now that
    # framework filtering reduces overall volume.
    cfg_text = func_slice.raw_text
    if len(cfg_text) > 6000:
        cfg_text = cfg_text[:6000] + "\n... [truncated for brevity] ..."
    prompt = TIER1_USER_TEMPLATE.format(cfg_content=cfg_text)
    response = llm.chat(TIER1_SYSTEM, prompt)

    # Extract risk level from response
    risk = "UNKNOWN"
    for line in response.split("\n"):
        if "RISK_ASSESSMENT:" in line.upper() or "RISK:" in line.upper():
            if "HIGH" in line.upper() or "CRITICAL" in line.upper():
                risk = "HIGH"
            elif "MEDIUM" in line.upper():
                risk = "MEDIUM"
            elif "LOW" in line.upper():
                risk = "LOW"
            break

    return Tier1Result(
        function_name=func_slice.function_name,
        suspicious_api=func_slice.suspicious_api,
        summary=response,
        risk_level=risk,
    )


# =============================================================================
#  Sanity Check (replaces complex DRC — works with any model size)
# =============================================================================

def sanity_check_tier1(func_slice: FunctionSlice, tier1_summary: str) -> tuple[bool, str]:
    """
    Lightweight sanity check for Tier 1 output. No LLM call needed.

    Checks that the response:
      1. Mentions the suspicious API (or a recognizable part of it)
      2. Contains a RISK_ASSESSMENT or RISK line
      3. Is at least 100 characters (not a garbage/empty response)

    Returns (is_sane, reason_if_failed).
    """
    if len(tier1_summary.strip()) < 100:
        return False, "Response too short (< 100 chars)"

    summary_lower = tier1_summary.lower()

    # Check API mention — use last part of qualified name
    # e.g. "android.telephony.SmsManager.sendTextMessage" → "sendtextmessage"
    api_parts = func_slice.suspicious_api.split(".")
    api_short = api_parts[-1].lower() if api_parts else func_slice.suspicious_api.lower()
    if api_short not in summary_lower and func_slice.suspicious_api.lower() not in summary_lower:
        return False, f"API '{func_slice.suspicious_api}' not mentioned"

    # Check for structured output (RISK or BEHAVIOR)
    has_risk = "risk" in summary_lower
    has_behavior = "behavior" in summary_lower or "behaviour" in summary_lower or "data_flow" in summary_lower
    if not has_risk and not has_behavior:
        return False, "Missing RISK/BEHAVIOR fields"

    return True, "OK"


# =============================================================================
#  Tier 2 — API-Level Aggregation
# =============================================================================

def run_tier2(
    llm: LLMBackend, api_name: str, function_summaries: list[Tier1Result]
) -> Tier2Result:
    """Aggregate function summaries for a single suspicious API."""
    summaries_text = ""
    for i, t1 in enumerate(function_summaries, 1):
        summaries_text += f"\n--- Function {i}: {t1.function_name} ---\n"
        summaries_text += t1.summary + "\n"

    api_type = classify_api_type(api_name)
    prompt = TIER2_USER_TEMPLATE.format(
        api_name=api_name,
        api_type=api_type,
        function_summaries=summaries_text,
        usage_count=len(function_summaries),
    )
    response = llm.chat(TIER2_SYSTEM, prompt)

    # Extract risk level
    risk = "UNKNOWN"
    for line in response.split("\n"):
        if "RISK_LEVEL:" in line.upper() or "RISK:" in line.upper():
            if "CRITICAL" in line.upper():
                risk = "CRITICAL"
            elif "HIGH" in line.upper():
                risk = "HIGH"
            elif "MEDIUM" in line.upper():
                risk = "MEDIUM"
            elif "LOW" in line.upper():
                risk = "LOW"
            break

    return Tier2Result(
        api_name=api_name,
        api_type=api_type,
        summary=response,
        risk_level=risk,
    )


# =============================================================================
#  Tier 3 — APK-Level Prediction
# =============================================================================

def run_tier3(llm: LLMBackend, sha256: str, api_results: list[Tier2Result]) -> Tier3Result:
    """Final malware/benign prediction for one APK."""
    api_summaries = [
        {"api_name": r.api_name, "api_type": r.api_type, "summary": r.summary}
        for r in api_results
    ]
    api_text = format_api_summaries_for_tier3(api_summaries)

    prompt = TIER3_USER_TEMPLATE.format(api_summaries=api_text)
    response = llm.chat(TIER3_SYSTEM, prompt)

    # Extract prediction from response
    prediction = "BENIGN"  # default
    for line in response.split("\n"):
        upper = line.upper().strip()
        if "MALWARE" in upper and ("PREDICTION" in upper or "FINAL" in upper):
            prediction = "MALWARE"
            break
        elif upper.strip("* ").startswith("MALWARE"):
            prediction = "MALWARE"
            break

    return Tier3Result(
        sha256=sha256,
        prediction=prediction,
        analysis=response,
    )


# =============================================================================
#  Full Pipeline — One APK
# =============================================================================

def analyse_one_apk(
    llm: LLMBackend, sha256: str, cfg_path: Path,
    verify_drc: bool = True, verbose: bool = True
) -> Tier3Result | None:
    """
    Runs the full 3-tier pipeline for a single APK.

    Args:
        llm:        LLM backend to use
        sha256:     SHA-256 hash of the APK
        cfg_path:   Path to the sliced CFG text file
        verify_drc: Whether to run factual consistency verification
        verbose:    Print progress

    Returns:
        Tier3Result with the final prediction, or None on failure.
    """
    # ── Parse CFG file ────────────────────────────────────────────────────────
    try:
        slices = parse_cfg_file(cfg_path)
    except Exception as e:
        if verbose:
            print(f"  [ERROR] Cannot parse {cfg_path.name}: {e}")
        return None

    if not slices:
        if verbose:
            print(f"  [SKIP] No suspicious APIs in {sha256[:16]}...")
        return Tier3Result(sha256=sha256, prediction="BENIGN",
                           analysis="No suspicious APIs found.")

    # ── Pre-Processing: Deduplication & Framework Filtering ───────────────────
    original_count = len(slices)
    
    # Proposal 2: Deduplication
    seen_hashes = set()
    unique_slices = []
    for s in slices:
        import hashlib
        # Hash the CFG text to identify exact duplicates
        cfg_hash = hashlib.md5(s.raw_text.encode('utf-8')).hexdigest()
        if cfg_hash not in seen_hashes:
            seen_hashes.add(cfg_hash)
            unique_slices.append(s)
            
    # Proposal 1: Filter Framework/SDK code
    FRAMEWORK_PREFIXES = (
        'android.', 'androidx.', 'java.', 'javax.',
        'com.google.ads.', 'com.google.android.gms.',
        'com.google.firebase.', 'com.facebook.',
        'org.apache.', 'dalvik.'
    )
    # APIs that should ALWAYS be analyzed, even if inside a framework
    SENSITIVE_APIS = (
        'dexclassloader', 'loadclass', 'forname', 'newinstance',
        'load', 'loadlibrary', 'exec', 'getmethod'
    )
    
    filtered_slices = []
    for s in unique_slices:
        api_lower = s.suspicious_api.lower()
        is_sensitive = any(sec in api_lower for sec in SENSITIVE_APIS)
        
        if s.function_name.startswith(FRAMEWORK_PREFIXES) and not is_sensitive:
            continue
        filtered_slices.append(s)

    slices = filtered_slices

    if verbose and original_count > 0:
        print(f"    [INFO] CFGs: {original_count} raw -> {len(unique_slices)} unique -> {len(slices)} filtered")

    # Safety cap: even after filtering, some APKs have 200+ app functions.
    # Cap at 25 to keep per-APK time reasonable (~1-2 min).
    MAX_FUNCTIONS = 25
    if len(slices) > MAX_FUNCTIONS:
        if verbose:
            print(f"    [INFO] Capping at {MAX_FUNCTIONS} functions (from {len(slices)})")
        slices = slices[:MAX_FUNCTIONS]

    tier1_results: list[Tier1Result] = []
    for func_slice in slices:
        try:
            t1 = run_tier1(llm, func_slice)

            # Sanity check (free — no LLM call)
            if verify_drc:
                is_sane, reason = sanity_check_tier1(func_slice, t1.summary)
                if not is_sane:
                    if verbose:
                        print(f"    [SANITY] Retrying {func_slice.function_name}: {reason}")
                    t1 = run_tier1(llm, func_slice)  # retry once

            tier1_results.append(t1)
        except Exception as e:
            if verbose:
                print(f"    [ERROR] Tier 1 failed for {func_slice.function_name}: {e}")

    if not tier1_results:
        return Tier3Result(sha256=sha256, prediction="BENIGN",
                           analysis="All function analyses failed.")

    # ── Tier 2: API-level aggregation ─────────────────────────────────────────
    # Group Tier 1 results by suspicious API
    api_groups: dict[str, list[Tier1Result]] = {}
    for t1 in tier1_results:
        api_groups.setdefault(t1.suspicious_api, []).append(t1)

    tier2_results: list[Tier2Result] = []
    for api_name, functions in api_groups.items():
        try:
            t2 = run_tier2(llm, api_name, functions)
            tier2_results.append(t2)
        except Exception as e:
            if verbose:
                print(f"    [ERROR] Tier 2 failed for {api_name}: {e}")

    if not tier2_results:
        return Tier3Result(sha256=sha256, prediction="BENIGN",
                           analysis="All API analyses failed.")

    # ── Tier 3: APK-level prediction ──────────────────────────────────────────
    try:
        result = run_tier3(llm, sha256, tier2_results)
        return result
    except Exception as e:
        if verbose:
            print(f"    [ERROR] Tier 3 failed: {e}")
        return None


# =============================================================================
#  Mode: Analyse from existing malware logs
# =============================================================================

def parse_malware_log(log_path: Path) -> tuple[str, str]:
    """
    Parses a pre-computed malware analysis log from lamd/malware_logs/.
    Returns (prediction, full_analysis_text).
    """
    text = log_path.read_text(encoding="utf-8")
    prediction = "BENIGN"

    for line in text.split("\n"):
        upper = line.upper().strip()
        if "MALWARE" in upper and ("PREDICTION" in upper or "FINAL" in upper):
            prediction = "MALWARE"
            break
        elif upper.strip("* ").startswith("MALWARE"):
            prediction = "MALWARE"
            break

    return prediction, text


# =============================================================================
#  Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="LAMD Phase 2: Tier-wise LLM code reasoning for malware detection."
    )
    parser.add_argument(
        "--mode", choices=["cfg", "logs", "direct"], default="cfg",
        help="Analysis mode: 'cfg' (from extracted CFGs), 'logs' (from pre-computed "
             "malware logs), 'direct' (single-shot on CFG without tiers)."
    )
    parser.add_argument(
        "--backend", choices=["openai", "gemini", "ollama", "groq", "openrouter"], default="openai",
        help="LLM backend to use (default: openai)."
    )
    parser.add_argument(
        "--csv", type=Path, default=TRAIN_CSV,
        help="CSV file with sha256 + labels for evaluation."
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Process only the first N samples."
    )
    parser.add_argument(
        "--no-drc", action="store_true",
        help="Skip factual consistency verification (faster but less reliable)."
    )
    parser.add_argument(
        "--output", type=Path, default=None,
        help="Output JSONL file for predictions."
    )
    args = parser.parse_args()

    print("=" * 65)
    print("  LAMD Phase 2 — Tier-Wise LLM Code Reasoning")
    print("=" * 65)
    print(f"  Mode    : {args.mode}")
    print(f"  Backend : {args.backend}")
    print(f"  CSV     : {args.csv}")
    print(f"  DRC     : {'disabled' if args.no_drc else 'enabled'}")
    print("=" * 65)
    print()

    # ── Output path ───────────────────────────────────────────────────────────
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = args.output or (RESULTS_DIR / f"predictions_{args.mode}.jsonl")

    # ── Mode: Pre-computed logs ───────────────────────────────────────────────
    if args.mode == "logs":
        print(f"[INFO] Reading pre-computed logs from {LOG_DIR}")
        if not LOG_DIR.is_dir():
            print(f"[ERROR] Log directory not found: {LOG_DIR}", file=sys.stderr)
            sys.exit(1)

        log_files = sorted(LOG_DIR.glob("*.log"))
        if args.limit:
            log_files = log_files[:args.limit]

        print(f"[INFO] {len(log_files)} log file(s) found.")

        results = []
        for idx, log_path in enumerate(log_files, 1):
            sha256 = log_path.stem.lower()
            prediction, analysis = parse_malware_log(log_path)
            results.append({
                "sha256": sha256,
                "prediction": prediction,
                "analysis_length": len(analysis),
            })
            if idx % 50 == 0 or idx == len(log_files):
                print(f"  Processed {idx}/{len(log_files)}...")

        with open(output_path, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

        mal = sum(1 for r in results if r["prediction"] == "MALWARE")
        ben = sum(1 for r in results if r["prediction"] == "BENIGN")
        print(f"\n[OK] {len(results)} predictions written to {output_path}")
        print(f"    MALWARE: {mal}  |  BENIGN: {ben}")
        return

    # ── Mode: CFG analysis (full tier-wise pipeline) ──────────────────────────
    if args.mode in ("cfg", "direct"):
        # Create the LLM backend
        llm = create_backend(args.backend)
        print(f"[OK] LLM backend '{args.backend}' initialized.\n")

        # Load CSV for ground truth
        if args.csv.is_file():
            df = pd.read_csv(
                args.csv,
                usecols=["sha256", "family", "label"],
                dtype={"sha256": str, "family": str, "label": float},
            )
            df["sha256"] = df["sha256"].str.strip().str.lower()
            df.dropna(subset=["sha256"], inplace=True)
            df.drop_duplicates(subset=["sha256"], inplace=True)

            if args.limit:
                df = df.head(args.limit)

            print(f"[INFO] {len(df)} sample(s) loaded from {args.csv.name}")
        else:
            print(f"[WARN] CSV not found: {args.csv}. Running without ground truth.")
            df = pd.DataFrame(columns=["sha256", "family", "label"])

        # Find CFG files
        if not CFG_DIR.is_dir():
            print(f"[ERROR] CFG directory not found: {CFG_DIR}", file=sys.stderr)
            print("  Run  python src_python/2_extract_cfg.py  first.")
            sys.exit(1)

        results = []
        total = len(df)
        run_start = time.time()

        for idx, row in df.iterrows():
            sha256 = row["sha256"]
            cfg_path = CFG_DIR / f"{sha256}_cfg.txt"
            i = len(results) + 1

            print(f"[{i:>5}/{total}] {sha256[:20]}...", end="  ", flush=True)

            if not cfg_path.is_file():
                print("SKIP (no CFG)")
                continue

            t0 = time.time()

            if args.mode == "direct":
                # Single-shot analysis without tiers
                try:
                    cfg_text = cfg_path.read_text(encoding="utf-8")
                    # Truncate for rate-limited backends
                    if len(cfg_text) > 1500:
                        cfg_text = cfg_text[:1500] + "\n... [truncated] ..."
                    prompt = DIRECT_ANALYSIS_TEMPLATE.format(cfg_content=cfg_text)
                    response = llm.chat(DIRECT_ANALYSIS_SYSTEM, prompt)
                    prediction = "MALWARE" if "MALWARE" in response.upper().split("PREDICTION")[0:2].__repr__() else "BENIGN"
                    for line in response.split("\n"):
                        if "MALWARE" in line.upper() and "PREDICTION" in line.upper():
                            prediction = "MALWARE"
                            break
                    result = Tier3Result(sha256=sha256, prediction=prediction, analysis=response)
                except Exception as e:
                    print(f"ERROR: {e}")
                    continue
            else:
                # Full tier-wise pipeline
                result = analyse_one_apk(
                    llm, sha256, cfg_path,
                    verify_drc=not args.no_drc,
                    verbose=True,
                )

            if result is None:
                print("FAILED")
                continue

            elapsed = time.time() - t0
            gt_label = "MALWARE" if row.get("label", 0) == 1.0 else "BENIGN"
            match = "OK" if result.prediction == gt_label else "X"

            print(f"{result.prediction:8s} (gt={gt_label}) [{match}] ({elapsed:.1f}s)")

            results.append({
                "sha256": sha256,
                "prediction": result.prediction,
                "ground_truth": gt_label,
                "family": str(row.get("family", "")),
                "analysis": result.analysis,
            })

        # ── Write results ─────────────────────────────────────────────────────
        with open(output_path, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

        elapsed_total = time.time() - run_start

        # ── Summary ───────────────────────────────────────────────────────────
        correct = sum(1 for r in results if r["prediction"] == r["ground_truth"])
        total_done = len(results)

        print()
        print("=" * 65)
        print("  Inference Complete")
        print("=" * 65)
        print(f"  Samples processed : {total_done}")
        print(f"  Correct           : {correct}")
        print(f"  Accuracy          : {correct/total_done*100:.1f}%" if total_done else "  Accuracy          : N/A")
        print(f"  Total time        : {elapsed_total:.1f}s")
        print(f"  Predictions saved : {output_path}")
        print("=" * 65)
        print()
        print(f"  Run evaluation:  python src_python/5_evaluate.py --predictions {output_path}")


if __name__ == "__main__":
    main()
