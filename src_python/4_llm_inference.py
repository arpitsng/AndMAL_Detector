"""
LAMD Pipeline — Step 4: LLM Code Reasoning for Malware Detection
=================================================================
Implements the LAMD malware detection pipeline with multiple modes:

  - Single-Call (recommended): Send ALL CFGs + RAG context in one LLM call
  - 3-Tier: Function → API → APK level analysis (paper-faithful)
  - Direct: Single-shot without tiers or RAG

Supports multiple LLM backends:
  - Google Gemini (gemini-3.5-flash — primary, 1M token context)
  - OpenAI (GPT-4o-mini)
  - Ollama (local models like Llama 3, Mistral)

Usage:
  # Single-Call with RAG (recommended)
  python src_python/4_llm_inference.py --mode cfg --backend gemini --single --csv data/test_1.csv

  # With offset and limit
  python src_python/4_llm_inference.py --mode cfg --backend gemini --single --csv data/train.csv --offset 2000 --limit 20

Environment:
  Set your API keys in .env:
    GEMINI_API_KEY1=... / GEMINI_API_KEY2=... / GEMINI_API_KEY3=...
    QDRANT_URL=... / QDRANT_API_KEY=...
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
import time
import zipfile

# Configure HuggingFace mirror endpoint before importing fastembed/huggingface_hub
os.environ["HF_ENDPOINT"] = os.environ.get("HF_ENDPOINT", "https://hf-mirror.com")

from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict

import pandas as pd
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv

# Allow running from project root or src_python/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src_python"))

from prompts import (
    TIER1_SYSTEM, TIER1_USER_TEMPLATE,
    TIER2_SYSTEM, TIER2_USER_TEMPLATE,
    TIER2_BATCH_SYSTEM, TIER2_BATCH_USER_TEMPLATE,
    TIER3_SYSTEM, TIER3_USER_TEMPLATE,
    DRC_SYSTEM, DRC_USER_TEMPLATE,
    DRC_VERIFY_SYSTEM, DRC_VERIFY_USER_TEMPLATE,
    DIRECT_ANALYSIS_SYSTEM, DIRECT_ANALYSIS_TEMPLATE,
    SINGLE_CALL_SYSTEM, SINGLE_CALL_TEMPLATE,
    format_api_summaries_for_tier3, classify_api_type,
)
from console_ui import (
    console, banner, section, ok, fail, warn, info,
    sample_result_line, sample_skip_line, sample_error_line,
    make_progress,
)

# =============================================================================
#  Paths
# =============================================================================

TRAIN_CSV    = PROJECT_ROOT / "data" / "train.csv"
CFG_DIR      = PROJECT_ROOT / "extracted_cfgs"
APK_DIR      = PROJECT_ROOT / "apks"
JAR_PATH     = PROJECT_ROOT / "Slicer" / "target" / "slicer-1.0.jar"
ANDROZOO_URL = "https://androzoo.uni.lu/api/download"
LOG_DIR      = PROJECT_ROOT / "lamd" / "malware_logs"
RESULTS_DIR  = PROJECT_ROOT / "results"

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
#  Token counting
# =============================================================================
# Jimple IR text tokenizes much more densely than English prose — measured
# directly on real CFG content: ~2.85 chars/token, not the ~4 chars/token
# rule of thumb (that gap is exactly what caused a real Groq 413 error this
# session: a request estimated at ~12,700 tokens via chars//4 was actually
# ~23,800 tokens by Groq's own count). Use a real tokenizer for budget
# decisions instead of a flat character heuristic.

_tiktoken_encoder = None

def count_tokens(text: str) -> int:
    """Real token count via tiktoken (cl100k_base) — not exact for every
    backend's specific tokenizer, but far closer than a chars/N guess for
    this IR-heavy content. Falls back to a conservative chars//3 estimate
    if tiktoken is unavailable for any reason."""
    global _tiktoken_encoder
    try:
        if _tiktoken_encoder is None:
            import tiktoken
            _tiktoken_encoder = tiktoken.get_encoding("cl100k_base")
        return len(_tiktoken_encoder.encode(text, disallowed_special=()))
    except Exception:
        return len(text) // 3


# =============================================================================
#  LLM Backend Abstraction
# =============================================================================

class LLMBackend:
    """Abstract interface for LLM API calls."""

    # Safe single-call prompt budget in TOKENS (see count_tokens() above),
    # sized to leave headroom under this backend's real context window
    # AND rate-limit quota for the system prompt, template text, RAG
    # context, and response. The single-call pipeline
    # (analyse_one_apk_single_call) reads this via
    # getattr(llm, "MAX_CONTEXT_TOKENS", ...) — subclasses override it.
    # Conservative default for unknown/small-context backends.
    MAX_CONTEXT_TOKENS = 15_000

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        raise NotImplementedError


class OpenAIBackend(LLMBackend):
    """OpenAI GPT-4o-mini backend (default — as used in LAMD paper)."""

    MAX_CONTEXT_TOKENS = 80_000  # within gpt-4o-mini's 128K ctx — capability-based, not empirically rate-limit-tested

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
    """
    OpenRouter backend (using OpenAI client compatibility).

    OpenRouter routes ":free" model slugs to shared, sometimes-congested
    upstream pools — different free models have very different real
    throughput. Verified directly this session: google/gemma-4-31b-it:free
    and openai/gpt-oss-20b:free hit transient 429 "temporarily rate-limited
    upstream" errors, while nvidia/nemotron-3-super-120b-a12b:free accepted
    6 back-to-back ~20K-token requests with no rate limit at all (sub-2s
    each). Context budget below is bumped up for models confirmed to
    handle that; stays conservative for anything unverified.
    """

    # Models empirically confirmed (this session) to accept large single-call
    # requests without hitting OpenRouter's shared free-tier congestion.
    _VERIFIED_LARGE_CONTEXT_FREE_MODELS = {
        "nvidia/nemotron-3-ultra-550b-a55b:free",
        "nvidia/nemotron-3-super-120b-a12b:free",
        "nvidia/nemotron-3.5-lightning:free",
        "nvidia/llama-3.1-nemotron-70b-instruct:free",
    }

    def __init__(self, api_keys: list[str], model: str = "nvidia/nemotron-3-ultra-550b-a55b:free"):
        # pyrefly: ignore [import, missing-import]
        from openai import OpenAI
        self.api_keys = [k for k in api_keys if k]
        if not self.api_keys:
            raise ValueError("OpenRouterBackend requires at least one API key")
        self.current_key_idx = 0
        self.model = model
        self._OpenAI = OpenAI
        self.client = OpenAI(
            api_key=self.api_keys[0],
            base_url="https://openrouter.ai/api/v1",
        )
        if model in self._VERIFIED_LARGE_CONTEXT_FREE_MODELS or "nemotron" in model.lower():
            self.MAX_CONTEXT_TOKENS = 200_000  # verified 262K ctx model, safety margin below it
        else:
            self.MAX_CONTEXT_TOKENS = 30_000  # conservative — unverified free model

    def switch_key(self):
        """Rotate to the next API key in the pool."""
        self.current_key_idx = (self.current_key_idx + 1) % len(self.api_keys)
        self.client = self._OpenAI(
            api_key=self.api_keys[self.current_key_idx],
            base_url="https://openrouter.ai/api/v1",
        )
        print(f"\n    [INFO] Switched to OpenRouter API Key #{self.current_key_idx + 1}", file=sys.stderr, flush=True)

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        import time
        # pyrefly: ignore [missing-import]
        from openai import RateLimitError
        max_retries = 15
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
                    max_tokens=4096,
                )
                return response.choices[0].message.content.strip()
            except RateLimitError as e:
                if len(self.api_keys) > 1:
                    print(f"\n    [WARN] Rate limit hit on Key #{self.current_key_idx + 1}. Rotating to next key...", file=sys.stderr, flush=True)
                    self.switch_key()
                    if (attempt + 1) % len(self.api_keys) == 0:
                        time.sleep(5.0)
                    continue
                if attempt == max_retries - 1:
                    raise
                wait_time = base_wait * (2 ** attempt)
                print(f"\n    [WARN] OpenRouter rate limit hit. Waiting {wait_time}s before retry...", file=sys.stderr, flush=True)
                time.sleep(wait_time)
            except Exception as e:
                if "429" in str(e) or "402" in str(e): # 402 Payment Required or 429 Too Many Requests
                    if len(self.api_keys) > 1:
                        print(f"\n    [WARN] OpenRouter error ({e}). Rotating to next key...", file=sys.stderr, flush=True)
                        self.switch_key()
                        continue
                    if attempt == max_retries - 1:
                        raise
                    wait_time = base_wait * (2 ** attempt)
                    print(f"\n    [WARN] OpenRouter rate limit/payment error. Waiting {wait_time}s before retry...", file=sys.stderr, flush=True)
                    time.sleep(wait_time)
                else:
                    raise


class NvidiaBackend(LLMBackend):
    """
    NVIDIA NIM API backend with multi-key rotation.
    Base URL: https://integrate.api.nvidia.com/v1
    Default model: nvidia/llama-3.1-nemotron-70b-instruct
    """
    MAX_CONTEXT_TOKENS = 120_000

    def __init__(self, api_keys: list[str], model: str = "nvidia/llama-3.1-nemotron-70b-instruct"):
        from openai import OpenAI
        self.api_keys = [k for k in api_keys if k]
        if not self.api_keys:
            raise ValueError("NvidiaBackend requires at least one API key")
        self.current_key_idx = 0
        self.model = model
        self._OpenAI = OpenAI
        self.client = OpenAI(
            api_key=self.api_keys[0],
            base_url="https://integrate.api.nvidia.com/v1",
        )

    def switch_key(self):
        self.current_key_idx = (self.current_key_idx + 1) % len(self.api_keys)
        self.client = self._OpenAI(
            api_key=self.api_keys[self.current_key_idx],
            base_url="https://integrate.api.nvidia.com/v1",
        )
        print(f"\n    [INFO] Switched to NVIDIA API Key #{self.current_key_idx + 1}", file=sys.stderr, flush=True)

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        import time
        from openai import RateLimitError
        max_retries = 15
        base_wait = 10
        time.sleep(1.0)
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
                if len(self.api_keys) > 1:
                    print(f"\n    [WARN] Rate limit hit on NVIDIA Key #{self.current_key_idx + 1}. Rotating to next key...", file=sys.stderr, flush=True)
                    self.switch_key()
                    if (attempt + 1) % len(self.api_keys) == 0:
                        time.sleep(5.0)
                    continue
                if attempt == max_retries - 1:
                    raise
                wait_time = base_wait * (2 ** attempt)
                print(f"\n    [WARN] NVIDIA rate limit hit. Waiting {wait_time}s before retry...", file=sys.stderr, flush=True)
                time.sleep(wait_time)
            except Exception as e:
                if "429" in str(e) or "402" in str(e):
                    if len(self.api_keys) > 1:
                        print(f"\n    [WARN] NVIDIA error ({e}). Rotating to next key...", file=sys.stderr, flush=True)
                        self.switch_key()
                        continue
                    if attempt == max_retries - 1:
                        raise
                    wait_time = base_wait * (2 ** attempt)
                    print(f"\n    [WARN] NVIDIA API error. Waiting {wait_time}s before retry...", file=sys.stderr, flush=True)
                    time.sleep(wait_time)
                else:
                    raise


class GroqBackend(LLMBackend):
    """
    Groq backend (using OpenAI client compatibility), with multi-key rotation.

    NOTE: as with Gemini, rotation only multiplies effective throughput if
    each key is genuinely a separate account/org — keys created under the
    same Groq account/org typically share one quota pool, so rotating
    between those just adds latency with no throughput benefit. Verify at
    https://console.groq.com/settings/limits per key before assuming N keys
    = N x throughput.

    IMPORTANT — verified directly this session, not a spec-sheet number:
    Groq's free/on_demand tier caps at 8,000 TOKENS PER MINUTE, org-wide,
    confirmed identically across openai/gpt-oss-120b, openai/gpt-oss-20b,
    and qwen/qwen3.6-27b. This is far below the model's ~128K context
    window capability — a single request over ~8K tokens gets HARD
    REJECTED (413), not just throttled. MAX_CONTEXT_TOKENS reflects the
    rate limit, not the context window, and leaves room for max_tokens
    (below) plus the fixed prompt template + RAG context overhead.
    Practically: single-call mode can only handle small APKs on this tier
    — the tiered pipeline (many small calls) is the realistic option for
    Groq's free tier, or a paid Dev Tier removes this ceiling.
    """

    MAX_CONTEXT_TOKENS = 4_000  # leaves ~1.5K for template/RAG + ~2.5K for completion, under the real 8K/min ceiling

    def __init__(self, api_keys: list[str], model: str = "openai/gpt-oss-120b"):
        # pyrefly: ignore [import, missing-import]
        from openai import OpenAI
        self.api_keys = [k for k in api_keys if k]
        if not self.api_keys:
            raise ValueError("GroqBackend requires at least one API key")
        self.current_key_idx = 0
        self.model = model
        self._OpenAI = OpenAI
        self.client = OpenAI(api_key=self.api_keys[0], base_url="https://api.groq.com/openai/v1")

    def switch_key(self):
        """Rotate to the next API key in the pool."""
        self.current_key_idx = (self.current_key_idx + 1) % len(self.api_keys)
        self.client = self._OpenAI(
            api_key=self.api_keys[self.current_key_idx],
            base_url="https://api.groq.com/openai/v1",
        )
        print(f"\n    [INFO] Switched to Groq API Key #{self.current_key_idx + 1}", file=sys.stderr, flush=True)

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        import time
        # pyrefly: ignore [missing-import]
        from openai import RateLimitError
        max_retries = 15  # allow cycling through the key pool multiple times
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
                    # Kept modest deliberately — the real 8K TPM ceiling
                    # (see class docstring) has to cover prompt + completion
                    # together, so a large completion reservation starves
                    # the prompt budget.
                    max_tokens=1024,
                )
                return response.choices[0].message.content.strip()
            except RateLimitError as e:
                if len(self.api_keys) > 1:
                    print(f"\n    [WARN] Rate limit hit on Key #{self.current_key_idx + 1}. Rotating to next key...", file=sys.stderr, flush=True)
                    self.switch_key()
                    if (attempt + 1) % len(self.api_keys) == 0:
                        time.sleep(5.0)  # full cycle through all keys — brief cooldown
                    continue
                if attempt == max_retries - 1:
                    raise
                wait_time = base_wait * (2 ** attempt)
                print(f"\n    [WARN] Groq rate limit hit. Waiting {wait_time}s before retry...", file=sys.stderr, flush=True)
                time.sleep(wait_time)
            except Exception as e:
                if "429" in str(e):
                    if len(self.api_keys) > 1:
                        print(f"\n    [WARN] Rate limit hit (429) on Key #{self.current_key_idx + 1}. Rotating to next key...", file=sys.stderr, flush=True)
                        self.switch_key()
                        if (attempt + 1) % len(self.api_keys) == 0:
                            time.sleep(5.0)
                        continue
                    if attempt == max_retries - 1:
                        raise
                    wait_time = base_wait * (2 ** attempt)
                    print(f"\n    [WARN] Groq rate limit hit (429). Waiting {wait_time}s before retry...", file=sys.stderr, flush=True)
                    time.sleep(wait_time)
                else:
                    raise

        raise RuntimeError("Exhausted all retries and API keys.")


class GeminiBackend(LLMBackend):
    """
    Google Gemini backend with multi-key rotation.

    NOTE: Gemini rate limits are applied per Google Cloud PROJECT, not per
    API key. Rotating between keys only increases your effective throughput
    if each key belongs to a *different* project (or different Google
    accounts). Keys generated inside the same project all share one quota
    pool — rotation between those just adds latency with no benefit.

    Uses the new unified `google-genai` SDK (the old `google-generativeai`
    package is deprecated and gemini-2.0-flash has been retired).
    """

    MAX_CONTEXT_TOKENS = 800_000  # within Gemini's 1M ctx — this is the one empirically validated at real scale (80% acc, 15-sample run)

    def __init__(self, api_keys: list[str], model: str = "gemini-3.5-flash"):
        # pyrefly: ignore [missing-import]
        from google import genai
        # pyrefly: ignore [missing-import]
        from google.genai import types
        self.api_keys = [k for k in api_keys if k]
        self.current_key_idx = 0
        self.model_name = model
        self._genai = genai
        self._types = types

        # Client for the first key initially
        self.client = genai.Client(api_key=self.api_keys[self.current_key_idx])

    def switch_key(self):
        """Rotate to the next API key in the pool."""
        self.current_key_idx = (self.current_key_idx + 1) % len(self.api_keys)
        self.client = self._genai.Client(api_key=self.api_keys[self.current_key_idx])
        print(f"\n    [INFO] Switched to Gemini API Key #{self.current_key_idx + 1}", file=sys.stderr, flush=True)

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        import time
        # pyrefly: ignore [missing-import]
        from google.genai.errors import ClientError

        max_retries = 15  # Increased so we can cycle through keys multiple times if needed
        base_wait = 15

        # With 3 keys (ideally 3 separate projects), we have more combined
        # throughput. A tiny 1-second sleep is enough to prevent hammering.
        time.sleep(1.0)

        for attempt in range(max_retries):
            try:
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=user,
                    config=self._types.GenerateContentConfig(
                        system_instruction=system,
                        temperature=temperature,
                        # Newer Gemini models spend part of max_output_tokens on
                        # hidden "thinking" tokens before writing the visible
                        # answer. Verified directly: with max_output_tokens=2048,
                        # a real call spent 1710 tokens on thoughts_token_count
                        # and got cut off (finish_reason=MAX_TOKENS) after only
                        # ~250 characters of visible output — silently truncating
                        # the structured PREDICTION/EVIDENCE fields mid-sentence.
                        # Bound thinking explicitly and give the visible answer
                        # a generous, separate ceiling so it can never starve.
                        max_output_tokens=8192,
                        thinking_config=self._types.ThinkingConfig(thinking_budget=1024),
                    ),
                )
                try:
                    return response.text.strip()
                except (ValueError, AttributeError):
                    # Occurs if Google blocks the response for safety reasons
                    # or returns no candidates.
                    return "RISK_ASSESSMENT: UNKNOWN\nSafety Blocked by Google."

            except Exception as e:
                err_str = str(e).upper()
                is_rate_limited = "429" in err_str or "RESOURCE_EXHAUSTED" in err_str
                is_unavailable = "503" in err_str or "UNAVAILABLE" in err_str
                is_permission = "403" in err_str or "PERMISSION_DENIED" in err_str or "401" in err_str or "UNAUTHENTICATED" in err_str
                is_not_found = "404" in err_str or "NOT_FOUND" in err_str
                is_network = "GETADDRINFO" in err_str or "CONNECTION" in err_str or "TIMEOUT" in err_str or "NAMERESOLUTIONERROR" in err_str or "WINERROR 10054" in err_str or "WINERROR 11001" in err_str

                if is_network:
                    wait_time = min(5 * (attempt + 1), 30)
                    print(f"\n    [WARN] Network/DNS connection issue ({e}). Waiting {wait_time}s before retry ({attempt + 1}/{max_retries})...", file=sys.stderr, flush=True)
                    time.sleep(wait_time)
                    continue

                if is_permission or is_not_found:
                    print(f"\n    [WARN] Key #{self.current_key_idx + 1} failed ({'Permission Denied' if is_permission else 'Model Not Found'}).", file=sys.stderr, flush=True)
                    if len(self.api_keys) > 1:
                        print(f"    [INFO] Rotating to next Gemini key...", file=sys.stderr, flush=True)
                        self.switch_key()
                        continue
                    else:
                        raise

                if is_rate_limited or is_unavailable:
                    if len(self.api_keys) > 1:
                        print(f"\n    [WARN] Rate limit (429/503) hit on Key #{self.current_key_idx + 1}. Rotating to next key...", file=sys.stderr, flush=True)
                        self.switch_key()
                        if (attempt + 1) % len(self.api_keys) == 0:
                            time.sleep(5.0)
                        continue

                    if attempt == max_retries - 1:
                        raise
                    wait_time = base_wait * (2 ** attempt)
                    print(f"\n    [WARN] Gemini API error (429/503). Waiting {wait_time}s before retry...", file=sys.stderr, flush=True)
                    time.sleep(wait_time)
                else:
                    raise

        # If we completely exhaust the retry loop without returning
        raise RuntimeError("Exhausted all retries and API keys.")


class OllamaBackend(LLMBackend):
    """
    Ollama (local) backend — for locally-served models like Qwen, Gemma, Llama.

    IMPORTANT: Ollama silently defaults to a small context window (often
    2048-4096 tokens) regardless of what the underlying model actually
    supports, UNLESS num_ctx is explicitly passed per-request or baked into
    a custom Modelfile. Without this, a 32B model nominally capable of 32K+
    context would silently truncate/ignore most of a CFG prompt with no
    error — a likely silent-failure trap for local testing.

    num_ctx is set explicitly below (default 32768, override via
    OLLAMA_NUM_CTX) — but this must fit your GPU's VRAM at your model's
    quant level; lower it if you hit OOM errors. MAX_CONTEXT_TOKENS is
    derived directly from num_ctx (already a token count) so the
    single-call pipeline doesn't build prompts bigger than what you've
    actually configured Ollama to accept.
    """

    def __init__(self, model: str = None, host: str = "http://localhost:11434"):
        import requests
        self.host = host.rstrip("/")
        self._requests = requests
        self.num_ctx = int(os.environ.get("OLLAMA_NUM_CTX", "32768"))
        self.timeout = int(os.environ.get("OLLAMA_TIMEOUT", "600"))
        # 15% headroom for system+template+RAG context+response.
        self.MAX_CONTEXT_TOKENS = int(self.num_ctx * 0.85)

        # Auto-detect model if not explicitly specified
        if not model:
            model = os.environ.get("OLLAMA_MODEL", "").strip()

        if not model:
            try:
                tags_resp = self._requests.get(f"{self.host}/api/tags", timeout=5)
                if tags_resp.status_code == 200:
                    models = tags_resp.json().get("models", [])
                    if models:
                        model = models[0].get("name", "llama3")
            except Exception:
                pass

        self.model = model or "llama3"
        print(f"    [INFO] Initialized Ollama backend (model: {self.model}, num_ctx: {self.num_ctx}, host: {self.host})")

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
                "options": {"temperature": temperature, "num_ctx": self.num_ctx},
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()["message"]["content"].strip()


MODEL_ALIASES = {
    "qwen2.5:32b": "Qwen/Qwen2.5-32B-Instruct",
    "qwen2.5-coder:32b": "Qwen/Qwen2.5-Coder-32B-Instruct",
    "qwen2.5:14b": "Qwen/Qwen2.5-14B-Instruct",
    "qwen2.5-coder:14b": "Qwen/Qwen2.5-Coder-14B-Instruct",
    "qwen2.5:7b": "Qwen/Qwen2.5-7B-Instruct",
    "qwen2.5-coder:7b": "Qwen/Qwen2.5-Coder-7B-Instruct",
    "qwen2.5:3b": "Qwen/Qwen2.5-3B-Instruct",
    "qwen2.5:1.5b": "Qwen/Qwen2.5-Coder-1.5B-Instruct",
}


class LocalGPUBackend:
    """
    Native Multi-GPU CUDA backend using PyTorch + HuggingFace Transformers.
    Directly offloads and balances model layers across dual Quadro RTX 5000 GPUs.
    Bypasses Ollama Windows DLL discovery issues with 100% hardware acceleration.
    """
    def __init__(self, model_name: str | None = None, load_in_4bit: bool = False):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        
        raw_name = (model_name or os.environ.get("LOCAL_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")).strip()
        self.model_name = MODEL_ALIASES.get(raw_name.lower(), raw_name)
        
        self.device_count = torch.cuda.device_count()
        print(f"    [INFO] Initializing Native Dual-GPU Local Backend ({self.device_count} GPUs detected)...")
        for i in range(self.device_count):
            prop = torch.cuda.get_device_properties(i)
            print(f"           GPU {i}: {prop.name} ({prop.total_memory / (1024**3):.1f} GB VRAM)")

        print(f"    [INFO] Loading '{self.model_name}' with device_map='auto' across all GPUs...")
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name, trust_remote_code=True)
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                device_map="auto",
                dtype=torch.float16,
                trust_remote_code=True,
            )
            self.MAX_CONTEXT_TOKENS = 32768
            device_map = getattr(self.model, "hf_device_map", "cuda")
            print(f"    [OK] Model successfully loaded & balanced across GPUs: {device_map}")
        except Exception as e:
            print(f"    [ERROR] Failed to load local model '{self.model_name}': {e}", file=sys.stderr)
            raise e

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        import torch
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer([text], return_tensors="pt").to("cuda")
        eos_id = self.tokenizer.eos_token_id
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=384,
                temperature=temperature if temperature > 0 else None,
                do_sample=(temperature > 0),
                eos_token_id=eos_id,
                pad_token_id=eos_id,
            )
        response = self.tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
        return response.strip()


class LlamaCppBackend:
    """
    Local GGUF backend using llama-cpp-python with dual-GPU tensor splitting.
    Executes the 18.5 GB Qwen 2.5 32B model with 50/50 VRAM distribution across
    GPU 0 (Quadro RTX 5000) and GPU 1 (Quadro RTX 5000).
    """
    def __init__(self, model_path: str | None = None, n_ctx: int | None = None):
        torch_lib = PROJECT_ROOT / "venv" / "Lib" / "site-packages" / "torch" / "lib"
        if torch_lib.is_dir():
            os.add_dll_directory(str(torch_lib))
            os.environ["PATH"] = str(torch_lib) + ";" + os.environ.get("PATH", "")

        from llama_cpp import Llama

        default_blob = Path.home() / ".ollama" / "models" / "blobs" / "sha256-eabc98a9bcbfce7fd70f3e07de599f8fda98120fefed5881934161ede8bd1a41"
        target_model = model_path or str(default_blob)
        if not os.path.isfile(target_model):
            # Check model aliases
            if target_model.lower() in ("qwen2.5:32b", "qwen2.5-32b", "32b"):
                target_model = str(default_blob)

        if n_ctx is None:
            n_ctx = int(os.environ.get("LOCAL_NUM_CTX", "16384"))

        print(f"    [INFO] Initializing Native Dual-GPU GGUF Engine (llama.cpp CUDA)...")
        print(f"           Model Path   : {target_model}")
        print(f"           Tensor Split : [0.5, 0.5] (GPU 0 & GPU 1)")
        print(f"           Context Size : {n_ctx}")

        self.llm = Llama(
            model_path=target_model,
            n_gpu_layers=-1,          # Offload 100% of layers to GPU VRAM
            tensor_split=[0.5, 0.5],  # 50% on GPU 0 (16GB), 50% on GPU 1 (16GB)
            n_ctx=n_ctx,
            flash_attn=True,
            verbose=False,
        )
        self.MAX_CONTEXT_TOKENS = int(n_ctx * 0.85)
        print(f"    [OK] Qwen 2.5 32B GGUF successfully loaded and balanced across Dual GPUs!")

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        response = self.llm.create_chat_completion(
            messages=messages,
            max_tokens=1024,
            temperature=temperature if temperature > 0 else 0.0,
        )
        return response["choices"][0]["message"]["content"].strip()



def create_backend(backend_name: str, model_override: str = None) -> LLMBackend:
    """Factory to create the appropriate LLM backend."""
    load_dotenv(PROJECT_ROOT / ".env")

    if backend_name == "openai":
        key = os.environ.get("OPENAI_API_KEY", "").strip()
        if not key:
            print("[ERROR] OPENAI_API_KEY not found in .env", file=sys.stderr)
            sys.exit(1)
        model = model_override or os.environ.get("OPENAI_MODEL", "gpt-4o-mini").strip()
        return OpenAIBackend(api_key=key, model=model)

    elif backend_name in ("openrouter", "nemotron", "nvidia"):
        keys = [
            os.environ.get("OPENROUTER_API_KEY1", "").strip(),
            os.environ.get("OPENROUTER_API_KEY2", "").strip(),
            os.environ.get("OPENROUTER_API_KEY3", "").strip(),
            os.environ.get("OPENROUTER_API_KEY4", "").strip(),
            os.environ.get("OPENROUTER_API_KEY5", "").strip(),
        ]
        valid_keys = [k for k in keys if k]
        if not valid_keys:
            single_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
            if single_key:
                valid_keys = [single_key]

        # Check for direct NVIDIA NIM API keys
        nvidia_keys = [
            os.environ.get("NVIDIA_API_KEY1", "").strip(),
            os.environ.get("NVIDIA_API_KEY2", "").strip(),
            os.environ.get("NVIDIA_API_KEY3", "").strip(),
            os.environ.get("NVIDIA_API_KEY4", "").strip(),
            os.environ.get("NVIDIA_API_KEY5", "").strip(),
        ]
        valid_nvidia_keys = [k for k in nvidia_keys if k]
        if not valid_nvidia_keys:
            single_nv = os.environ.get("NVIDIA_API_KEY", "").strip()
            if single_nv:
                valid_nvidia_keys = [single_nv]

        if valid_nvidia_keys and (backend_name == "nvidia" or not valid_keys):
            model = model_override or os.environ.get("NVIDIA_MODEL", "nvidia/llama-3.1-nemotron-70b-instruct").strip()
            print(f"    [INFO] Initialized NVIDIA backend with {len(valid_nvidia_keys)} rotating key(s) (model: {model}).")
            return NvidiaBackend(api_keys=valid_nvidia_keys, model=model)

        if not valid_keys:
            print("[ERROR] No OPENROUTER_API_KEY1..3 (or NVIDIA_API_KEY) found in .env", file=sys.stderr)
            sys.exit(1)

        default_model = "nvidia/nemotron-3-ultra-550b-a55b:free"
        model = model_override or os.environ.get("OPENROUTER_MODEL", default_model).strip()
        print(f"    [INFO] Initialized OpenRouter/Nemotron backend with {len(valid_keys)} rotating key(s) (model: {model}).")
        return OpenRouterBackend(api_keys=valid_keys, model=model)

    elif backend_name == "groq":
        keys = [
            os.environ.get("GROQ_API_KEY1", "").strip(),
            os.environ.get("GROQ_API_KEY2", "").strip(),
            os.environ.get("GROQ_API_KEY3", "").strip(),
            os.environ.get("GROQ_API_KEY4", "").strip(),
            os.environ.get("GROQ_API_KEY5", "").strip(),
        ]
        valid_keys = [k for k in keys if k]
        if not valid_keys:
            single_key = os.environ.get("GROQ_API_KEY", "").strip()
            if single_key:
                valid_keys = [single_key]

        if not valid_keys:
            print("[ERROR] No GROQ_API_KEY (or GROQ_API_KEY1..5) found in .env", file=sys.stderr)
            sys.exit(1)

        model = model_override or os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b").strip()
        print(f"    [INFO] Initialized Groq backend with {len(valid_keys)} rotating key(s) (model: {model}).")
        return GroqBackend(api_keys=valid_keys, model=model)

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

        model = model_override or os.environ.get("GEMINI_MODEL", "gemini-3.5-flash").strip()
        print(f"    [INFO] Initialized Gemini backend with {len(valid_keys)} rotating keys (model: {model}).")
        return GeminiBackend(api_keys=valid_keys, model=model)

    elif backend_name == "ollama":
        model = model_override or os.environ.get("OLLAMA_MODEL", "").strip()
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").strip()
        return OllamaBackend(model=model, host=host)

    elif backend_name in ("gguf", "llama-cpp", "llama_cpp", "local-gguf", "32b"):
        model_path = model_override or os.environ.get("GGUF_MODEL", "")
        try:
            return LlamaCppBackend(model_path=model_path if model_path else None)
        except Exception as e:
            import traceback
            print(f"[ERROR] Failed to initialize Dual-GPU GGUF backend: {e}", file=sys.stderr)
            traceback.print_exc()
            sys.exit(1)

    elif backend_name in ("local", "gpu", "transformers"):
        model = model_override or os.environ.get("LOCAL_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct").strip()
        load_in_4bit = bool(os.environ.get("LOAD_IN_4BIT", "0") == "1")
        try:
            return LocalGPUBackend(model_name=model, load_in_4bit=load_in_4bit)
        except Exception as e:
            import traceback
            print(f"[ERROR] Failed to initialize local GPU backend: {e}", file=sys.stderr)
            traceback.print_exc()
            sys.exit(1)

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

    # Newer CFGs start with a "=== SLICER_VERSION: N ===" header (see
    # CfgSerializer.SLICER_VERSION) — strip it before parsing. Files without
    # it (pre-versioning extractions) are unaffected; this check is a no-op.
    if text.startswith("=== SLICER_VERSION:"):
        first_newline = text.find("\n")
        text = text[first_newline + 1:] if first_newline != -1 else ""

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
#  Function Call Graph (FCG) & Tier 2 API Intent Mapping
# =============================================================================

INVOKE_REGEX = re.compile(
    r'(?:virtualinvoke|staticinvoke|interfaceinvoke|specialinvoke|dynamicinvoke)\s+[^<]*<([^:]+):\s*([^\s(]+)\s+([^(]+)\(([^)]*)\)>'
)

HIGH_RISK_APIS = {
    "sendTextMessage", "sendMultipartTextMessage", "DexClassLoader", "dalvik.system.DexClassLoader",
    "getDeviceId", "getSubscriberId", "getSimSerialNumber", "getLine1Number", "getMacAddress",
    "exec", "loadLibrary", "openFileOutput", "getOutputStream", "openConnection",
    "loadClass", "setComponentEnabledSetting", "getLastKnownLocation", "requestLocationUpdates"
}


def extract_invokes(nodes: list[str]) -> list[dict]:
    """Extract method call signatures from Jimple IR node statements."""
    calls = []
    for node in nodes:
        for match in INVOKE_REGEX.finditer(node):
            decl_class, ret_type, method_name, params = match.groups()
            calls.append({
                "declaring_class": decl_class.strip(),
                "method_name": method_name.strip(),
                "full_signature": f"{decl_class.strip()}.{method_name.strip()}",
            })
    return calls


def build_fcg_representation(
    slices: list[FunctionSlice], max_content_tokens: int = 14000
) -> tuple[str, int, list[str]]:
    """
    Groups sliced functions by Suspicious API and structures them into
    Function Call Graphs (FCGs) with explicit caller -> callee call chains
    to reveal the high-level intent behind sensitive API invocations.

    Returns:
      (fcg_formatted_text, total_included_functions, unique_api_names)
    """
    if not slices:
        return "No functions to analyze.", 0, []

    fn_name_to_slice = {s.function_name: s for s in slices}
    class_to_slices = defaultdict(list)
    for s in slices:
        cls = s.function_name.rsplit(".", 1)[0] if "." in s.function_name else s.function_name
        class_to_slices[cls].append(s)

    # Build caller -> callee graph between sliced functions
    callees_by_caller = defaultdict(set)
    callers_by_callee = defaultdict(set)

    for s in slices:
        invokes = extract_invokes(s.nodes)
        for inv in invokes:
            callee_sig = inv["full_signature"]
            callee_cls = inv["declaring_class"]
            callee_method = inv["method_name"]

            if callee_sig in fn_name_to_slice:
                callees_by_caller[s.function_name].add(callee_sig)
                callers_by_callee[callee_sig].add(s.function_name)
            elif callee_cls in class_to_slices:
                for candidate in class_to_slices[callee_cls]:
                    if candidate.function_name.endswith("." + callee_method) or candidate.function_name == callee_sig:
                        callees_by_caller[s.function_name].add(candidate.function_name)
                        callers_by_callee[candidate.function_name].add(s.function_name)

    # Group slices by suspicious API
    api_groups = defaultdict(list)
    for s in slices:
        api_groups[s.suspicious_api].append(s)

    # Prioritize high-risk APIs first, then larger groups
    def api_sort_key(item):
        api_name, group = item
        is_high = 1 if api_name in HIGH_RISK_APIS or any(hr in api_name for hr in HIGH_RISK_APIS) else 0
        return (is_high, len(group))

    sorted_api_groups = sorted(api_groups.items(), key=api_sort_key, reverse=True)

    formatted_blocks = []
    total_tokens = 0
    included_fns = set()
    unique_apis_included = []

    for api_idx, (api_name, group_slices) in enumerate(sorted_api_groups, 1):
        # Discover call chains involving these functions
        chains = []
        for fn in group_slices:
            callers = callers_by_callee.get(fn.function_name, set())
            callees = callees_by_caller.get(fn.function_name, set())
            if callers:
                for c in sorted(callers):
                    chains.append(f"  [CALL CHAIN] {c} --> {fn.function_name} (invokes {api_name})")
            if callees:
                for c in sorted(callees):
                    chains.append(f"  [CALL CHAIN] {fn.function_name} (invokes {api_name}) --> {c}")

        chains = sorted(set(chains))
        chain_summary = "\n".join(chains[:10]) if chains else "  (Isolated invocation / intra-component)"

        group_header = (
            f"\n{'='*75}\n"
            f"=== API GROUP {api_idx}: {api_name} ({len(group_slices)} function(s)) ===\n"
            f"FUNCTION CALL GRAPH (FCG) RELATIONSHIPS:\n"
            f"{chain_summary}\n"
            f"{'='*75}\n"
        )

        group_body_parts = []
        for s in group_slices:
            # Keyed by (function_name, suspicious_api), NOT function_name
            # alone: a single method can be the target of two different
            # suspicious-API slicing criteria (e.g. one function that both
            # opens a connection AND writes to its output stream produces
            # two distinct FunctionSlice entries — one per API — each with
            # its own NODE/EDGE content specific to that API's data flow).
            # Deduping by function_name alone would silently drop the
            # second API's entire group whenever it was that function's
            # only member, discarding real per-API signal.
            slice_key = (s.function_name, s.suspicious_api)
            if slice_key in included_fns:
                continue

            # Annotate function with call relationships
            callers = sorted(callers_by_callee.get(s.function_name, set()))
            callees = sorted(callees_by_caller.get(s.function_name, set()))

            fn_header = f"--- FUNCTION: {s.function_name} ---\n"
            fn_header += f"SUSPICIOUS_API: {s.suspicious_api}\n"
            if callers:
                fn_header += f"CALLED_BY: {', '.join(callers)}\n"
            if callees:
                fn_header += f"CALLS: {', '.join(callees)}\n"

            # Raw nodes and edges
            node_edge_text = "\n".join(s.nodes + s.edges)
            if len(node_edge_text) > 8000:
                node_edge_text = node_edge_text[:8000] + "\n... [truncated] ..."

            fn_block = f"{fn_header}{node_edge_text}\n--- END FUNCTION ---\n"
            block_tokens = count_tokens(fn_block)

            if total_tokens + block_tokens > max_content_tokens:
                break

            group_body_parts.append(fn_block)
            total_tokens += block_tokens
            included_fns.add(slice_key)

        if group_body_parts:
            formatted_blocks.append(group_header + "\n".join(group_body_parts))
            unique_apis_included.append(api_name)

        if total_tokens >= max_content_tokens:
            break

    full_text = "\n".join(formatted_blocks)
    return full_text, len(included_fns), unique_apis_included


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
#  Free formatting sanity check (Layer 1 — no LLM call)
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
#  Data Relationship Coverage (DRC) — paper Section 3.3.4 / Appendix C, Eq. 1
# =============================================================================
# DRC = #{correctly reconstructed dependencies} / #{all ground-truth
# dependencies}, threshold θ = 0.95. The paper prompts the LLM to identify
# variable dependencies from the sliced CFG (DRC_USER_TEMPLATE, already
# defined above and — until this fix — never actually called) and checks
# whether it "accurately reconstructs variable dependencies."
#
# The missing piece was the ground truth to compare against. Soot already
# computed the real data-flow relationships during slicing, but didn't
# serialize them — so this re-derives them by parsing the same Jimple
# NODE/EDGE text the LLM sees, using the exact 5 categories from Table 7 /
# DRC_USER_TEMPLATE (Direct, Transitive, Conditional, Parallel, Derived).
# This is a heuristic re-parse (regex over Jimple, not a full grammar), the
# same tradeoff extract_invokes()/build_fcg_representation() already accept
# elsewhere in this file — good enough to score LLM recall against, not a
# claim of perfect precision on every exotic Jimple construct.

DRC_THRESHOLD = 0.95

_DRC_VAR_TOKEN_RE = re.compile(r"\$?[A-Za-z_][\w#-]*")
_DRC_ARITH_OP_RE = re.compile(r"\s[+\-*/%]\s")  # spaced operator — NOT the '-' inside "$u-1"


_DRC_KEYWORDS = {
    "if", "goto", "return", "new", "newarray", "newmultiarray", "null",
    "this", "virtualinvoke", "staticinvoke", "specialinvoke",
    "interfaceinvoke", "dynamicinvoke", "instanceof", "true", "false",
    "class", "lengthof", "cmp", "cmpg", "cmpl",
    # Java primitive type names — never dotted, so the qualified-name
    # stripper above doesn't catch them (e.g. "newarray (int)[2]").
    "int", "long", "short", "byte", "char", "boolean", "float", "double", "void",
}


def _drc_extract_vars(text: str) -> set[str]:
    """
    Variable-like tokens in `text`, with everything that ISN'T a Jimple
    local stripped out first: <...> method/field signatures, quoted string
    literals, and dotted qualified type names (java.lang.Object etc — a
    Jimple local never contains a '.', so any dotted identifier chain is
    always a type/package reference, never a variable).
    """
    text = re.sub(r"<[^>]*>", " ", text)
    text = re.sub(r'"[^"]*"', " ", text)
    text = re.sub(r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\b", " ", text)
    return {
        tok for tok in _DRC_VAR_TOKEN_RE.findall(text)
        if tok.lower() not in _DRC_KEYWORDS and not tok.lstrip("$").lstrip("-").isdigit()
    }


def extract_ground_truth_dependencies(func_slice: FunctionSlice) -> dict[str, set[str]]:
    """
    Re-derives the 5 dependency categories (paper Table 7) directly from the
    sliced CFG's own NODE/EDGE text, to use as ground truth for scoring the
    LLM's DRC response against.
    """
    deps: dict[str, set[str]] = {
        "direct": set(), "transitive": set(), "conditional": set(),
        "parallel": set(), "derived": set(),
    }

    nodes = func_slice.nodes
    if not nodes:
        return deps

    # ── Locate the final invocation node (the one containing the suspicious API) ──
    api_short = func_slice.suspicious_api.split(".")[-1] if func_slice.suspicious_api else ""
    final_node = None
    for line in nodes:
        if api_short and api_short in line and "invoke" in line.lower():
            final_node = line  # last match wins — the invocation is usually the terminal slice node
    if final_node is None:
        final_node = nodes[-1]

    # ── Direct: variables passed as arguments (or the instance receiver) to
    #    that final call — mirrors exactly what BackwardSlicer.slice() seeds
    #    as relevantLocals in the first place. ──
    call_match = re.search(r"<[^>]+>\(([^()]*)\)", final_node)
    if call_match:
        deps["direct"] |= _drc_extract_vars(call_match.group(1))
    recv_match = re.search(r"(?:virtualinvoke|specialinvoke|interfaceinvoke)\s+([\w$#-]+)\.<", final_node)
    if recv_match:
        deps["direct"] |= _drc_extract_vars(recv_match.group(1))

    # ── Build a def-map: variable -> (line_index, rhs_text) for the LAST
    #    assignment to that variable at or before the final node (adequate
    #    approximation since the slice already contains only relevant units,
    #    in program order). ──
    final_idx = nodes.index(final_node) if final_node in nodes else len(nodes) - 1
    def_map: dict[str, str] = {}
    for idx, line in enumerate(nodes[:final_idx + 1]):
        body = line.split(":", 2)[-1].strip() if line.startswith("NODE") else line
        m = re.match(r"^([\w$#-]+)\s*=\s*(.+)$", body)
        if m:
            def_map[m.group(1)] = m.group(2)

    # ── Transitive / Derived: walk each direct variable's definition and
    #    classify what feeds it. Derived = the RHS is an arithmetic
    #    expression (spaced +/-/*/%, distinct from '-' inside a local name
    #    like "$u-1"); otherwise (copy, field read, invoke result) = Transitive. ──
    receiver_groups: dict[str, set[str]] = {}
    for var in list(deps["direct"]):
        rhs = def_map.get(var)
        if not rhs:
            continue
        rhs_vars = _drc_extract_vars(rhs) - {var}
        if _DRC_ARITH_OP_RE.search(rhs):
            deps["derived"] |= rhs_vars
        else:
            deps["transitive"] |= rhs_vars

        recv = re.search(r"(?:virtualinvoke|specialinvoke|interfaceinvoke)\s+([\w$#-]+)\.<", rhs)
        if recv:
            receiver_groups.setdefault(recv.group(1), set()).add(var)

    # ── Parallel: 2+ direct/transitive variables assigned via calls on the
    #    SAME receiver object (a shared source). ──
    for receiver, group_vars in receiver_groups.items():
        if len(group_vars) > 1:
            deps["parallel"] |= group_vars

    # ── Conditional: variables in any branch (if/goto) node present in the
    #    slice — these are exactly the control-dependence nodes
    #    performControlDependenceStep() already included. ──
    for line in nodes:
        body = line.split(":", 2)[-1].strip() if line.startswith("NODE") else line
        m = re.match(r"^if\s+(.+?)\s+goto\b", body)
        if m:
            deps["conditional"] |= _drc_extract_vars(m.group(1))

    return deps


def parse_drc_response(response: str) -> dict[str, set[str]]:
    """Parses the LLM's DRC_USER_TEMPLATE response (`<type>: <var1>, <var2>`
    lines) into the same {category: {vars}} shape as the ground truth."""
    claimed: dict[str, set[str]] = {
        "direct": set(), "transitive": set(), "conditional": set(),
        "parallel": set(), "derived": set(),
    }
    for line in response.split("\n"):
        line = line.strip().lstrip("-*").strip()
        m = re.match(r"^\**\s*(Direct|Transitive|Conditional|Parallel|Derived)\**\s*:\s*(.+)$", line, re.IGNORECASE)
        if not m:
            continue
        category = m.group(1).lower()
        for raw_var in re.split(r"[,\s]+", m.group(2)):
            raw_var = raw_var.strip().strip(".").lstrip("$")
            if raw_var and raw_var.lower() not in ("none", "n/a", "-"):
                claimed[category].add(raw_var)
    return claimed


def compute_drc_score(ground_truth: dict[str, set[str]], claimed: dict[str, set[str]]) -> tuple[float, str]:
    """
    DRC = #{correctly reconstructed dependencies} / #{all ground-truth
    dependencies} (paper Eq. 1), pooled across all 5 categories into one
    scalar score to compare against θ=0.95. Variable names are compared
    with the '$' sigil stripped on both sides (the LLM often echoes Jimple
    locals without it) — everything else stays case-sensitive, matching
    real Java/Jimple identifier semantics.

    Returns (score, human_readable_detail). An empty ground truth (nothing
    to verify — e.g. a suspicious call with only constant arguments) scores
    1.0 rather than being undefined.
    """
    def norm(vs: set[str]) -> set[str]:
        return {v.lstrip("$") for v in vs}

    total = 0
    correct = 0
    missed_detail = []
    for category, gt_vars in ground_truth.items():
        gt_vars = norm(gt_vars)
        claimed_vars = norm(claimed.get(category, set()))
        total += len(gt_vars)
        hit = gt_vars & claimed_vars
        correct += len(hit)
        missed = gt_vars - claimed_vars
        if missed:
            missed_detail.append(f"{category}: missed {sorted(missed)}")

    if total == 0:
        return 1.0, "No ground-truth dependencies to verify (trivial slice)"

    score = correct / total
    detail = f"{correct}/{total} dependencies matched"
    if missed_detail:
        detail += " — " + "; ".join(missed_detail)
    return score, detail


def run_drc_check(llm: LLMBackend, func_slice: FunctionSlice) -> tuple[bool, str, float]:
    """
    The paper's actual DRC verification: prompts the LLM (DRC_USER_TEMPLATE)
    to identify variable dependencies in the sliced CFG, scores its answer
    against dependencies re-derived from the CFG itself
    (extract_ground_truth_dependencies), and applies the paper's θ=0.95
    threshold. Costs one extra LLM call per function, only when verify_drc=True.

    Returns (is_consistent, reason, score).
    """
    ground_truth = extract_ground_truth_dependencies(func_slice)

    cfg_text = func_slice.raw_text
    if len(cfg_text) > 4000:
        cfg_text = cfg_text[:4000] + "\n... [truncated] ..."

    prompt = DRC_USER_TEMPLATE.format(
        function_name=func_slice.function_name,
        cfg_content=cfg_text,
    )
    response = llm.chat(DRC_SYSTEM, prompt, temperature=0.0)
    claimed = parse_drc_response(response)

    score, detail = compute_drc_score(ground_truth, claimed)
    is_consistent = score >= DRC_THRESHOLD
    # ASCII-only: this string gets printed via a raw print() in the Tier 1
    # loop, which on a default Windows console (cp1252) crashes on 'θ'/'—'.
    reason = f"DRC={score:.2f} (threshold={DRC_THRESHOLD}) - {detail}"
    return is_consistent, reason, score


def verify_consistency(
    llm: LLMBackend, func_slice: FunctionSlice, tier1_summary: str
) -> tuple[bool, str]:
    """
    Supplementary hallucination check — NOT the paper's DRC mechanism (see
    run_drc_check() above for that). This asks the LLM directly whether a
    Tier 1 summary's claims are supported by the code, which catches a
    different failure mode than DRC: DRC scores whether variable
    *relationships* were reconstructed correctly, this catches invented
    *details* (e.g. "hardcoded premium number") that DRC's dependency-only
    view wouldn't flag either way. Available as an extra opt-in layer;
    not called by the default Tier 1 loop (see analyse_one_apk).

    Returns (is_consistent, reason).
    """
    cfg_text = func_slice.raw_text
    if len(cfg_text) > 4000:
        cfg_text = cfg_text[:4000] + "\n... [truncated] ..."

    prompt = DRC_VERIFY_USER_TEMPLATE.format(
        cfg_content=cfg_text,
        tier1_summary=tier1_summary,
    )
    response = llm.chat(DRC_VERIFY_SYSTEM, prompt, temperature=0.0)

    # "INCONSISTENT" is a strict superstring of "CONSISTENT", so a plain
    # substring check is unambiguous regardless of minor formatting drift
    # (e.g. missing the "VERDICT:" label). If neither word appears at all
    # (the model didn't follow the format), default to trusting Tier 1
    # rather than forcing a retry loop on an unparseable response.
    response_upper = response.upper()
    if "INCONSISTENT" in response_upper:
        reason = "Consistency check failed"
        for line in response.split("\n"):
            if line.strip().upper().startswith("REASON:"):
                reason = line.strip().split(":", 1)[1].strip()
                break
        return False, reason

    return True, "OK"


# =============================================================================
#  Tier 2 — API-Level Aggregation
# =============================================================================

def _extract_tier2_risk(response: str) -> str:
    """Parses a RISK_LEVEL/RISK line out of a Tier-2-shaped LLM response."""
    for line in response.split("\n"):
        if "RISK_LEVEL:" in line.upper() or "RISK:" in line.upper():
            if "CRITICAL" in line.upper():
                return "CRITICAL"
            elif "HIGH" in line.upper():
                return "HIGH"
            elif "MEDIUM" in line.upper():
                return "MEDIUM"
            elif "LOW" in line.upper():
                return "LOW"
            break
    return "UNKNOWN"


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

    return Tier2Result(
        api_name=api_name,
        api_type=api_type,
        summary=response,
        risk_level=_extract_tier2_risk(response),
    )


# =============================================================================
#  Tier 2 (bulk path) — API-Level Aggregation directly from sliced FCG content
# =============================================================================
# Used by the hybrid/HBCR pipeline for large APKs where a full per-function
# Tier 1 pass would be too slow. Restores the paper's API-intent-aggregation
# step (Section 3.3.2) that the old chunk-based bulk pipeline skipped
# entirely — one LLM call per suspicious API GROUP (never split across
# unrelated chunks), keeping call count at O(#distinct suspicious APIs)
# instead of O(#functions).

_RISK_ORDER = {"UNKNOWN": -1, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _split_group_into_subchunks(
    group_slices: list[FunctionSlice], max_tokens_per_subchunk: int
) -> list[list[FunctionSlice]]:
    """
    Splits ONE (oversized) suspicious-API group's functions into token-bounded
    sub-chunks, preserving function order. Only used as a fallback when a
    single API group's own functions don't fit within one call's budget —
    the common case (a group that fits) never goes through this.
    """
    subchunks: list[list[FunctionSlice]] = []
    current: list[FunctionSlice] = []
    current_tokens = 0

    for s in group_slices:
        node_edge_text = "\n".join(s.nodes + s.edges)
        if len(node_edge_text) > 8000:
            node_edge_text = node_edge_text[:8000]
        fn_block = f"--- FUNCTION: {s.function_name} ---\nSUSPICIOUS_API: {s.suspicious_api}\n{node_edge_text}\n--- END FUNCTION ---\n"
        s_tokens = count_tokens(fn_block)

        if current_tokens + s_tokens > max_tokens_per_subchunk and current:
            subchunks.append(current)
            current = [s]
            current_tokens = s_tokens
        else:
            current.append(s)
            current_tokens += s_tokens

    if current:
        subchunks.append(current)

    return subchunks


def _merge_tier2_group_results(api_name: str, sub_results: list[Tier2Result]) -> Tier2Result:
    """Merges per-sub-chunk Tier2Results for ONE oversized API group into one."""
    best = max(sub_results, key=lambda r: _RISK_ORDER.get(r.risk_level, -1))
    combined_summary = "\n\n".join(
        f"[Part {i}/{len(sub_results)} — Risk: {r.risk_level}]\n{r.summary}"
        for i, r in enumerate(sub_results, 1)
    )
    return Tier2Result(
        api_name=api_name,
        api_type=sub_results[0].api_type,
        summary=combined_summary,
        risk_level=best.risk_level,
    )


# Hard cap on how many of one API's call sites get individually analyzed in
# the bulk path. Without this, a pathological APK can blow the sub-chunk
# fallback below out to thousands of LLM calls for ONE api group — verified
# directly: a real sample in test_extracted_cfgs/ has 10,789 forName() call
# sites and 10,750 invoke() call sites alone (98.9% of all 26,810 functions
# in that one APK), almost certainly templated/generated reflection glue.
# Evenly sampling down to a bounded representative subset keeps runtime/cost
# bounded while still capturing the pattern — near-identical call sites are
# highly redundant by construction, so a representative sample carries most
# of the signal a full pass would.
MAX_FUNCTIONS_PER_GROUP_ANALYSIS = 200

# Second, independent bound: caps LLM calls per group directly regardless of
# backend context size. A tight-context backend (e.g. Groq's real 4K-token
# budget) can still split even the post-sampling 200-function cap above into
# many sub-chunks; this guarantees at most this many extra calls per group
# no matter how small the backend's context window is.
MAX_SUBCHUNKS_PER_GROUP = 8


def _sample_group(group_slices: list[FunctionSlice], cap: int) -> tuple[list[FunctionSlice], int]:
    """Evenly samples down to `cap` functions if the group exceeds it.
    Returns (sampled_slices, original_count)."""
    original_count = len(group_slices)
    if original_count <= cap:
        return group_slices, original_count
    step = original_count / cap
    sampled = [group_slices[int(i * step)] for i in range(cap)]
    return sampled, original_count


def run_tier2_from_group(
    llm: LLMBackend, api_name: str, group_slices: list[FunctionSlice],
    content_budget: int, verbose: bool = True,
) -> Tier2Result:
    """
    Bulk-path Tier 2: aggregates ALL functions calling one suspicious API
    directly from their sliced FCG content (skipping the per-function Tier 1
    LLM pass) into a single structured API-intent summary — the same shape
    `run_tier2` produces, so downstream (Tier 3) can't tell the difference.
    """
    group_slices, original_group_count = _sample_group(group_slices, MAX_FUNCTIONS_PER_GROUP_ANALYSIS)
    sampled = original_group_count > len(group_slices)
    if sampled and verbose:
        print(f"        [WARN] API group '{api_name}' has {original_group_count} call sites — "
              f"sampled down to {len(group_slices)} representative site(s) to bound cost/runtime", flush=True)

    fcg_text, included, _ = build_fcg_representation(group_slices, max_content_tokens=content_budget)
    api_type = classify_api_type(api_name)

    def _annotate(result: Tier2Result, analyzed_count: int) -> Tier2Result:
        if not sampled:
            return result
        note = (f"\n\n[NOTE: this API has {original_group_count} call sites in the APK; "
                 f"analysis is based on {analyzed_count} representative sampled site(s).]")
        return Tier2Result(
            api_name=result.api_name, api_type=result.api_type,
            summary=result.summary + note, risk_level=result.risk_level,
        )

    if included >= len(group_slices):
        # Whole (possibly sampled) group fits in one call — the common case.
        prompt = TIER2_USER_TEMPLATE.format(
            api_name=api_name, api_type=api_type,
            function_summaries=fcg_text, usage_count=len(group_slices),
        )
        response = llm.chat(TIER2_SYSTEM, prompt)
        return _annotate(Tier2Result(
            api_name=api_name, api_type=api_type,
            summary=response, risk_level=_extract_tier2_risk(response),
        ), analyzed_count=len(group_slices))

    # Oversized (post-sampling) group: split into sub-chunks, analyze each,
    # merge — but the API grouping itself is never broken (every sub-chunk
    # is still 100% this one API's functions).
    subchunks = _split_group_into_subchunks(group_slices, max_tokens_per_subchunk=content_budget)
    if len(subchunks) > MAX_SUBCHUNKS_PER_GROUP:
        if verbose:
            print(f"        [WARN] API group '{api_name}' split into {len(subchunks)} sub-chunks — "
                  f"capping to {MAX_SUBCHUNKS_PER_GROUP} to bound cost/runtime", flush=True)
        subchunks = subchunks[:MAX_SUBCHUNKS_PER_GROUP]
        sampled = True  # partial coverage — make sure the result gets annotated
    elif verbose:
        print(f"        [INFO] API group '{api_name}' ({len(group_slices)} funcs) exceeds budget — "
              f"split into {len(subchunks)} sub-chunk(s) of this SAME API", flush=True)

    analyzed_count = sum(len(sc) for sc in subchunks)
    sub_results: list[Tier2Result] = []
    for idx, sub in enumerate(subchunks, 1):
        sub_text, _, _ = build_fcg_representation(sub, max_content_tokens=content_budget + 2000)
        prompt = TIER2_USER_TEMPLATE.format(
            api_name=f"{api_name} (part {idx}/{len(subchunks)})", api_type=api_type,
            function_summaries=sub_text, usage_count=len(sub),
        )
        try:
            response = llm.chat(TIER2_SYSTEM, prompt)
        except Exception as e:
            response = f"RISK_LEVEL: UNKNOWN\nOVERALL_INTENT: Analysis failed: {e}"
        sub_results.append(Tier2Result(
            api_name=api_name, api_type=api_type,
            summary=response, risk_level=_extract_tier2_risk(response),
        ))

    return _annotate(_merge_tier2_group_results(api_name, sub_results), analyzed_count=analyzed_count)


# =============================================================================
#  Tier 2 (batched) — several SMALL API groups analyzed in one call
# =============================================================================
# Pure call-count optimization: many suspicious-API groups in the bulk path
# have only 1-4 functions, each still paying the same fixed per-call
# overhead as a large group. Batching several small groups into one request
# never changes what gets analyzed or how — each API's content and output
# are exactly as they'd be individually, just packaged together — and any
# API whose result can't be confidently parsed back out of the batch
# response is transparently reprocessed individually, so nothing is ever
# silently dropped or blended between APIs.

def parse_tier2_batch_response(response: str) -> dict[str, str]:
    """Splits a TIER2_BATCH_USER_TEMPLATE response into {api_name: block_text}."""
    blocks: dict[str, str] = {}
    pattern = re.compile(
        r"===\s*API_RESULT:\s*(.+?)\s*===(.*?)===\s*END API_RESULT\s*===",
        re.DOTALL,
    )
    for m in pattern.finditer(response):
        api_name = m.group(1).strip()
        content = m.group(2).strip()
        if api_name and content:
            blocks[api_name] = content
    return blocks


def partition_groups_for_batching(
    api_groups: dict[str, list[FunctionSlice]], content_budget: int,
) -> tuple[list[list[str]], list[str]]:
    """
    Splits API groups into (a) batches of small groups to analyze together
    in one call each, and (b) groups that keep their own individual call —
    exactly as before batching existed. A group is "small" only if its own
    formatted content is comfortably under a quarter of the budget — kept
    conservative, since that's what keeps any ONE api's content simple
    enough for the model to reliably keep separate from its batch-mates.
    batch_target is deliberately much larger (most of the budget): packing
    MORE small (individually-simple) groups into one call is where the real
    call-count savings come from, and the eligibility bar above is what
    keeps that safe — not the batch size itself.
    """
    small_threshold = max(500, content_budget // 4)
    batch_target = max(1000, int(content_budget * 0.85))

    small: list[tuple[str, int]] = []
    standalone: list[str] = []
    for api_name, group_slices in api_groups.items():
        text, _, _ = build_fcg_representation(group_slices, max_content_tokens=content_budget)
        tokens = count_tokens(text)
        if tokens <= small_threshold:
            small.append((api_name, tokens))
        else:
            standalone.append(api_name)

    # Greedy bin-packing, largest-small-first.
    small.sort(key=lambda x: -x[1])
    batches: list[list[str]] = []
    batch_tokens: list[int] = []
    for api_name, tokens in small:
        placed = False
        for i in range(len(batches)):
            if batch_tokens[i] + tokens <= batch_target:
                batches[i].append(api_name)
                batch_tokens[i] += tokens
                placed = True
                break
        if not placed:
            batches.append([api_name])
            batch_tokens.append(tokens)

    # A "batch" of exactly one API gains nothing over an individual call —
    # unwrap those back into the standalone path rather than paying the
    # (slightly larger) batch-template overhead for zero benefit.
    real_batches = [b for b in batches if len(b) > 1]
    unwrapped_singletons = [b[0] for b in batches if len(b) == 1]

    return real_batches, standalone + unwrapped_singletons


def run_tier2_batch(
    llm: LLMBackend, groups: list[tuple[str, list[FunctionSlice]]],
    content_budget: int, verbose: bool = True,
) -> dict[str, Tier2Result]:
    """
    Analyzes several small suspicious-API groups in ONE LLM call. Falls back
    to run_tier2_from_group individually for any API missing or unparseable
    in the batch response — the safety net that guarantees batching can only
    ever cost time savings on failure, never coverage.
    """
    all_slices = [s for _, group_slices in groups for s in group_slices]
    grouped_content, _, _ = build_fcg_representation(all_slices, max_content_tokens=content_budget)
    api_names = [name for name, _ in groups]

    prompt = TIER2_BATCH_USER_TEMPLATE.format(
        group_count=len(api_names),
        grouped_content=grouped_content,
    )

    response = ""
    try:
        response = llm.chat(TIER2_BATCH_SYSTEM, prompt)
    except Exception as e:
        if verbose:
            print(f"        [WARN] Batch Tier 2 call failed ({e}) — falling back to "
                  f"individual calls for all {len(api_names)} API(s) in this batch", flush=True)

    parsed_blocks = parse_tier2_batch_response(response) if response else {}

    results: dict[str, Tier2Result] = {}
    missing: list[str] = []
    for api_name, group_slices in groups:
        block = parsed_blocks.get(api_name)
        if block is None:
            missing.append(api_name)
            continue
        api_type = classify_api_type(api_name)
        results[api_name] = Tier2Result(
            api_name=api_name, api_type=api_type,
            summary=block, risk_level=_extract_tier2_risk(block),
        )

    if missing:
        if verbose:
            print(f"        [WARN] Batch response missing/unparseable for {len(missing)} "
                  f"API(s) {missing} — falling back to individual calls for those only", flush=True)
        group_map = dict(groups)
        for api_name in missing:
            results[api_name] = run_tier2_from_group(
                llm, api_name, group_map[api_name], content_budget, verbose=verbose
            )

    return results


# =============================================================================
#  Tier 3 — APK-Level Prediction
# =============================================================================

# Keyword-density fallback signals — used only when structured parsing fails.
MALWARE_SIGNAL_KEYWORDS = (
    "MALWARE", "MALICIOUS", "SPYWARE", "TROJAN", "ADWARE",
    "DATA HARVESTING", "DATA EXFILTRATION", "HIGHLY SUSPICIOUS",
    "SMS FRAUD", "HIDDEN AD",
)


def _parse_marker_value(response: str, marker_prefixes: tuple[str, ...]) -> str:
    """
    Extracts the value following a marker line, handling both inline style
    ('CONFIDENCE: HIGH') and bold-header-with-value-on-next-line style
    ('**Confidence:**\\nHIGH' — what TIER3_USER_TEMPLATE uses for
    **Final Prediction:**/**Confidence:**, mirroring the "structured marker"
    lookup `parse_final_prediction` already does for the prediction itself).
    Returns "" if no marker line is found or it has no value anywhere nearby.
    """
    lines = response.split("\n")
    for i, line in enumerate(lines):
        stripped = line.strip().strip("*").strip()
        upper = stripped.upper()
        if any(upper.startswith(p) for p in marker_prefixes):
            candidate = stripped.split(":", 1)[1].strip() if ":" in stripped else ""
            if not candidate:
                for nxt_line in lines[i + 1 : i + 3]:
                    nxt = nxt_line.strip().strip("*").strip()
                    if nxt:
                        candidate = nxt
                        break
            return candidate
    return ""


def parse_final_prediction(response: str, verbose: bool = True, context: str = "") -> str:
    """
    Robustly extracts MALWARE/BENIGN from an LLM response.

    Tries, in order:
      1. A structured "Final Prediction:" / "PREDICTION:" marker line — reads
         the value after the colon, or the next non-empty line if the value
         wraps.
      2. A loose line containing both "MALWARE" and "PREDICTION"/"FINAL"
         (handles minor formatting drift from (1)).
      3. Keyword-density fallback: MALWARE if >= 2 malware-indicator
         keywords appear anywhere in the response.
      4. "UNKNOWN", loudly logged — this means the LLM's output didn't match
         any expected format. Deliberately NOT "BENIGN": on a dataset where
         BENIGN is the ~90% majority class, silently coding an unparseable
         response as BENIGN inflates accuracy while quietly hiding false
         negatives — exactly the failure mode this was causing. Callers
         should retry once (see `_retry_prediction_parse`) and, failing
         that, record "UNKNOWN" so it's excluded from strict metrics rather
         than miscounted as a free correct answer.
    """
    lines = response.split("\n")

    # 1. Structured marker
    for i, line in enumerate(lines):
        stripped = line.strip().strip("*").strip()
        upper = stripped.upper()
        if upper.startswith("FINAL PREDICTION") or upper.startswith("PREDICTION"):
            candidate = stripped.split(":", 1)[1].strip() if ":" in stripped else ""
            if not candidate:
                for nxt_line in lines[i + 1 : i + 3]:
                    nxt = nxt_line.strip().strip("*").strip()
                    if nxt:
                        candidate = nxt
                        break
            candidate_upper = candidate.upper()
            if "MALWARE" in candidate_upper:
                return "MALWARE"
            if "BENIGN" in candidate_upper:
                return "BENIGN"

    # 2. Loose line-level match
    for line in lines:
        upper = line.upper().strip()
        if "MALWARE" in upper and ("PREDICTION" in upper or "FINAL" in upper or "VERDICT" in upper):
            return "MALWARE"
        if "BENIGN" in upper and ("PREDICTION" in upper or "FINAL" in upper or "VERDICT" in upper):
            return "BENIGN"
        if upper.strip("* ").startswith("MALWARE"):
            return "MALWARE"
        if upper.strip("* ").startswith("BENIGN"):
            return "BENIGN"

    # 2b. Conversational classification verdict phrasing (common in reasoning models like Nemotron/DeepSeek)
    response_upper = response.upper()
    if "CLASSIFY THIS AS BENIGN" in response_upper or "CLASSIFY THIS APPLICATION AS BENIGN" in response_upper or "CLASSIFY AS BENIGN" in response_upper or "VERDICT IS BENIGN" in response_upper:
        return "BENIGN"
    if "CLASSIFY THIS AS MALWARE" in response_upper or "CLASSIFY THIS APPLICATION AS MALWARE" in response_upper or "CLASSIFY AS MALWARE" in response_upper or "VERDICT IS MALWARE" in response_upper:
        return "MALWARE"

    # 3. Keyword-density fallback
    signal_count = sum(1 for sig in MALWARE_SIGNAL_KEYWORDS if sig in response_upper)
    if signal_count >= 2:
        if verbose:
            print(f"\n    [WARN] {context}No structured prediction marker found; "
                  f"used keyword-density fallback ({signal_count} signals) -> MALWARE",
                  file=sys.stderr, flush=True)
        return "MALWARE"

    if verbose:
        print(f"\n    [WARN] {context}Could not confidently parse a prediction; "
              f"recording UNKNOWN (not BENIGN). Response head: {response[:150]!r}",
              file=sys.stderr, flush=True)
    return "UNKNOWN"


def _retry_prediction_parse(
    llm: LLMBackend, system: str, original_prompt: str, previous_response: str,
    context: str = "",
) -> tuple[str, str]:
    """
    One retry when `parse_final_prediction` couldn't confidently extract a
    verdict. Appends a stricter formatting instruction and asks again.

    Returns (prediction, response_to_store). On a second parse failure,
    prediction is "UNKNOWN" — never silently "BENIGN" (see the docstring on
    `parse_final_prediction` for why that matters on this dataset).
    """
    retry_prompt = (
        original_prompt
        + "\n\n--- IMPORTANT ---\n"
          "Your previous response did not include a clear verdict line. "
          "Restate your final verdict as EXACTLY one line in the form:\n"
          "PREDICTION: MALWARE\nor\nPREDICTION: BENIGN"
    )
    try:
        retry_response = llm.chat(system, retry_prompt, temperature=0.0)
    except Exception as e:
        print(f"\n    [WARN] {context}Retry call for unparsed prediction failed: {e}",
              file=sys.stderr, flush=True)
        return "UNKNOWN", previous_response

    retry_prediction = parse_final_prediction(retry_response, context=context)
    if retry_prediction != "UNKNOWN":
        return retry_prediction, retry_response

    print(f"\n    [WARN] {context}Retry also failed to parse a verdict — recording UNKNOWN.",
          file=sys.stderr, flush=True)
    return "UNKNOWN", previous_response + "\n\n[RETRY RESPONSE]\n" + retry_response


def run_tier3(llm: LLMBackend, sha256: str, api_results: list[Tier2Result]) -> Tier3Result:
    """Final malware/benign prediction for one APK."""
    api_summaries = [
        {"api_name": r.api_name, "api_type": r.api_type, "summary": r.summary}
        for r in api_results
    ]
    api_text = format_api_summaries_for_tier3(api_summaries)

    prompt = TIER3_USER_TEMPLATE.format(api_summaries=api_text)
    response = llm.chat(TIER3_SYSTEM, prompt)

    context = f"[Tier3 {sha256[:12]}] "
    prediction = parse_final_prediction(response, context=context)
    if prediction == "UNKNOWN":
        prediction, response = _retry_prediction_parse(llm, TIER3_SYSTEM, prompt, response, context=context)

    confidence = _parse_marker_value(response, ("CONFIDENCE",)).upper() or "UNKNOWN"
    if confidence == "UNKNOWN" and prediction == "MALWARE":
        confidence = "MEDIUM"

    return Tier3Result(
        sha256=sha256,
        prediction=prediction,
        analysis=response,
        confidence=confidence,
    )


# =============================================================================
#  Full Pipeline — One APK
# =============================================================================

def analyse_one_apk(
    llm: LLMBackend, sha256: str, cfg_path: Path,
    verify_drc: bool = True, verbose: bool = True,
    no_filter: bool = False,
) -> Tier3Result | None:
    """
    Runs the full 3-tier pipeline for a single APK.

    Args:
        llm:        LLM backend to use
        sha256:     SHA-256 hash of the APK
        cfg_path:   Path to the sliced CFG text file
        verify_drc: Whether to run factual consistency verification
        verbose:    Print progress
        no_filter:  Disable framework filtering, keeping all functions

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
    slices, original_count, unique_count = preprocess_slices(slices, no_filter=no_filter)

    if verbose and original_count > 0:
        filter_status = "unfiltered" if no_filter else "filtered"
        print(f"    [INFO] CFGs: {original_count} raw -> {unique_count} unique -> {len(slices)} {filter_status}")

    tier1_results: list[Tier1Result] = []
    total_slices = len(slices)
    if verbose:
        print(f"\n    [Phase 1 / Tier 1] Analyzing {total_slices} function slices...", flush=True)

    for idx, func_slice in enumerate(slices, 1):
        try:
            t_t1 = time.time()
            t1 = run_tier1(llm, func_slice)
            t1_dur = time.time() - t_t1

            func_short = func_slice.function_name
            if len(func_short) > 42:
                func_short = func_short[:20] + "..." + func_short[-19:]

            if verbose:
                print(f"      [Tier 1] [{idx:>3}/{total_slices}] {func_short:<45} | API: {func_slice.suspicious_api:<22} -> Risk: {t1.risk_level:<8} ({t1_dur:.1f}s)", flush=True)

            if verify_drc:
                # Layer 1: free formatting sanity check (no LLM call).
                is_sane, reason = sanity_check_tier1(func_slice, t1.summary)
                if not is_sane:
                    if verbose:
                        print(f"        [SANITY] Format check failed ({reason}) -> Retrying...", flush=True)
                    t1 = run_tier1(llm, func_slice)  # retry once
                else:
                    # Layer 2: paper's actual DRC check (1 extra LLM call) —
                    # score the LLM's reconstructed dependencies against the
                    # slice's real ones, retry if below θ=0.95.
                    try:
                        t_drc = time.time()
                        is_consistent, drc_reason, drc_score = run_drc_check(llm, func_slice)
                        drc_dur = time.time() - t_drc
                        if not is_consistent:
                            if verbose:
                                print(f"        [DRC]    BELOW THRESHOLD ({drc_reason}) -> Retrying... ({drc_dur:.1f}s)", flush=True)
                            t1 = run_tier1(llm, func_slice)  # retry once
                        else:
                            if verbose:
                                print(f"        [DRC]    {drc_reason} [OK] ({drc_dur:.1f}s)", flush=True)
                    except Exception as e:
                        if verbose:
                            print(f"        [DRC]    Verification call warning: {e}", flush=True)

            tier1_results.append(t1)
        except Exception as e:
            if verbose:
                print(f"      [ERROR] Tier 1 failed for {func_slice.function_name}: {e}", flush=True)

    if not tier1_results:
        return Tier3Result(sha256=sha256, prediction="BENIGN",
                           analysis="All function analyses failed.")

    # ── Tier 2: API-level aggregation ─────────────────────────────────────────
    # Group Tier 1 results by suspicious API
    api_groups: dict[str, list[Tier1Result]] = {}
    for t1 in tier1_results:
        api_groups.setdefault(t1.suspicious_api, []).append(t1)

    tier2_results: list[Tier2Result] = []
    total_apis = len(api_groups)
    if verbose:
        print(f"\n    [Phase 2 / Tier 2] Aggregating {total_apis} API group(s)...", flush=True)

    for api_idx, (api_name, functions) in enumerate(api_groups.items(), 1):
        try:
            t_t2 = time.time()
            t2 = run_tier2(llm, api_name, functions)
            t2_dur = time.time() - t_t2
            if verbose:
                print(f"      [Tier 2] [{api_idx:>2}/{total_apis}] API: {api_name:<28} ({len(functions):>2} funcs) -> Risk: {t2.risk_level:<8} ({t2_dur:.1f}s)", flush=True)
            tier2_results.append(t2)
        except Exception as e:
            if verbose:
                print(f"      [ERROR] Tier 2 failed for {api_name}: {e}", flush=True)

    if not tier2_results:
        return Tier3Result(sha256=sha256, prediction="BENIGN",
                           analysis="All API analyses failed.")

    # ── Tier 3: APK-level prediction ──────────────────────────────────────────
    try:
        if verbose:
            print(f"\n    [Phase 3 / Tier 3] Synthesizing holistic APK verdict...", flush=True)
        t_t3 = time.time()
        result = run_tier3(llm, sha256, tier2_results)
        t3_dur = time.time() - t_t3
        if verbose and result:
            print(f"      [Tier 3] Verdict: {result.prediction:<8} ({t3_dur:.1f}s)\n", flush=True)
        return result
    except Exception as e:
        if verbose:
            print(f"    [ERROR] Tier 3 failed: {e}", flush=True)
        return None


# --- Global RAG Clients (v3: LOCAL FAISS — no cloud dependency) ---
_faiss_index = None
_faiss_metadata = None
_faiss_label_indices = None
_embed_model = None
_rag_hybrid_mod = None  # lazy-loaded 6_build_qdrant_db module for hybrid vector construction

_LOCAL_DB_DIR = PROJECT_ROOT / "data" / "rag_local"

def _get_hybrid_mod():
    """Lazy-load 6_build_qdrant_db.py to reuse its linearize_slice / extract_graph_features."""
    global _rag_hybrid_mod
    if _rag_hybrid_mod is None:
        spec = importlib.util.spec_from_file_location(
            "rag_mod", Path(__file__).resolve().parent / "6_build_qdrant_db.py"
        )
        _rag_hybrid_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_rag_hybrid_mod)
    return _rag_hybrid_mod

def get_rag_clients():
    """Return (faiss_index, TextEmbedding) using LOCAL FAISS index, or (None, None) if not built."""
    global _faiss_index, _faiss_metadata, _faiss_label_indices, _embed_model
    if _faiss_index is None:
        faiss_path = _LOCAL_DB_DIR / "faiss_index.bin"
        meta_path = _LOCAL_DB_DIR / "metadata.pkl"
        label_path = _LOCAL_DB_DIR / "label_indices.pkl"

        if not faiss_path.is_file():
            # Fallback: try Qdrant cloud if local index not available
            return _get_qdrant_fallback()

        import faiss
        import pickle as _pkl
        from fastembed import TextEmbedding

        _faiss_index = faiss.read_index(str(faiss_path))
        with open(meta_path, "rb") as f:
            _faiss_metadata = _pkl.load(f)
        with open(label_path, "rb") as f:
            _faiss_label_indices = _pkl.load(f)

        model_dir = Path(__file__).resolve().parent.parent / "fastembed_models" / "bge-small-en"
        if (model_dir / "fast-bge-small-en").is_dir():
            model_dir = model_dir / "fast-bge-small-en"

        kwargs = {
            "model_name": "BAAI/bge-small-en",
            "providers": ["CUDAExecutionProvider", "CPUExecutionProvider"]
        }
        if model_dir.is_dir() and any(model_dir.glob("*.onnx")):
            kwargs["specific_model_path"] = str(model_dir)

        _embed_model = TextEmbedding(**kwargs)
    return _faiss_index, _embed_model


def _get_qdrant_fallback():
    """Fallback to Qdrant cloud if local FAISS index not built yet."""
    global _embed_model
    try:
        load_dotenv(PROJECT_ROOT / ".env")
        from qdrant_client import QdrantClient
        from fastembed import TextEmbedding
        qdrant_url = os.environ.get("QDRANT_URL")
        qdrant_api_key = os.environ.get("QDRANT_API_KEY")
        qdrant_port = int(os.environ.get("QDRANT_PORT", "443"))
        if qdrant_url and qdrant_api_key:
            qc = QdrantClient(url=qdrant_url, api_key=qdrant_api_key, port=qdrant_port, timeout=15)
            model_dir = Path(__file__).resolve().parent.parent / "fastembed_models" / "bge-small-en"
            if (model_dir / "fast-bge-small-en").is_dir():
                model_dir = model_dir / "fast-bge-small-en"
            kwargs = {"model_name": "BAAI/bge-small-en", "providers": ["CUDAExecutionProvider", "CPUExecutionProvider"]}
            if model_dir.is_dir() and any(model_dir.glob("*.onnx")):
                kwargs["specific_model_path"] = str(model_dir)
            _embed_model = TextEmbedding(**kwargs)
            return qc, _embed_model
    except Exception:
        pass
    return None, None


def build_hybrid_vector(func_slice: FunctionSlice, embed_model) -> list[float]:
    """Build a 409-dim hybrid vector for a function slice (384 semantic + 25 graph)."""
    import numpy as np
    rag_mod = _get_hybrid_mod()

    linearized = rag_mod.linearize_slice(func_slice)
    graph_feats = rag_mod.extract_graph_features(func_slice)

    sem = list(embed_model.embed([linearized]))[0]
    sem = np.array(sem, dtype=np.float32)
    gf = np.array(graph_feats, dtype=np.float32)
    gf_norm = np.linalg.norm(gf)
    if gf_norm > 0:
        gf = gf / gf_norm

    return np.concatenate([sem, gf]).tolist()

# =============================================================================
#  Shared Pre-Processing: Deduplication & Framework Filtering
# =============================================================================

# Framework packages whose functions are filtered out UNLESS they call
# sensitive APIs. This removes benign boilerplate from the LLM prompt.
# NOTE: this list only controls whether the PURE-REFLECTION bucket
# (REFLECTION_DYNAMIC_LOADING_APIS below) gets dropped — dynamic class
# loading, SMS, location, device-ID, exfiltration, etc. are in
# ALWAYS_SENSITIVE_APIS and are kept regardless of package. So expanding
# this list to cover more well-known SDKs reduces reflection noise further
# without hiding genuinely high-value signal, even if that SDK's namespace
# happens to be spoofed/impersonated by malware.
FRAMEWORK_PREFIXES = (
    'android.', 'androidx.', 'java.', 'javax.',
    'com.google.ads.', 'com.google.android.gms.',
    'com.google.android.youtube.',  # verified this session: pure reflection glue
    'com.google.android.maps.',     # pre-GMS Maps v1 API, common in older APKs
    'com.google.gson.',             # reflection-based JSON (de)serialization by design
    'com.google.firebase.', 'com.facebook.',
    'com.squareup.',                # OkHttp/Retrofit/Picasso — ubiquitous, low malware assoc.
    'com.unity3d.',                 # game engine — named explicitly in our own prompt calibration
    'com.crashlytics.', 'io.fabric.',  # named explicitly in our own prompt calibration
    'com.flurry.',                     # named explicitly in our own prompt calibration
    'org.apache.', 'dalvik.'
)

# Catches a RELOCATED/shaded copy of AndroidX/Support library — e.g. build
# tooling (ProGuard/R8 package relocation) renaming the top-level package to
# something like "fgl.android.support.transition.*" while keeping the
# "android.support"/"androidx" segment intact internally. FRAMEWORK_PREFIXES
# above only matches when that segment is at the very START of the name (the
# normal, non-relocated case); this catches it anywhere else too. Verified
# directly this session: one real sample had 184 of its 504 post-filter
# functions in exactly this pattern, ~97% pure reflection
# (invoke/getDeclaredMethod/newInstance/getDeclaredField/forName/loadClass) —
# the same well-established "framework reflection is noise" reasoning
# FRAMEWORK_PREFIXES already applies, just for a relocated copy of a library
# already on that list. Carries the same (already-accepted) risk profile as
# the rest of this mechanism: ALWAYS_SENSITIVE_APIS still bypasses this
# regardless of package name, so genuinely sensitive behavior inside a
# relocated support-library class is still never dropped.
_SHADED_ANDROIDX_RE = re.compile(r"\.androidx\.|\.android\.support\.")

# Pure reflection / native-lib-loading APIs — the single largest category
# of slices produced by the Java slicer (~75% of all suspicious-API slices
# in the full corpus). The overwhelming majority of these, inside NAMED
# framework/SDK packages (Play Services, Firebase, Facebook, support
# libs), are benign ProGuard-minified compatibility-shim boilerplate —
# NOT evidence of obfuscation. Reflection is only a meaningful signal
# when it appears in application-owned or unknown/obfuscated packages
# (which is unaffected by this list, since FRAMEWORK_PREFIXES filtering
# never touches non-framework code in the first place).
#
# NOTE: dynamic DEX/CLASS loading (loadClass/DexClassLoader/<init>) is
# deliberately NOT in this list — see ALWAYS_SENSITIVE_APIS below. A real
# validation run caught a "dnotua" (silent-downloader family) malware
# sample whose entire suspicious-API surface was 45 loadClass/<init>
# dynamic-loading calls sitting inside a com.google.android.gms.* package
# — dropping those produced a false negative. Loading new code at runtime
# is a much rarer, higher-signal action than plain reflection, and is
# exactly the kind of thing a dropper would hide inside a named-looking
# SDK package to dodge a filter like this one.
REFLECTION_DYNAMIC_LOADING_APIS = (
    'forname', 'newinstance', 'load', 'loadlibrary',
    'getdeclaredmethod', 'getdeclaredfield', 'getmethod', 'invoke',
)

# APIs that should ALWAYS be analyzed, even inside NAMED framework/SDK
# packages — these are high-value signals (telephony/device harvesting,
# location, SMS, exfiltration, dynamic code loading, etc.) that matter
# regardless of which package they're called from; unlike plain
# reflection, they are rare enough that keeping them everywhere doesn't
# reintroduce the noise problem.
# Kept in sync with Slicer/src/main/java/SuspiciousApiList.java — every
# UNAMBIGUOUS_NAMES / CONTEXT_DEPENDENT_NAMES entry that Java can seed on
# must appear in one of these two lists, or Java-flagged signal gets
# silently dropped by this filter.
ALWAYS_SENSITIVE_APIS = (
    'exec',  # native process execution — never boilerplate
    # Dynamic dex/class loading — second-stage-payload dropper pattern
    'dexclassloader', 'loadclass', '<init>',
    # Telephony / device harvesting
    'getdeviceid', 'getsubscriberid', 'getline1number', 'getimei', 'getmeid',
    'getsimoperator', 'getsimserialnumber', 'getandroidid',
    # Location tracking
    'getlastknownlocation', 'requestlocationupdates',
    # SMS fraud
    'sendtextmessage', 'sendmultiparttextmessage', 'senddatamessage',
    # Content provider abuse
    'query',  # ContentResolver.query on contacts/sms/call_log
    # Network state / fingerprinting
    'getmacaddress', 'getconnectioninfo',
    # File-system access
    'openfileoutput', 'openfileinput',
    'getexternalstoragedirectory', 'getexternalfilesdir',
    # Network exfiltration
    'openconnection', 'connect', 'getoutputstream',
    # Crypto / obfuscation
    'dofinal', 'update',
    # Component manipulation (hidden icon)
    'setcomponentenabledsetting',
    # Camera / microphone recording
    'takepicture', 'startrecording',
    # Installed-package enumeration
    'getinstalledpackages', 'getinstalledapplications',
)

# Combined set, used only to keep the Java/Python sync check meaningful —
# NOT used directly for filtering (see preprocess_slices).
SENSITIVE_APIS = ALWAYS_SENSITIVE_APIS + REFLECTION_DYNAMIC_LOADING_APIS


def preprocess_slices(
    slices: list[FunctionSlice],
    no_filter: bool = False,
) -> tuple[list[FunctionSlice], int, int]:
    """
    Shared pre-processing: deduplication + framework filtering.

    If no_filter is True, framework filtering is completely bypassed and
    all unique function slices are retained.
    """
    original_count = len(slices)

    # Deduplication by content hash
    seen_hashes: set[str] = set()
    unique_slices: list[FunctionSlice] = []
    for s in slices:
        cfg_hash = hashlib.md5(s.raw_text.encode('utf-8')).hexdigest()
        if cfg_hash not in seen_hashes:
            seen_hashes.add(cfg_hash)
            unique_slices.append(s)

    unique_count = len(unique_slices)

    if no_filter:
        return unique_slices, original_count, unique_count

    # Framework/SDK filter — drop framework-package functions unless they
    # hit a high-value (non-reflection) sensitive API.
    filtered: list[FunctionSlice] = []
    for s in unique_slices:
        api_lower = s.suspicious_api.lower()
        is_framework = s.function_name.startswith(FRAMEWORK_PREFIXES) or bool(
            _SHADED_ANDROIDX_RE.search(s.function_name)
        )
        if is_framework:
            is_always_sensitive = any(api in api_lower for api in ALWAYS_SENSITIVE_APIS)
            if not is_always_sensitive:
                continue
        filtered.append(s)

    return filtered, original_count, unique_count


# =============================================================================
#  On-Demand CFG Extraction Pipeline
# =============================================================================

def _is_valid_apk(path: Path) -> bool:
    """
    Sanity-checks that *path* is a complete, parseable APK.

    AndroZoo occasionally serves truncated downloads or error payloads that
    still land on disk as {sha256}.apk — Soot then fails deep inside zip
    parsing with a confusing "no apk file given" RuntimeException. Catching
    this here (cheap: zipfile only reads the central directory) turns that
    into a clean, retriable download failure instead of a wasted Soot call.
    """
    if not zipfile.is_zipfile(path):
        return False
    try:
        with zipfile.ZipFile(path) as zf:
            if zf.testzip() is not None:
                return False
            return "AndroidManifest.xml" in zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return False


def ensure_cfg_extracted(sha256: str, cfg_dir: Path | None = None, verbose: bool = True) -> Path | None:
    """
    Ensures that the CFG for the given SHA256 exists in cfg_dir (defaults to extracted_cfgs/).
    If missing, automatically downloads the APK from AndroZoo, runs the Soot Slicer,
    and removes the APK to keep disk usage near zero.

    Returns:
        Path to the CFG file, or None if extraction failed / APK unavailable.
    """
    target_dir = cfg_dir if cfg_dir is not None else CFG_DIR
    cfg_path = target_dir / f"{sha256}_cfg.txt"
    if cfg_path.is_file():
        return cfg_path

    load_dotenv(PROJECT_ROOT / ".env")
    androzoo_key = os.environ.get("ANDROZOO_API_KEY", "").strip()
    if not androzoo_key or androzoo_key in ("paste_your_key_here", "your_androzoo_api_key_here"):
        if verbose:
            print(f"\n    [WARN] ANDROZOO_API_KEY not configured. Cannot auto-extract CFG for {sha256[:16]}...")
        return None

    if not JAR_PATH.is_file():
        if verbose:
            print(f"\n    [WARN] Slicer JAR not found at {JAR_PATH}. Cannot auto-extract CFG.")
        return None

    APK_DIR.mkdir(parents=True, exist_ok=True)
    apk_path = APK_DIR / f"{sha256}.apk"

    if verbose:
        print(f"\n    [ON-DEMAND EXTRACTION] CFG not found for {sha256[:16]}...", flush=True)

    # 1. Download APK from AndroZoo (with 3 retries for transient connection drops)
    t_dl_start = time.time()
    if verbose:
        print(f"       [1/3] Downloading APK from AndroZoo...", end="", flush=True)
    dl_success = False
    for dl_attempt in range(3):
        try:
            import requests
            with requests.get(
                ANDROZOO_URL,
                params={"apikey": androzoo_key, "sha256": sha256},
                stream=True,
                timeout=180,
            ) as resp:
                resp.raise_for_status()
                with open(apk_path, "wb") as fh:
                    for chunk in resp.iter_content(chunk_size=65536):
                        if chunk:
                            fh.write(chunk)

            if not _is_valid_apk(apk_path):
                raise ValueError(
                    "downloaded file is not a valid/complete APK "
                    "(truncated download or AndroZoo error payload)"
                )

            dl_time = time.time() - t_dl_start
            size_mb = apk_path.stat().st_size / (1024 * 1024)
            if verbose:
                print(f" Done! ({size_mb:.1f} MB in {dl_time:.1f}s)", flush=True)
            dl_success = True
            break
        except Exception as e:
            if apk_path.is_file():
                try:
                    os.remove(apk_path)
                except OSError:
                    pass
            if dl_attempt < 2:
                time.sleep(3.0)
                continue
            if verbose:
                print(f" FAILED ({e})", flush=True)
            return None

    # 2. Run Soot Java Slicer
    t_slice_start = time.time()
    if verbose:
        print(f"       [2/3] Slicing CFGs with Soot Java Slicer...", end="", flush=True)
    try:
        import subprocess
        cmd = [
            "java", "-Xmx4g", "-jar", str(JAR_PATH),
            str(apk_path), str(cfg_path),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        slice_time = time.time() - t_slice_start
        if res.returncode == 0 and cfg_path.is_file():
            if verbose:
                print(f" Done! (Sliced in {slice_time:.1f}s)", flush=True)
        else:
            if verbose:
                err_lines = [l.strip() for l in (res.stderr or res.stdout or "").splitlines() if l.strip()]
                err_summary = err_lines[-1] if err_lines else f"exit code {res.returncode}"
                print(f" Slicer error ({err_summary[:140]})", flush=True)
    except Exception as e:
        if verbose:
            print(f" Slicer error ({e})", flush=True)
    finally:
        # 3. Clean up temporary APK
        if apk_path.is_file():
            try:
                os.remove(apk_path)
                if verbose:
                    print(f"       [3/3] Cleaned up temporary APK to free disk space.", flush=True)
            except OSError:
                pass

    return cfg_path if cfg_path.is_file() else None


# =============================================================================
#  RAG Retrieval Helper
# =============================================================================

def retrieve_rag_context_for_slices(
    slices: list[FunctionSlice], query_count: int = 10, verbose: bool = True
) -> str:
    """Retrieve stratified top MALWARE and BENIGN matches from FAISS / Qdrant knowledge base."""
    rag_context = "No similar CFGs found in knowledge base."
    try:
        rag_client, em = get_rag_clients()
        if rag_client and em:
            import numpy as _np
            _using_local_faiss = _faiss_index is not None
            if verbose:
                mode_str = "local FAISS" if _using_local_faiss else "Qdrant cloud (fallback)"
                print(f"    [INFO] Querying RAG knowledge base ({mode_str}, stratified)...", flush=True)

            query_slices = slices[:min(len(slices), query_count)]
            all_rag_hits = []
            seen_keys = set()

            for qs in query_slices:
                try:
                    hybrid_vec = build_hybrid_vector(qs, em)
                except Exception:
                    continue

                if _using_local_faiss:
                    query_vec = _np.array([hybrid_vec], dtype=_np.float32)
                    norm = _np.linalg.norm(query_vec)
                    if norm > 0:
                        query_vec = query_vec / norm

                    for gt_label in ("MALWARE", "BENIGN"):
                        try:
                            scores, indices = _faiss_index.search(query_vec, 100)
                            count = 0
                            for score, idx in zip(scores[0], indices[0]):
                                if idx < 0 or count >= 3:
                                    break
                                payload = _faiss_metadata[idx]
                                if payload.get("ground_truth", "") != gt_label:
                                    continue
                                dedup_key = f"{payload.get('sha256', '')}:{payload.get('function_name', '')}"
                                if dedup_key not in seen_keys:
                                    seen_keys.add(dedup_key)
                                    all_rag_hits.append((float(score), payload, qs.function_name))
                                    count += 1
                        except Exception:
                            continue
                else:
                    from qdrant_client.models import FieldCondition, MatchValue, Filter
                    for gt_label in ("MALWARE", "BENIGN"):
                        try:
                            results = rag_client.query_points(
                                collection_name="lamd_cfgs",
                                query=hybrid_vec,
                                query_filter=Filter(
                                    must=[FieldCondition(key="ground_truth", match=MatchValue(value=gt_label))]
                                ),
                                limit=3,
                            ).points
                        except Exception:
                            results = []
                        for hit in results:
                            dedup_key = f"{hit.payload.get('sha256', '')}:{hit.payload.get('function_name', '')}"
                            if dedup_key not in seen_keys:
                                seen_keys.add(dedup_key)
                                all_rag_hits.append((hit.score, hit.payload, qs.function_name))

            if all_rag_hits:
                all_rag_hits.sort(key=lambda x: x[0], reverse=True)
                top_hits = all_rag_hits[:6]
                rag_parts = []
                mal_count = sum(1 for _, p, _ in top_hits if p.get("ground_truth") == "MALWARE")
                ben_count = sum(1 for _, p, _ in top_hits if p.get("ground_truth") == "BENIGN")
                rag_parts.append(f"[RAG Summary: {mal_count} MALWARE matches, {ben_count} BENIGN matches]")

                for idx, (score, payload, query_fn) in enumerate(top_hits, 1):
                    truth = payload.get("ground_truth", "UNKNOWN")
                    family = payload.get("family", "unknown")
                    func_name = payload.get("function_name", "unknown")
                    api = payload.get("suspicious_api", "")
                    lin_path = payload.get("linearized_path", "")
                    preview = payload.get("cfg_preview", "")[:300]
                    rag_parts.append(
                        f"Match {idx} (Similarity: {score:.3f}) [Queried from: {query_fn}]\n"
                        f"  Ground Truth: {truth} (Family: {family})\n"
                        f"  Function: {func_name} | API: {api}\n"
                        f"  Data Flow: {lin_path}\n"
                        f"  CFG Snippet: {preview}..."
                    )
                rag_context = "\n\n".join(rag_parts)
                if verbose:
                    print(f"    [INFO] RAG: {len(top_hits)} matches ({mal_count} MAL, {ben_count} BEN) from {len(query_slices)} function queries", flush=True)
    except Exception as e:
        if verbose:
            print(f"    [WARN] RAG Retrieval failed (skipping): {e}")

    return rag_context


# =============================================================================
#  Hierarchical Bulk-Chunked Code Reasoning (HBCR)
# =============================================================================

def analyse_one_apk_single_call(
    llm: LLMBackend, sha256: str, cfg_path: Path,
    verbose: bool = True, no_filter: bool = False,
) -> Tier3Result | None:
    """
    Hybrid pipeline:
      - If all functions fit in one prompt -> single call (~2-4s), same as before.
      - If they exceed the budget -> group by suspicious API (never split one
        API's functions across calls), run one Tier-2 API-intent call per
        group (`run_tier2_from_group`), then feed every API's Tier2Result into
        the SAME `run_tier3` the plain 3-tier pipeline uses for the final
        verdict. This keeps call count at O(#distinct suspicious APIs) instead
        of O(#functions) while preserving the paper's Tier-2 API-intent-
        aggregation signal, which the previous token-chunked bulk path (binary
        per-chunk YES/NO) discarded entirely.
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
            print(f"  [SKIP] No suspicious APIs in {sha256[:16]}...", flush=True)
        return Tier3Result(sha256=sha256, prediction="BENIGN",
                           analysis="No suspicious APIs found.")

    # ── Pre-Processing: Deduplication & Framework Filtering ───────────────────
    slices, original_count, unique_count = preprocess_slices(slices, no_filter=no_filter)

    if verbose and original_count > 0:
        filter_status = "unfiltered" if no_filter else "filtered"
        print(f"    [INFO] CFGs: {original_count} raw -> {unique_count} unique -> {len(slices)} {filter_status}", flush=True)

    if not slices:
        if verbose:
            print(f"  [SKIP] All functions filtered out for {sha256[:16]}...", flush=True)
        return Tier3Result(sha256=sha256, prediction="BENIGN",
                           analysis="All functions were framework/SDK code.")

    MAX_TOTAL_TOKENS = getattr(llm, "MAX_CONTEXT_TOKENS", LLMBackend.MAX_CONTEXT_TOKENS)
    TEMPLATE_OVERHEAD_TOKENS = 1_500
    content_budget = max(500, MAX_TOTAL_TOKENS - TEMPLATE_OVERHEAD_TOKENS)

    all_cfgs_text, included_count, unique_apis = build_fcg_representation(
        slices, max_content_tokens=content_budget
    )

    # ──────────────────────────────────────────────────────────────────────────
    # CASE 1: Single Call Path (All functions fit within token budget)
    # ──────────────────────────────────────────────────────────────────────────
    if included_count >= len(slices):
        api_list = ", ".join(unique_apis) if unique_apis else "None"
        total_tokens = count_tokens(all_cfgs_text)

        if verbose:
            print(f"    [INFO] Sending {included_count}/{len(slices)} functions across {len(unique_apis)} API group(s) "
                  f"(~{total_tokens} tokens, budget {MAX_TOTAL_TOKENS}) in single call", flush=True)

        rag_context = retrieve_rag_context_for_slices(slices, query_count=10, verbose=verbose)

        prompt = SINGLE_CALL_TEMPLATE.format(
            rag_context=rag_context,
            all_cfgs=all_cfgs_text,
            func_count=included_count,
            api_list=api_list,
        )

        try:
            response = llm.chat(SINGLE_CALL_SYSTEM, prompt)
        except Exception as e:
            if verbose:
                print(f"    [ERROR] Single-call analysis failed: {e}")
            return None

        confidence = _parse_marker_value(response, ("CONFIDENCE",)).upper() or "UNKNOWN"

        prediction = parse_final_prediction(response, context=f"[single-call {sha256[:12]}] ")
        if prediction == "UNKNOWN":
            prediction, response = _retry_prediction_parse(llm, SINGLE_CALL_SYSTEM, prompt, response,
                                                             context=f"[single-call {sha256[:12]}] ")
        if confidence == "UNKNOWN" and prediction == "MALWARE":
            confidence = "MEDIUM"

        return Tier3Result(
            sha256=sha256,
            prediction=prediction,
            analysis=response,
            confidence=confidence,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # CASE 2: API-Grouped Bulk Path (functions exceed the single-call budget)
    # ──────────────────────────────────────────────────────────────────────────
    total_fns = len(slices)
    api_groups: dict[str, list[FunctionSlice]] = {}
    for s in slices:
        api_groups.setdefault(s.suspicious_api, []).append(s)

    # Batch small groups together (pure call-count optimization — never
    # changes what gets analyzed; see run_tier2_batch's safety-net fallback
    # for any API that doesn't parse cleanly out of a batch).
    batches, standalone_apis = partition_groups_for_batching(api_groups, content_budget)
    total_steps = len(batches) + len(standalone_apis)

    if verbose:
        batched_count = sum(len(b) for b in batches)
        print(f"    [INFO] Bulk Mode: {total_fns} functions across {len(api_groups)} suspicious API "
              f"group(s) exceed the single-call budget — running Tier 2: "
              f"{len(standalone_apis)} individually, {batched_count} API(s) combined into "
              f"{len(batches)} batch call(s)...", flush=True)

    tier2_results: list[Tier2Result] = []
    step = 0

    for batch_api_names in batches:
        step += 1
        batch_groups = [(name, api_groups[name]) for name in batch_api_names]
        try:
            t_t2 = time.time()
            batch_results = run_tier2_batch(llm, batch_groups, content_budget, verbose=verbose)
            t2_dur = time.time() - t_t2
            if verbose:
                print(f"      [Tier 2] [{step:>2}/{total_steps}] BATCH ({len(batch_api_names)} APIs): "
                      f"{', '.join(batch_api_names)} -> {len(batch_results)} result(s) ({t2_dur:.1f}s)", flush=True)
            tier2_results.extend(batch_results.values())
        except Exception as e:
            if verbose:
                print(f"      [ERROR] Tier 2 batch failed for {batch_api_names}: {e}", flush=True)

    for api_name in standalone_apis:
        step += 1
        group_slices = api_groups[api_name]
        try:
            t_t2 = time.time()
            t2 = run_tier2_from_group(llm, api_name, group_slices, content_budget, verbose=verbose)
            t2_dur = time.time() - t_t2
            if verbose:
                print(f"      [Tier 2] [{step:>2}/{total_steps}] API: {api_name:<28} "
                      f"({len(group_slices):>2} funcs) -> Risk: {t2.risk_level:<8} ({t2_dur:.1f}s)", flush=True)
            tier2_results.append(t2)
        except Exception as e:
            if verbose:
                print(f"      [ERROR] Tier 2 (bulk) failed for {api_name}: {e}", flush=True)

    if not tier2_results:
        return Tier3Result(sha256=sha256, prediction="BENIGN",
                           analysis="All API group analyses failed.")

    if verbose:
        print(f"\n    [Phase 3 / Tier 3] Synthesizing holistic APK verdict from "
              f"{len(tier2_results)} API group(s)...", flush=True)

    try:
        result = run_tier3(llm, sha256, tier2_results)
    except Exception as e:
        if verbose:
            print(f"    [ERROR] Tier 3 failed: {e}")
        return None

    if verbose and result:
        print(f"      [Tier 3] Verdict: {result.prediction:<8}\n", flush=True)

    return result



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
        "--backend", choices=["openai", "gemini", "ollama", "groq", "openrouter", "nemotron", "nvidia", "local", "gpu", "gguf", "llama-cpp", "32b"], default="gguf",
        help="LLM backend to use (default: gguf). Use 'gguf' or '32b' for native dual-GPU Qwen 2.5 32B execution."
    )
    parser.add_argument(
        "--model", type=str, default=None,
        help="Custom model name to override the default for the chosen backend (e.g. qwen2.5:32b, gemini-2.5-flash)."
    )
    parser.add_argument(
        "--csv", type=Path, default=TRAIN_CSV,
        help="CSV file with sha256 + labels for evaluation."
    )
    parser.add_argument(
        "--cfg-dir", type=Path, default=CFG_DIR,
        help="Directory containing extracted CFG files (default: extracted_cfgs)."
    )
    parser.add_argument(
        "--offset", type=int, default=0,
        help="Skip the first N samples."
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
        "--no-filter", action="store_true",
        help="Disable framework filtering: keep 100%% of raw sliced CFG functions without dropping anything."
    )
    parser.add_argument(
        "--single", action="store_true",
        help="Use single-call architecture (send ALL CFGs in one prompt). "
             "Much faster and works within free-tier limits."
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume from existing predictions file. Skips already-processed "
             "APKs and appends new results instead of overwriting."
    )
    parser.add_argument(
        "--output", type=Path, default=None,
        help="Output JSONL file for predictions."
    )
    args = parser.parse_args()

    # Resolve CSV and CFG directory paths relative to PROJECT_ROOT if not absolute
    csv_path = args.csv
    if not csv_path.is_absolute():
        if not csv_path.is_file() and (PROJECT_ROOT / csv_path).is_file():
            csv_path = (PROJECT_ROOT / csv_path).resolve()
        else:
            csv_path = csv_path.resolve()

    cfg_dir = args.cfg_dir
    if not cfg_dir.is_absolute():
        if not cfg_dir.is_dir() and (PROJECT_ROOT / cfg_dir).is_dir():
            cfg_dir = (PROJECT_ROOT / cfg_dir).resolve()
        else:
            cfg_dir = cfg_dir.resolve()

    info_lines = [
        f"Mode    : {args.mode}{'  [SINGLE-CALL]' if args.single else ''}",
        f"Backend : {args.backend}",
        f"CSV     : {csv_path.name if csv_path.is_file() else csv_path}",
        f"CFG Dir : {cfg_dir.name if cfg_dir.is_dir() else cfg_dir}",
    ]
    if args.offset > 0:
        info_lines.append(f"Offset  : {args.offset}")
    if args.limit:
        info_lines.append(f"Limit   : {args.limit}")
    if not args.single:
        info_lines.append(f"DRC     : {'disabled' if args.no_drc else 'enabled'}")
    if args.resume:
        info_lines.append("Resume  : enabled")
    banner("LAMD Phase 2 - Tier-Wise LLM Code Reasoning", info_lines)
    console.print()

    # ── Output path ───────────────────────────────────────────────────────────
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if args.output:
        output_path = args.output
    else:
        # Include the CSV name in the output filename to prevent cross-CSV
        # resume collisions (e.g., laptop1 vs laptop2 results stay separate).
        csv_stem = csv_path.stem  # e.g., "split_laptop1"
        output_path = RESULTS_DIR / f"predictions_{csv_stem}.jsonl"

    # ── Mode: Pre-computed logs ───────────────────────────────────────────────
    if args.mode == "logs":
        info(f"Reading pre-computed logs from {LOG_DIR}")
        if not LOG_DIR.is_dir():
            fail(f"Log directory not found: {LOG_DIR}")
            sys.exit(1)

        log_files = sorted(LOG_DIR.glob("*.log"))
        if args.offset > 0:
            log_files = log_files[args.offset:]
            info(f"Skipping first {args.offset} logs (--offset).")
        if args.limit:
            log_files = log_files[:args.limit]

        info(f"{len(log_files)} log file(s) found.")

        results = []
        with make_progress() as progress:
            task = progress.add_task("Processing logs", total=len(log_files))
            for log_path in log_files:
                sha256 = log_path.stem.lower()
                prediction, analysis = parse_malware_log(log_path)
                results.append({
                    "sha256": sha256,
                    "prediction": prediction,
                    "analysis_length": len(analysis),
                })
                progress.advance(task)

        with open(output_path, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

        mal = sum(1 for r in results if r["prediction"] == "MALWARE")
        ben = sum(1 for r in results if r["prediction"] == "BENIGN")
        console.print()
        ok(f"{len(results)} predictions written to {output_path}")
        console.print(f"    MALWARE: [bold red]{mal}[/bold red]  |  BENIGN: [bold green]{ben}[/bold green]")
        return

    # ── Mode: CFG analysis (full tier-wise pipeline) ──────────────────────────
    if args.mode in ("cfg", "direct"):
        # Create the LLM backend
        llm = create_backend(args.backend, model_override=args.model)
        ok(f"LLM backend '{args.backend}' initialized.")
        if args.single:
            budget = getattr(llm, "MAX_CONTEXT_TOKENS", LLMBackend.MAX_CONTEXT_TOKENS)
            if budget < 10_000:
                warn(
                    f"'{args.backend}' has a small per-request budget (~{budget} tokens) - "
                    f"--single will heavily truncate any APK with more than a few dozen "
                    f"functions. Consider dropping --single (tiered pipeline) for this backend."
                )
        console.print()

        # Load CSV for ground truth
        if csv_path.is_file():
            df = pd.read_csv(
                csv_path,
                usecols=["sha256", "family", "label"],
                dtype={"sha256": str, "family": str, "label": float},
            )
            df["sha256"] = df["sha256"].str.strip().str.lower()
            df.dropna(subset=["sha256"], inplace=True)
            df.drop_duplicates(subset=["sha256"], inplace=True)

            if args.offset > 0:
                df = df.iloc[args.offset:]
                info(f"Skipping first {args.offset} samples (--offset).")

            if args.limit:
                df = df.head(args.limit)

            info(f"{len(df)} sample(s) loaded from {csv_path.name}")
        else:
            warn(f"CSV not found: {csv_path}. Running without ground truth.")
            df = pd.DataFrame(columns=["sha256", "family", "label"])

        # Find CFG files
        if not cfg_dir.is_dir():
            fail(f"CFG directory not found: {cfg_dir}")
            console.print("  Run  python src_python/2_extract_cfg.py  first.")
            sys.exit(1)

        results = []
        already_done = set()

        # ── Resume: load existing predictions ─────────────────────────────
        if args.resume and output_path.is_file():
            with open(output_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        already_done.add(record["sha256"])
                        results.append(record)
                    except (json.JSONDecodeError, KeyError):
                        continue
            info(f"Resuming: {len(already_done)} APKs already processed, skipping them.")

        total = len(df)
        run_start = time.time()

        with make_progress() as progress:
            task = progress.add_task("Processing samples", total=total)
            for idx, row in df.iterrows():
                try:
                    sha256 = row["sha256"]
                    cfg_path = cfg_dir / f"{sha256}_cfg.txt"
                    i = len(results) + 1
                    sha_short = sha256[:20]

                    if sha256 in already_done:
                        sample_skip_line(i, total, sha_short, "already done")
                        continue

                    if not cfg_path.is_file():
                        # On-demand extraction
                        cfg_path = ensure_cfg_extracted(sha256, cfg_dir=cfg_dir, verbose=True)
                        if not cfg_path or not cfg_path.is_file():
                            sample_skip_line(i, total, sha_short, "no CFG / download unavailable")
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
                            prediction = parse_final_prediction(response, context=f"[direct {sha256[:12]}] ")
                            result = Tier3Result(sha256=sha256, prediction=prediction, analysis=response)
                        except Exception as e:
                            sample_error_line(i, total, sha_short, str(e))
                            continue
                    elif args.single:
                        # Single-call pipeline (1 LLM call per APK)
                        result = analyse_one_apk_single_call(
                            llm, sha256, cfg_path,
                            verbose=True,
                            no_filter=args.no_filter,
                        )
                    else:
                        # Full tier-wise pipeline
                        result = analyse_one_apk(
                            llm, sha256, cfg_path,
                            verify_drc=not args.no_drc,
                            verbose=True,
                            no_filter=args.no_filter,
                        )

                    if result is None:
                        sample_error_line(i, total, sha_short, "failed")
                        continue

                    elapsed = time.time() - t0
                    gt_label = "MALWARE" if row.get("label", 0) == 1.0 else "BENIGN"

                    sample_result_line(i, total, sha_short, result.prediction, gt_label, elapsed)

                    record = {
                        "sha256": sha256,
                        "prediction": result.prediction,
                        "ground_truth": gt_label,
                        "family": str(row.get("family", "")),
                        "analysis": result.analysis,
                    }
                    results.append(record)

                    # ── Incremental save: write immediately so crashes don't lose data ──
                    if len(results) == len(already_done) + 1:
                        # First new result: rewrite file (resumed + this one)
                        with open(output_path, "w", encoding="utf-8") as f:
                            for r in results:
                                f.write(json.dumps(r, ensure_ascii=False) + "\n")
                    else:
                        # Append subsequent results
                        with open(output_path, "a", encoding="utf-8") as f:
                            f.write(json.dumps(record, ensure_ascii=False) + "\n")
                finally:
                    progress.advance(task)

        elapsed_total = time.time() - run_start

        # ── Summary ───────────────────────────────────────────────────────────
        correct = sum(1 for r in results if r["prediction"] == r["ground_truth"])
        total_done = len(results)

        section("Inference Complete")
        console.print(f"  Samples processed : {total_done}")
        console.print(f"  Correct           : {correct}")
        if total_done:
            acc = correct / total_done * 100
            acc_color = "green" if acc >= 80 else ("yellow" if acc >= 50 else "red")
            console.print(f"  Accuracy          : [{acc_color}]{acc:.1f}%[/{acc_color}]")
        else:
            console.print("  Accuracy          : N/A")
        console.print(f"  Total time        : {elapsed_total:.1f}s")
        console.print(f"  Predictions saved : {output_path}")
        console.print()
        console.print(f"  Run evaluation:  python src_python/5_evaluate.py --predictions {output_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"\n[FATAL ERROR] {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)