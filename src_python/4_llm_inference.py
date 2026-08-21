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

    def __init__(self, model: str = "llama3", host: str = "http://localhost:11434"):
        import requests
        self.model = model
        self.host = host
        self._requests = requests
        self.num_ctx = int(os.environ.get("OLLAMA_NUM_CTX", "32768"))
        self.timeout = int(os.environ.get("OLLAMA_TIMEOUT", "600"))
        # 15% headroom for system+template+RAG context+response.
        self.MAX_CONTEXT_TOKENS = int(self.num_ctx * 0.85)

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


def create_backend(backend_name: str) -> LLMBackend:
    """Factory to create the appropriate LLM backend."""
    load_dotenv(PROJECT_ROOT / ".env")

    if backend_name == "openai":
        key = os.environ.get("OPENAI_API_KEY", "").strip()
        if not key:
            print("[ERROR] OPENAI_API_KEY not found in .env", file=sys.stderr)
            sys.exit(1)
        return OpenAIBackend(api_key=key)

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
            model = os.environ.get("NVIDIA_MODEL", "nvidia/llama-3.1-nemotron-70b-instruct").strip()
            print(f"    [INFO] Initialized NVIDIA backend with {len(valid_nvidia_keys)} rotating key(s) (model: {model}).")
            return NvidiaBackend(api_keys=valid_nvidia_keys, model=model)

        if not valid_keys:
            print("[ERROR] No OPENROUTER_API_KEY1..3 (or NVIDIA_API_KEY) found in .env", file=sys.stderr)
            sys.exit(1)

        default_model = "nvidia/nemotron-3-ultra-550b-a55b:free"
        model = os.environ.get("OPENROUTER_MODEL", default_model).strip()
        print(f"    [INFO] Initialized OpenRouter/Nemotron backend with {len(valid_keys)} rotating key(s) (model: {model}).")
        return OpenRouterBackend(api_keys=valid_keys, model=model)

    elif backend_name == "groq":
        # Supports GROQ_API_KEY1..5 for multi-key rotation (same pattern as
        # Gemini), falling back to a single GROQ_API_KEY for backward
        # compatibility with existing .env files.
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

        model = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b").strip()
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

        model = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash").strip()
        print(f"    [INFO] Initialized Gemini backend with {len(valid_keys)} rotating keys (model: {model}).")
        return GeminiBackend(api_keys=valid_keys, model=model)

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


def verify_consistency(
    llm: LLMBackend, func_slice: FunctionSlice, tier1_summary: str
) -> tuple[bool, str]:
    """
    Real factual-consistency check: an LLM call that compares the Tier 1
    summary against the CFG it was generated from, looking for claims not
    actually supported by the code (hallucination).

    This is the genuine DRC verification described in the LAMD writeup —
    sanity_check_tier1() above is a free formatting check and cannot catch
    this class of error (a well-formatted summary can still invent details).
    Costs one extra LLM call per function, only when verify_drc=True.

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

# Keyword-density fallback signals — used only when structured parsing fails.
MALWARE_SIGNAL_KEYWORDS = (
    "MALWARE", "MALICIOUS", "SPYWARE", "TROJAN", "ADWARE",
    "DATA HARVESTING", "DATA EXFILTRATION", "HIGHLY SUSPICIOUS",
    "SMS FRAUD", "HIDDEN AD",
)


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
      4. BENIGN, loudly logged — this means the LLM's output didn't match
         any expected format and the result should be treated with
         suspicion, not silently trusted.
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
              f"defaulting to BENIGN. Response head: {response[:150]!r}",
              file=sys.stderr, flush=True)
    return "BENIGN"


def run_tier3(llm: LLMBackend, sha256: str, api_results: list[Tier2Result]) -> Tier3Result:
    """Final malware/benign prediction for one APK."""
    api_summaries = [
        {"api_name": r.api_name, "api_type": r.api_type, "summary": r.summary}
        for r in api_results
    ]
    api_text = format_api_summaries_for_tier3(api_summaries)

    prompt = TIER3_USER_TEMPLATE.format(api_summaries=api_text)
    response = llm.chat(TIER3_SYSTEM, prompt)

    prediction = parse_final_prediction(response, context=f"[Tier3 {sha256[:12]}] ")

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
    slices, original_count, unique_count = preprocess_slices(slices)

    if verbose and original_count > 0:
        print(f"    [INFO] CFGs: {original_count} raw -> {unique_count} unique -> {len(slices)} filtered")

    tier1_results: list[Tier1Result] = []
    for func_slice in slices:
        try:
            t1 = run_tier1(llm, func_slice)

            if verify_drc:
                # Layer 1: free formatting sanity check (no LLM call).
                is_sane, reason = sanity_check_tier1(func_slice, t1.summary)
                if not is_sane:
                    if verbose:
                        print(f"    [SANITY] Retrying {func_slice.function_name}: {reason}")
                    t1 = run_tier1(llm, func_slice)  # retry once
                else:
                    # Layer 2: real factual-consistency check (1 extra LLM
                    # call) — catches well-formatted but hallucinated claims
                    # that the free check above cannot see.
                    try:
                        is_consistent, drc_reason = verify_consistency(llm, func_slice, t1.summary)
                        if not is_consistent:
                            if verbose:
                                print(f"    [DRC] Retrying {func_slice.function_name}: {drc_reason}")
                            t1 = run_tier1(llm, func_slice)  # retry once
                    except Exception as e:
                        if verbose:
                            print(f"    [WARN] DRC verification call failed for "
                                  f"{func_slice.function_name}, keeping original summary: {e}")

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


# --- Global RAG Clients (v2: hybrid function-level embeddings) ---
_q_client = None
_embed_model = None
_rag_hybrid_mod = None  # lazy-loaded 6_build_qdrant_db module for hybrid vector construction

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
    """Return (QdrantClient, TextEmbedding) or (None, None) if not configured."""
    global _q_client, _embed_model
    if _q_client is None:
        load_dotenv(PROJECT_ROOT / ".env")
        from qdrant_client import QdrantClient
        from fastembed import TextEmbedding
        qdrant_url = os.environ.get("QDRANT_URL")
        qdrant_api_key = os.environ.get("QDRANT_API_KEY")
        qdrant_port = int(os.environ.get("QDRANT_PORT", "443"))
        if qdrant_url and qdrant_api_key:
            _q_client = QdrantClient(
                url=qdrant_url, api_key=qdrant_api_key,
                port=qdrant_port, timeout=15,
            )
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
    return _q_client, _embed_model


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
) -> tuple[list[FunctionSlice], int, int]:
    """
    Shared pre-processing: deduplication + framework filtering.

    Framework-package functions are dropped UNLESS they hit an
    ALWAYS_SENSITIVE_APIS call. Reflection/dynamic-loading calls
    (REFLECTION_DYNAMIC_LOADING_APIS) do NOT override the framework drop —
    inside named SDK packages they're almost always benign compatibility
    boilerplate (see the module-level comment above). Reflection in
    application-owned or unknown/obfuscated packages is untouched by this
    filter and is always kept, which is exactly where reflection-based
    evasion actually matters.

    Returns:
        (filtered_slices, original_count, unique_count)
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

    # Framework/SDK filter — drop framework-package functions unless they
    # hit a high-value (non-reflection) sensitive API. Reflection calls do
    # NOT rescue a function from the framework drop (see module comment).
    filtered: list[FunctionSlice] = []
    for s in unique_slices:
        api_lower = s.suspicious_api.lower()
        if s.function_name.startswith(FRAMEWORK_PREFIXES):
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
#  Single-Call Pipeline — One APK, One LLM Call
# =============================================================================

def analyse_one_apk_single_call(
    llm: LLMBackend, sha256: str, cfg_path: Path,
    verbose: bool = True
) -> Tier3Result | None:
    """
    Analyses an APK by sending ALL filtered CFGs in a single LLM call.

    This leverages large-context models (Gemini 3.5 Flash: 1M tokens) to
    avoid the 300+ individual calls of the 3-tier pipeline. ALL unique,
    non-framework functions are included — no arbitrary cap.

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
            print(f"  [SKIP] No suspicious APIs in {sha256[:16]}...", flush=True)
        return Tier3Result(sha256=sha256, prediction="BENIGN",
                           analysis="No suspicious APIs found.")

    # ── Pre-Processing: Deduplication & Framework Filtering ───────────────────
    slices, original_count, unique_count = preprocess_slices(slices)

    if verbose and original_count > 0:
        print(f"    [INFO] CFGs: {original_count} raw -> {unique_count} unique -> {len(slices)} filtered", flush=True)

    if not slices:
        if verbose:
            print(f"  [SKIP] All functions filtered out for {sha256[:16]}...", flush=True)
        return Tier3Result(sha256=sha256, prediction="BENIGN",
                           analysis="All functions were framework/SDK code.")

    # ── Build single prompt with ALL CFGs ─────────────────────────────────────
    # Include as many filtered functions as fit within THIS backend's real
    # budget (see LLMBackend.MAX_CONTEXT_TOKENS / per-subclass overrides),
    # using real token counts (count_tokens) rather than a chars/N guess —
    # that guess was measured to be off by up to ~1.9x on Jimple IR text,
    # which is exactly what caused real Groq 413 errors this session.
    # Gemini's 800K-token budget tolerates "send everything," but Groq's
    # real rate-limit-derived budget (4K) needs every token accounted for.
    MAX_TOTAL_TOKENS = getattr(llm, "MAX_CONTEXT_TOKENS", LLMBackend.MAX_CONTEXT_TOKENS)
    TEMPLATE_OVERHEAD_TOKENS = 1_500  # fixed system+template text + RAG context, measured ~1035 + margin
    content_budget = max(500, MAX_TOTAL_TOKENS - TEMPLATE_OVERHEAD_TOKENS)

    all_cfg_parts = []
    total_tokens = 0
    included_count = 0

    for s in slices:
        text = s.raw_text
        # Truncate individual functions longer than 8K chars (rough
        # anti-pathological-outlier guard — the real budget check below is
        # what actually governs how many functions get included).
        if len(text) > 8000:
            text = text[:8000] + "\n... [truncated] ...\n=== END FUNCTION ===\n"

        func_tokens = count_tokens(text)
        if total_tokens + func_tokens > content_budget:
            if verbose:
                print(f"    [INFO] Token budget reached at {included_count}/{len(slices)} functions "
                      f"({total_tokens}/{content_budget} tokens)", flush=True)
            break

        all_cfg_parts.append(text)
        total_tokens += func_tokens
        included_count += 1

    all_cfgs_text = "\n".join(all_cfg_parts)

    # Collect unique API names for context
    api_set = sorted(set(s.suspicious_api for s in slices[:included_count]))
    api_list = ", ".join(api_set) if api_set else "None"

    if verbose:
        print(f"    [INFO] Sending {included_count} functions (~{total_tokens} tokens, budget {MAX_TOTAL_TOKENS}) in single call", flush=True)

    # ── RAG Retrieval v2 (Hybrid Function-Level + Stratified) ────────────────
    # Instead of one whole-APK query, sample up to 10 of the most suspicious
    # function slices, build a hybrid vector for each, and do STRATIFIED
    # retrieval: top-3 MALWARE + top-3 BENIGN matches per function.
    # This guarantees the LLM always sees both perspectives regardless of
    # class imbalance in the database.
    rag_context = "No similar CFGs found in knowledge base."
    try:
        qc, em = get_rag_clients()
        if qc and em:
            from qdrant_client.models import FieldCondition, MatchValue, Filter

            if verbose:
                print(f"    [INFO] Querying RAG knowledge base (hybrid v2, stratified)...", flush=True)

            # Sample up to 10 slices for per-function querying
            query_slices = slices[:min(included_count, 10)]
            all_rag_hits = []  # (score, payload, query_func_name)
            seen_keys = set()  # deduplicate by sha256+function

            for qs in query_slices:
                try:
                    hybrid_vec = build_hybrid_vector(qs, em)
                except Exception:
                    continue  # skip if hybrid vector construction fails

                # Stratified: top-3 MALWARE matches + top-3 BENIGN matches
                for gt_label in ("MALWARE", "BENIGN"):
                    try:
                        results = qc.query_points(
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
                # Sort by score descending, take top 6 overall
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
                    print(f"    [INFO] RAG: {len(top_hits)} matches ({mal_count} MAL, {ben_count} BEN) "
                          f"from {len(query_slices)} function queries", flush=True)
    except Exception as e:
        if verbose:
            print(f"    [WARN] RAG Retrieval failed (skipping): {e}")

    # ── Single LLM call ───────────────────────────────────────────────────────
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

    # ── Parse response ────────────────────────────────────────────────────────
    confidence = "UNKNOWN"
    for line in response.split("\n"):
        line_stripped = line.strip()
        if line_stripped.upper().startswith("CONFIDENCE:"):
            confidence = line_stripped.split(":", 1)[1].strip().upper()
            break

    prediction = parse_final_prediction(response, context=f"[single-call {sha256[:12]}] ")
    if confidence == "UNKNOWN" and prediction == "MALWARE":
        # Keyword-density fallback fired inside parse_final_prediction with no
        # explicit CONFIDENCE: line — flag it as lower-confidence downstream.
        confidence = "MEDIUM"

    return Tier3Result(
        sha256=sha256,
        prediction=prediction,
        analysis=response,
        confidence=confidence,
    )


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
        "--backend", choices=["openai", "gemini", "ollama", "groq", "openrouter", "nemotron", "nvidia"], default="openai",
        help="LLM backend to use (default: openai)."
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
        llm = create_backend(args.backend)
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
                        )
                    else:
                        # Full tier-wise pipeline
                        result = analyse_one_apk(
                            llm, sha256, cfg_path,
                            verify_drc=not args.no_drc,
                            verbose=True,
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
    main()