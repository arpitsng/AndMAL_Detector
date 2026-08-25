"""
LAMD Chatbot — Core Logic (APK Malware Analysis Only)
=====================================================
Business logic for on-demand APK analysis via SHA-256 hash or direct APK upload.
Transparent procedural step tracking (Soot slicing -> FCG mapping -> RAG -> LLM).
No wasted LLM calls on hash checking / cached lookups.
Supports switching between Gemini and Groq for analysis and explanations.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import sys
import threading
import time
import uuid
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"
CFG_SEARCH_DIRS = [
    PROJECT_ROOT / "test_extracted_cfgs_new",
    PROJECT_ROOT / "test_extracted_cfgs",
    PROJECT_ROOT / "fresh_test_20",
    PROJECT_ROOT / "extracted_cfgs",
    PROJECT_ROOT / "chatbot_uploads_cfgs",
]

sys.path.insert(0, str(PROJECT_ROOT / "src_python"))
load_dotenv(PROJECT_ROOT / ".env")


# =============================================================================
#  Lazy-load pipeline modules
# =============================================================================

_lamd = None
_evaluate = None


def _load_module(filename: str, modname: str):
    spec = importlib.util.spec_from_file_location(modname, PROJECT_ROOT / "src_python" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def lamd():
    global _lamd
    if _lamd is None:
        _lamd = _load_module("4_llm_inference.py", "lamd_inference")
    return _lamd


def evaluate_mod():
    global _evaluate
    if _evaluate is None:
        _evaluate = _load_module("5_evaluate.py", "lamd_evaluate")
    return _evaluate


# =============================================================================
#  Backend Management (Gemini / Groq / GGUF)
# =============================================================================

SUPPORTED_BACKENDS = ("gemini", "groq", "gguf")
_backend_cache: dict[str, object] = {}
_backend_lock = threading.Lock()


def get_llm_backend(name: str = "gemini"):
    name = name.lower().strip()
    if name not in SUPPORTED_BACKENDS:
        name = "gemini"
    
    with _backend_lock:
        if name in _backend_cache:
            return _backend_cache[name]
        
        mod = lamd()
        try:
            if name == "gemini":
                backend = mod.create_backend("gemini", model_override=os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"))
            elif name == "groq":
                backend = mod.create_backend("groq", model_override=os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b"))
            elif name == "gguf":
                backend = mod.create_backend("gguf")
            else:
                backend = mod.create_backend("gemini")
            _backend_cache[name] = backend
            return backend
        except Exception as e:
            # Fallback to Gemini if requested backend fails
            print(f"[WARN] Backend '{name}' failed: {e}. Falling back to Gemini...", file=sys.stderr)
            if "gemini" not in _backend_cache:
                _backend_cache["gemini"] = mod.create_backend("gemini", model_override="gemini-2.5-flash")
            return _backend_cache["gemini"]


# =============================================================================
#  Hash & Scope Parsing
# =============================================================================

_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

_OFFTOPIC_REFUSAL = (
    "I am the **LAMD APK Malware Analyst**, specialized strictly in Android binary analysis. "
    "Please provide a SHA-256 hash or upload an `.apk` file to analyze, or ask about past detection findings."
)

EXPLAIN_SYSTEM_PROMPT = """\
You are an expert Android malware analyst explaining static binary analysis findings from the LAMD detector.
Analyze the provided Control Flow Graphs (CFGs), Function Call Graphs (FCGs), and detector verdict to directly answer the user's question.
Be specific, cite actual functions/APIs when relevant, and stay strictly focused on Android security.
"""


def extract_sha256(text: str) -> str | None:
    if not text:
        return None
    m = _SHA256_RE.search(text.strip())
    return m.group(0).lower() if m else None


# =============================================================================
#  Cached Result & CFG Lookup
# =============================================================================

def lookup_cached_result(sha256: str) -> dict | None:
    sha256 = sha256.lower().strip()
    if not RESULTS_DIR.is_dir():
        return None
    
    # Check predictions files
    for jsonl_path in sorted(RESULTS_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            with open(jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip() or line.startswith("//"):
                        continue
                    try:
                        rec = json.loads(line)
                        if str(rec.get("sha256", "")).strip().lower() == sha256:
                            rec["_source_file"] = jsonl_path.name
                            return rec
                    except Exception:
                        continue
        except Exception:
            continue
    return None


def lookup_cached_cfg(sha256: str) -> Path | None:
    sha256 = sha256.lower().strip()
    for cdir in CFG_SEARCH_DIRS:
        if not cdir.is_dir():
            continue
        p = cdir / f"{sha256}_cfg.txt"
        if p.is_file() and p.stat().st_size > 0:
            return p
        p_upper = cdir / f"{sha256.upper()}_cfg.txt"
        if p_upper.is_file() and p_upper.stat().st_size > 0:
            return p_upper
    return None


# =============================================================================
#  Background Analysis Jobs with Real-Time Procedural Steps
# =============================================================================

JOBS: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def get_job(job_id: str) -> dict | None:
    with _jobs_lock:
        job = JOBS.get(job_id)
        return dict(job) if job else None


def start_analysis_job(sha256: str, backend_name: str = "gemini", apk_path: Path | None = None) -> str:
    job_id = uuid.uuid4().hex[:12]
    with _jobs_lock:
        JOBS[job_id] = {
            "job_id": job_id,
            "sha256": sha256,
            "backend": backend_name,
            "status": "running",
            "current_step": "Initializing analysis pipeline...",
            "step_index": 0,
            "total_steps": 5,
            "steps": [
                {"name": "Check Local CFG Cache", "status": "pending", "detail": "Scanning extracted CFG repositories"},
                {"name": "Obtain / Slice APK", "status": "pending", "detail": "Downloading APK & executing Soot Slicer"},
                {"name": "FCG & Call Chain Mapping", "status": "pending", "detail": "Reconstructing inter-function call graph"},
                {"name": "RAG Knowledge Retrieval", "status": "pending", "detail": "Querying local vector database"},
                {"name": "LLM Reasoning & Verdict", "status": "pending", "detail": f"Executing reasoning on {backend_name.upper()}"},
            ],
            "log": [],
            "result": None,
            "error": None,
            "started_at": time.time(),
        }
    
    thread = threading.Thread(target=_run_job_worker, args=(job_id, sha256, backend_name, apk_path), daemon=True)
    thread.start()
    return job_id


def _update_step(job_id: str, step_idx: int, status: str, detail: str = ""):
    with _jobs_lock:
        if job_id not in JOBS:
            return
        job = JOBS[job_id]
        if 0 <= step_idx < len(job["steps"]):
            job["steps"][step_idx]["status"] = status
            if detail:
                job["steps"][step_idx]["detail"] = detail
            job["step_index"] = step_idx
            job["current_step"] = job["steps"][step_idx]["name"]
            job["log"].append(f"[{status.upper()}] {job['steps'][step_idx]['name']}: {detail}")


def _run_job_worker(job_id: str, sha256: str, backend_name: str, apk_path: Path | None):
    try:
        mod = lamd()
        
        # ── Step 1: Check Local CFG Cache ─────────────────────────────────────
        _update_step(job_id, 0, "running", "Searching local CFG stores for existing slices...")
        cfg_path = lookup_cached_cfg(sha256)
        
        if cfg_path and cfg_path.is_file():
            _update_step(job_id, 0, "done", f"Found cached CFG ({cfg_path.stat().st_size // 1024} KB in {cfg_path.parent.name})")
            _update_step(job_id, 1, "done", "Skipped APK download (CFG already available)")
        else:
            _update_step(job_id, 0, "done", "No existing CFG found. Proceeding to extract.")
            
            # ── Step 2: Obtain / Slice APK ────────────────────────────────────
            _update_step(job_id, 1, "running", "Obtaining APK and running Soot backward program slicer...")
            
            if apk_path and apk_path.is_file():
                # Direct local upload slice
                cfg_dir = PROJECT_ROOT / "chatbot_uploads_cfgs"
                cfg_dir.mkdir(parents=True, exist_ok=True)
                cfg_path = cfg_dir / f"{sha256}_cfg.txt"
                
                import subprocess
                _update_step(job_id, 1, "running", f"Running Soot backward slicer JAR on uploaded APK ({apk_path.stat().st_size // 1024} KB)...")
                res = subprocess.run(
                    ["java", "-Xmx4g", "-jar", str(mod.JAR_PATH), str(apk_path), str(cfg_path)],
                    capture_output=True, text=True, timeout=300
                )
                if res.returncode != 0 or not cfg_path.is_file():
                    err_msg = (res.stderr or res.stdout or "Soot slicer failed to generate CFG").strip()[-300:]
                    raise RuntimeError(f"Soot analysis failed: {err_msg}")
            else:
                # AndroZoo download + slice
                _update_step(job_id, 1, "running", "Downloading APK from AndroZoo & executing Soot Slicer...")
                cfg_path = mod.ensure_cfg_extracted(sha256, cfg_dir=PROJECT_ROOT / "test_extracted_cfgs_new", verbose=True)
            
            if not cfg_path or not cfg_path.is_file():
                raise RuntimeError("Could not generate sliced CFG for this APK.")
            _update_step(job_id, 1, "done", f"CFG successfully sliced ({cfg_path.stat().st_size // 1024} KB)")

        # ── Step 3: FCG & Call Chain Mapping ──────────────────────────────────
        _update_step(job_id, 2, "running", "Parsing Jimple IR and discovering caller -> callee call chains...")
        slices = mod.parse_cfg_file(cfg_path)
        slices, orig_c, uniq_c = mod.preprocess_slices(slices, no_filter=False)
        
        fcg_text, fn_count, apis = mod.build_fcg_representation(slices, max_content_tokens=14000)
        _update_step(job_id, 2, "done", f"Mapped {fn_count} functions across {len(apis)} sensitive API groups ({', '.join(apis[:4])}...)")

        # ── Step 4: RAG Knowledge Base Retrieval ──────────────────────────────
        _update_step(job_id, 3, "running", "Querying local vector database for stratified malware/benign matches...")
        rag_context = mod.retrieve_rag_context_for_slices(slices, query_count=10, verbose=False)
        _update_step(job_id, 3, "done", "Retrieved nearest neighbor attack/benign patterns from FAISS")

        # ── Step 5: LLM Reasoning & Verdict ───────────────────────────────────
        _update_step(job_id, 4, "running", f"Sending FCG-structured prompt to {backend_name.upper()}...")
        llm = get_llm_backend(backend_name)
        
        result = mod.analyse_one_apk_single_call(llm, sha256, cfg_path, verbose=False, no_filter=False)
        if result is None:
            raise RuntimeError("LLM reasoning produced no verdict.")
        
        _update_step(job_id, 4, "done", f"Verdict rendered: {result.prediction} (Confidence: {result.confidence})")

        # Parse sections from analysis
        app_purpose = ""
        key_findings = []
        evidence = ""
        
        for line in result.analysis.split("\n"):
            line_str = line.strip()
            if line_str.upper().startswith("APP_PURPOSE:"):
                app_purpose = line_str.split(":", 1)[1].strip()
            elif line_str.startswith("- ") or line_str.startswith("* "):
                key_findings.append(line_str[2:].strip())
            elif line_str.upper().startswith("EVIDENCE:"):
                evidence = line_str.split(":", 1)[1].strip()

        # Finalize Job Record
        with _jobs_lock:
            JOBS[job_id]["status"] = "done"
            JOBS[job_id]["current_step"] = "Analysis Complete"
            JOBS[job_id]["result"] = {
                "sha256": sha256,
                "prediction": result.prediction,
                "confidence": result.confidence,
                "analysis": result.analysis,
                "app_purpose": app_purpose,
                "key_findings": key_findings[:5],
                "evidence": evidence or result.analysis,
                "function_count": fn_count,
                "api_list": apis,
                "fcg_preview": fcg_text[:3000],
                "backend_used": backend_name,
                "duration_seconds": round(time.time() - JOBS[job_id]["started_at"], 1)
            }

    except Exception as e:
        with _jobs_lock:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"] = str(e)
            JOBS[job_id]["log"].append(f"[ERROR] {e}")


# =============================================================================
#  Interactive Explanations (Q&A)
# =============================================================================

def explain_finding(sha256: str, question: str, backend_name: str = "gemini") -> str:
    """Answers user questions grounded strictly in the APK's analysis and CFG."""
    cached = lookup_cached_result(sha256)
    cfg_path = lookup_cached_cfg(sha256)
    
    cfg_preview = ""
    if cfg_path and cfg_path.is_file():
        cfg_preview = cfg_path.read_text(encoding="utf-8", errors="replace")[:4000]
    
    analysis_text = cached.get("analysis", "") if cached else "(Analysis in progress or fresh run)"
    pred = cached.get("prediction", "UNKNOWN") if cached else "UNKNOWN"
    
    prompt = (
        f"APK SHA-256: {sha256}\n"
        f"Verdict: {pred}\n"
        f"Analysis Findings:\n{analysis_text}\n\n"
        f"CFG Code Snippet:\n{cfg_preview}\n\n"
        f"User Question: {question}\n\n"
        "Provide a direct, helpful, and technical explanation based strictly on the data above."
    )
    
    llm = get_llm_backend(backend_name)
    try:
        return llm.chat(EXPLAIN_SYSTEM_PROMPT, prompt)
    except Exception as e:
        return f"Unable to generate explanation: {e}"
