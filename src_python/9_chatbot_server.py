"""
LAMD Pipeline — Step 9: Interactive APK Malware Analyst Server
=============================================================
FastAPI server powering the modern APK analysis UI:
- Analyzes APK by SHA-256 hash or direct APK file upload.
- Procedural real-time step streaming (Soot Slicing -> FCG -> RAG -> LLM).
- Zero wasted LLM calls on cached lookups.
- User-selectable LLM backends (Gemini 2.5 Flash / Groq Llama 3.3).
"""

import os
import sys
import hashlib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src_python"))

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import chatbot_core as core

app = FastAPI(title="LAMD APK Malware Analyst")

STATIC_DIR = PROJECT_ROOT / "static"
CHAT_HTML_PATH = STATIC_DIR / "chatbot.html"


class AnalyzeRequest(BaseModel):
    sha256: str
    backend: str = "gemini"


class ExplainRequest(BaseModel):
    sha256: str
    question: str
    backend: str = "gemini"


@app.get("/", response_class=HTMLResponse)
def index():
    if not CHAT_HTML_PATH.is_file():
        return HTMLResponse("<h1>static/chatbot.html not found</h1>", status_code=500)
    return HTMLResponse(CHAT_HTML_PATH.read_text(encoding="utf-8"))


@app.get("/api/samples")
def get_sample_hashes():
    """Returns quick test sample hashes (both Malware & Benign)."""
    return {
        "malware": [
            {"sha256": "50a440e0b42c8d234d7d91e6b36e344e2efcae965f3f019f3900cb83a45c3866", "family": "dnotua (Silent Dropper)"},
            {"sha256": "c0851675fc9efd3cc17d8042a7864b462a6a50c59a5e5bb91480eaf526458362", "family": "phishingapp"},
            {"sha256": "5cb02398484ddbad28d572fb09fedc67dbd6d1bd324586d4269da2f3f6eb8c87", "family": "artemis"},
        ],
        "benign": [
            {"sha256": "36ee117b5cc6935530b18afaa47fb32d8bdc9211495777a360de745a1aa2c1a4", "family": "Benign Utility"},
            {"sha256": "b004e91ca68c5a9b0ece29168674099222f8358bfb14e4165f2da770442c8a06", "family": "Adobe AIR Multimedia"},
            {"sha256": "e9b225f39eedfb04538e0173366b62fa730189d496c076b2ffe6ad6f53229d82", "family": "Support Library Utility"},
        ]
    }


@app.post("/api/analyze")
def analyze_hash(req: AnalyzeRequest):
    sha = core.extract_sha256(req.sha256)
    if not sha:
        return JSONResponse({"error": "Invalid SHA-256 hash. Please provide a 64-character hexadecimal hash."}, status_code=400)
    
    # 1. Zero-waste check: Check if already analyzed
    cached = core.lookup_cached_result(sha)
    if cached:
        analysis_text = cached.get("analysis", "")
        app_purpose = ""
        key_findings = []
        evidence = ""
        
        for line in analysis_text.split("\n"):
            line_str = line.strip()
            if line_str.upper().startswith("APP_PURPOSE:"):
                app_purpose = line_str.split(":", 1)[1].strip()
            elif line_str.startswith("- ") or line_str.startswith("* "):
                key_findings.append(line_str[2:].strip())
            elif line_str.upper().startswith("EVIDENCE:"):
                evidence = line_str.split(":", 1)[1].strip()
        
        return JSONResponse({
            "status": "cached",
            "message": "Loaded instantly from existing verified results (0 LLM tokens wasted)",
            "result": {
                "sha256": sha,
                "prediction": cached.get("prediction", "UNKNOWN"),
                "confidence": cached.get("confidence", "HIGH"),
                "analysis": analysis_text,
                "app_purpose": app_purpose,
                "key_findings": key_findings[:5],
                "evidence": evidence or analysis_text,
                "ground_truth": cached.get("ground_truth"),
                "family": cached.get("family"),
                "source_file": cached.get("_source_file", "results"),
            }
        })
    
    # 2. Not cached: Start procedural background analysis job
    job_id = core.start_analysis_job(sha, backend_name=req.backend)
    return JSONResponse({
        "status": "job_started",
        "job_id": job_id,
        "sha256": sha,
        "backend": req.backend,
    })


@app.post("/api/upload")
async def upload_apk(file: UploadFile = File(...), backend: str = Form("gemini")):
    try:
        apk_bytes = await file.read()
        if not apk_bytes:
            return JSONResponse({"error": "Uploaded APK file was empty."}, status_code=400)
        
        sha = hashlib.sha256(apk_bytes).hexdigest().lower()
        
        uploads_dir = PROJECT_ROOT / "chatbot_uploads"
        uploads_dir.mkdir(parents=True, exist_ok=True)
        apk_path = uploads_dir / f"{sha}.apk"
        apk_path.write_bytes(apk_bytes)
        
        # Check if already cached
        cached = core.lookup_cached_result(sha)
        if cached:
            return JSONResponse({
                "status": "cached",
                "message": "This APK hash was previously analyzed (0 LLM tokens wasted)",
                "result": {
                    "sha256": sha,
                    "prediction": cached.get("prediction", "UNKNOWN"),
                    "confidence": cached.get("confidence", "HIGH"),
                    "analysis": cached.get("analysis", ""),
                }
            })
        
        job_id = core.start_analysis_job(sha, backend_name=backend, apk_path=apk_path)
        return JSONResponse({
            "status": "job_started",
            "job_id": job_id,
            "sha256": sha,
            "filename": file.filename,
            "size_kb": len(apk_bytes) // 1024,
            "backend": backend,
        })
    except Exception as e:
        return JSONResponse({"error": f"Upload processing failed: {e}"}, status_code=500)


@app.get("/api/status/{job_id}")
def check_status(job_id: str):
    job = core.get_job(job_id)
    if not job:
        return JSONResponse({"error": f"Job '{job_id}' not found."}, status_code=404)
    return JSONResponse(job)


@app.post("/api/explain")
def explain(req: ExplainRequest):
    sha = core.extract_sha256(req.sha256)
    if not sha:
        return JSONResponse({"error": "Invalid SHA-256 hash."}, status_code=400)
    
    reply = core.explain_finding(sha, req.question, backend_name=req.backend)
    return JSONResponse({"sha256": sha, "reply": reply})


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("CHATBOT_PORT", "8765"))
    print(f"\n=======================================================")
    print(f" [OK] LAMD APK Malware Analyst UI running at:")
    print(f"      http://127.0.0.1:{port}")
    print(f"=======================================================\n")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
