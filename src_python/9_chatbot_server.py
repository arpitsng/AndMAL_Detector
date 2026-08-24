"""
LAMD Pipeline — Step 9: Interactive Chatbot (local web UI)
============================================================
A small local web server for chatting with the LAMD malware-analysis
system: analyze an APK by SHA-256 hash or direct upload, ask about past
results, or ask aggregate questions ("how many false negatives so far").

Deliberately scoped to APK malware analysis ONLY (see chatbot_core.py's
scope gate) — it will not answer unrelated questions.

Usage:
  ./venv/Scripts/python.exe src_python/9_chatbot_server.py
  # then open http://127.0.0.1:8765 in a browser

Environment:
  ANALYSIS_BACKEND   backend used to actually analyze APKs (default: gguf,
                      the local Qwen model — matches the real deployment).
                      Falls back to Gemini automatically if unavailable.
  CHATBOT_PORT        default 8765
"""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src_python"))

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

import chatbot_core as core

app = FastAPI(title="LAMD Chatbot")

STATIC_DIR = PROJECT_ROOT / "static"
CHAT_HTML_PATH = STATIC_DIR / "chatbot.html"


class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None
    chat_backend: str = "gemini"


@app.get("/", response_class=HTMLResponse)
def index():
    if not CHAT_HTML_PATH.is_file():
        return HTMLResponse("<h1>static/chatbot.html not found</h1>", status_code=500)
    return HTMLResponse(CHAT_HTML_PATH.read_text(encoding="utf-8"))


@app.post("/api/chat")
def chat(req: ChatRequest):
    try:
        result = core.handle_message(req.session_id, req.message, req.chat_backend)
        return JSONResponse(result)
    except Exception as e:
        return JSONResponse(
            {
                "reply": f"Something went wrong handling that: {e}",
                "session_id": req.session_id or "",
                "job_id": None,
            },
            status_code=200,  # keep it in the chat UI rather than a raw HTTP error
        )


@app.post("/api/upload")
async def upload(file: UploadFile = File(...), session_id: str = Form(None), chat_backend: str = Form("gemini")):
    try:
        apk_bytes = await file.read()
        if not apk_bytes:
            return JSONResponse({"reply": "That upload looked empty — try again.", "session_id": session_id or "", "job_id": None})
        job_id, sha256 = core.start_analysis_job_from_upload(apk_bytes)
        session_id, session = core.get_or_create_session(session_id)
        session["current_sha"] = sha256
        session["last_explained_sha"] = sha256
        return JSONResponse({
            "reply": f"Got `{file.filename}` ({len(apk_bytes)//1024} KB, sha256 `{sha256[:16]}...`) — "
                     f"analyzing now (slice + AI review). I'll post the verdict here when it's done.",
            "session_id": session_id,
            "job_id": job_id,
        })
    except Exception as e:
        return JSONResponse({"reply": f"Upload failed: {e}", "session_id": session_id or "", "job_id": None})


@app.get("/api/status/{job_id}")
def status(job_id: str):
    job = core.get_job(job_id)
    if job is None:
        return JSONResponse({"error": "unknown job_id"}, status_code=404)
    return JSONResponse(job)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("CHATBOT_PORT", "8765"))
    print(f"[INFO] LAMD Chatbot starting at http://127.0.0.1:{port}")
    print(f"[INFO] Analysis backend: {os.environ.get('ANALYSIS_BACKEND', core.ANALYSIS_BACKEND_ENV_DEFAULT)} "
          f"(falls back to Gemini automatically if unavailable)")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
