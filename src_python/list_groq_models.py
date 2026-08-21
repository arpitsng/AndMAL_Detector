"""
List models currently available to your Groq account.

Groq's hosted model catalog changes over time — model IDs get deprecated
or renamed without notice (this is how we discovered "llama-3.3-70b-versatile"
had disappeared entirely). Run this before any large batch run to confirm
GROQ_MODEL in .env still points at something real.

Usage:
  python src_python/list_groq_models.py
"""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

key = (
    os.environ.get("GROQ_API_KEY1", "").strip()
    or os.environ.get("GROQ_API_KEY", "").strip()
)
if not key:
    print("[ERROR] No GROQ_API_KEY1 or GROQ_API_KEY found in .env", file=sys.stderr)
    sys.exit(1)

from openai import OpenAI

client = OpenAI(api_key=key, base_url="https://api.groq.com/openai/v1")
models = sorted(m.id for m in client.models.list().data)

configured = os.environ.get("GROQ_MODEL", "").strip()

print(f"[INFO] {len(models)} model(s) available to this Groq account:\n")
for m in models:
    marker = "  <- GROQ_MODEL in .env" if m == configured else ""
    print(f"  {m}{marker}")

if configured and configured not in models:
    print(f"\n[WARN] GROQ_MODEL='{configured}' in .env is NOT in the list above.")
    print("       It has likely been deprecated/renamed. Pick a replacement before running a large batch.")
elif configured:
    print(f"\n[OK] GROQ_MODEL='{configured}' is valid.")
