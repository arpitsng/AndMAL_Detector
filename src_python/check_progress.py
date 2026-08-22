"""
Real-time Qdrant RAG Upload Progress Checker

Usage:
  python src_python/check_progress.py
  python src_python/check_progress.py --watch   # Live refresh every 3 seconds
"""

import argparse
import json
import os
import ssl
import sys
import time
import urllib.request
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Read .env file directly without external dependencies
QDRANT_URL = "https://b732edfe-6b97-4cf1-8f15-60ab50ad6c01.eu-west-1-0.aws.cloud.qdrant.io"
QDRANT_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3MiOiJtIiwic3ViamVjdCI6ImFwaS1rZXk6MDJlNThkMzYtMzE5MC00NDNiLTlmZDQtNDVhYjU3YjQ5MmJhIn0.ttX9TfL0ZPnuvHDGrGSRPKWBImUf9ugc96vPjgrTU9g"

env_file = PROJECT_ROOT / ".env"
if env_file.is_file():
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("QDRANT_URL="):
            QDRANT_URL = line.split("=", 1)[1].strip().strip('"').strip("'").rstrip("/")
        elif line.startswith("QDRANT_API_KEY="):
            QDRANT_API_KEY = line.split("=", 1)[1].strip().strip('"').strip("'")

COLLECTION_NAME = "lamd_cfgs"
TARGET_POINTS = 1_898_349

headers = {
    "api-key": QDRANT_API_KEY,
    "Content-Type": "application/json"
}
ctx = ssl.create_default_context()


def get_collection_stats():
    req = urllib.request.Request(f"{QDRANT_URL}/collections/{COLLECTION_NAME}", headers=headers, method="GET")
    with urllib.request.urlopen(req, context=ctx) as res:
        data = json.loads(res.read().decode())
        return data.get("result", {})


def get_label_count(label_val):
    payload = json.dumps({
        "exact": True,
        "filter": {"must": [{"key": "ground_truth", "match": {"value": label_val}}]}
    }).encode("utf-8")
    req = urllib.request.Request(f"{QDRANT_URL}/collections/{COLLECTION_NAME}/points/count", data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(req, context=ctx) as res:
        data = json.loads(res.read().decode())
        return data.get("result", {}).get("count", 0)


def render_bar(current, total, length=35):
    pct = min(100.0, (current / total) * 100.0) if total > 0 else 0.0
    filled = int(length * current // total) if total > 0 else 0
    bar = "=" * filled + "-" * (length - filled)
    return f"[{bar}] {pct:.2f}%"


def display_stats():
    stats = get_collection_stats()
    status = stats.get("status", "unknown")
    points = stats.get("points_count", 0) or 0
    indexed = stats.get("indexed_vectors_count", 0) or 0
    segments = stats.get("segments_count", 0)

    try:
        mal_cnt = get_label_count("MALWARE")
        ben_cnt = get_label_count("BENIGN")
    except Exception:
        mal_cnt, ben_cnt = None, None

    print("\n" + "=" * 65)
    print("       QDRANT RAG VECTOR DATABASE -- LIVE SYNC MONITOR")
    print("=" * 65)
    print(f" Target Collection    : {COLLECTION_NAME}")
    print(f" Cluster Status       : {status.upper()}")
    print(f" Segments in Qdrant   : {segments}")
    print("-" * 65)
    print(f" Progress             : {render_bar(points, TARGET_POINTS)}")
    print(f" Points Uploaded      : {points:,} / {TARGET_POINTS:,}")
    print(f" Remaining to Push    : {max(0, TARGET_POINTS - points):,}")
    print(f" HNSW Indexed Vectors : {indexed:,}")
    if mal_cnt is not None and ben_cnt is not None:
        print(f"   |-- Malware Slices : {mal_cnt:,}")
        print(f"   \\-- Benign Slices  : {ben_cnt:,}")
    print("=" * 65)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--watch", action="store_true", help="Live auto-refresh every 3s")
    args = parser.parse_args()

    if args.watch:
        try:
            while True:
                # Clear terminal screen
                os.system("cls" if os.name == "nt" else "clear")
                display_stats()
                print(" (Live monitor running... Press Ctrl+C to exit)\n")
                time.sleep(3)
        except KeyboardInterrupt:
            print("\nExiting monitor.")
    else:
        display_stats()


if __name__ == "__main__":
    main()
