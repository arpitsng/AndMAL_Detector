"""
LAMD Pipeline — Step 1: Download APKs from AndroZoo
====================================================
Reads every SHA-256 hash from  data/train.csv  and downloads the
corresponding APK from the AndroZoo API into  apks/<sha256>.apk.

This script is intentionally separate from Step 2 (Soot analysis) so
you can download a batch of APKs in advance if needed. However, the
normal recommended flow is to let  2_extract_cfg.py  handle both
downloading and analysis in a single loop (download → analyse → delete).

Idempotent:  already-downloaded APKs are skipped automatically.

Usage:
  python src_python/1_download_apk.py [--limit N]

  --limit N    Download only the first N APKs (useful for testing).

Prerequisites:
  - .env file in the project root containing your API key:
      ANDROZOO_API_KEY=<your_key>
  - pip install -r requirements.txt
"""

import argparse
import os
import sys
import time
from pathlib import Path

import pandas as pd
import requests
from dotenv import load_dotenv

# =============================================================================
#  Paths — resolved relative to this file so the script works from any cwd
# =============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent   # d:\LAMD_Project
TRAIN_CSV    = PROJECT_ROOT / "data" / "train.csv"
APK_DIR      = PROJECT_ROOT / "apks"
ANDROZOO_URL = "https://androzoo.uni.lu/api/download"

DOWNLOAD_TIMEOUT = 300   # seconds per APK
CHUNK_SIZE       = 65_536  # 64 KB


# =============================================================================
#  Load API key
# =============================================================================

def load_api_key() -> str:
    load_dotenv(PROJECT_ROOT / ".env")
    key = os.environ.get("ANDROZOO_API_KEY", "").strip()
    if not key or key in ("paste_your_key_here", "your_androzoo_api_key_here"):
        print(
            "\n[ERROR] ANDROZOO_API_KEY is not set.\n"
            f"  Open:  {PROJECT_ROOT}\\.env\n"
            "  Paste your key on the line:  ANDROZOO_API_KEY=<key>\n"
            "  Get a free key at https://androzoo.uni.lu/\n",
            file=sys.stderr,
        )
        sys.exit(1)
    return key


# =============================================================================
#  Load hashes from train.csv
# =============================================================================

def load_hashes(limit: int | None) -> list[str]:
    """
    Reads the sha256 column from  data/train.csv  and returns a list of
    lowercase hash strings, deduplicated and in CSV order.
    """
    if not TRAIN_CSV.is_file():
        print(f"[ERROR] CSV not found: {TRAIN_CSV}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Reading hashes from: {TRAIN_CSV}")
    df = pd.read_csv(TRAIN_CSV, usecols=["sha256"], dtype=str)

    hashes = (
        df["sha256"]
        .dropna()
        .str.strip()
        .str.lower()        # normalize to lowercase (CSV has uppercase)
        .drop_duplicates()
        .tolist()
    )

    if limit:
        hashes = hashes[:limit]

    print(f"[INFO] {len(hashes)} unique hash(es) loaded from CSV.")
    return hashes


# =============================================================================
#  Download one APK
# =============================================================================

def download_apk(sha256: str, api_key: str) -> Path:
    """
    Streams the APK for *sha256* from AndroZoo into  apks/{sha256}.apk.
    Returns the path to the saved file.
    """
    dest = APK_DIR / f"{sha256}.apk"
    with requests.get(
        ANDROZOO_URL,
        params={"apikey": api_key, "sha256": sha256},
        stream=True,
        timeout=DOWNLOAD_TIMEOUT,
    ) as resp:
        resp.raise_for_status()
        with open(dest, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:
                    fh.write(chunk)
    return dest


# =============================================================================
#  Main loop
# =============================================================================

def main(limit: int | None) -> None:
    print("=" * 60)
    print("  LAMD Phase 1 — Step 1: Download APKs from AndroZoo")
    print("=" * 60)
    print()

    api_key = load_api_key()
    print("[OK] API key loaded.\n")

    hashes = load_hashes(limit)
    total  = len(hashes)
    if total == 0:
        print("[INFO] No hashes found in CSV. Nothing to download.")
        return

    APK_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[INFO] APK destination: {APK_DIR}\n")

    skipped  = 0
    succeeded = 0
    failed    = 0
    run_start = time.time()

    for idx, sha256 in enumerate(hashes, start=1):
        dest = APK_DIR / f"{sha256}.apk"

        print(f"[{idx:>6}/{total}] {sha256[:20]}...", end="  ", flush=True)

        # Skip if already downloaded
        if dest.is_file():
            print("SKIP (already exists)")
            skipped += 1
            continue

        t0 = time.time()
        try:
            path = download_apk(sha256, api_key)
            size_mb = path.stat().st_size / (1024 * 1024)
            elapsed = time.time() - t0
            print(f"OK  ({size_mb:.1f} MB, {elapsed:.1f}s)")
            succeeded += 1

        except requests.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else "?"
            print(f"HTTP ERROR {code}")
            failed += 1

        except requests.Timeout:
            print(f"TIMEOUT (>{DOWNLOAD_TIMEOUT}s)")
            failed += 1
            if dest.is_file():           # partial file — remove it
                os.remove(dest)

        except Exception as exc:
            print(f"ERROR: {exc}")
            failed += 1
            if dest.is_file():
                os.remove(dest)

    # Summary
    total_elapsed = time.time() - run_start
    print()
    print("=" * 60)
    print("  Download Complete")
    print("=" * 60)
    print(f"  Total in CSV   : {total}")
    print(f"  Skipped        : {skipped}")
    print(f"  Downloaded     : {succeeded}")
    print(f"  Failed         : {failed}")
    print(f"  Total time     : {total_elapsed:.1f}s")
    print(f"  APK directory  : {APK_DIR}")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Download APKs from AndroZoo using hashes from train.csv."
    )
    parser.add_argument(
        "--limit", type=int, default=None, metavar="N",
        help="Only download the first N APKs (for testing).",
    )
    args = parser.parse_args()
    main(limit=args.limit)
