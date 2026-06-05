"""
LAMD Pipeline — Step 2: Download APKs, Extract Sliced CFGs, Clean Up
=====================================================================
Master pipeline script for LAMD Phase 1. Per-sample lifecycle:

  1. Load all SHA-256 hashes + labels from  data/train.csv.
  2. Skip any sample whose  extracted_cfgs/{hash}_cfg.txt  already exists.
  3. Download the APK from the AndroZoo API (streaming, one at a time).
  4. Run the Soot backward slicer JAR:  java -jar Slicer/target/slicer-1.0.jar
  5. Immediately delete the APK to keep disk usage to ~1 APK at a time.
  6. On any per-sample error: log it, delete the APK, and continue.

API Key Setup:
  1. Open the  .env  file in the project root.
  2. Replace "paste_your_key_here" with your real AndroZoo key.
  3. Save.  (The file is gitignored — your key stays private.)

Usage:
  python src_python/2_extract_cfg.py [--limit N] [--csv PATH]

  --limit N    Only process the first N samples (great for dry-runs).
  --csv PATH   Use a different CSV instead of data/train.csv.
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd
import requests
from dotenv import load_dotenv

# =============================================================================
#  Paths — all relative to the project root, resolved at runtime.
# =============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAIN_CSV    = PROJECT_ROOT / "data" / "train.csv"
APK_DIR      = PROJECT_ROOT / "apks"
CFG_DIR      = PROJECT_ROOT / "extracted_cfgs"
JAR_PATH     = PROJECT_ROOT / "Slicer" / "target" / "slicer-1.0.jar"

# AndroZoo REST download endpoint
ANDROZOO_URL = "https://androzoo.uni.lu/api/download"

# Per-sample timeouts (seconds)
DOWNLOAD_TIMEOUT = 300   # 5 min — large APKs can be 100+ MB
ANALYSIS_TIMEOUT = 300   # 5 min — pathological CFGs can stall

CHUNK_SIZE = 65_536      # 64 KB streaming chunks


# =============================================================================
#  Step 0 — Load API key from .env
# =============================================================================

def load_api_key() -> str:
    """
    Loads ANDROZOO_API_KEY from the local .env file.
    Exits with a clear message if the key is missing or still a placeholder.
    """
    load_dotenv(PROJECT_ROOT / ".env")
    key = os.environ.get("ANDROZOO_API_KEY", "").strip()

    if not key or key in ("paste_your_key_here", "your_androzoo_api_key_here"):
        print(
            "\n[ERROR] ANDROZOO_API_KEY is not configured.\n"
            "  1. Open the file:  d:\\LAMD_Project\\.env\n"
            "  2. Replace 'paste_your_key_here' with your real API key.\n"
            "  3. Save the file and re-run this script.\n"
            "  (Get a free key at https://androzoo.uni.lu/)\n",
            file=sys.stderr,
        )
        sys.exit(1)

    return key


# =============================================================================
#  Step 1 — Load hashes + labels from the CSV
# =============================================================================

def load_csv(csv_path: Path, limit: int | None) -> list[dict]:
    """
    Reads the training CSV and returns a list of sample dicts.

    Each dict has:
      sha256 (str)  — lowercase hash used as the unique file key
      label  (str)  — "MALWARE" or "BENIGN"
      family (str)  — malware family name, or "benign"

    The CSV column layout is:
      sha256, family, date, label, vt, vt_scan_date, vt_year
    where label 0.0 = benign, 1.0 = malware.
    """
    if not csv_path.is_file():
        print(f"[ERROR] CSV not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Reading {csv_path.name} ...")
    df = pd.read_csv(
        csv_path,
        usecols=["sha256", "family", "label"],
        dtype={"sha256": str, "family": str, "label": float},
    )

    df["sha256"] = df["sha256"].str.strip().str.lower()
    df.dropna(subset=["sha256"], inplace=True)
    df.drop_duplicates(subset=["sha256"], inplace=True)

    if limit:
        df = df.head(limit)

    samples = []
    for _, row in df.iterrows():
        samples.append({
            "sha256": row["sha256"],
            "label":  "MALWARE" if row["label"] == 1.0 else "BENIGN",
            "family": str(row["family"]).strip(),
        })

    print(f"[INFO] {len(samples)} unique sample(s) loaded.")
    return samples


# =============================================================================
#  Step 2 — Download one APK from AndroZoo
# =============================================================================

def download_apk(sha256: str, api_key: str) -> Path:
    """
    Streams the APK for *sha256* from AndroZoo into apks/{sha256}.apk.

    Raises:
        requests.HTTPError   — server returned a non-2xx code
        requests.Timeout     — download stalled past DOWNLOAD_TIMEOUT
    """
    APK_DIR.mkdir(parents=True, exist_ok=True)
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
#  Step 3 — Run the Soot slicer on the downloaded APK
# =============================================================================

def run_slicer(apk_path: Path, cfg_path: Path) -> None:
    """
    Invokes  java -jar slicer-1.0.jar <apk> <output>  and waits for it.

    Raises:
        subprocess.TimeoutExpired      — analysis exceeded ANALYSIS_TIMEOUT
        subprocess.CalledProcessError  — JVM exited with a non-zero code
    """
    cmd = [
        "java",
        "-Xmx4g",                    # 4 GB heap — Soot needs it for large APKs
        "-jar", str(JAR_PATH),
        str(apk_path),
        str(cfg_path),
    ]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=ANALYSIS_TIMEOUT,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, cmd, result.stdout, result.stderr
        )


# =============================================================================
#  Utility — safe file deletion
# =============================================================================

def safe_delete(path: Path) -> None:
    """Deletes *path* silently. Never raises — deletion is best-effort."""
    try:
        if path.is_file():
            os.remove(path)
    except OSError:
        pass


# =============================================================================
#  Main pipeline loop
# =============================================================================

def main(csv_path: Path, limit: int | None) -> None:
    print("=" * 65)
    print("  LAMD Phase 1 — Step 2: Download + Analyse + Clean Up")
    print("=" * 65)
    print()

    # ── Validate prerequisites ─────────────────────────────────────────────────
    api_key = load_api_key()
    print("[OK] API key loaded from .env")

    if not JAR_PATH.is_file():
        print(
            f"\n[ERROR] Soot JAR not found: {JAR_PATH}\n"
            "  Build it first:\n"
            "      cd Slicer\n"
            "      mvn clean package -DskipTests\n"
            "      cd ..\n",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"[OK] Soot JAR found: {JAR_PATH.name}")

    CFG_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[OK] Output directory: {CFG_DIR}")
    print()

    # ── Load work list ─────────────────────────────────────────────────────────
    samples = load_csv(csv_path, limit)
    total   = len(samples)
    if total == 0:
        print("[INFO] No samples to process.")
        return
    print()

    # ── Counters ───────────────────────────────────────────────────────────────
    skipped   = 0   # CFG already exists from a previous run
    succeeded = 0   # fully processed this run
    dl_errors = 0   # download failure
    soot_errs = 0   # slicer failure
    other_errs = 0  # unexpected errors

    run_start = time.time()

    # ── Per-sample loop ────────────────────────────────────────────────────────
    for idx, sample in enumerate(samples, start=1):
        sha256 = sample["sha256"]
        apk_path = APK_DIR / f"{sha256}.apk"
        cfg_path = CFG_DIR / f"{sha256}_cfg.txt"

        print(f"[{idx:>6}/{total}] {sha256[:20]}...", end="  ", flush=True)

        # ── Skip if already done ───────────────────────────────────────────────
        if cfg_path.is_file():
            print("SKIP (already extracted)")
            skipped += 1
            continue

        t0 = time.time()

        # ── Download ───────────────────────────────────────────────────────────
        try:
            download_apk(sha256, api_key)
        except requests.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else "?"
            print(f"DOWNLOAD FAILED (HTTP {code})")
            dl_errors += 1
            continue
        except requests.Timeout:
            print(f"DOWNLOAD TIMEOUT (>{DOWNLOAD_TIMEOUT}s)")
            dl_errors += 1
            continue
        except Exception as exc:
            print(f"DOWNLOAD ERROR: {exc}")
            dl_errors += 1
            continue

        # ── Soot Analysis ──────────────────────────────────────────────────────
        try:
            run_slicer(apk_path, cfg_path)
        except subprocess.TimeoutExpired:
            elapsed = time.time() - t0
            print(f"SOOT TIMEOUT ({elapsed:.0f}s)")
            (CFG_DIR / f"{sha256}_timeout.log").write_text(
                f"Soot timed out after {ANALYSIS_TIMEOUT}s\n", encoding="utf-8"
            )
            soot_errs += 1
            safe_delete(apk_path)
            continue
        except subprocess.CalledProcessError as exc:
            print(f"SOOT ERROR (exit {exc.returncode})")
            if exc.stderr:
                (CFG_DIR / f"{sha256}_error.log").write_text(
                    exc.stderr, encoding="utf-8"
                )
            soot_errs += 1
            safe_delete(apk_path)
            continue
        except Exception as exc:
            print(f"UNEXPECTED ERROR: {exc}")
            other_errs += 1
            safe_delete(apk_path)
            continue

        # ── Verify output and clean up APK ─────────────────────────────────────
        if cfg_path.is_file() and cfg_path.stat().st_size > 0:
            elapsed = time.time() - t0
            print(f"OK  ({elapsed:.1f}s)")
            succeeded += 1
        else:
            print("WARN: Soot produced no output (exit 0 but empty/missing file)")
            soot_errs += 1

        safe_delete(apk_path)   # always remove APK after analysis attempt

    # ── Summary ────────────────────────────────────────────────────────────────
    elapsed_total = time.time() - run_start
    total_errors  = dl_errors + soot_errs + other_errs
    print()
    print("=" * 65)
    print("  Run Complete")
    print("=" * 65)
    print(f"  Total samples     : {total}")
    print(f"  Skipped (existing): {skipped}")
    print(f"  Succeeded         : {succeeded}")
    print(f"  Download errors   : {dl_errors}")
    print(f"  Soot errors       : {soot_errs}")
    print(f"  Other errors      : {other_errs}")
    print(f"  Total time        : {elapsed_total:.1f}s")
    print(f"  CFGs written to   : {CFG_DIR}")
    print("=" * 65)

    if total_errors:
        print(
            f"\n[WARN] {total_errors} failure(s). "
            "Check *_error.log / *_timeout.log files in extracted_cfgs/"
        )
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="LAMD Phase 1: download APKs, extract Sliced CFGs, delete APKs."
    )
    parser.add_argument(
        "--csv", type=Path, default=TRAIN_CSV,
        help=f"Path to the training CSV (default: {TRAIN_CSV})"
    )
    parser.add_argument(
        "--limit", type=int, default=None, metavar="N",
        help="Process only the first N samples (useful for testing)."
    )
    args = parser.parse_args()
    main(csv_path=args.csv, limit=args.limit)
