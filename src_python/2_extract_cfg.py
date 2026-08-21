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
import zipfile
from pathlib import Path

import pandas as pd
import requests
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent))
from console_ui import console, banner, section, ok, fail, warn, info, make_progress

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

def load_csv(csv_path: Path, limit: int | None, offset: int = 0) -> list[dict]:
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

    # Apply offset first, then limit
    if offset > 0:
        df = df.iloc[offset:]
        print(f"[INFO] Skipping first {offset} samples (--offset).")

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

class CorruptDownloadError(Exception):
    """Raised when a downloaded file is not a valid, complete APK (zip)."""


KNOWN_PACKER_INDICATORS = {
    "libjiagu.so": "Qihoo 360 / Jiagu",
    "libjiagu_art.so": "Qihoo 360 / Jiagu",
    "libprotectClass.so": "Qihoo 360",
    "libsecexe.so": "SecShell / Bangcle",
    "libSecShell.so": "SecShell / Bangcle",
    "libshell.so": "Tencent Legu",
    "libtx3g.so": "Tencent Legu",
    "libtup.so": "Tencent Legu",
    "libexec.so": "Ijiami",
    "libexecmain.so": "Ijiami",
    "libbaiduprotect.so": "Baidu Protect",
    "libAPKProtect.so": "APKProtect",
    "libchaosvmp.so": "ChaosVMP",
    "libkwscmm.so": "Kony",
    "libnqshield.so": "NQ Shield",
}


def check_apk_packer(path: Path) -> str | None:
    """
    Checks if an APK is packed or protected by known commercial packers.
    Returns the packer name if detected, else None.
    """
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            for entry in names:
                filename = entry.split("/")[-1]
                if filename in KNOWN_PACKER_INDICATORS:
                    return KNOWN_PACKER_INDICATORS[filename]
            # If there's no classes.dex at all
            if "classes.dex" not in names:
                return "Missing classes.dex (Encrypted / Native payload)"
    except Exception:
        pass
    return None


def is_valid_apk(path: Path) -> bool:
    """
    Sanity-checks that *path* is a complete, parseable APK.

    AndroZoo occasionally serves truncated downloads or error payloads that
    still land in apks/{sha256}.apk — Soot then fails deep inside zip parsing
    with a confusing "no apk file given" RuntimeException. Catching this here
    (cheap: zipfile only reads the central directory) turns that into a clean,
    retriable download error instead of a wasted Soot invocation.
    """
    if not zipfile.is_zipfile(path):
        return False
    try:
        with zipfile.ZipFile(path) as zf:
            bad_entry = zf.testzip()  # None if all CRCs check out
            if bad_entry is not None:
                return False
            names = zf.namelist()
            return "AndroidManifest.xml" in names
    except (zipfile.BadZipFile, OSError):
        return False


def download_apk(sha256: str, api_key: str) -> Path:
    """
    Streams the APK for *sha256* from AndroZoo into apks/{sha256}.apk.

    Raises:
        requests.HTTPError    — server returned a non-2xx code
        requests.Timeout      — download stalled past DOWNLOAD_TIMEOUT
        CorruptDownloadError  — downloaded file is not a valid, complete APK
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

    if not is_valid_apk(dest):
        safe_delete(dest)
        raise CorruptDownloadError(
            f"Downloaded file for {sha256} is not a valid/complete APK "
            "(truncated download or AndroZoo error payload)."
        )

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

def main(csv_path: Path, limit: int | None, offset: int = 0, cfg_dir: Path = CFG_DIR) -> None:
    banner("LAMD Phase 1 - Step 2: Download + Analyse + Clean Up")
    console.print()

    # ── Validate prerequisites ─────────────────────────────────────────────────
    api_key = load_api_key()
    ok("API key loaded from .env")

    if not JAR_PATH.is_file():
        fail(f"Soot JAR not found: {JAR_PATH}")
        console.print(
            "  Build it first:\n"
            "      cd Slicer\n"
            "      mvn clean package -DskipTests\n"
            "      cd .."
        )
        sys.exit(1)
    ok(f"Soot JAR found: {JAR_PATH.name}")

    cfg_dir.mkdir(parents=True, exist_ok=True)
    ok(f"Output directory: {cfg_dir}")
    console.print()

    # ── Load work list ─────────────────────────────────────────────────────────
    samples = load_csv(csv_path, limit, offset)
    total   = len(samples)
    if total == 0:
        info("No samples to process.")
        return
    console.print()

    # ── Counters ───────────────────────────────────────────────────────────────
    skipped   = 0   # CFG already exists from a previous run
    succeeded = 0   # fully processed this run
    dl_errors = 0   # download failure
    soot_errs = 0   # slicer failure
    other_errs = 0  # unexpected errors

    run_start = time.time()

    # ── Per-sample loop ────────────────────────────────────────────────────────
    def line(sha_short: str, status: str, style: str, detail: str = "") -> None:
        suffix = f" [dim]({detail})[/dim]" if detail else ""
        console.print(f"[dim]{sha_short}...[/dim]  [{style}]{status}[/{style}]{suffix}")

    with make_progress() as progress:
        task = progress.add_task("Extracting CFGs", total=total)
        for idx, sample in enumerate(samples, start=1):
            try:
                sha256 = sample["sha256"]
                apk_path = APK_DIR / f"{sha256}.apk"
                cfg_path = cfg_dir / f"{sha256}_cfg.txt"
                sha_short = sha256[:20]

                # ── Skip if already done ───────────────────────────────────────
                if cfg_path.is_file():
                    line(sha_short, "SKIP", "dim", "already extracted")
                    skipped += 1
                    continue

                t0 = time.time()

                # ── Download ────────────────────────────────────────────────────
                try:
                    download_apk(sha256, api_key)
                except requests.HTTPError as exc:
                    code = exc.response.status_code if exc.response is not None else "?"
                    line(sha_short, "DOWNLOAD FAILED", "red", f"HTTP {code}")
                    dl_errors += 1
                    continue
                except requests.Timeout:
                    line(sha_short, "DOWNLOAD TIMEOUT", "red", f">{DOWNLOAD_TIMEOUT}s")
                    dl_errors += 1
                    continue
                except CorruptDownloadError as exc:
                    line(sha_short, "CORRUPT DOWNLOAD", "red", str(exc)[:60])
                    dl_errors += 1
                    continue
                except Exception as exc:
                    line(sha_short, "DOWNLOAD ERROR", "red", str(exc)[:60])
                    dl_errors += 1
                    continue

                # ── Pre-check: Packer / Encryption ───────────────────────────────
                packer_name = check_apk_packer(apk_path)
                if packer_name:
                    line(sha_short, "PACKED / ENCRYPTED", "yellow", packer_name)
                    (cfg_dir / f"{sha256}_error.log").write_text(
                        f"Skipped Soot analysis: APK is packed or encrypted ({packer_name})\n",
                        encoding="utf-8"
                    )
                    soot_errs += 1
                    safe_delete(apk_path)
                    continue

                # ── Soot Analysis ───────────────────────────────────────────────
                try:
                    run_slicer(apk_path, cfg_path)
                except subprocess.TimeoutExpired:
                    elapsed = time.time() - t0
                    line(sha_short, "SOOT TIMEOUT", "red", f"{elapsed:.0f}s")
                    (cfg_dir / f"{sha256}_timeout.log").write_text(
                        f"Soot timed out after {ANALYSIS_TIMEOUT}s\n", encoding="utf-8"
                    )
                    soot_errs += 1
                    safe_delete(apk_path)
                    continue
                except subprocess.CalledProcessError as exc:
                    line(sha_short, "SOOT ERROR", "red", f"exit {exc.returncode}")
                    if exc.stderr:
                        (cfg_dir / f"{sha256}_error.log").write_text(
                            exc.stderr, encoding="utf-8"
                        )
                    soot_errs += 1
                    safe_delete(apk_path)
                    continue
                except Exception as exc:
                    line(sha_short, "UNEXPECTED ERROR", "red", str(exc)[:60])
                    other_errs += 1
                    safe_delete(apk_path)
                    continue

                # ── Verify output and clean up APK ──────────────────────────────
                if cfg_path.is_file() and cfg_path.stat().st_size > 0:
                    elapsed = time.time() - t0
                    line(sha_short, "OK", "bold green", f"{elapsed:.1f}s")
                    succeeded += 1
                else:
                    line(sha_short, "WARN", "yellow", "Soot produced no output")
                    soot_errs += 1

                safe_delete(apk_path)   # always remove APK after analysis attempt
            finally:
                progress.advance(task)

    # ── Summary ────────────────────────────────────────────────────────────────
    elapsed_total = time.time() - run_start
    total_errors  = dl_errors + soot_errs + other_errs
    section("Run Complete")
    console.print(f"  Total samples     : {total}")
    console.print(f"  Skipped (existing): {skipped}")
    console.print(f"  Succeeded         : [green]{succeeded}[/green]")
    console.print(f"  Download errors   : {'[red]' if dl_errors else ''}{dl_errors}{'[/red]' if dl_errors else ''}")
    console.print(f"  Soot errors       : {'[red]' if soot_errs else ''}{soot_errs}{'[/red]' if soot_errs else ''}")
    console.print(f"  Other errors      : {'[red]' if other_errs else ''}{other_errs}{'[/red]' if other_errs else ''}")
    console.print(f"  Total time        : {elapsed_total:.1f}s")
    console.print(f"  CFGs written to   : {cfg_dir}")

    if total_errors:
        console.print()
        warn(f"{total_errors} failure(s). Check *_error.log / *_timeout.log files in {cfg_dir}/")
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
        "--cfg-dir", type=Path, default=CFG_DIR,
        help=f"Directory to save extracted CFGs (default: {CFG_DIR})"
    )
    parser.add_argument(
        "--limit", type=int, default=None, metavar="N",
        help="Process only the first N samples (useful for testing)."
    )
    parser.add_argument(
        "--offset", type=int, default=0, metavar="N",
        help="Skip the first N samples (use to split work across machines)."
    )
    args = parser.parse_args()
    main(csv_path=args.csv, limit=args.limit, offset=args.offset, cfg_dir=args.cfg_dir)
