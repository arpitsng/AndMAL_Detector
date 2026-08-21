"""
Find (and optionally clear) stale CFGs before a re-extraction run.
=====================================================================
Simply re-running 2_extract_cfg.py does NOT know a CFG is "wrong" — it
only checks whether the output file already exists, so it would silently
keep every CFG extracted with an older/buggier slicer version mixed in
with newly-extracted ones. This script tells stale files (extracted before
a fix that changes output — multidex support, new suspicious-API seeds,
filtering corrections, etc.) apart from fresh ones, so re-extraction only
touches what actually needs it.

How staleness is determined:
  1. Every CFG written by the current slicer starts with a
     "=== SLICER_VERSION: N ===" header (see CfgSerializer.SLICER_VERSION
     in the Java source). A file with no header, or an older N, is stale.
  2. Bootstrap exception: a handful of CFGs from earlier this session were
     extracted with the CURRENT slicer logic but BEFORE the version header
     itself was added, so they have no header despite being fresh. For
     files with no header, a content check (presence of API categories
     that only the current slicer can seed — openConnection, getSimOperator,
     loadClass, dexclassloader, or "<init>" as a SUSPICIOUS_API) rescues
     these from being needlessly re-extracted. This heuristic is imperfect
     (a genuinely fresh file that happens not to contain any of these APIs
     would still be flagged stale) — it only ever causes unnecessary
     re-work, never data loss, so erring toward "stale" is the safe
     direction if in doubt.

Usage:
  python src_python/find_stale_cfgs.py                  # report only, no changes
  python src_python/find_stale_cfgs.py --delete          # delete stale files
  python src_python/find_stale_cfgs.py --delete --yes    # skip confirmation prompt
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from console_ui import console, banner, section, ok, warn, info, fail

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CFG_DIR = PROJECT_ROOT / "extracted_cfgs"

# Keep in sync with Slicer/src/main/java/CfgSerializer.java SLICER_VERSION.
CURRENT_SLICER_VERSION = 2

# API names that only the current (or later) slicer can ever seed on — see
# SuspiciousApiList.java. Any of these appearing as a SUSPICIOUS_API value
# is proof the file was extracted with the current logic, even if it
# predates the version header itself.
BOOTSTRAP_FRESH_MARKERS = {
    "openConnection", "getOutputStream", "getSimOperator",
    "loadClass", "dexClassLoader", "<init>",
}


def classify_file(path: Path) -> tuple[bool, str]:
    """
    Returns (is_fresh, reason).
    """
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            first_line = f.readline().strip()
            if first_line.startswith("=== SLICER_VERSION:"):
                m = re.search(r"SLICER_VERSION:\s*(\d+)", first_line)
                if m:
                    version = int(m.group(1))
                    if version >= CURRENT_SLICER_VERSION:
                        return True, f"version {version}"
                    return False, f"version {version} < {CURRENT_SLICER_VERSION}"
                return False, "malformed version header"

            # No header — bootstrap check via content.
            f.seek(0)
            content = f.read()
    except OSError as e:
        return False, f"unreadable ({e})"

    for line in content.split("\n"):
        if line.startswith("SUSPICIOUS_API:"):
            api = line.split(":", 1)[1].strip()
            if api in BOOTSTRAP_FRESH_MARKERS:
                return True, f"no header, but contains '{api}' (current-slicer-only marker)"

    return False, "no version header, no current-slicer markers"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Find and optionally clear stale CFGs before re-extraction."
    )
    parser.add_argument(
        "--delete", action="store_true",
        help="Delete stale CFG files (default: report only, no changes)."
    )
    parser.add_argument(
        "--yes", action="store_true",
        help="Skip the confirmation prompt when using --delete."
    )
    args = parser.parse_args()

    banner("Find Stale CFGs", [f"Current slicer version: {CURRENT_SLICER_VERSION}"])
    console.print()

    if not CFG_DIR.is_dir():
        fail(f"CFG directory not found: {CFG_DIR}")
        sys.exit(1)

    cfg_files = sorted(CFG_DIR.glob("*_cfg.txt"))
    info(f"Scanning {len(cfg_files)} CFG file(s) in {CFG_DIR}...")
    console.print()

    fresh: list[Path] = []
    stale: list[Path] = []
    bootstrap_rescued = 0

    with console.status("[bold cyan]Classifying files..."):
        for path in cfg_files:
            is_fresh, reason = classify_file(path)
            if is_fresh:
                fresh.append(path)
                if "bootstrap" not in reason and "no header" in reason:
                    bootstrap_rescued += 1
            else:
                stale.append(path)

    section("Results")
    console.print(f"  Fresh (version {CURRENT_SLICER_VERSION}, keep)      : [green]{len(fresh)}[/green]")
    if bootstrap_rescued:
        console.print(f"    (of which rescued by content check, no header) : {bootstrap_rescued}")
    console.print(f"  Stale (needs re-extraction)         : [red]{len(stale)}[/red]")
    console.print(f"  Total                                : {len(cfg_files)}")

    if not stale:
        console.print()
        ok("Nothing stale - corpus is fully up to date with the current slicer.")
        return

    if not args.delete:
        console.print()
        info(f"Dry run - no files deleted. Re-run with --delete to remove the "
             f"{len(stale)} stale file(s) so 2_extract_cfg.py re-extracts them.")
        return

    console.print()
    if not args.yes:
        warn(f"About to delete {len(stale)} stale CFG file(s) from {CFG_DIR}.")
        console.print("  These will be regenerated the next time 2_extract_cfg.py runs")
        console.print("  against the matching CSV - this does not touch train.csv or")
        console.print("  any results/ files, only extracted_cfgs/.")
        answer = input("  Proceed? [y/N] ").strip().lower()
        if answer != "y":
            info("Aborted - no files deleted.")
            return

    deleted = 0
    errors = 0
    for path in stale:
        try:
            path.unlink()
            deleted += 1
        except OSError as e:
            warn(f"Could not delete {path.name}: {e}")
            errors += 1

    console.print()
    ok(f"Deleted {deleted} stale CFG file(s).")
    if errors:
        warn(f"{errors} file(s) could not be deleted.")
    info("Re-run 2_extract_cfg.py against your CSV - it will skip the "
         f"{len(fresh)} fresh file(s) and only (re-)extract what's missing.")


if __name__ == "__main__":
    main()
