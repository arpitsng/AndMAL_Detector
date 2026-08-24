"""Batch runner script for CFG extraction on test_1.csv in chunks of 500."""
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = PROJECT_ROOT / "data" / "test_1.csv"
CFG_DIR = PROJECT_ROOT / "test_extracted_cfgs_new"
CFG_DIR.mkdir(parents=True, exist_ok=True)

BATCHES = [
    (0, 500),
    (500, 500),
    (1000, 500),
    (1500, 500),
    (2000, 500),
    (2500, 500),
    (3000, 500),
]

def print_commands():
    print("=== Commands for Batch CFG Extraction (3,015 samples total) ===")
    for i, (offset, limit) in enumerate(BATCHES, 1):
        cmd = f"python src_python/2_extract_cfg.py --csv data/test_1.csv --cfg-dir test_extracted_cfgs_new --offset {offset} --limit {limit}"
        print(f"Batch {i} (samples {offset} to {min(offset + limit - 1, 3014)}):")
        print(f"  {cmd}\n")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--run-all":
        for i, (offset, limit) in enumerate(BATCHES, 1):
            print(f"\n==========================================")
            print(f"Starting Batch {i}/7: offset={offset}, limit={limit}")
            print(f"==========================================")
            cmd = [
                sys.executable,
                "src_python/2_extract_cfg.py",
                "--csv", str(CSV_PATH),
                "--cfg-dir", str(CFG_DIR),
                "--offset", str(offset),
                "--limit", str(limit),
            ]
            ret = subprocess.run(cmd)
            print(f"Batch {i} finished with return code {ret.returncode}")
    else:
        print_commands()
