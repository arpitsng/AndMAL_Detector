import pandas as pd
from pathlib import Path
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CSV_200 = PROJECT_ROOT / "data" / "test_smallest_200.csv"
CFG_DIR = PROJECT_ROOT / "test_extracted_cfgs_new"

df_200 = pd.read_csv(CSV_200)
new_extracted_shas = {p.name.replace("_cfg.txt", "").lower() for p in CFG_DIR.glob("*_cfg.txt")}

missing_200 = df_200[~df_200['sha256'].str.strip().str.lower().isin(new_extracted_shas)].copy()
print(f"Total unextracted among the 200 smallest: {len(missing_200)}")

# Split into 6 parts
parts = np.array_split(missing_200, 6)
for i, part in enumerate(parts, 1):
    part_path = PROJECT_ROOT / "data" / f"test_smallest_missing_part{i}.csv"
    part.to_csv(part_path, index=False)
    print(f"Part {i}: {len(part)} samples -> {part_path.name}")
