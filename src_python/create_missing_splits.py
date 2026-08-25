import pandas as pd
from pathlib import Path
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = PROJECT_ROOT / "data" / "test_1.csv"
CFG_DIR = PROJECT_ROOT / "test_extracted_cfgs_new"

df = pd.read_csv(CSV_PATH)
extracted_shas = {f.name.replace("_cfg.txt", "").lower() for f in CFG_DIR.glob("*_cfg.txt")}

# Only keep samples that do not have an extracted CFG yet
missing_df = df[~df['sha256'].str.strip().str.lower().isin(extracted_shas)].copy()
print(f"Total unextracted samples: {len(missing_df)}")

# Split into 6 equal parts
parts = np.array_split(missing_df, 6)
for i, part_df in enumerate(parts, 1):
    part_path = PROJECT_ROOT / "data" / f"test_missing_part{i}.csv"
    part_df.to_csv(part_path, index=False)
    print(f"Part {i}: {len(part_df)} samples -> {part_path.name}")
