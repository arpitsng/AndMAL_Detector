"""
Generate balanced CSV splits for CFG extraction across two laptops.
Each split has equal malware and benign samples.
"""
import pandas as pd
from pathlib import Path

TRAIN_CSV = Path("data/train.csv")
OUT_DIR = Path("data")

df = pd.read_csv(TRAIN_CSV, dtype={"sha256": str, "family": str, "label": float})
df["sha256"] = df["sha256"].str.strip().str.lower()
df.dropna(subset=["sha256"], inplace=True)
df.drop_duplicates(subset=["sha256"], inplace=True)

malware = df[df["label"] == 1.0].sample(frac=1, random_state=42).reset_index(drop=True)
benign  = df[df["label"] == 0.0].sample(frac=1, random_state=42).reset_index(drop=True)

print(f"Total malware: {len(malware)}")
print(f"Total benign:  {len(benign)}")
print()

# --- Split: 100 malware + 100 benign per laptop = 200 per laptop, 400 total ---
PER_LAPTOP = 100  # per class

# Laptop 1: first 100 malware + first 100 benign
split1_mal = malware.head(PER_LAPTOP)
split1_ben = benign.head(PER_LAPTOP)
split1 = pd.concat([split1_mal, split1_ben]).sample(frac=1, random_state=1).reset_index(drop=True)

# Laptop 2: next 100 malware + next 100 benign
split2_mal = malware.iloc[PER_LAPTOP : PER_LAPTOP * 2]
split2_ben = benign.iloc[PER_LAPTOP : PER_LAPTOP * 2]
split2 = pd.concat([split2_mal, split2_ben]).sample(frac=1, random_state=2).reset_index(drop=True)

# Save
split1.to_csv(OUT_DIR / "split_laptop1.csv", index=False)
split2.to_csv(OUT_DIR / "split_laptop2.csv", index=False)

print("=== Laptop 1 (split_laptop1.csv) ===")
print(f"  Total: {len(split1)}")
print(f"  Malware: {(split1.label == 1.0).sum()}")
print(f"  Benign:  {(split1.label == 0.0).sum()}")
print()
print("=== Laptop 2 (split_laptop2.csv) ===")
print(f"  Total: {len(split2)}")
print(f"  Malware: {(split2.label == 1.0).sum()}")
print(f"  Benign:  {(split2.label == 0.0).sum()}")
print()
print("Commands to run:")
print("  YOUR laptop:    python src_python/2_extract_cfg.py --csv data/split_laptop1.csv")
print("  FRIEND's laptop: python src_python/2_extract_cfg.py --csv data/split_laptop2.csv")
