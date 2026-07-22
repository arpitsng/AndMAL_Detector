"""
Build Qdrant Cloud Vector Database for RAG Pipeline

This script reads the ground-truth dataset (split_laptop2.csv),
extracts the CFG files, creates dense vector embeddings using FastEmbed locally,
and uploads them to Qdrant Cloud via standard upsert.

This acts as the "Knowledge Base" for the RAG-augmented Single-Call inference.
"""

import os
import sys
import uuid
import pandas as pd
from pathlib import Path
from dotenv import load_dotenv
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from fastembed import TextEmbedding
from tqdm import tqdm

# --- Configuration ---
DATA_FILE = Path("data/split_laptop2.csv")
CFG_DIR = Path("extracted_cfgs")
COLLECTION_NAME = "lamd_cfgs"
MAX_CFG_LENGTH = 3000  # Truncate to avoid massive embedding noise

def main():
    print("=" * 60)
    print("  LAMD RAG DB Builder (Manual FastEmbed)")
    print("=" * 60)

    # 1. Load credentials
    load_dotenv()
    qdrant_url = os.environ.get("QDRANT_URL")
    qdrant_api_key = os.environ.get("QDRANT_API_KEY")

    if not qdrant_url or not qdrant_api_key:
        print("[ERROR] QDRANT_URL or QDRANT_API_KEY is missing in .env")
        sys.exit(1)

    print("[INFO] Connecting to Qdrant Cloud...")
    client = QdrantClient(
        url=qdrant_url, 
        api_key=qdrant_api_key,
        timeout=30
    )

    # 2. Initialize FastEmbed manually
    print("[INFO] Loading FastEmbed model (BAAI/bge-small-en-v1.5) locally...")
    embedding_model = TextEmbedding("BAAI/bge-small-en-v1.5")
    # bge-small-en produces 384-dimensional vectors
    vector_size = 384

    # 3. Create Collection (if not exists)
    collections = client.get_collections().collections
    exists = any(c.name == COLLECTION_NAME for c in collections)
    
    if exists:
        print(f"[INFO] Collection '{COLLECTION_NAME}' already exists. Overwriting...")
        client.delete_collection(collection_name=COLLECTION_NAME)
    
    print(f"[INFO] Creating collection '{COLLECTION_NAME}' (dim={vector_size})...")
    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=vector_size, distance=Distance.COSINE),
    )

    # 4. Process Data
    print(f"[INFO] Loading dataset from {DATA_FILE}")
    if not DATA_FILE.exists():
        print(f"[ERROR] Cannot find {DATA_FILE}")
        sys.exit(1)
        
    df = pd.read_csv(DATA_FILE)
    
    documents = []
    metadata = []
    ids = []
    for idx, row in df.iterrows():
        sha256 = str(row.get("sha256", ""))
        label = int(row.get("label", 0))
        family = str(row.get("family", "benign"))
        
        cfg_path = CFG_DIR / f"{sha256}_cfg.txt"
        if not cfg_path.is_file():
            continue
            
        cfg_text = cfg_path.read_text(encoding="utf-8")
        if len(cfg_text) > MAX_CFG_LENGTH:
            cfg_text = cfg_text[:MAX_CFG_LENGTH]
            
        ground_truth = "MALWARE" if label == 1 else "BENIGN"
        
        documents.append(cfg_text)
        metadata.append({
            "sha256": sha256,
            "ground_truth": ground_truth,
            "family": family,
            "cfg_preview": cfg_text[:500]
        })
        ids.append(str(uuid.uuid5(uuid.NAMESPACE_DNS, sha256)))

    print(f"[INFO] Computing embeddings locally using FastEmbed for {len(documents)} documents...")
    embeddings = list(embedding_model.embed(documents))

    # Convert to Qdrant points
    points = [
        PointStruct(id=ids[i], vector=embeddings[i].tolist(), payload=metadata[i])
        for i in range(len(documents))
    ]

    # 5. Upload to Qdrant
    print(f"\n[INFO] Uploading {len(points)} vectors to Qdrant Cloud...")
    
    batch_size = 100
    for i in tqdm(range(0, len(points), batch_size)):
        batch = points[i : i + batch_size]
        client.upsert(
            collection_name=COLLECTION_NAME,
            points=batch
        )
        
    print("\n[OK] RAG Database successfully populated!")
    print(f"[OK] Collection: {COLLECTION_NAME}")

if __name__ == "__main__":
    main()
