# RAG-Augmented Single-Call Architecture Flowchart

This document illustrates how the proposed Dynamic RAG pipeline works, allowing the system to achieve high accuracy (by dynamically fetching similar past examples) while remaining extremely fast and API-efficient (only 1 API call per APK).

```mermaid
graph TD
    %% Define Styles
    classDef input fill:#e1f5fe,stroke:#03a9f4,stroke-width:2px;
    classDef offline fill:#e8f5e9,stroke:#4caf50,stroke-width:2px;
    classDef online fill:#fff3e0,stroke:#ff9800,stroke-width:2px;
    classDef final fill:#fce4ec,stroke:#e91e63,stroke-width:2px;
    classDef db fill:#f3e5f5,stroke:#9c27b0,stroke-width:2px;

    %% Team Sync
    GitSync[("Team GitHub Repo<br>Syncs Code & Vector DB")]:::db

    %% Offline Phase
    subgraph Offline_Phase [Phase 1: Build the Vector Database]
        direction TB
        L2["laptop2_predictions.jsonl<br>Perfectly Classified 90% Acc"]:::input --> Ext["Extract CFGs & Ground Truth"]:::offline
        Ext --> Emb1["Local Embedding Model<br>e.g., all-MiniLM-L6-v2"]:::offline
        Emb1 --> DB[("ChromaDB Vector Database<br>Stored locally in /rag_db")]:::db
    end

    %% Sync DB via Git
    DB -.-> |"Commit to GitHub"| GitSync
    GitSync -.-> |"Team Pulls Repo"| DB

    %% Online Phase
    subgraph Online_Phase [Phase 2: Analyze New APK]
        direction TB
        NewAPK["New APK to Analyze<br>e.g., from laptop1"]:::input --> Slicer["Extract CFG via Slicing"]:::online
        Slicer --> Emb2["Local Embedding Model"]:::online
        Emb2 --> Query["Query Vector DB for Top 3 Matches"]:::online
        Query --> |"Retrieve CFG + Ground Truth"| Prompt["Construct Single Prompt"]:::online
        Prompt --> LLM["Gemini 3.5 Flash API"]:::online
    end

    %% Connections
    DB --> |"Fast Vector Search"| Query
    Slicer --> |"New CFG"| Prompt
    
    LLM --> Verdict["Final Verdict:<br>MALWARE / BENIGN"]:::final
```

## How the Team Collaborates (Multi-Implementation)

1. **The Vector Database (`/rag_db`) is just a folder.** 
   When we use a tool like ChromaDB, the entire database is saved locally as files in a folder (e.g., `AndMAL_Detector/rag_db/`).
2. **Syncing via GitHub:** 
   Because the database is lightweight (just text embeddings), you simply commit the `rag_db` folder to GitHub. 
3. **Working on different laptops:**
   When your friends run `git pull`, they will download the exact same Vector Database to their laptops. When they run the script, their local script queries their local copy of the database. 
4. **No Cloud Bottlenecks:** 
   Because the embedding and querying happen locally on each laptop's CPU in milliseconds, there is zero cloud latency. The only cloud component is the final API call to Gemini.
