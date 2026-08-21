# RAG-Augmented Single-Call Architecture Flowchart

This document illustrates how the proposed Dynamic RAG pipeline works, allowing the system to achieve high accuracy (by dynamically fetching similar past examples) while remaining extremely fast and API-efficient (only 1 API call per APK).

```mermaid
graph TD
    %% Define Styles
    classDef input fill:#e1f5fe,stroke:#03a9f4,stroke-width:2px,color:#000000;
    classDef offline fill:#e8f5e9,stroke:#4caf50,stroke-width:2px,color:#000000;
    classDef online fill:#fff3e0,stroke:#ff9800,stroke-width:2px,color:#000000;
    classDef final fill:#fce4ec,stroke:#e91e63,stroke-width:2px,color:#000000;
    classDef db fill:#f3e5f5,stroke:#9c27b0,stroke-width:2px,color:#000000;

    %% Database
    Qdrant[("Qdrant Cloud<br>Centralized Vector DB")]:::db

    %% Offline Phase
    subgraph Offline_Phase [Phase 1: Build the Knowledge Base]
        direction TB
        L2["Ground Truth Dataset<br>(e.g. laptop2 predictions)"]:::input --> Ext["Extract CFGs & Ground Truth"]:::offline
        Ext --> Emb1["Local Embedding Model<br>FastEmbed (bge-small-en)"]:::offline
        Emb1 --> |"Upsert Vectors via API"| Qdrant
    end

    %% Online Phase
    subgraph Online_Phase [Phase 2: Analyze New APK]
        direction TB
        NewAPK["New APK to Analyze<br>e.g., from laptop1"]:::input --> Slicer["Extract CFG via Slicing"]:::online
        Slicer --> Emb2["Local Embedding Model<br>FastEmbed (bge-small-en)"]:::online
        Emb2 --> Query["Query Qdrant Cloud for Top 3 Matches"]:::online
        Query --> |"Retrieve CFG + Ground Truth"| Prompt["Construct Single Prompt"]:::online
        Prompt --> LLM["Gemini API"]:::online
    end

    %% Connections
    Qdrant --> |"Fast Vector Search"| Query
    Slicer --> |"New CFG"| Prompt
    
    LLM --> Verdict["Final Verdict:<br>MALWARE / BENIGN"]:::final
```

## How the Team Collaborates (Cloud Architecture)

1. **Centralized Vector Database (Qdrant Cloud):** 
   Instead of storing the database locally and relying on Git pulls (which causes merge conflicts when multiple people process APKs simultaneously), all vectors are stored securely in a free Qdrant Cloud cluster.
2. **Local FastEmbed:** 
   The heavy lifting of converting code to vectors is done locally on each team member's laptop using `fastembed`. This prevents you from paying for OpenAI embeddings or overloading your Gemini API keys.
3. **No Git Merge Conflicts:**
   As you and your friends process new APKs, you can all write directly to Qdrant Cloud via the API. There is no need to commit database files to GitHub.
4. **Future-Proof for Chatbot UI:** 
   When you eventually build your AI UI Chatbot, it can instantly connect to the Qdrant Cloud cluster via API to fetch knowledge, meaning the backend is entirely ready for scale.
