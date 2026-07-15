# LAMD RAG Architecture

This diagram illustrates how the K-Nearest Neighbors (KNN) logic fits into the overall Retrieval-Augmented Generation (RAG) architecture of your malware detection system.

```mermaid
graph TD
    classDef file fill:#e1f5fe,stroke:#01579b,stroke-width:2px;
    classDef process fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    classDef database fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    classDef llm fill:#f3e5f5,stroke:#4a148c,stroke-width:2px;

    %% Phase 1: Building the Knowledge Base (Offline)
    subgraph KB_Phase [1. Knowledge Base Construction Phase]
        A1["train.csv (Labels & Families)"]:::file
        A2["Known APKs Extracted CFGs"]:::file
        B["Parse CFGs into Function Slices<br/>(6_build_rag_kb.py)"]:::process
        C["Local Embedder<br/>(all-MiniLM-L6-v2)"]:::process
        D[("Qdrant Cloud Vector DB<br/>(lamd_cfg_kb)")]:::database
        
        A1 --> B
        A2 --> B
        B -- "Raw Function Text + API Name" --> C
        C -- "384-dimensional Vectors" --> D
    end

    %% Phase 2: RAG Inference (Online)
    subgraph Query_Phase [2. Query / Inference Phase]
        E["New Unknown APK"]:::file
        F["Slicer<br/>(Extract CFG)"]:::process
        G["Parse into Function Slices"]:::process
        H["Local Embedder<br/>(all-MiniLM-L6-v2)"]:::process
        
        E --> F
        F --> G
        G -- "New Function Slice" --> H
        
        %% KNN Fetching happens here
        H -- "Query Vector" --> D
        D -- "K=5 Nearest Neighbors<br/>(Cosine Similarity)" --> I["RAG Prompt Builder<br/>(rag_utils.py)"]:::process
        
        G -- "Raw Target Function" --> I
        I -- "Constructed Prompt with Few-Shot Examples" --> J["LLM (Groq / Llama 3.3)"]:::llm
        J -- "Tier 1 / Tier 2 / Tier 3 Analysis" --> K["Final Verdict<br/>(MALWARE or BENIGN)"]:::file
    end
```

### Key Components Explained:

*   **Function Slices**: The core unit of data. The CFG is not processed as one giant block; it's sliced into individual functions that contain suspicious APIs.
*   **Local Embedder**: The `sentence-transformers/all-MiniLM-L6-v2` model converts the text of a function slice into a 384-dimensional mathematical array (a vector).
*   **Qdrant Cloud (Vector DB)**: Stores the vectors of the known training dataset. 
*   **K=5 Nearest Neighbors**: During inference, Qdrant mathematically compares the new function's vector against all stored vectors to find the 5 most similar functions.
*   **RAG Prompt Builder**: Injects those 5 nearest historical examples (along with whether they were malware or benign) into the LLM's prompt as context before asking it to analyze the new function.
