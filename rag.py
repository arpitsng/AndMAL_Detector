"""
Query-time RAG pipeline: embeds the question, retrieves the most relevant
chunks from the FAISS index, and (optionally) sends them to an LLM to
generate a grounded answer.

Usage:
    python rag.py "What does the document say about X?"
"""

import pickle
import sys

import faiss
from sentence_transformers import SentenceTransformer

import config

_model = None
_index = None
_metadata = None


def _lazy_load():
    """Load the embedding model and index once, on first use."""
    global _model, _index, _metadata
    if _model is None:
        _model = SentenceTransformer(config.EMBEDDING_MODEL)
    if _index is None:
        index_path = config.INDEX_DIR / "faiss.index"
        meta_path = config.INDEX_DIR / "metadata.pkl"
        if not index_path.exists():
            raise FileNotFoundError(
                "No index found. Run `python ingest.py` first to build one."
            )
        _index = faiss.read_index(str(index_path))
        with open(meta_path, "rb") as f:
            _metadata = pickle.load(f)


def retrieve(query, k=config.TOP_K):
    """Return the top-k most relevant chunks for a query, with their sources."""
    _lazy_load()
    query_vec = _model.encode([query], convert_to_numpy=True).astype("float32")
    faiss.normalize_L2(query_vec)

    scores, indices = _index.search(query_vec, k)

    results = []
    for score, idx in zip(scores[0], indices[0]):
        if idx == -1:
            continue
        results.append({
            "text": _metadata["chunks"][idx],
            "source": _metadata["sources"][idx],
            "score": float(score),
        })
    return results


def build_prompt(query, retrieved_chunks):
    """Combine retrieved context with the user's question into a single prompt."""
    context = "\n\n".join(
        f"[{r['source']}]\n{r['text']}" for r in retrieved_chunks
    )
    return f"""Answer the question using ONLY the context below. If the context doesn't contain the answer, say so clearly instead of guessing.

Context:
{context}

Question: {query}

Answer:"""


def generate_with_anthropic(prompt):
    import anthropic
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
    response = client.messages.create(
        model=config.ANTHROPIC_MODEL,
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def generate_with_openai(prompt):
    from openai import OpenAI
    client = OpenAI()  # reads OPENAI_API_KEY from env
    response = client.chat.completions.create(
        model=config.OPENAI_MODEL,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content


def answer(query, k=config.TOP_K, provider=None):
    """Full RAG pipeline: retrieve chunks, build prompt, generate an answer."""
    provider = provider or config.LLM_PROVIDER
    retrieved = retrieve(query, k=k)

    if not retrieved:
        return "No relevant content found in the index.", retrieved

    if provider == "none":
        return None, retrieved  # retrieval-only mode

    prompt = build_prompt(query, retrieved)

    if provider == "anthropic":
        result = generate_with_anthropic(prompt)
    elif provider == "openai":
        result = generate_with_openai(prompt)
    else:
        raise ValueError(f"Unknown LLM_PROVIDER: {provider}")

    return result, retrieved


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python rag.py "your question here"')
        sys.exit(1)

    question = " ".join(sys.argv[1:])
    result, sources = answer(question)

    print("\n--- Retrieved chunks ---")
    for r in sources:
        print(f"({r['score']:.3f}) {r['source']}")

    if result:
        print("\n--- Answer ---")
        print(result)
