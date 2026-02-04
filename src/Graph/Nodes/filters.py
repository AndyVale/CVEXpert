import numpy as np
from sentence_transformers import CrossEncoder
from llama_index.embeddings.huggingface import HuggingFaceEmbedding

EMBED_MODEL = HuggingFaceEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")
def cosine_filter(chunks: list[str], query: str, threshold: float = 0.30) -> list[str]:
    """
    Filters chunks by semantic similarity while preserving original document order.
    Replaces sequences of removed chunks with '...'.
    """
    if not chunks:
        return []

    query_embedding = np.array(EMBED_MODEL.get_query_embedding(query))
    chunk_embeddings = np.array(EMBED_MODEL.get_text_embedding_batch(chunks))
    similarities = np.dot(chunk_embeddings, query_embedding)

    final_content = []
    gap_added = False

    for i, score in enumerate(similarities):
        if score >= threshold:
            final_content.append(chunks[i])
            gap_added = False
        else:
            if not gap_added:
                final_content.append("...")
                gap_added = True

    return final_content

CROSS_MODEL = CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2')
def filter_with_cross_encoder(chunks: list[str], query: str, top_k: int = 8, threshold: float = -8.0):
    """
    Selects top-k most relevant chunks based on Cross-Encoder logits, 
    but returns them in their original order with '...' for gaps.
    """
    if not chunks:
        return []

    pairs = [[query, chunk] for chunk in chunks]
    logits = CROSS_MODEL.predict(pairs)
    
    # Identify indices of the top_k chunks that also meet the absolute threshold
    indexed_scores = sorted(enumerate(logits), key=lambda x: x[1], reverse=True)
    top_indices = {idx for idx, score in indexed_scores[:top_k] if score > threshold}

    final_content = []
    gap_added = False

    for i in range(len(chunks)):
        if i in top_indices:
            final_content.append(chunks[i])
            gap_added = False
        else:
            if not gap_added:
                final_content.append("...")
                gap_added = True

    return final_content