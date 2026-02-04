import numpy as np
from sentence_transformers import CrossEncoder
from llama_index.embeddings.huggingface import HuggingFaceEmbedding

from Graph.state import CVEClassifierState

class CosineFilterNode:
    """
    A LangGraph node that filters text chunks based on semantic similarity (Cosine Similarity).

    This class initializes a HuggingFace embedding model once and uses it to filter
    irrelevant chunks from the pipeline state. It preserves the original order of the 
    document and inserts a "..." placeholder to indicate gaps where content was removed.

    Attributes:
        embed_model (HuggingFaceEmbedding): The embedding model used for vectorization.
        query (str): The semantic query used as a reference for relevance.
        threshold (float): The similarity score (0.0 to 1.0) below which chunks are discarded.
    """

    def __init__(self, 
                 query: str, 
                 model_name: str = "sentence-transformers/all-MiniLM-L6-v2", 
                 threshold: float = 0.30):
        """
        Initializes the CosineFilterNode.

        Args:
            query (str): The text description of what constitutes "relevant" content.
            model_name (str): The HuggingFace model hub name for embeddings.
            threshold (float): Minimum cosine similarity score to keep a chunk.
        """
        print(f"Loading Embedding Model: {model_name}...")
        self.embed_model = HuggingFaceEmbedding(model_name=model_name)
        self.query = query
        self.threshold = threshold
        # Pre-compute query embedding once to save time during execution
        self.query_embedding = np.array(self.embed_model.get_query_embedding(query))

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        """
        Processes the state to filter chunks for all references.

        Args:
            state (CVEClassifierState): Current pipeline state containing 'nvd_references_chunks'.

        Returns:
            CVEClassifierState: Updated state with 'nvd_filtered_chunks'.
        """
        references_chunks = state.get("nvd_references_chunks", {})
        filtered_results = {}

        if not references_chunks:
             return {**state, "nvd_filtered_chunks": {}}

        for url, chunks in references_chunks.items():
            if not chunks:
                filtered_results[url] = []
                continue

            # Vectorize chunks
            chunk_embeddings = np.array(self.embed_model.get_text_embedding_batch(chunks))
            
            # Calculate Cosine Similarity (Dot product of normalized vectors)
            similarities = np.dot(chunk_embeddings, self.query_embedding)

            final_content = []
            gap_added = False

            for i, score in enumerate(similarities):
                if score >= self.threshold:
                    final_content.append(chunks[i])
                    gap_added = False
                else:
                    if not gap_added:
                        final_content.append("...")
                        gap_added = True
            
            filtered_results[url] = final_content

        return {**state, 
                "nvd_filtered_chunks": filtered_results}


class CrossEncoderFilterNode:
    """
    A LangGraph node that filters text chunks using a Cross-Encoder for high-precision reranking.

    Unlike bi-encoders (cosine similarity), this model processes the query and chunk 
    simultaneously, offering higher accuracy. It selects the top-k most relevant chunks 
    while preserving the original narrative flow and inserting "..." for gaps.

    Attributes:
        cross_model (CrossEncoder): The model used to score query-chunk pairs.
        query (str): The question or description used to evaluate chunk relevance.
        top_k (int): The maximum number of chunks to keep per reference.
        threshold (float): The minimum logit score required to keep a chunk.
    """

    def __init__(self, 
                 query: str, 
                 model_name: str = 'cross-encoder/ms-marco-MiniLM-L-6-v2', 
                 top_k: int = 8, 
                 threshold: float = -8.0):
        """
        Initializes the CrossEncoderFilterNode.

        Args:
            query (str): The relevance query (best phrased as a question for MS-MARCO models).
            model_name (str): The HuggingFace Cross-Encoder model name.
            top_k (int): Number of top-scoring chunks to retain.
            threshold (float): Logit threshold (usually negative for MS-MARCO) to filter noise.
        """
        print(f"Loading Cross-Encoder Model: {model_name}...")
        self.cross_model = CrossEncoder(model_name)
        self.query = query
        self.top_k = top_k
        self.threshold = threshold

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        """
        Processes the state to filter chunks using the Cross-Encoder.

        Args:
            state (CVEClassifierState): Current pipeline state containing 'nvd_references_chunks'.

        Returns:
            CVEClassifierState: Updated state with 'nvd_filtered_chunks'.
        """
        references_chunks = state.get("nvd_references_chunks", {})
        filtered_results = {}

        if not references_chunks:
            return {**state, "nvd_filtered_chunks": {}}

        for url, chunks in references_chunks.items():
            if not chunks:
                filtered_results[url] = []
                continue

            # Prepare pairs for the Cross-Encoder
            pairs = [[self.query, chunk] for chunk in chunks]
            
            # Predict scores (logits)
            logits = self.cross_model.predict(pairs)
            
            # Identify indices of the top_k chunks that also meet the absolute threshold
            # We define importance by score, but we need to retrieve them by original index
            indexed_scores = sorted(enumerate(logits), key=lambda x: x[1], reverse=True)
            
            # Create a set of indices to keep (Logic: Top K AND > Threshold)
            top_indices = {
                idx for idx, score in indexed_scores[:self.top_k] 
                if score > self.threshold
            }

            final_content = []
            gap_added = False

            # Reconstruct the list in original order
            for i in range(len(chunks)):
                if i in top_indices:
                    final_content.append(chunks[i])
                    gap_added = False
                else:
                    if not gap_added:
                        final_content.append("...")
                        gap_added = True
            
            filtered_results[url] = final_content

        return {**state,
                "nvd_filtered_chunks": filtered_results}