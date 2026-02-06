from tqdm import tqdm
import numpy as np
from Graph.state import CVEClassifierState

class CosineFilterNode:
    """
    A LangGraph node that filters text chunks based on semantic similarity (Cosine Similarity).

    This class uses an injected embedding model to filter irrelevant chunks from the pipeline state. 
    It preserves the original order of the document and inserts a "..." placeholder 
    to indicate gaps where content was removed.

    Attributes:
        embed_model: The LangChain embedding model used for vectorization.
        query (str): The semantic query used as a reference for relevance.
        threshold (float): The similarity score (0.0 to 1.0) below which chunks are discarded.
    """

    def __init__(self, 
                 embed_model,
                 query: str, 
                 threshold: float = 0.30):
        """
        Initializes the CosineFilterNode.

        Args:
            embed_model: A LangChain Embeddings object.
            query (str): The text description of what constitutes "relevant" content.
            threshold (float): Minimum cosine similarity score to keep a chunk.
        """
        self.embed_model = embed_model
        self.query = query
        self.threshold = threshold
        # Pre-compute query embedding once using LangChain's embed_query method
        self.query_embedding = np.array(self.embed_model.embed_query(query))

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

        for url, chunks in tqdm(references_chunks.items(), "Filtering chunks using cosine"):
            if not chunks:
                filtered_results[url] = []
                continue

            # Vectorize chunks using LangChain's embed_documents method
            chunk_embeddings = np.array(self.embed_model.embed_documents(chunks))
            
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
        cross_model: The model used to score query-chunk pairs.
        query (str): The question or description used to evaluate chunk relevance.
        top_k (int): The maximum number of chunks to keep per reference.
        threshold (float): The minimum logit score required to keep a chunk.
    """

    def __init__(self, 
                 cross_model,
                 query: str, 
                 top_k: int = 8, 
                 threshold: float = -8.0):
        """
        Initializes the CrossEncoderFilterNode with a pre-configured model.

        Args:
            cross_model: An initialized CrossEncoder model instance.
            query (str): The relevance query.
            top_k (int): Number of top-scoring chunks to retain.
            threshold (float): Logit threshold to filter noise.
        """
        self.cross_model = cross_model
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

        for url, chunks in tqdm(references_chunks.items(), "Filtering chunks using CrossEncoder"):
            if not chunks:
                filtered_results[url] = []
                continue

            # Prepare pairs for the Cross-Encoder
            pairs = [[self.query, chunk] for chunk in chunks]
            
            # Predict scores (logits)
            logits = self.cross_model.predict(pairs)
            
            # Identify indices of the top_k chunks that also meet the absolute threshold
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