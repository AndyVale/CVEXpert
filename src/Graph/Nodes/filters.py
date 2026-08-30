from tqdm import tqdm
import numpy as np
from Graph.errors import PipelineStageError
from Graph.reporting import get_logger
from Graph.state import CVEClassifierState


LOGGER = get_logger("filter")


def _normalize_query_embedding(embedding) -> np.ndarray:
    vector = np.asarray(embedding, dtype=float)
    if vector.ndim != 1 or vector.size == 0:
        raise ValueError("Query embedding must be a non-empty one-dimensional vector")
    if not np.all(np.isfinite(vector)):
        raise ValueError("Query embedding contains non-finite values")

    norm = np.linalg.norm(vector)
    if norm == 0:
        raise ValueError("Query embedding must not be a zero vector")
    return vector / norm


def _normalize_document_embeddings(
    embeddings,
    *,
    document_count: int,
    embedding_dimension: int,
) -> np.ndarray:
    matrix = np.asarray(embeddings, dtype=float)
    if matrix.ndim != 2:
        raise ValueError("Document embeddings must be a two-dimensional matrix")
    if matrix.shape[0] != document_count:
        raise ValueError("Document embedding count does not match chunk count")
    if matrix.shape[1] != embedding_dimension:
        raise ValueError("Query and document embedding dimensions do not match")
    if not np.all(np.isfinite(matrix)):
        raise ValueError("Document embeddings contain non-finite values")

    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    return np.divide(
        matrix,
        norms,
        out=np.zeros_like(matrix, dtype=float),
        where=norms != 0,
    )


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
        self.query_embedding = _normalize_query_embedding(
            self.embed_model.embed_query(query)
        )

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

        cve_id = state.get("cve_id", "Unknown")
        input_chunk_count = sum(len(chunks) for chunks in references_chunks.values())
        LOGGER.debug(
            "Cosine filtering started for %s: references=%s chunks=%s threshold=%s",
            cve_id,
            len(references_chunks),
            input_chunk_count,
            self.threshold,
        )
        try:
            for url, chunks in tqdm(references_chunks.items(), "Filtering chunks using cosine"):
                if not chunks:
                    filtered_results[url] = []
                    continue

                # Vectorize chunks using LangChain's embed_documents method
                chunk_embeddings = _normalize_document_embeddings(
                    self.embed_model.embed_documents(chunks),
                    document_count=len(chunks),
                    embedding_dimension=self.query_embedding.shape[0],
                )

                # Both operands are L2-normalized, so their dot product is cosine similarity.
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
        except Exception as error:
            raise PipelineStageError(
                stage="filter",
                cve_id=cve_id,
                error=error,
                safe_message="Embedding or cosine filtering failed",
            ) from error

        retained_chunk_count = sum(
            1
            for chunks in filtered_results.values()
            for chunk in chunks
            if chunk != "..."
        )
        LOGGER.debug(
            "Cosine filtering completed for %s: retained=%s/%s chunks",
            cve_id,
            retained_chunk_count,
            input_chunk_count,
        )

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

        cve_id = state.get("cve_id", "Unknown")
        try:
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
        except Exception as error:
            raise PipelineStageError(
                stage="filter",
                cve_id=cve_id,
                error=error,
                safe_message="Cross-encoder filtering failed",
            ) from error

        return {**state,
                "nvd_filtered_chunks": filtered_results}
