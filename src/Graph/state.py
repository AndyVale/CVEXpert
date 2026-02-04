from typing import TypedDict

class CVEClassifierState(TypedDict):
    """
    Represents the state of the CVE classification pipeline.

    Attributes:
        cve_id: The unique identifier of the CVE.
        nvd_description: The official vulnerability description retrieved from the NVD API.
        nvd_url_references: A complete list of all external reference URLs provided by NVD.
        nvd_references_chunks: A dictionary mapping each (processed) URL to its full list of 
            extracted chunks (e.g. after a chunking phase).
        nvd_filtered_chunks: A dictionary mapping each URL to the subset of chunks 
            that passed the relevance filtering (e.g., cosine similarity).
        summaries: A dictionary mapping each URL to a summary of its relevant chunks.
        rag: The final context string formatted for the classifier.
        cve_labels: The list of security labels assigned to the CVE by the classifier.
    """
    cve_id: str
    nvd_description: str
    nvd_url_references: list[str]
    nvd_references_chunks: dict[str, list[str]]
    nvd_filtered_chunks: dict[str, list[str]]
    summaries: dict[str, str]
    rag: str
    cve_labels: list[str]