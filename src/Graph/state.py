from typing import TypedDict

class CVEClassifierState(TypedDict):
    """
    Represents the state of the CVE classification pipeline.

    Attributes:
        cve_id: The unique identifier of the CVE.
        nvd_description: The official vulnerability description retrieved from the NVD API.
        nvd_url_references: A complete list of all external reference URLs provided by NVD.
        nvd_references_pages: A dictionary mapping each URL to its full extracted text content.
        nvd_references_chunks: A dictionary mapping each (processed) URL to its full list of 
            extracted chunks.
        nvd_filtered_chunks: A dictionary mapping each URL to the subset of chunks 
            that passed the relevance filtering.
        summaries: A dictionary mapping each URL to a summary of its relevant chunks.
        rag: The final context string formatted for the classifier.
        cve_labels: The list of security labels assigned to the CVE.
        labels_motivation: A dictionary mapping each assigned label to its textual explanation/justification.
        labels_confidence: A dictionary mapping each assigned label to a confidence score (0.0 - 1.0).
    """
    cve_id: str
    nvd_description: str
    nvd_url_references: list[str]
    nvd_references_pages: dict[str, str]
    nvd_references_chunks: dict[str, list[str]]
    nvd_filtered_chunks: dict[str, list[str]]
    summaries: dict[str, str]
    rag: str
    cve_labels: list[str]
    new_labels: list[str]
    labels_motivation: dict[str, str]
    labels_confidence: dict[str, float]