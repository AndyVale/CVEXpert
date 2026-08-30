import trafilatura
from tqdm import tqdm
from Graph.errors import make_pipeline_warning
from Graph.state import CVEClassifierState

def extract_md_trafilatura(
    state: CVEClassifierState,
    *,
    max_pages: int,
) -> CVEClassifierState:
    """
    Fetches and extracts Markdown content from NVD reference URLs using Trafilatura.

    This function randomly shuffles the available reference URLs to ensure a diverse 
    sample and avoid processing bias. It attempts to download and extract content
    in Markdown format (prioritizing recall) until the configured page limit
    of successfully extracted pages is reached.

    Args:
        state (CVEClassifierState): The current pipeline state containing the list 
            of 'nvd_url_references'.

    Returns:
        dict: A new state dictionary containing the original data plus the 
            'nvd_references_pages' field, which maps each processed URL to its 
            extracted Markdown content.
    """
    url_refs = state["nvd_url_references"].copy()

    pages_dict = {}
    warnings = list(state.get("pipeline_warnings", []))
    for url_ref in tqdm(url_refs, "Extracting references"):
        try:
            downloaded = trafilatura.fetch_url(url_ref)
            if not downloaded:
                raise ValueError("Reference download returned no content")
            text = trafilatura.extract(downloaded, output_format="markdown", favor_recall=True)
            if not isinstance(text, str) or not text.strip():
                raise ValueError("Reference extraction returned no text")

            pages_dict[url_ref] = text

            if len(pages_dict) >= max_pages:
                break

        except Exception as error:
            warnings.append(
                make_pipeline_warning(
                    stage="scrape",
                    source=url_ref,
                    error=error,
                    safe_message="Reference download or text extraction failed",
                )
            )

    return {**state,
            "nvd_references_pages": pages_dict,
            "pipeline_warnings": warnings}
