import trafilatura
import random
from tqdm import tqdm
from Graph.state import CVEClassifierState
from Definitions.config import REF_MAX

def extract_md_trafilatura(state: CVEClassifierState) -> CVEClassifierState:
    """
    Fetches and extracts Markdown content from NVD reference URLs using Trafilatura.

    This function randomly shuffles the available reference URLs to ensure a diverse 
    sample and avoid processing bias. It attempts to download and extract content 
    in Markdown format (prioritizing recall) until a defined limit (`REF_MAX`) 
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
    for url_ref in tqdm(url_refs, "Extracting references"):
        try:
            downloaded = trafilatura.fetch_url(url_ref)
            text = trafilatura.extract(downloaded, output_format="markdown", favor_recall=True)

            if text:
                pages_dict[url_ref] = text

            if len(pages_dict) >= REF_MAX:
                break

        except Exception as e:
            print(f"Fail in extracting content of page at: {url_ref}\n{e}")

    return {**state,
            "nvd_references_pages": pages_dict}