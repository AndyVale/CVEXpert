import trafilatura
import random
from Graph.state import CVEClassifierState
from Definitions.config import REF_MAX 
def extract_main_text_from_url(url: str) -> str:
    """
    Fetch a URL and extract only the main meaningful text content using Trafilatura.
    """
    try:
        downloaded = trafilatura.fetch_url(url)
        if downloaded is None:
            return ""
        
        text = trafilatura.extract(downloaded, output_format="markdown", favor_recall=True)
        if text is None:
            return ""
        return text
    except Exception:
        return ""

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
    random.shuffle(url_refs)
    
    pages_dict = {}
    for url_ref in url_refs:
        try:
            downloaded = trafilatura.fetch_url(url_ref)
            text = trafilatura.extract(downloaded, output_format="markdown", favor_recall=True)

            if text:
                pages_dict[url_ref] = text

            if len(pages_dict) >= REF_MAX:
                break

        except Exception as e:
            print(f"Fail in extracting content of page at: {url_ref}\n{e}")

    return {**state, "nvd_references_pages": pages_dict}


def get_filtered_content_from_url(url: str, similarity_query, filter_parameter, filter_function): # TODO: REMOVE THIS FUNCTION
    """
    Wrapper function to call extract_main_text_from_url->get_semantic_chunks->filter_relevant_chunks
    """
    from Graph.Nodes.chunkers import semantic_chunker
    main_text = extract_main_text_from_url(url)
    if not main_text:
        return [],[]
    
    chunks = semantic_chunker(main_text)
    filtered_chunks = filter_function(chunks, similarity_query, filter_parameter)

    return filtered_chunks, chunks