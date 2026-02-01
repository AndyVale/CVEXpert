import trafilatura
from llama_index.core import Document
from llama_index.core.node_parser import SemanticSplitterNodeParser
from llama_index.embeddings.huggingface import HuggingFaceEmbedding

from UrlRetriver.filters import *

EMBED_MODEL = HuggingFaceEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")

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

def get_semantic_chunks(text: str) -> list[str]:
    """
    Splits text into chunks based on semantic similarity using LlamaIndex.
    """
    if not text:
        return []

    splitter = SemanticSplitterNodeParser(
        buffer_size=1,
        breakpoint_percentile_threshold=25, 
        embed_model=EMBED_MODEL
    )

    document = Document(text=text)
    nodes = splitter.get_nodes_from_documents([document])
    
    return [node.get_content() for node in nodes]


def get_filtered_content_from_url(url: str, similarity_query, filter_parameter, filter_function = cosine_filter) :
    """
    Wrapper function to call extract_main_text_from_url->get_semantic_chunks->filter_relevant_chunks
    """
    main_text = extract_main_text_from_url(url)
    if not main_text:
        return [],[]
    
    chunks = get_semantic_chunks(main_text)
    filtered_chunks = filter_function(chunks, similarity_query, filter_parameter)

    return filtered_chunks, chunks

if __name__ == '__main__':
    url = "https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised"
    
    # This query defines what "signal" we want to keep vs "noise".
    RELEVANCE_QUERY = "What type of vulnerability is it?"
    T = 5
    print(get_filtered_content_from_url(url, RELEVANCE_QUERY, T, filter_with_cross_encoder))