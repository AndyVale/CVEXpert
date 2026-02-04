from llama_index.core import Document
from llama_index.core.node_parser import SemanticSplitterNodeParser
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from Graph.state import CVEClassifierState

EMBED_MODEL = HuggingFaceEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")

def semantic_chunker(state: CVEClassifierState) -> CVEClassifierState:
    """
    Splits the extracted text of each reference page into semantic chunks.

    This function iterates through the 'nvd_references_pages' dictionary. For each 
    page, it uses LlamaIndex's SemanticSplitterNodeParser to divide the text 
    based on semantic similarity (embedding distance) rather than fixed character 
    counts. This ensures that topically related sentences stay together.

    Args:
        state (CVEClassifierState): The current pipeline state containing 
            'nvd_references_pages'.

    Returns:
        CVEClassifierState: A new state dictionary with the 'nvd_references_chunks' 
            field populated. This field maps each URL to its list of semantic 
            text chunks.
    """
    pages = state.get("nvd_references_pages", {})
    
    chunks_dict = {}

    if not pages:
        return {**state, "nvd_references_chunks": {}}

    splitter = SemanticSplitterNodeParser(
        buffer_size=1, # Compares each sentence with the next one.
        breakpoint_percentile_threshold=25, # lower -> more granular splits
        embed_model=EMBED_MODEL
    )

    for url, text in pages.items():
        if not text.strip():
            continue

        try:
            document = Document(text=text)
            nodes = splitter.get_nodes_from_documents([document])
            chunks_dict[url] = [node.get_content() for node in nodes]
            
        except Exception as e:
            print(f"Error chunking content for {url}: {e}")
            chunks_dict[url] = []

    return {**state,
            "nvd_references_chunks": chunks_dict}