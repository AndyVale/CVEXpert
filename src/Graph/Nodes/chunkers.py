from llama_index.core import Document
from llama_index.core.node_parser import SemanticSplitterNodeParser
from llama_index.core.embeddings import BaseEmbedding

from Graph.state import CVEClassifierState

class SemanticChunkerNode:
    """
    A LangGraph node that performs semantic chunking via a provided Embedding Model.

    This node uses an injected embedding model instance to split text from 
    'nvd_references_pages' into semantically coherent chunks.
    """

    def __init__(self, embed_model: BaseEmbedding):
        """
        Initializes the Semantic Chunker with a pre-configured embedding model.

        Args:
            embed_model (BaseEmbedding): An initialized LlamaIndex embedding model instance.
        """
        self.embed_model = embed_model

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        """
        Executes semantic chunking on all pages in the state.
        Iterates through the 'nvd_references_pages' dictionary.
        For each page, it uses LlamaIndex's SemanticSplitterNodeParser 
        to divide the text based on semantic similarity (embedding distance).
        """
        pages = state.get("nvd_references_pages", {})
        chunks_dict = {}

        if not pages:
            return {**state,
                    "nvd_references_chunks": {}}

        # The splitter uses the injected embed_model
        splitter = SemanticSplitterNodeParser(
            buffer_size=1,
            breakpoint_percentile_threshold=25,
            embed_model=self.embed_model
        )

        for url, text in pages.items():
            if not text.strip():
                continue

            try:
                document = Document(text=text)
                nodes = splitter.get_nodes_from_documents([document])
                chunks_dict[url] = [node.get_content() for node in nodes]
            except Exception as e:
                print(f"Error during semantic chunking for {url}: {e}")
                chunks_dict[url] = []

        return {**state,
                "nvd_references_chunks": chunks_dict}