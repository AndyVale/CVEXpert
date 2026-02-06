from tqdm import tqdm
from langchain_experimental.text_splitter import SemanticChunker
from Graph.state import CVEClassifierState

class SemanticChunkerNode:
    """
    A LangGraph node that performs semantic chunking using LangChain's experimental splitter.

    This node takes a pre-initialized LangChain Embeddings object and splits text from 
    'nvd_references_pages' into semantically coherent chunks based on embedding distance.
    """

    def __init__(self, embed_model):
        """
        Initializes the Semantic Chunker with a LangChain Embeddings model.

        Args:
            embed_model: A LangChain Embeddings object (e.g., OpenAIEmbeddings).
        """
        self.embed_model = embed_model
        # The splitter is initialized once. 
        # breakpoint_threshold_amount=25.0 corresponds to the 25th percentile.
        self.splitter = SemanticChunker(
            self.embed_model, 
            breakpoint_threshold_type="percentile",
            breakpoint_threshold_amount=25.0 
        )

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        """
        Executes semantic chunking on all pages stored in the state.
        Iterates through the 'nvd_references_pages' dictionary and updates 
        'nvd_references_chunks' with the resulting list of strings.

        Args:
            state (CVEClassifierState): The current pipeline state.

        Returns:
            CVEClassifierState: Updated state with semantic chunks for each reference.
        """
        pages = state.get("nvd_references_pages", {})
        chunks_dict = {}

        if not pages:
            return {**state, "nvd_references_chunks": {}}

        for url, text in tqdm(pages.items(), "Chunking pages"):
            if not text or not text.strip():
                continue

            try:
                # split_text returns a list of strings
                chunks = self.splitter.split_text(text)
                chunks_dict[url] = chunks
            except Exception as e:
                print(f"Error during semantic chunking for {url}: {e}")
                chunks_dict[url] = []

        return {**state,
                "nvd_references_chunks": chunks_dict}