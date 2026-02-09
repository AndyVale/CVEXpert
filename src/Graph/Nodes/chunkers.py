from tqdm import tqdm
from langchain_experimental.text_splitter import SemanticChunker
from langchain_text_splitters import MarkdownHeaderTextSplitter
from Graph.state import CVEClassifierState

class MarkdownChunkerNode:
    """
    A LangGraph node that performs structural chunking based on Markdown headers.

    This node splits text from 'nvd_references_pages' into chunks by identifying 
    Markdown headers (#, ##, ###, etc.). This preserves the logical sections of 
    technical documents.
    """

    def __init__(self, headers_to_split_on: list[tuple[str, str]] = None):
        """
        Initializes the Markdown Chunker.

        Args:
            headers_to_split_on: A list of tuples containing the markdown symbol 
                and the header name (e.g., [("#", "Header 1"), ("##", "Header 2")]).
        """
        # Default headers if none provided
        self.headers_to_split_on = headers_to_split_on or [
            ("#", "Header 1"),
            ("##", "Header 2"),
            ("###", "Header 3"),
        ]
        self.splitter = MarkdownHeaderTextSplitter(
            headers_to_split_on=self.headers_to_split_on,
            strip_headers=False # Keeping headers helps LLMs understand context
        )

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        """
        Executes markdown structural splitting on all pages stored in the state.
        
        Args:
            state (CVEClassifierState): The current pipeline state.

        Returns:
            CVEClassifierState: Updated state with chunks mapped by URL.
        """
        pages = state.get("nvd_references_pages", {})
        chunks_dict = {}

        if not pages:
            return {**state, "nvd_references_chunks": {}}

        for url, text in tqdm(pages.items(), "Markdown splitting pages"):
            if not text or not text.strip():
                continue

            try:
                documents = self.splitter.split_text(text)
                chunks_dict[url] = [doc.page_content for doc in documents]
            except Exception as e:
                print(f"Error during markdown chunking for {url}: {e}")
                chunks_dict[url] = []

        return {**state,
                "nvd_references_chunks": chunks_dict}

class SemanticChunkerNode:
    """
    A LangGraph node that performs semantic chunking using LangChain's experimental splitter.

    This node takes a pre-initialized LangChain Embeddings object and splits text 
    based on semantic similarity. Parameters for the splitting logic can be 
    customized during initialization.
    """

    def __init__(self, 
                 embed_model, 
                 breakpoint_threshold_type: str = "percentile", 
                 breakpoint_threshold_amount: float = 25.0,
                 number_of_chunks: int = None):
        """
        Initializes the Semantic Chunker with configurable parameters.

        Args:
            embed_model: A LangChain Embeddings object.
            breakpoint_threshold_type: The strategy for determining breakpoints 
                ("percentile", "standard_deviation", "interquartile").
            breakpoint_threshold_amount: The threshold value for the chosen strategy.
            number_of_chunks: If provided, attempts to split the text into a 
                specific number of chunks (overrides threshold).
        """
        self.embed_model = embed_model
        self.breakpoint_threshold_type = breakpoint_threshold_type
        self.breakpoint_threshold_amount = breakpoint_threshold_amount
        self.number_of_chunks = number_of_chunks

        # The splitter is initialized once with the provided parameters
        self.splitter = SemanticChunker(
            self.embed_model, 
            breakpoint_threshold_type=self.breakpoint_threshold_type,
            breakpoint_threshold_amount=self.breakpoint_threshold_amount,
            number_of_chunks=self.number_of_chunks
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

        for url, text in tqdm(pages.items(), "Semantic chunking pages"):
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