from tqdm import tqdm
from langchain_experimental.text_splitter import SemanticChunker
from langchain_text_splitters import RecursiveCharacterTextSplitter, MarkdownHeaderTextSplitter
from Graph.errors import make_pipeline_warning
from Graph.state import CVEClassifierState

class RecursiveCharacterChunkerNode:
    """
    A LangGraph node that performs text splitting based on recursive character sequencing.

    This node splits Markdown text from 'nvd_references_pages' into chunks of a 
    specific size. it uses a sequence of separators (e.g., newlines, periods, spaces) 
    to find the best places to break the text, maintaining structural continuity 
    where possible.
    """

    def __init__(self, 
                 chunk_size: int = 1000, 
                 chunk_overlap: int = 100, 
                 separators: list[str] = ["\n\n", "\n", ". ", " ", ""]):
        """
        Initializes the Recursive Character Chunker.

        Args:
            chunk_size: The maximum number of characters per chunk.
            chunk_overlap: The number of characters to overlap between adjacent chunks 
                to preserve context.
            separators: A list of strings to use as splitting delimiters in order of 
                priority. Defaults to paragraphs, newlines, sentences, and spaces.
        """
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.separators = separators
        
        self.splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.chunk_size,
            chunk_overlap=self.chunk_overlap,
            separators=self.separators
        )

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        """
        Executes recursive character splitting on all pages stored in the state.

        Args:
            state (CVEClassifierState): The current pipeline state.

        Returns:
            CVEClassifierState: Updated state with chunks mapped by URL.
        """
        pages = state.get("nvd_references_pages", {})
        chunks_dict = {}
        warnings = list(state.get("pipeline_warnings", []))

        if not pages:
            return {**state, "nvd_references_chunks": {}}

        for url, text in tqdm(pages.items(), "Recursive splitting pages"):
            if not text or not text.strip():
                continue

            try:
                # split_text returns a list of strings
                chunks = self.splitter.split_text(text)
                if not chunks:
                    raise ValueError("Chunker returned no chunks")
                chunks_dict[url] = chunks
            except Exception as error:
                chunks_dict[url] = []
                warnings.append(
                    make_pipeline_warning(
                        stage="chunk",
                        source=url,
                        error=error,
                        safe_message="Recursive character chunking failed",
                    )
                )

        return {**state,
                "nvd_references_chunks": chunks_dict,
                "pipeline_warnings": warnings}

class MarkdownChunkerNode:
    """
    A LangGraph node that performs structural chunking based on Markdown headers.

    This node splits text from 'nvd_references_pages' into chunks by identifying 
    Markdown headers (#, ##, ###, etc.). This preserves the logical sections of 
    technical documents.
    """

    def __init__(self, headers_to_split_on: list[tuple[str, str]] = [("#", "Header 1"),("##", "Header 2"),("###", "Header 3"),]):
        """
        Initializes the Markdown Chunker.

        Args:
            headers_to_split_on: A list of tuples containing the markdown symbol 
                and the header name (e.g., [("#", "Header 1"), ("##", "Header 2")]).
        """
        self.headers_to_split_on = headers_to_split_on
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
        warnings = list(state.get("pipeline_warnings", []))

        if not pages:
            return {**state, "nvd_references_chunks": {}}

        for url, text in tqdm(pages.items(), "Markdown splitting pages"):
            if not text or not text.strip():
                continue

            try:
                documents = self.splitter.split_text(text)
                chunks = [doc.page_content for doc in documents]
                if not chunks:
                    raise ValueError("Chunker returned no chunks")
                chunks_dict[url] = chunks
            except Exception as error:
                chunks_dict[url] = []
                warnings.append(
                    make_pipeline_warning(
                        stage="chunk",
                        source=url,
                        error=error,
                        safe_message="Markdown chunking failed",
                    )
                )

        return {**state,
                "nvd_references_chunks": chunks_dict,
                "pipeline_warnings": warnings}

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
        warnings = list(state.get("pipeline_warnings", []))

        if not pages:
            return {**state, "nvd_references_chunks": {}}

        for url, text in tqdm(pages.items(), "Semantic chunking pages"):
            if not text or not text.strip():
                continue

            try:
                # split_text returns a list of strings
                chunks = self.splitter.split_text(text)
                if not chunks:
                    raise ValueError("Chunker returned no chunks")
                chunks_dict[url] = chunks
            except Exception as error:
                chunks_dict[url] = []
                warnings.append(
                    make_pipeline_warning(
                        stage="chunk",
                        source=url,
                        error=error,
                        safe_message="Semantic chunking failed",
                    )
                )

        return {**state,
                "nvd_references_chunks": chunks_dict,
                "pipeline_warnings": warnings}
