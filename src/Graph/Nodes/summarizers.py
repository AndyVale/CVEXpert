from tqdm import tqdm
from Graph.state import CVEClassifierState

class ReferenceSummarizerNode:
    """
    A LangGraph node that summarizes filtered technical chunks for each reference URL.

    This node iterates through 'nvd_filtered_chunks', processing each URL separately. 
    It combines the filtered snippets and uses a structured LLM call to determine 
    if the content is CVE-related and, if so, generates a technical summary focused 
    on features useful for classification.

    Attributes:
        model: The LLM instance used for summarization (without structured output).
        labels_descriptions (dict): A mapping of security labels to their descriptions 
            used to guide the summarization focus.
    """

    def __init__(self, 
                 model, 
                 labels_descriptions: dict,
                 prompt_func):
        """
        Initializes the ReferenceSummarizerNode with a pre-initialized LLM.

        Args:
            model: A LangChain chat model instance (e.g., initialized via init_chat_model).
            labels_descriptions (dict): Dictionary of classification labels to include in the prompt.
            prompt_func: A callable to generate the summarizer prompt.
        """
        # Define the JSON schema for structured output
        self.json_schema = {
            "title": "cve_summarizer_output",
            "description": "Schema for summarizing CVE related texts",
            "type": "object",
            "properties": {
                "is_cve_related": {"type": "boolean"},
                "summary": {"type": "string"}
            },
            "required": ["is_cve_related", "summary"]
        }

        # Bind the structured output to the provided model instance
        self.struct_model = model.with_structured_output(self.json_schema)
        self.labels_descriptions = labels_descriptions
        self.prompt_func = prompt_func

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        """
        Processes the state by summarizing each reference's filtered chunks.

        Args:
            state (CVEClassifierState): The current pipeline state.

        Returns:
            CVEClassifierState: Updated state with the 'summaries' dictionary populated.
        """
        filtered_chunks_dict = state.get("nvd_filtered_chunks", {})
        summaries_dict = {}

        if not filtered_chunks_dict:
            return {**state, "summaries": {}}

        for url, chunks in tqdm(filtered_chunks_dict.items(), "Summarizing filtered chunks"):
            if all([c == "..." for c in chunks]):
                continue

            text_to_analyze = "\n\n".join(chunks).strip()

            # print(f"Summarizing reference: {url}...")
            
            try:
                prompt = self.prompt_func(text_to_analyze, self.labels_descriptions)
                response = self.struct_model.invoke(prompt)
                
                if response and response.get("is_cve_related") and response.get("summary"):
                    summaries_dict[url] = response["summary"].strip()

                # print("Summarization completed")
                
            except Exception as e:
                print(f"Error during structured summarization for {url}: {e}")
                continue

        return {**state,
                "summaries": summaries_dict}

class CVEAwareSummarizerNode:
    """
    A LangGraph node that summarizes filtered technical chunks for each reference URL,
    using the specific CVE ID and NVD description as context to filter relevance.

    This node iterates through 'nvd_filtered_chunks'. For each reference, it uses 
    the official NVD description to verify if the content matches the specific 
    vulnerability. It generates a summary only if the content is semantically 
    aligned with the provided CVE context.

    Attributes:
        struct_model: The LLM instance with structured output binding.
        labels_descriptions (dict): A mapping of security labels to guide focus.
    """

    def __init__(self, 
                 model, 
                 labels_descriptions: dict,
                 prompt_func):
        """
        Initializes the CVEAwareSummarizerNode with a pre-initialized LLM.

        Args:
            model: A LangChain chat model instance.
            labels_descriptions (dict): Dictionary of classification labels.
            prompt_func: A callable to generate the summarizer prompt.
        """
        # Define the JSON schema for structured output
        self.json_schema = {
            "title": "cve_summarizer_output",
            "description": "Schema for summarizing CVE related texts",
            "type": "object",
            "properties": {
                "is_cve_related": {"type": "boolean"},
                "summary": {"type": "string"}
            },
            "required": ["is_cve_related", "summary"]
        }

        # Bind the structured output to the provided model instance
        self.struct_model = model.with_structured_output(self.json_schema)
        self.labels_descriptions = labels_descriptions
        self.prompt_func = prompt_func

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        """
        Processes the state by summarizing each reference's filtered chunks,
        using the CVE ID and Description as a relevance filter.

        Args:
            state (CVEClassifierState): The current pipeline state.

        Returns:
            CVEClassifierState: Updated state with the 'summaries' dictionary populated.
        """
        filtered_chunks_dict = state.get("nvd_filtered_chunks", {})
        summaries_dict = {}
        
        # Extract context from state
        cve_id = state["cve_id"]
        nvd_description = state["nvd_description"]

        if not filtered_chunks_dict:
            return {**state, "summaries": {}}

        for url, chunks in tqdm(filtered_chunks_dict.items(), "Summarizing filtered chunks"):
            # Skip empty or gap-only chunks
            if not chunks or all(c == "..." for c in chunks):
                continue

            text_to_analyze = "\n\n".join(chunks).strip()
            
            try:
                # Pass the CVE context to the prompt generator
                prompt = self.prompt_func(text_to_analyze, cve_id, nvd_description, self.labels_descriptions)
                
                response = self.struct_model.invoke(prompt)
                
                if response and response.get("is_cve_related") and response.get("summary"):
                    summaries_dict[url] = response["summary"].strip()
                
            except Exception as e:
                print(f"Error during structured summarization for {url}: {e}")
                continue

        return {**state,
                "summaries": summaries_dict}

class NoSummarizerNode:
    """
    A LangGraph node that substitutes the summarizer; it executes no LLM summarization.
    
    The purpose of this node is to conduct ablation studies (testing the pipeline 
    without the summarization step) while maintaining the exact same state structure 
    and data flow. It simply concatenates the filtered chunks into a single string 
    per reference.
    """

    def __init__(self):
        """
        Initializes the node. No model or configuration is required.
        """
        pass

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        """
        Processes the state by concatenating filtered chunks for each reference.

        Args:
            state (CVEClassifierState): The current pipeline state.

        Returns:
            CVEClassifierState: Updated state with the 'summaries' dictionary populated
            with raw concatenated text instead of LLM-generated summaries.
        """
        filtered_chunks_dict = state.get("nvd_filtered_chunks", {})
        summaries_dict = {}

        if not filtered_chunks_dict:
            return {**state, "summaries": {}}

        for url, chunks in filtered_chunks_dict.items():

            valid_chunks = [c for c in chunks if c != "..."]
            if not valid_chunks:
                continue
            
            concatenated_text = "\n\n".join(valid_chunks).strip()
            
            if concatenated_text:
                summaries_dict[url] = concatenated_text

        return {**state,
                "summaries": summaries_dict}