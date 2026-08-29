from tqdm import tqdm
from Graph.errors import make_pipeline_warning
from Graph.state import CVEClassifierState


def _validate_summary_response(response) -> tuple[bool, str]:
    if not isinstance(response, dict):
        raise TypeError("Summarizer result must be an object")

    is_cve_related = response.get("is_cve_related")
    summary = response.get("summary")
    if not isinstance(is_cve_related, bool):
        raise TypeError("Summarizer result must include a boolean is_cve_related")
    if not isinstance(summary, str):
        raise TypeError("Summarizer result must include a string summary")
    if is_cve_related and not summary.strip():
        raise ValueError("Related reference summary must not be empty")
    return is_cve_related, summary.strip()


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
                 labels_descriptions: dict):
        """
        Initializes the ReferenceSummarizerNode with a pre-initialized LLM.

        Args:
            model: A LangChain chat model instance (e.g., initialized via init_chat_model).
            labels_descriptions (dict): Dictionary of classification labels to include in the prompt.
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

    def _get_prompt(self, text: str) -> str:
        """Constructs the prompt with the labels and the text to summarize."""
        labels_str = '\n'.join([f"* {k}: {v}" for k, v in self.labels_descriptions.items()])
        
        return f"""
You are a specialized cybersecurity analyst. Your task is to process a "filtered" extraction from a web page linked to a CVE (Common Vulnerabilities and Exposures).
Your goal is to make a clear summary that will help another cybersecurity analyst to classify the CVE into several labels:

{labels_str}

CONTEXT FOR THE INPUT:
- The text below is not a full page. It is a sequence of highly relevant snippets.
- The symbol "..." indicates where irrelevant content (like ads, navigation, or boilerplate) has been removed.
- Your goal is to bridge these snippets into a single, cohesive technical summary that will help the other analyst, ignoring the gaps.

TASK:
1. Determine if the text contains specific technical evidence of a vulnerability (e.g., a bug description, a PoC, affected versions, or an advisory).
2. If related, create a summary that:
   - Preserves all technical keywords (e.g., "buffer overflow", "null pointer", "CVE-XXXX").
   - Describes the root cause and the impact.
   - Identifies the affected software and version.
   - Maintains the exact semantic meaning of the source.
   - Focus on creating a summary that will help the classification of the CVE.

CONSTRAINTS:
- Produce the summary as described above.
- Use 3 to 6 sentences.
- Use a professional, dry, technical tone.
- If the remaining text is too fragmented to identify a specific vulnerability, mark `is_cve_related` as false.

OUTPUT FORMAT:
Return a JSON object with:
- `is_cve_related`: (boolean)
- `summary`: (string)

EXTRACTED TEXT TO ANALYZE:
---
{text}
---
"""

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
        warnings = list(state.get("pipeline_warnings", []))

        if not filtered_chunks_dict:
            return {**state, "summaries": {}}

        for url, chunks in tqdm(filtered_chunks_dict.items(), "Summarizing filtered chunks"):
            if all([c == "..." for c in chunks]):
                continue

            text_to_analyze = "\n\n".join(chunks).strip()

            # print(f"Summarizing reference: {url}...")
            
            try:
                response = self.struct_model.invoke(self._get_prompt(text_to_analyze))
                is_cve_related, summary = _validate_summary_response(response)

                if is_cve_related:
                    summaries_dict[url] = summary

                # print("Summarization completed")
                
            except Exception as error:
                warnings.append(
                    make_pipeline_warning(
                        stage="summarize",
                        source=url,
                        error=error,
                        safe_message="Reference summarization failed",
                    )
                )
                continue

        return {**state,
                "summaries": summaries_dict,
                "pipeline_warnings": warnings}

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
                 labels_descriptions: dict):
        """
        Initializes the CVEAwareSummarizerNode with a pre-initialized LLM.

        Args:
            model: A LangChain chat model instance.
            labels_descriptions (dict): Dictionary of classification labels.
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

    def _get_prompt(self, text: str, cve_id: str, nvd_description: str) -> str:
        """
        Constructs a prompt that grounds the summarization in the specific CVE context.
        """
        labels_str = '\n'.join([f"* {k}: {v}" for k, v in self.labels_descriptions.items()])
        
        return f"""
You are a specialized cybersecurity analyst. Your task is to extract technical details from a set of text fragments found on a webpage referenced by the National Vulnerability Database.

TARGET VULNERABILITY:
- **CVE ID**: {cve_id}
- **Official Description**: {nvd_description}

YOUR GOAL:
Determine if the provided text fragments describe THIS specific vulnerability ({cve_id}). If they do, summarize the technical details found *in the fragments* that are not already obvious, focusing on information helpful for classification.

TARGET CLASSIFICATION LABELS:
{labels_str}

INPUT CONTEXT:
- The text below contains snippets extracted from a webpage.
- The symbol "..." indicates gaps where irrelevant content was removed.

INSTRUCTIONS:
1. **Verification**: Compare the text fragments against the "Official Description". 
   - If the text talks about a different CVE, a different software, or is just a general homepage/login screen, set `is_cve_related` to False.
   - If the text matches {cve_id}, set `is_cve_related` to True.

2. **Summarization** (Only if related):
   - Extract specific technical details: affected versions, root cause (e.g., "heap overflow in function X"), exploit vectors, and impact.
   - Do NOT just repeat the NVD description. Look for *additional* technical depth in the fragments.
   - Ignore the "..." gaps. Bridge the fragments into a cohesive technical summary.
   - Use a professional, dry, technical tone (3-6 sentences).

OUTPUT FORMAT:
Return a JSON object with:
- `is_cve_related`: (boolean) True ONLY if the text explicitly discusses {cve_id}.
- `summary`: (string) The technical summary.

EXTRACTED TEXT TO ANALYZE:
---
{text}
---
"""

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
        warnings = list(state.get("pipeline_warnings", []))
        
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
                prompt = self._get_prompt(text_to_analyze, cve_id, nvd_description)
                
                response = self.struct_model.invoke(prompt)
                is_cve_related, summary = _validate_summary_response(response)

                if is_cve_related:
                    summaries_dict[url] = summary

            except Exception as error:
                warnings.append(
                    make_pipeline_warning(
                        stage="summarize",
                        source=url,
                        error=error,
                        safe_message="CVE-aware reference summarization failed",
                    )
                )
                continue

        return {**state,
                "summaries": summaries_dict,
                "pipeline_warnings": warnings}

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
        warnings = list(state.get("pipeline_warnings", []))

        if not filtered_chunks_dict:
            return {**state, "summaries": {}}

        for url, chunks in filtered_chunks_dict.items():
            try:
                valid_chunks = [c for c in chunks if c != "..."]
                if not valid_chunks:
                    continue

                concatenated_text = "\n\n".join(valid_chunks).strip()

                if concatenated_text:
                    summaries_dict[url] = concatenated_text
            except Exception as error:
                warnings.append(
                    make_pipeline_warning(
                        stage="summarize",
                        source=url,
                        error=error,
                        safe_message="Reference concatenation failed",
                    )
                )

        return {**state,
                "summaries": summaries_dict,
                "pipeline_warnings": warnings}
