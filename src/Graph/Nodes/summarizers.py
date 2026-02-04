import json
from langchain.chat_models import init_chat_model
from Graph.state import CVEClassifierState

class ReferenceSummarizerNode:
    """
    A LangGraph node that summarizes filtered technical chunks for each reference URL.

    This node iterates through 'nvd_filtered_chunks', processing each URL separately. 
    It combines the filtered snippets and uses a structured LLM call to determine 
    if the content is CVE-related and, if so, generates a technical summary focused 
    on features useful for classification.

    Attributes:
        model: The structured LLM instance used for summarization.
        labels_descriptions (dict): A mapping of security labels to their descriptions 
            used to guide the summarization focus.
    """

    def __init__(self, 
                 model_name: str, 
                 api_key: str, 
                 base_url: str, 
                 labels_descriptions: dict):
        """
        Initializes the ReferenceSummarizerNode.

        Args:
            model_name (str): Name of the model to use (e.g., Phi-4, Qwen).
            api_key (str): Authentication token for the LLM provider.
            base_url (str): The base URL for the LLM API.
            labels_descriptions (dict): Dictionary of classification labels to include in the prompt.
        """

        llm = init_chat_model(
            model=model_name,
            model_provider="openai",
            api_key=api_key,
            base_url=base_url,
        )

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

        # Bind the structured output to the model
        self.struct_model = llm.with_structured_output(self.json_schema)
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

        if not filtered_chunks_dict:
            return {**state, "summaries": {}}

        for url, chunks in filtered_chunks_dict.items():
            if all([c == "..." for c in chunks]):
                continue

            text_to_analyze = "\n\n".join(chunks).strip()

            print(f"Summarizing reference: {url}...")
            
            try:
                response = self.struct_model.invoke(self._get_prompt(text_to_analyze))
                
                if response and response.get("is_cve_related") and response.get("summary"):
                    summaries_dict[url] = response["summary"].strip()
                
            except Exception as e:
                print(f"Error during structured summarization for {url}: {e}")
                continue

        return {**state,
                "summaries": summaries_dict}