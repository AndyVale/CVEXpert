from langchain.chat_models import init_chat_model
from Graph.state import CVEClassifierState

class CVEClassifierNode:
    """
    A LangGraph node that classifies a CVE into security categories using an LLM.

    This node takes the aggregated technical context (RAG) and the primary NVD description 
    to assign one or more security labels. It uses a structured output approach to 
    ensure that the returned labels belong to a predefined set of supported categories.

    Attributes:
        labels_descriptions (dict): A mapping of label names to their technical definitions.
        all_labels (list): A list of valid label strings, including the "NONE" fallback.
        struct_model: The LLM instance configured with a structured output schema.
    """

    def __init__(self, 
                 model_name: str, 
                 api_key: str, 
                 base_url: str, 
                 temperature: float, 
                 labels_descriptions: dict):
        """
        Initializes the CVEClassifierNode.

        Args:
            model_name (str): Name of the classification model.
            api_key (str): API key for the model provider.
            base_url (str): Base URL for the LLM API.
            temperature (float): Sampling temperature for the model.
            labels_descriptions (dict): Definitions of the security labels.
        """
        self.labels_descriptions = labels_descriptions
        # Generate the list of allowed strings for the JSON enum validation
        self.all_labels = list(labels_descriptions.keys()) + ["NONE"]

        chat_model = init_chat_model(
            model=model_name,
            model_provider="openai",
            api_key=api_key,
            base_url=base_url,
            temperature=temperature,
        )

        # Define the structured output schema with enum constraints
        output_schema = {
            "title": "CVEClassification",
            "type": "object",
            "properties": {
                "labels": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": self.all_labels
                    },
                    "minItems": 1,
                }
            },
            "required": ["labels"],
        }

        # Bind the schema to the model once
        self.struct_model = chat_model.with_structured_output(output_schema)

    def _get_prompt(self, cve_id: str, rag_content: str) -> str:
        """Constructs the classification prompt with hierarchical context."""
        labels_and_descriptions = '\n'.join(
            [f"* {k}: {v}" for k, v in self.labels_descriptions.items()]
        )
        
        return f"""You are a Security Research Assistant specialized in vulnerability classification.

OBJECTIVE:
Assign the most accurate security labels to the given CVE based on the evidence provided.

CONTEXT ON DATA SOURCES:
1. PRIMARY SOURCE (NVD): This is the official high-level summary. Use this to identify the general scope.
2. SECONDARY SOURCES (Technical Summaries): These are distillations of external advisories and exploit details. Use these to find specific technical behaviors, root causes, and attack vectors that might be missing from the NVD text.

SUPPORTED LABELS:
{labels_and_descriptions}

VULNERABILITY DATA (ID: {cve_id}):
{rag_content}

ASSIGNMENT STEPS:
1. Analyze the Primary Source for the main vulnerability impact.
2. Evaluate the Secondary Sources for technical specifics (e.g., specific code injection methods, memory management issues).
3. Select labels where the technical description matches the label definition.
4. If the information is insufficient to match any specific category, select the special label "NONE".

OUTPUT REQUIREMENTS:
- Provide a structured JSON object with a single field "labels" containing an array of strings.
- Ensure every label is selected directly from the list below.

ALLOWED LABELS:
{self.all_labels}
"""

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        """
        Executes the classification logic on the current state.

        Args:
            state (CVEClassifierState): The current state containing 'cve_id' and 'rag'.

        Returns:
            CVEClassifierState: Updated state with assigned labels in 'cve_labels'.
        """
        cve_id = state.get("cve_id", "Unknown")
        rag_content = state.get("rag", "")

        if not rag_content:
            print(f"Warning: No RAG content found for {cve_id}.")

        print(f"Classifying {cve_id}...")
        
        try:
            prompt = self._get_prompt(cve_id, rag_content)
            result = self.struct_model.invoke(prompt)
            
            # Ensure we return the labels field from the JSON response
            labels = result.get("labels", ["NONE"])
            return {**state,
                    "cve_labels": labels}

        except Exception as e:
            print(f"Classification error for {cve_id}: {e}")
            # Return "NONE" to maintain state integrity in case of LLM failure
            return {**state,
                    "cve_labels": ["NONE"]}