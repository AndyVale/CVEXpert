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
                 model, 
                 labels_descriptions: dict):
        """
        Initializes the CVEClassifierNode with a pre-initialized LLM.

        Args:
            model: The LLM instance used for classification (without structured output).
            labels_descriptions (dict): Definitions of the security labels.
        """
        self.labels_descriptions = labels_descriptions
        # Generate the list of allowed strings for the JSON enum validation
        self.all_labels = list(labels_descriptions.keys()) + ["NONE"]

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

        # Bind the schema to the provided model instance
        self.struct_model = model.with_structured_output(output_schema)

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
        
class CVEConfidenceClassifierNode:
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
                 model, 
                 labels_descriptions: dict):
        """
        Initializes the CVEClassifierNode with a pre-initialized LLM.

        Args:
            model: The LLM instance used for classification (without structured output).
            labels_descriptions (dict): Definitions of the security labels.
        """
        self.labels_descriptions = labels_descriptions
        # Generate the list of allowed strings for the JSON enum validation
        self.all_labels = list(labels_descriptions.keys()) + ["NONE"]

        # Define the structured output schema with enum constraints
        output_schema = {
            "title": "CVEClassification",
            "type": "object",
            "properties": {
                "classifications": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "label": {
                                "type": "string",
                                "enum": self.all_labels,
                                "description": "The security category label."
                            },
                            "motivation": {
                                "type": "string",
                                "description": "A concise explanation (1-2 sentences) citing specific evidence from the text that justifies this label."
                            },
                            "confidence": {
                                "type": "number",
                                "description": "A score between 0 (uncertain) and 10 (certain).",
                                "minimum": 0,
                                "maximum": 10
                            }
                        },
                        "required": ["label", "motivation", "confidence"]
                    },
                    "minItems": 1,
                }
            },
            "required": ["classifications"],
        }

        # Bind the schema to the provided model instance
        self.struct_model = model.with_structured_output(output_schema)

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
1. Review the definition of each label carefully.
2. Search the "VULNERABILITY DATA" for matching evidence, you should select all and only the labels that have a matching evidence.
3. If evidence exists, select the label and directly quote a small part of the evidence, providing also the id of the reference (e.g. 'NVDDescription', 'Reference 1', 'Reference 3'), along with a brief explanation (motivation).
4. Assign a confidence score based on the clarity of the evidence: 0 if the evidence does not suggest the label, 10 if the label is explicitly assigned to the CVE.
5. If NO specific technical information is present, select "NONE" with low confidence and provide a brief motivation.

OUTPUT REQUIREMENTS:
- Return a structured object containing a list of classifications.
- Each classification must have a 'label', 'motivation', and 'confidence'.

ALLOWED LABELS:
{self.all_labels}
"""

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        """
        Executes the classification logic on the current state.
        Parses the structured output to separate labels, motivations, and scores.

        Args:
            state (CVEClassifierState): The current state containing 'cve_id' and 'rag'.

        Returns:
            CVEClassifierState: Updated state with 'cve_labels', 'labels_motivation', and 'labels_confidence'.
        """
        cve_id = state.get("cve_id", "Unknown")
        rag_content = state.get("rag", "")

        if not rag_content:
            print(f"Warning: No RAG content found for {cve_id}.")
        
        # Default fallback values
        default_labels = ["NONE"]
        default_motivation = {"NONE": "Failure or missing content"}
        default_confidence = {"NONE": 0.0}

        try:
            print(f"Classifying {cve_id}...")
            prompt = self._get_prompt(cve_id, rag_content)
            result = self.struct_model.invoke(prompt)
            
            # The result['labels'] is now a list of dictionaries (objects)
            raw_classifications = result.get("classifications", [])
            
            if not raw_classifications:
                return {**state, 
                        "cve_labels": default_labels,
                        "labels_motivation": default_motivation,
                        "labels_confidence": default_confidence}

            parsed_labels = []
            parsed_motivations = {}
            parsed_confidences = {}

            for item in raw_classifications:
                lbl = item.get("label", "NONE")
                parsed_labels.append(lbl)
                parsed_motivations[lbl] = item.get("motivation", "No motivation provided")
                parsed_confidences[lbl] = item.get("confidence", 0.0)

            return {**state,
                    "cve_labels": parsed_labels,
                    "labels_motivation": parsed_motivations,
                    "labels_confidence": parsed_confidences}

        except Exception as e:
            print(f"Classification error for {cve_id}: {e}")
            return {**state,
                    "cve_labels": default_labels,
                    "labels_motivation": {"NONE": f"Error: {str(e)}"},
                    "labels_confidence": default_confidence}