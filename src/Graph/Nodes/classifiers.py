from typing import NoReturn

from Graph.errors import PipelineStageError
from Graph.reporting import get_logger
from Graph.state import CVEClassifierState


LOGGER = get_logger("classify")


def _validate_labels(labels, allowed_labels: list[str]) -> list[str]:
    if not isinstance(labels, list) or not labels:
        raise ValueError("Classifier labels must be a non-empty list")
    if any(not isinstance(label, str) for label in labels):
        raise TypeError("Classifier labels must be strings")

    unknown_labels = [label for label in labels if label not in allowed_labels]
    if unknown_labels:
        raise ValueError("Classifier returned an unsupported label")
    if len(labels) != len(set(labels)):
        raise ValueError("Classifier returned duplicate labels")
    if "NONE" in labels and len(labels) > 1:
        raise ValueError("NONE cannot be combined with vulnerability labels")
    return labels


def _labels_from_result(result, allowed_labels: list[str]) -> list[str]:
    if not isinstance(result, dict):
        raise TypeError("Classifier result must be an object")
    if "labels" not in result:
        raise ValueError("Classifier result is missing labels")
    return _validate_labels(result["labels"], allowed_labels)


def _raise_classifier_error(cve_id: str, error: BaseException) -> NoReturn:
    raise PipelineStageError(
        stage="classify",
        cve_id=cve_id,
        error=error,
        safe_message="Classifier invocation or output validation failed",
    ) from error


class CVENoRagClassifierNode:
    def __init__(self, 
                 model, 
                 labels_descriptions: dict):

        self.labels_descriptions = labels_descriptions
        self.all_labels = list(labels_descriptions.keys()) + ["NONE"]

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
                    "uniqueItems": True,
                }
            },
            "required": ["labels"],
        }
        self.struct_model = model.with_structured_output(output_schema)

    def _get_prompt(self, cve_id) -> str:
        labels_and_descriptions = '\n'.join(
            [f"* {k}: {v}" for k, v in self.labels_descriptions.items()]
        )
        
        return f"""You are a Security Research Assistant specialized in vulnerability classification.

OBJECTIVE:
Assign the most accurate security labels to the CVE {cve_id} based on your knowledge.

SUPPORTED LABELS:
{labels_and_descriptions}

ASSIGNMENT STEPS:
1. Select labels where the technical description matches the label definition.

OUTPUT REQUIREMENTS:
- Provide a structured JSON object with a single field "labels" containing an array of strings.
- Ensure every label is selected directly from the list below.

ALLOWED LABELS:
{self.all_labels}
"""

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        cve_id = state.get("cve_id", "Unknown")
        LOGGER.debug("Classification started for %s without RAG context", cve_id)
        try:
            prompt = self._get_prompt(cve_id)
            result = self.struct_model.invoke(prompt)

            labels = _labels_from_result(result, self.all_labels)
            LOGGER.debug("Classification completed for %s: labels=%s", cve_id, labels)
            return {**state,
                    "cve_labels": labels}

        except Exception as error:
            _raise_classifier_error(cve_id, error)

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
                    "uniqueItems": True,
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

        LOGGER.debug("Classification started for %s", cve_id)

        try:
            if not isinstance(rag_content, str) or not rag_content.strip():
                raise ValueError("Classifier requires non-empty RAG content")
            prompt = self._get_prompt(cve_id, rag_content)
            result = self.struct_model.invoke(prompt)

            labels = _labels_from_result(result, self.all_labels)
            LOGGER.debug("Classification completed for %s: labels=%s", cve_id, labels)
            return {**state,
                    "cve_labels": labels}

        except Exception as error:
            _raise_classifier_error(cve_id, error)
        
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
                                "description": "A short quote (1-2 sentences) from the text that justifies this label, specifing the reference."
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
                    "uniqueItems": True,
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

2. Search the "VULNERABILITY DATA" for matching evidence. You must select ALL labels that have supporting evidence and ONLY those labels.

3. For each selected label, the motivation MUST be a direct quote from the evidence, prefixed with the specific Reference ID (e.g., 'NVD Description', 'Reference 1').
   Example format: 'Reference 2: "A buffer overflow is used to achieve RCE."'

4. Assign a confidence score (0-10) based on the clarity of the connection to {cve_id}:
   - **10 (Certain)**: The text explicitly assigns the label to {cve_id} (e.g., "CVE-202X-XXXX is a SQL Injection").
   - **1-9 (Inferred)**: The text describes the technical mechanism associated with the label clearly, but might not explicitly name the CVE in that specific sentence, or the context is slightly ambiguous.
   - *Note: If the evidence does not support the label (Score 0), do not select that label.*

5. If NO specific technical information matches any category, select the special label "NONE" with a low confidence score (e.g., 1) and provide a brief motivation such as "Insufficient technical information provided".
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

        try:
            if not isinstance(rag_content, str) or not rag_content.strip():
                raise ValueError("Classifier requires non-empty RAG content")
            LOGGER.debug("Confidence classification started for %s", cve_id)
            prompt = self._get_prompt(cve_id, rag_content)
            result = self.struct_model.invoke(prompt)

            if not isinstance(result, dict):
                raise TypeError("Classifier result must be an object")
            raw_classifications = result.get("classifications")
            if not isinstance(raw_classifications, list) or not raw_classifications:
                raise ValueError("Classifier classifications must be a non-empty list")

            parsed_labels = []
            parsed_motivations = {}
            parsed_confidences = {}

            for item in raw_classifications:
                if not isinstance(item, dict):
                    raise TypeError("Each classification must be an object")
                lbl = item.get("label")
                parsed_labels.append(lbl)
                parsed_motivations[lbl] = item.get("motivation", "No motivation provided")
                parsed_confidences[lbl] = item.get("confidence", 0.0)

            _validate_labels(parsed_labels, self.all_labels)
            LOGGER.debug(
                "Confidence classification completed for %s: labels=%s",
                cve_id,
                parsed_labels,
            )

            return {**state,
                    "cve_labels": parsed_labels,
                    "labels_motivation": parsed_motivations,
                    "labels_confidence": parsed_confidences}

        except Exception as error:
            _raise_classifier_error(cve_id, error)
        
class CVESelfConsistentClassifierNode:
    """
    A LangGraph node that classifies a CVE using a self-consistency approach.
    Confidence is calculated as the frequency of a label appearing across multiple runs.
    """

    def __init__(self, 
                 model, 
                 labels_descriptions: dict,
                 total_runs = 5):
        """
        Initializes the CVEClassifierNode with a pre-initialized LLM.

        Args:
            model: The LLM instance used for classification (without structured output).
            labels_descriptions (dict): Definitions of the security labels.
            total_runs (int): Number of query to compute confidence on labels.
        """
        self.labels_descriptions = labels_descriptions
        self.all_labels = list(labels_descriptions.keys()) + ["NONE"]
        self.total_runs = total_runs
        
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
                                "description": "A short quote (1-2 sentences) from the text that justifies this label, specifing the reference."
                            }
                        },
                        "required": ["label", "motivation"]
                    },
                    "minItems": 1,
                    "uniqueItems": True,
                }
            },
            "required": ["classifications"],
        }

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

2. Search the "VULNERABILITY DATA" for matching evidence. You must select ALL labels that have supporting evidence and ONLY those labels.

3. For each selected label, the motivation MUST be a direct quote from the evidence, prefixed with the specific Reference ID (e.g., 'NVD Description', 'Reference 1').
   Example format: 'Reference 2: "A buffer overflow is used to achieve RCE."'

5. If NO specific technical information matches any category, select the special label "NONE" and provide a brief motivation such as "Insufficient technical information provided".
OUTPUT REQUIREMENTS:
- Return a structured object containing a list of classifications.
- Each classification must have a 'label' and a 'motivation'.

ALLOWED LABELS:
{self.all_labels}
"""

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        cve_id = state.get("cve_id", "Unknown")
        rag_content = state.get("rag", "")

        LOGGER.debug(
            "Self-consistency classification started for %s: runs=%s",
            cve_id,
            self.total_runs,
        )

        label_counts = {}
        label_motivations = {}
        prompt = self._get_prompt(cve_id, rag_content)

        try:
            if not isinstance(rag_content, str) or not rag_content.strip():
                raise ValueError("Classifier requires non-empty RAG content")
            if self.total_runs < 1:
                raise ValueError("Self-consistency total_runs must be positive")

            for _ in range(self.total_runs):
                result = self.struct_model.invoke(prompt)
                if not isinstance(result, dict):
                    raise TypeError("Classifier result must be an object")
                items = result.get("classifications")
                if not isinstance(items, list) or not items:
                    raise ValueError("Classifier classifications must be a non-empty list")

                run_labels = []

                for item in items:
                    if not isinstance(item, dict):
                        raise TypeError("Each classification must be an object")
                    run_labels.append(item.get("label"))

                _validate_labels(run_labels, self.all_labels)
                seen_in_run = set(run_labels)

                for item in items:
                    lbl = item["label"]
                    # Store the first valid motivation found for this label
                    if lbl not in label_motivations:
                        label_motivations[lbl] = item.get("motivation", "No motivation provided")

                # Update global frequency counts
                for lbl in seen_in_run:
                    if lbl not in label_counts:
                        label_counts[lbl] = 0
                    label_counts[lbl] += 1

            # Calculate confidence: Occurrences / Total Runs
            final_confidence = {}
            for lbl, count in label_counts.items():
                final_confidence[lbl] = count / self.total_runs

            final_labels = _validate_labels(list(label_counts.keys()), self.all_labels)
            LOGGER.debug(
                "Self-consistency classification completed for %s: labels=%s",
                cve_id,
                final_labels,
            )
            return {**state,
                    "cve_labels": final_labels,
                    "labels_motivation": label_motivations,
                    "labels_confidence": final_confidence}

        except Exception as error:
            _raise_classifier_error(cve_id, error)
