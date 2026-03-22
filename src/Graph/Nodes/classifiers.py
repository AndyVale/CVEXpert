from Graph.state import CVEClassifierState

class CVENoRagClassifierNode:
    def __init__(self, 
                 model, 
                 labels_descriptions: dict):

        self.labels_descriptions = labels_descriptions
        self.all_labels = list(labels_descriptions.keys())

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
        try:
            cve_id = state.get("cve_id", "Unknown")
            prompt = self._get_prompt(cve_id)
            result = self.struct_model.invoke(prompt)
            
            labels = result.get("labels", ["NONE"])
            return {**state,
                    "cve_labels": labels}

        except Exception as e:
            return {**state,
                    "cve_labels": ["NONE"]}

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

        if not rag_content:
            return {**state, "cve_labels": ["NONE"], "labels_motivation": {"NONE": "No data"}, "labels_confidence": {"NONE": 0.0}}

        print(f"Classifying {cve_id} (Self-Consistency: {self.total_runs} runs)...")

        label_counts = {}
        label_motivations = {}
        prompt = self._get_prompt(cve_id, rag_content)

        try:
            for _ in range(self.total_runs):
                result = self.struct_model.invoke(prompt)
                items = result.get("classifications", [])
                
                # Use a set to track labels found in THIS specific run (avoid double counting per run)
                seen_in_run = set()
                
                for item in items:
                    lbl = item.get("label")
                    if not lbl: continue
                    
                    # Store the first valid motivation found for this label
                    if lbl not in label_motivations:
                        label_motivations[lbl] = item.get("motivation", "No motivation provided")
                    
                    if lbl not in seen_in_run:
                        seen_in_run.add(lbl)
                
                # Update global frequency counts
                for lbl in seen_in_run:
                    if lbl not in label_counts:
                        label_counts[lbl] = 0
                    label_counts[lbl] += 1

            if not label_counts:
                return {**state, "cve_labels": ["NONE"], "labels_motivation": {"NONE": "Model returned empty"}, "labels_confidence": {"NONE": 0.0}}

            # Calculate confidence: Occurrences / Total Runs
            final_confidence = {}
            for lbl, count in label_counts.items():
                final_confidence[lbl] = count / self.total_runs

            return {**state,
                    "cve_labels": list(label_counts.keys()),
                    "labels_motivation": label_motivations,
                    "labels_confidence": final_confidence}

        except Exception as e:
            print(f"Classification error for {cve_id}: {e}")
            return {**state,
                    "cve_labels": ["NONE"],
                    "labels_motivation": {"NONE": str(e)},
                    "labels_confidence": {"NONE": 0.0}}
        
class HierarchicalClassifierNode:
    """
    A LangGraph node that classifies a CVE hierarchically.
    It dynamically adjusts the prompt and allowed labels based on the 
    previous step's output (traversing the tree), and injects past 
    decisions to maintain context and coherence.
    """

    def __init__(self, model, full_label_tree: dict, flatten_tree:dict):
        self.model = model
        self.full_label_tree = full_label_tree
        # Flatten tree for O(1) access to descriptions and children
        self.flat_map = flatten_tree

    def _get_candidates(self, state) -> list[str]:
        """Determine which labels can be selected in this step."""
        current_labels = state.get("cve_labels", [])
        new_labels = state.get("new_labels", [])

        # If no labels assigned yet, start with Root Nodes
        if not current_labels:
            return list(self.full_label_tree.keys())
        
        # Otherwise, get children of the labels found in the LAST step
        candidates = []
        for label in new_labels:
            if label in self.flat_map:
                candidates.extend(self.flat_map[label]["children"])
        return candidates

    def _get_prompt(self, cve_id: str, rag_content: str, candidates: list[str], past_decisions_str: str) -> str:
        # Build description string with dynamic hints for children
        label_lines = []
        for c in candidates:
            desc = self.flat_map[c]['description']
            children = self.flat_map[c].get("children", [])
            line = f"* {c}: {desc}"
            if children:
                children_str = ", ".join(children)
                line += f" (Includes sub-types: {children_str})"
            label_lines.append(line)

        labels_desc_str = '\n'.join(label_lines)

        return f"""You are a Security Research Assistant specialized in vulnerability classification.

OBJECTIVE:
Assign the most accurate security labels to the given CVE based on the evidence provided.

CONTEXT ON DATA SOURCES:
1. PRIMARY SOURCE (NVD): This is the official high-level summary. Use this to identify the general scope.
2. SECONDARY SOURCES (Technical Summaries): These are distillations of external advisories and exploit details. Use these to find specific technical behaviors, root causes, and attack vectors that might be missing from the NVD text.

PREVIOUS CLASSIFICATIONS (Context):
You have already assigned the following parent labels to this CVE:
{past_decisions_str}
Ensure your new sub-category selections are logically consistent with these previous choices.

AVAILABLE LABELS FOR THIS STEP:
{labels_desc_str}

VULNERABILITY DATA (ID: {cve_id}):
{rag_content}

ASSIGNMENT STEPS:
1. Analyze the Primary Source for the main vulnerability impact.
2. Evaluate the Secondary Sources for technical specifics (e.g., specific code injection methods, memory management issues).
3. Select labels where the technical description matches the label definition and its included sub-types.
4. Select all labels that are relevant to {cve_id}.
5. For each selected label, you must extract a direct quote from the data sources that explains why the label matches. It must follow this exact format: "Reference-ID": "citation from reference".
6. If the information is insufficient to match any specific category, select the special label "NONE".

OUTPUT REQUIREMENTS:
- If NO technical evidence matches any of the available labels, or if the evidence is too ambiguous, select "NONE".
- Do not guess. If the text is too vague to decide between the available options, select "NONE".
- Return a structured object containing the 'label' and 'motivation', if you plan to return "NONE" add a brief motivation such as "Not enough information".
"""

    def __call__(self, state) -> dict:
        cve_id = state.get("cve_id", "Unknown")
        rag_content = state.get("rag", "")
        
        candidates = self._get_candidates(state)
        if not candidates:
            return {**state, "new_labels": []}

        current_labels = state.get("cve_labels",[])
        current_motivations = state.get("labels_motivation", {})
        if current_labels:
            past_decisions_list =[f"- {lbl}: {current_motivations.get(lbl, '')}" for lbl in current_labels]
            past_decisions_str = "\n".join(past_decisions_list)
        else:
            past_decisions_str = "None (This is the first classification step at the root level)."

        output_schema = {
            "title": "CVEClassification",
            "type": "object",
            "properties": {
                "classifications": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "label": {"type": "string", "enum": candidates + ["NONE"]},
                            "motivation": {"type": "string", "description": "The justification for this label."}
                        },
                        "required": ["label", "motivation"]
                    },
                    "minItems": 1,
                }
            },
            "required": ["classifications"],
        }

        struct_model = self.model.with_structured_output(output_schema)

        try:
            prompt = self._get_prompt(cve_id, rag_content, candidates, past_decisions_str)
            result = struct_model.invoke(prompt)
            
            raw_classifications = result.get("classifications", [])
            
            found_labels = []
            motivations = current_motivations.copy()
            all_labels = current_labels.copy()

            for item in raw_classifications:
                lbl = item.get("label")
                if lbl == "NONE" and len(all_labels) > 0:
                    print(f"Warning: NONE was given but {all_labels} are provided")
                    continue
                found_labels.append(lbl)
                all_labels.append(lbl)
                motivations[lbl] = item.get("motivation", "No motivation provided")

            return {
                **state,
                "cve_labels": all_labels,
                "labels_motivation": motivations,
                "new_labels": found_labels
            }

        except Exception as e:
            print(f"Error in hierarchical step: {e}")
            return {**state, "new_labels": []}