from Graph.state import CVEClassifierState
import json

class CVENoRagClassifierNode:
    def __init__(self, 
                 model, 
                 labels_descriptions: dict,
                 prompt_func):

        self.labels_descriptions = labels_descriptions
        self.prompt_func = prompt_func
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

    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        try:
            cve_id = state.get("cve_id", "Unknown")
            prompt = self.prompt_func(cve_id, self.labels_descriptions, self.all_labels)
            result = self.struct_model.invoke(prompt)
            
            labels = result.get("labels", ["NONE"])
            return {**state,
                    "cve_labels": labels}

        except Exception as e:
            raise RuntimeError(f"Classification error for {cve_id}: {e}") from e

class CVEClassifierNode:
    """
    A LangGraph node that classifies a CVE into security categories using an LLM.

    This node takes the aggregated technical context (RAG) and the full vulnerability 
    tree. It instructs the LLM to select labels hierarchically (i.e., selecting a child 
    requires selecting all its ancestors).

    Attributes:
        full_label_tree (dict): The complete hierarchical tree of vulnerabilities.
        all_labels (list): A flat list of all valid label strings, including "NONE".
        struct_model: The LLM instance configured with a structured output schema.
    """

    def __init__(self, 
                 model, 
                 full_label_tree: dict,
                 all_tree_labels: list,
                 prompt_func):
        """
        Initializes the CVEClassifierNode with a pre-initialized LLM and the label tree.

        Args:
            model: The LLM instance used for classification.
            full_label_tree (dict): The hierarchical tree of security labels.
            all_tree_labels (list): Flat list of all valid labels (including "NONE").
        """
        self.full_label_tree = full_label_tree
        self.all_labels = all_tree_labels
        self.prompt_func = prompt_func

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

        print(f"Classifying {cve_id} (Hierarchical Mode)...")
        
        try:
            prompt = self.prompt_func(cve_id, rag_content, self.full_label_tree, self.all_labels)
            result = self.struct_model.invoke(prompt)
            
            # Ensure we return the labels field from the JSON response
            labels = result.get("labels", ["NONE"])
            return {**state,
                    "cve_labels": labels}

        except Exception as e:
            print(f"Classification error for {cve_id}: {e}")
            raise RuntimeError(f"Classification error for {cve_id}: {e}") from e
        
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
                 labels_descriptions: dict,
                 prompt_func):
        """
        Initializes the CVEClassifierNode with a pre-initialized LLM.

        Args:
            model: The LLM instance used for classification (without structured output).
            labels_descriptions (dict): Definitions of the security labels.
        """
        self.labels_descriptions = labels_descriptions
        self.prompt_func = prompt_func
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
            prompt = self.prompt_func(cve_id, rag_content, self.labels_descriptions, self.all_labels)
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
            raise RuntimeError(f"Classification error for {cve_id}: {e}") from e
        
class CVESelfConsistentClassifierNode:
    """
    A LangGraph node that classifies a CVE using a self-consistency approach.
    Confidence is calculated as the frequency of a label appearing across multiple runs.
    """

    def __init__(self, 
                 model, 
                 labels_descriptions: dict,
                 prompt_func,
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
        self.prompt_func = prompt_func
        
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
    
    def __call__(self, state: CVEClassifierState) -> CVEClassifierState:
        cve_id = state.get("cve_id", "Unknown")
        rag_content = state.get("rag", "")

        if not rag_content:
            return {**state, "cve_labels": ["NONE"], "labels_motivation": {"NONE": "No data"}, "labels_confidence": {"NONE": 0.0}}

        print(f"Classifying {cve_id} (Self-Consistency: {self.total_runs} runs)...")

        label_counts = {}
        label_motivations = {}
        prompt = self.prompt_func(cve_id, rag_content, self.labels_descriptions, self.all_labels)

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
            raise RuntimeError(f"Classification error for {cve_id}: {e}") from e
        
class HierarchicalClassifierNode:
    """
    A LangGraph node that classifies a CVE hierarchically.
    It dynamically adjusts the prompt and allowed labels based on the 
    previous step's output (traversing the tree), and injects past 
    decisions to maintain context and coherence.
    """

    def __init__(self, model, full_label_tree: dict, flatten_tree:dict, prompt_func):
        self.model = model
        self.full_label_tree = full_label_tree
        # Flatten tree for O(1) access to descriptions and children
        self.flat_map = flatten_tree
        self.prompt_func = prompt_func

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
            prompt = self.prompt_func(cve_id, rag_content, candidates, past_decisions_str, self.flat_map)
            result = struct_model.invoke(prompt)
            
            raw_classifications = result.get("classifications", [])
            
            found_labels = []
            motivations = current_motivations.copy()
            all_labels = current_labels.copy()

            for item in raw_classifications:
                lbl = item.get("label")
                if lbl == "NONE":
                    # If we already have some labels, we can just ignore NONE.
                    # If it's the very first step, found_labels remains empty and we stop.
                    if len(all_labels) > 0:
                        print(f"Warning: NONE was given but {all_labels} are provided")
                    continue
                
                # STRICT VALIDATION: Prevent infinite loops if LLM hallucinates an old label
                if lbl not in candidates:
                    print(f"Warning: Model hallucinated label '{lbl}' not in candidates. Ignoring.")
                    continue
                    
                # Avoid duplicates just in case
                if lbl in all_labels:
                    print(f"Warning: Label '{lbl}' already present. Ignoring duplicate.")
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
            raise RuntimeError(f"Classification error for {cve_id}: {e}") from e