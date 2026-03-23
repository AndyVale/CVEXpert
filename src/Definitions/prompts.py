import json
from typing import List, Dict, Any

"""
This file contains the prompts used by the system.
Functions defined here generate specific LLM prompts.
"""

# =============================================================================
# CLASSIFIER PROMPTS
# =============================================================================

# Prompt used in CVENoRagClassifierNode
def get_cve_no_rag_classifier_prompt(cve_id: str, labels_descriptions: Dict[str, str], all_labels: List[str]) -> str:
    """
    Generates the prompt for CVENoRagClassifierNode.
    
    Args:
        cve_id (str): The CVE identifier.
        labels_descriptions (Dict[str, str]): A mapping of label names to their descriptions.
        all_labels (List[str]): All valid labels to output.
        
    Returns:
        str: The generated prompt.
    """
    labels_and_descriptions = '\n'.join([f"* {k}: {v}" for k, v in labels_descriptions.items()])
        
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
{all_labels}
"""

# Prompt used in CVEClassifierNode
def get_cve_classifier_prompt(cve_id: str, rag_content: str, full_label_tree: Dict[str, Any], all_labels: List[str]) -> str:
    """
    Generates the prompt for CVEClassifierNode.
    
    Args:
        cve_id (str): The CVE identifier.
        rag_content (str): The RAG extracted content to analyze.
        full_label_tree (Dict[str, Any]): The hierarchical tree of security labels.
        all_labels (List[str]): All valid labels to output.
        
    Returns:
        str: The generated prompt.
    """
    tree_str = json.dumps(full_label_tree, indent=2)
        
    return f"""You are a Security Research Assistant specialized in vulnerability classification.

OBJECTIVE:
Assign the most accurate security labels to the given CVE based on the evidence provided.

CONTEXT ON DATA SOURCES:
1. PRIMARY SOURCE (NVD): This is the official high-level summary. Use this to identify the general scope.
2. SECONDARY SOURCES (Technical Summaries): These are distillations of external advisories and exploit details. Use these to find specific technical behaviors, root causes, and attack vectors.

VULNERABILITY TREE (HIERARCHY):
The labels are organized in a strict hierarchical tree structure:
{tree_str}

VULNERABILITY DATA (ID: {cve_id}):
{rag_content}

ASSIGNMENT STEPS & RULES:
1. Analyze the data sources to find the specific vulnerability type.
2. Map the vulnerability to the specific nodes in the VULNERABILITY TREE.
3. HIERARCHY RULE (CRITICAL): If you select a specific sub-category (child), you MUST ALSO select ALL of its parent categories up to the root.
   - Example 1: If the vulnerability is 'SQLi', you MUST output the entire path:["InputValidation", "InjectionFlaws", "SQLi"].
   - Example 2: If the vulnerability is 'BufferOverflow', you MUST output the entire path: ["Memory", "MemoryCorruption", "BufferOverflow"].
   - INVALID Example: Outputting ONLY["BufferOverflow"] is strictly forbidden because its parent labels ("Memory", "MemoryCorruption") are missing.
4. If the data is vague and you can only identify the high-level category (e.g., 'InputValidation' or 'AccessControl'), it is perfectly acceptable to select ONLY the parent without selecting any children.
5. If the information is insufficient to match any category, select the special label "NONE".

OUTPUT REQUIREMENTS:
- Provide a structured JSON object with a single field "labels" containing an array of strings.
- Ensure every label is selected directly from the allowed list.

ALLOWED LABELS:
{all_labels}
"""

# Prompt used in CVEConfidenceClassifierNode
def get_cve_confidence_classifier_prompt(cve_id: str, rag_content: str, labels_descriptions: Dict[str, str], all_labels: List[str]) -> str:
    """
    Generates the prompt for CVEConfidenceClassifierNode.
    
    Args:
        cve_id (str): The CVE identifier.
        rag_content (str): The RAG extracted content to analyze.
        labels_descriptions (Dict[str, str]): A mapping of label names to their descriptions.
        all_labels (List[str]): All valid labels to output.
        
    Returns:
        str: The generated prompt.
    """
    labels_and_descriptions = '\n'.join([f"* {k}: {v}" for k, v in labels_descriptions.items()])
        
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
{all_labels}
"""

# Prompt used in CVESelfConsistentClassifierNode
def get_cve_self_consistent_classifier_prompt(cve_id: str, rag_content: str, labels_descriptions: Dict[str, str], all_labels: List[str]) -> str:
    """
    Generates the prompt for CVESelfConsistentClassifierNode.
    
    Args:
        cve_id (str): The CVE identifier.
        rag_content (str): The RAG extracted content to analyze.
        labels_descriptions (Dict[str, str]): A mapping of label names to their descriptions.
        all_labels (List[str]): All valid labels to output.
        
    Returns:
        str: The generated prompt.
    """
    labels_and_descriptions = '\n'.join([f"* {k}: {v}" for k, v in labels_descriptions.items()])
        
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
{all_labels}
"""

# Prompt used in HierarchicalClassifierNode
def get_hierarchical_classifier_prompt(cve_id: str, rag_content: str, candidates: List[str], past_decisions_str: str, flat_map: Dict[str, Any]) -> str:
    """
    Generates the prompt for HierarchicalClassifierNode.
    
    Args:
        cve_id (str): The CVE identifier.
        rag_content (str): The RAG extracted content to analyze.
        candidates (List[str]): Allowed label candidates for this step.
        past_decisions_str (str): Previous parent label decisions as a string.
        flat_map (Dict[str, Any]): Flattened tree representing labels and their possible children.
        
    Returns:
        str: The generated prompt.
    """
    label_lines = []
    for c in candidates:
        desc = flat_map[c]['description']
        children = flat_map[c].get("children", [])
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

# Prompt used in CVEClassifierNode for Hierarchical Classification
def get_cve_classifier_prompt_hierarchical(cve_id: str, rag_content: str, full_label_tree: dict, all_labels: list) -> str:
    tree_str = json.dumps(full_label_tree, indent=2)
    return f"""You are a Security Research Assistant specialized in vulnerability classification.

OBJECTIVE:
Assign the most accurate security labels to the given CVE based on the evidence provided.

CONTEXT ON DATA SOURCES:
1. PRIMARY SOURCE (NVD): This is the official high-level summary. Use this to identify the general scope.
2. SECONDARY SOURCES (Technical Summaries): These are distillations of external advisories and exploit details. Use these to find specific technical behaviors, root causes, and attack vectors.

VULNERABILITY TREE (HIERARCHY):
The labels are organized in a strict hierarchical tree structure:
{tree_str}

VULNERABILITY DATA (ID: {cve_id}):
{rag_content}

ASSIGNMENT STEPS & RULES:
1. Analyze the data sources to find the specific vulnerability type.
2. Map the vulnerability to the specific nodes in the VULNERABILITY TREE.
3. HIERARCHY RULE (CRITICAL): If you select a specific sub-category (child), you MUST ALSO select ALL of its parent categories up to the root.
   - Example 1: If the vulnerability is 'SQLi', you MUST output the entire path:["InputValidation", "InjectionFlaws", "SQLi"].
   - Example 2: If the vulnerability is 'BufferOverflow', you MUST output the entire path: ["Memory", "MemoryCorruption", "BufferOverflow"].
   - INVALID Example: Outputting ONLY["BufferOverflow"] is strictly forbidden because its parent labels ("Memory", "MemoryCorruption") are missing.
4. If the data is vague and you can only identify the high-level category (e.g., 'InputValidation' or 'AccessControl'), it is perfectly acceptable to select ONLY the parent without selecting any children.
5. If the information is insufficient to match any category, select the special label "NONE".

OUTPUT REQUIREMENTS:
- Provide a structured JSON object with a single field "labels" containing an array of strings.
- Ensure every label is selected directly from the allowed list.

ALLOWED LABELS:
{all_labels}
"""

# =============================================================================
# SUMMARIZER PROMPTS
# =============================================================================

# Prompt used in ReferenceSummarizerNode
def get_reference_summarizer_prompt(text: str, labels_descriptions: Dict[str, str]) -> str:
    """
    Generates the prompt for ReferenceSummarizerNode.
    
    Args:
        text (str): Extracted text snippets to analyze.
        labels_descriptions (Dict[str, str]): A mapping of security labels to include in the prompt.
        
    Returns:
        str: The generated prompt.
    """
    labels_str = '\n'.join([f"* {k}: {v}" for k, v in labels_descriptions.items()])
        
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

# Prompt used in CVEAwareSummarizerNode
def get_cve_aware_summarizer_prompt(text: str, cve_id: str, nvd_description: str, labels_descriptions: Dict[str, str]) -> str:
    """
    Generates the prompt for CVEAwareSummarizerNode.
    
    Args:
        text (str): Extracted text snippets to analyze.
        cve_id (str): The CVE identifier.
        nvd_description (str): Official description from the NVD.
        labels_descriptions (Dict[str, str]): A mapping of security labels to include in the prompt.
        
    Returns:
        str: The generated prompt.
    """
    labels_str = '\n'.join([f"* {k}: {v}" for k, v in labels_descriptions.items()])
        
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