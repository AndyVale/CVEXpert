from ollama import Client
import json

def summarize_reference(text_to_summarize: str, model: str):
    """
    Summarize a NVD-CVE reference text, keeping only the core vulnerability information.
    """
    
    prompt = f"""
You are a cybersecurity analysis and summarization assistant.

You will receive text extracted from an external reference linked from the National Vulnerability Database (NVD).
This text may contain a mix of useful security information and unrelated content such as website navigation, advertisements, generic documentation, blog posts, or unrelated GitHub material.

Your task has two parts:

1. Determine whether the provided text explicitly describes a software vulnerability or a security issue related to a CVE.
   - The text must clearly mention a vulnerability, security flaw, or weakness, along with at least some technical details (e.g., vulnerability type, impact, affected component or version, or root cause).
   - If the text does not clearly describe a vulnerability or security issue, it is considered not CVE-related.

2. If the text is CVE-related, produce a concise summary of the vulnerability.
   - The summary must include only information explicitly stated in the text.
   - Focus on the vulnerability type, impact, affected components or versions, and underlying cause or mechanism when available.
   - Do not speculate, infer missing details, or add external context.
   - Use a neutral tone and plain sentences.
   - The summary should be concise and human-readable, ideally limited to three to six sentences.
   - Do not include introductions, explanations, headings, lists, or formatting.

Output rules (IMPORTANT):
- You must always provide a structured output with the following fields:
  - `is_cve_related`: a boolean indicating whether the text describes a vulnerability.
  - `summary`: a string containing the vulnerability summary.
- If `is_cve_related` is true, the `summary` must contain only the vulnerability summary text.

Below is the extracted reference text:

{text_to_summarize}
"""

    c = Client()

    response = c.generate(
        model=model,
        prompt=prompt,
        format={
            "type": "object",
            "properties": {
                "is_cve_related": {"type": "boolean"},
                "summary": {"type": "string"}
            },
            "required": ["is_cve_related", "summary"]
        }
    )

    try:
        parsed = json.loads(response.response)
    except Exception as e:
        print(f"Error in the summary:\n\t{e}")
        return ""
        
    return parsed["summary"].strip() if parsed["is_cve_related"] else ""
