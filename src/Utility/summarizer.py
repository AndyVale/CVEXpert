import os

from Config.const import SUMMARIZER_MODEL
from langchain.chat_models import init_chat_model

from dotenv import load_dotenv
load_dotenv(".env")
VAST_HOST = os.getenv('VAST_HOST')
OPEN_BUTTON_TOKEN = os.getenv('OPEN_BUTTON_TOKEN')

def summarize_reference(text_to_summarize: str, summarizer_model = SUMMARIZER_MODEL):
    """
    Summarize a NVD-CVE reference text, keeping only the core vulnerability information.
    The input contains "..." placeholders representing removed irrelevant content.
    """
    
    prompt = f"""
You are a specialized cybersecurity analyst. Your task is to process a "filtered" extraction from a web page linked to a CVE (Common Vulnerabilities and Exposures).

CONTEXT FOR THE INPUT:
- The text below is not a full page. It is a sequence of highly relevant snippets.
- The symbol "..." indicates where irrelevant content (like ads, navigation, or boilerplate) has been removed.
- Your goal is to bridge these snippets into a single, cohesive technical summary, ignoring the gaps.

TASK:
1. Determine if the text contains specific technical evidence of a vulnerability (e.g., a bug description, a PoC, affected versions, or an advisory).
2. If related, create a summary that:
   - Preserves all technical keywords (e.g., "buffer overflow", "null pointer", "CVE-XXXX").
   - Identifies the affected software and version.
   - Describes the root cause and the impact.
   - Maintains the exact semantic meaning of the source.

CONSTRAINTS:
- Use 3 to 6 sentences.
- Use a professional, dry, technical tone.
- If the remaining text is too fragmented to identify a specific vulnerability, mark `is_cve_related` as false.

OUTPUT FORMAT:
Return a JSON object with:
- `is_cve_related`: (boolean)
- `summary`: (string)

EXTRACTED TEXT TO ANALYZE:
---
{text_to_summarize}
---
"""

    json_schema = {
        "title": "cve_summarizer_output",
        "description": "Schema for summarizing CVE related texts",
        "type": "object",
        "properties": {
            "is_cve_related": {"type": "boolean"},
            "summary": {"type": "string"}
        },
        "required": ["is_cve_related", "summary"]
    }

    model = init_chat_model(
        model = summarizer_model,
        model_provider="openai",
        api_key= OPEN_BUTTON_TOKEN,
        base_url=f"http://{VAST_HOST}/v1",
    )

    struct_model = model.with_structured_output(json_schema)

    try:
        response = struct_model.invoke(prompt)
        if response["is_cve_related"]:
            return response["summary"].strip()
    except Exception as e:
        print(f"Error during structured summarization: {e}")
    
    return ""