from langchain.chat_models import init_chat_model
from Definitions.config import CHAT_MODEL, CHAT_MODEL_TEMP, VAST_HOST, OPEN_BUTTON_TOKEN
from Definitions.labels import LABELS_DESCRIPTIONS, ALL_LABELS
from Graph.state import CVEClassifierState

def classifier(state: CVEClassifierState):
    chat_model = init_chat_model(
        model= CHAT_MODEL,
        model_provider="openai",
        api_key= OPEN_BUTTON_TOKEN,
        base_url=f"http://{VAST_HOST}/v1",
        temperature=CHAT_MODEL_TEMP,
    )
    
    labels_and_descriptions = '\n'.join([f"* {k}: {v}" for k, v in LABELS_DESCRIPTIONS.items()])
    query = f"""You are a Security Research Assistant specialized in vulnerability classification.

OBJECTIVE:
Assign the most accurate security labels to the given CVE based on the evidence provided.

CONTEXT ON DATA SOURCES:
1. PRIMARY SOURCE (NVD): This is the official high-level summary. Use this to identify the general scope.
2. SECONDARY SOURCES (Technical Summaries): These are distillations of external advisories and exploit details. Use these to find specific technical behaviors, root causes, and attack vectors that might be missing from the NVD text.

SUPPORTED LABELS:
{labels_and_descriptions}

VULNERABILITY DATA (ID: {state['cve_id']}):
{state['rag']}

ASSIGNMENT STEPS:
1. Analyze the Primary Source for the main vulnerability impact.
2. Evaluate the Secondary Sources for technical specifics (e.g., specific code injection methods, memory management issues).
3. Select labels where the technical description matches the label definition.
4. If the information is insufficient to match any specific category, select the special label "NONE".

OUTPUT REQUIREMENTS:
- Provide a structured JSON object with a single field "labels" containing an array of strings.
- Ensure every label is selected directly from the list below.

ALLOWED LABELS:
{list(LABELS_DESCRIPTIONS.keys()) + ["NONE"]}
"""
    OUTPUT_SCHEMA = {
        "title": "CVEClassification",
        "type": "object",
        "properties": {
            "labels": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ALL_LABELS
                },
                "minItems": 1,
            }
        },
        "required": ["labels"],
    }

    try:
        structured_model = chat_model.with_structured_output(OUTPUT_SCHEMA)
        result = structured_model.invoke(query)
        return {**state, "output": result["labels"]}
    except Exception as e:
        print(f"Classification error: {e}")
        return {"labels": ["NONE"]}