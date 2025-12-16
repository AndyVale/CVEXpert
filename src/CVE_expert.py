from langgraph.graph import StateGraph, START, END
from langchain.chat_models import init_chat_model
import os
import requests
import random

import time

REQUEST_DELAY = 1.5

from UrlRetriver.url_retriver import extract_main_text_from_url
from Config.const import CHAT_MODEL, SUMMARIZER_MODEL, CVE_TEST, LABELS_DESCRIPTIONS, REF_MAX
from Utility.summarizer import summarize
from typing_extensions import TypedDict

random.seed(42)

class State(TypedDict):
    cve_id: str
    references: list[str]
    output: str
    rag: str

def instantiate_model(model = CHAT_MODEL, model_provider="ollama"):
    return init_chat_model(
        model=model,
        model_provider=model_provider,
        temperature=0.1,
    )

def references_extractor(state: State):
    cve_id = state['cve_id']
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "cveId": cve_id
    }

    headers = {}

    resp = requests.get(url, params=params, headers=headers, timeout=20)

    if resp.status_code != 200:
        return {"references": [f"Error calling NVD API: {resp.text}"]}

    data = resp.json()

    # Extract fields safely
    try:
        vuln = data["vulnerabilities"][0]["cve"]

        description = vuln["descriptions"][0]["value"]

        refs = []
        for ref in vuln.get("references", []):
            refs.append(ref.get("url"))

        return {
            "references": [description] + refs
        }

    except Exception as e:
        return {"references": [f"Parsing error: {e}"]}

def summary_extractor(state:State):
    summarized_references = [state['references'][0]] # include the description of nvd

    text_from_reference = []
    print("Extracting text from references...")
    for i, ref in enumerate(state['references'][1:]):
        time.sleep(REQUEST_DELAY)
        extracted_text = extract_main_text_from_url(ref)
        if extracted_text != '':
            text_from_reference.append(extracted_text)
        print(f"{i}-th reference of {len(state['references'][1:])} extracted...")
        if len(text_from_reference) > REF_MAX: break

    print(f"{len(text_from_reference)} valid textual references found")

    for i, ref in enumerate(random.sample(text_from_reference, min(REF_MAX, len(text_from_reference)))): 
        print(f"Summarizing {i}...")
        summarized_text = summarize(ref, SUMMARIZER_MODEL)
        summarized_references.append(summarized_text)
    
    return {"references" : summarized_references}

def formatter(state:State):
    return {"rag" : ''.join([f'{i+1}. {x}\n'for i, x in enumerate(state['references'])])}

def classifier(state:State):
    query = f"""
You are an AI security classifier. 
Your job is to analyze CVE descriptions, metadata, and external references, and classify the vulnerability using ONLY a predefined set of labels.
A label applies if the vulnerability clearly involves that behavior or attack class.
If in doubt, do not select it. Multiple labels may apply.

Below is the list of supported labels and their meanings:

{'\n'.join([f"* {k}: {v}" for k, v in LABELS_DESCRIPTIONS.items()])}

Now classify the Common Vulnerability known as {state['cve_id']}.

Here you have references and description excerpts about {state['cve_id']}:

{state['rag']}

Your task is to return only labels from the following list, without inventing new ones and selecting only the ones that apply given the references above.

The list of labels tha you can use:

{[l for l in LABELS_DESCRIPTIONS.keys()]}

If you think no lables apply, return the special label "NONE".
You can, and you should, decide more than ore label. But the most important thing is that they match the CVE.
"""
    print("-------------------------------",query,"-------------------------------")
    answer = chat_model.invoke(query)
    return {"output": answer.content}

if __name__ == "__main__":
    with open("output.md", "w") as f:
            f.write("")

    for cve in CVE_TEST:
        print(f"Analyzing {cve}")
        chat_model = instantiate_model(CHAT_MODEL)
        
        print("Graph building...")

        graph_builder = StateGraph(State)

        graph_builder.add_node("references_extractor", references_extractor)
        graph_builder.add_edge(START, "references_extractor")

        graph_builder.add_node("summary_extractor", summary_extractor)
        graph_builder.add_edge("references_extractor", "summary_extractor")

        graph_builder.add_node("formatter", formatter)
        graph_builder.add_edge("summary_extractor", "formatter")

        graph_builder.add_node("classifier", classifier)
        graph_builder.add_edge("formatter", "classifier")

        graph_builder.add_edge("classifier", END)

        graph = graph_builder.compile()
        
        print("Invoke...")
        state = graph.invoke({"cve_id":cve})

        to_write = f"""# {cve} - {CHAT_MODEL} - {SUMMARIZER_MODEL}
## Input:
{state['rag']}
        
## Output:
{state["output"]}
----------------------------

"""

        print("Writing results...")

        with open("output.md", "a") as f:
            f.write(to_write)

        os.system(f"ollama stop {CHAT_MODEL}")
        os.system(f"ollama stop {SUMMARIZER_MODEL}")

