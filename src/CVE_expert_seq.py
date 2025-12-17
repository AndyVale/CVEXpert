import os
import json
from typing_extensions import TypedDict

import requests
import random
import time
from datetime import datetime

from langchain.chat_models import init_chat_model
from langchain_core.runnables import RunnableLambda, RunnableSequence

from UrlRetriver.url_retriver import extract_main_text_from_url
from Config.const import CHAT_MODEL, SUMMARIZER_MODEL, CVE_TEST, LABELS_DESCRIPTIONS, REF_MAX
from Utility.summarizer import summarize

REQUEST_DELAY = 1.5
OLLAMA = "ollama"
CHAT_MODEL_TEMP = 0.2
NUMBER_OF_EVALUATIONS = 5

random.seed(42)

class CVEClassifierState(TypedDict):
    cve_id: str
    references: list[str]
    rag: str
    output: str


def nvd_caller(state: CVEClassifierState):
    cve_id = state["cve_id"]
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}

    resp = requests.get(url, params=params, timeout=20)

    if resp.status_code != 200:
        return {**state, "references": [f"Error calling NVD API: {resp.text}"]}

    data = resp.json()

    try:
        vuln = data["vulnerabilities"][0]["cve"]
        description = vuln["descriptions"][0]["value"]
        refs = [ref.get("url") for ref in vuln.get("references", [])]
        return {**state, "references": [description] + refs}

    except Exception as e:
        return {**state, "references": [f"Parsing error: {e}"]}

def summary_extractor(state: CVEClassifierState):
    description = state["references"][0]
    urls = state["references"][1:].copy()
    random.shuffle(urls)

    reference_objs = []

    # Since some CVEs has hundreds of references, 
    # we limit up to a given number 
    for ref in urls[:REF_MAX]:
        # TODO: we might check if we are calling the same 
        # domain instead of doing this at each iteration:
        time.sleep(REQUEST_DELAY)

        # Extract the text using "Trafilatura libary"
        extracted = extract_main_text_from_url(ref)

        if not extracted:
            continue

        summary = summarize(extracted, SUMMARIZER_MODEL)

        reference_objs.append({
            "url": ref,
            "extracted_text": extracted,
            "summary": summary
        })

    summarized_references = [description] + [r["summary"] for r in reference_objs]

    return {
        **state,
        "summarized_references": summarized_references,
        "_reference_objects": reference_objs  # for JSON logging
    }

def formatter(state: CVEClassifierState):
    rag_text = "".join([f"{i+1}. {x}\n" 
                        for i, x in 
                        enumerate(state["summarized_references"])])
    
    return {**state, "rag": rag_text}

def classifier(state: CVEClassifierState):
    chat_model = init_chat_model(
            model=CHAT_MODEL,
            model_provider=OLLAMA,
            temperature=CHAT_MODEL_TEMP,
        )
    
    print(f"{CHAT_MODEL} instantiated")

    query = f"""
You are an AI security classifier. 
Your job is to analyze CVE descriptions, metadata, and external references, and classify the vulnerability using ONLY a predefined set of labels.
A label applies if the vulnerability clearly involves that behavior or attack class.
If in doubt, do not select it. Multiple labels may apply.

Below is the list of supported labels and their meanings:

{'\n'.join([f"* {k}: {v}" for k, v in LABELS_DESCRIPTIONS.items()])}

Now classify the Common Vulnerability known as {state['cve_id']}.

Here you have official description and various summarization of references about {state['cve_id']}:

{state['rag']}

Your task is to return only labels from the following list, without inventing new ones and selecting only the ones that apply given the references above.

The list of labels tha you can use:

{[l for l in LABELS_DESCRIPTIONS.keys()]}

If you think no lables apply, return the special label "NONE".
You can, and you should, decide more than ore label. But the most important thing is that they match the CVE.

Return *only* valid labels or "NONE".
Write your labels below according to the format ["label1", "label2", "label3"...]:
"""
    answer = chat_model.invoke(query)
    os.system(f"ollama stop {CHAT_MODEL}")

    return {**state, "output": answer.content}

pipeline = RunnableSequence(
    RunnableLambda(nvd_caller),
    RunnableLambda(summary_extractor),
    RunnableLambda(formatter),
    RunnableLambda(classifier),
)


if __name__ == "__main__":
    for i in range(NUMBER_OF_EVALUATIONS):
        os.chdir(os.path.join(os.path.pardir, os.path.pardir, os.path.dirname(__file__)))
        print(f"Working directory : -{os.getcwd()}")

        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs("logs",exist_ok=True)

        output_file = os.path.join("logs",f"run_{run_id}.json")

        log = {
            "pipeline_metadata": {
                "run_id": run_id,
                "models": {
                    "chat_model": CHAT_MODEL,
                    "summarizer_model": SUMMARIZER_MODEL
                },
                "labels_schema": LABELS_DESCRIPTIONS
            },
            "cves": {}
        }

        for cve in CVE_TEST:
            print(f"Analyzing {cve}")

            state = pipeline.invoke({"cve_id": cve})

            print(f"Pipeline executed")

            log["cves"][cve] = {
                "description": state["references"][0],
                "references": state.get("_reference_objects", []),
                "rag_input": state["rag"],
                "classification_output": state["output"]
            }

            with open(output_file, "w") as f:
                json.dump(log, f, indent=2)

            print(f"Logs were updated \n - {os.path.abspath(output_file)}")