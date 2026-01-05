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
from Config.const import CHAT_MODEL, SUMMARIZER_MODEL, CVE_TEST, LABELS_DESCRIPTIONS, REF_MAX, OUTPUT_SCHEMA, ALL_LABELS
from Utility.summarizer import summarize_reference
from Evaluator.scores import *

REQUEST_DELAY = 1.5
OLLAMA = "ollama"
CHAT_MODEL_TEMP = 0.2
NUMBER_OF_EVALUATIONS = 1

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

        summary = summarize_reference(extracted, SUMMARIZER_MODEL)

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
    labels_and_descriptions = '\n'.join([f"* {k}: {v}" for k, v in LABELS_DESCRIPTIONS.items()])
    query = f"""
You are an AI security classification assistant.

You are given information about a Common Vulnerability and Exposure (CVE), including its official description and summarized content from external references.
Your task is to determine which security categories (labels) accurately describe the vulnerability.

A label should be selected only if the vulnerability clearly and explicitly involves that behavior or attack class.
Do not infer, assume, or speculate.
If there is insufficient evidence that a label applies, do not select it.
Multiple labels may apply if the vulnerability clearly involves more than one category.

Below is the list of supported labels and their definitions:

{labels_and_descriptions}

CVE identifier:
{state['cve_id']}

Information available for classification:
{state['rag']}

Classification rules (IMPORTANT):
- You must choose labels only from the predefined list provided.
- Do not invent new labels or output free text.
- Select only labels that are clearly supported by the provided information.
- If none of the labels apply, explicitly indicate this by returning the special label `NONE`.
- If labels apply, return all applicable labels.

Output rules:
- You must return a structured output containing a single field:
  - `labels`: an array of strings.
- Each element in `labels` must be a valid label from the predefined list or the special value `NONE`.
- Do not include explanations, reasoning, or any additional fields.

Allowed labels:
{ALL_LABELS}

"""
    structured_model = chat_model.with_structured_output(OUTPUT_SCHEMA)
    result = structured_model.invoke(query) # change function here
    
    os.system(f"ollama stop {CHAT_MODEL}")

    return {**state, "output": result["labels"]}

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
            "cves": {},
            "aggregated_scores": {}
        }

        all_y_true = []
        all_y_pred = []

        for cve, expected_labels in CVE_TEST.items():
            print(f"Analyzing {cve}")
            state = pipeline.invoke({"cve_id": cve})
            predicted_labels = state["output"]

            # store per-CVE scores
            individual_scores = compute_individual_scores(expected_labels, predicted_labels, ALL_LABELS)

            log["cves"][cve] = {
                "description": state["references"][0],
                "references": state.get("_reference_objects", []),
                "rag_input": state["rag"],
                "classification_output": predicted_labels,
                "individual_scores": individual_scores
            }

            with open(output_file, "w") as f:
                json.dump(log, f, indent=2)

            print(f"Logs were updated \n - {os.path.abspath(output_file)}")
            all_y_true.append(expected_labels)
            all_y_pred.append(predicted_labels)

        # grouped scores after all CVEs
        grouped_scores = compute_grouped_scores(all_y_true, all_y_pred, ALL_LABELS)
        log["aggregated_scores"] = grouped_scores