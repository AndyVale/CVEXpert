import os
import json
from typing_extensions import TypedDict

import requests
import random
import time
from datetime import datetime

from langchain.chat_models import init_chat_model
from langchain_core.runnables import RunnableLambda, RunnableSequence

from UrlRetriver.url_retriver import get_filtered_content_from_url, extract_main_text_from_url
from UrlRetriver.filters import filter_with_cross_encoder, cosine_filter
from Config.const import CHAT_MODEL, SUMMARIZER_MODEL, CVE_TEST, LABELS_DESCRIPTIONS, REF_MAX, NOT_NONE_REF_MAX, OUTPUT_SCHEMA, ALL_LABELS
from Utility.summarizer import summarize_reference
from Evaluator.scores import *

from dotenv import load_dotenv
load_dotenv(".env")
VAST_HOST = os.getenv('VAST_HOST')
OPEN_BUTTON_TOKEN = os.getenv('OPEN_BUTTON_TOKEN')

REQUEST_DELAY = .5
CHAT_MODEL_TEMP = 0.2
NUMBER_OF_EVALUATIONS = 4

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
    urls = state["references"][1:].copy()
    random.shuffle(urls)

    reference_objs = []

    # Since some CVEs has hundreds of references, 
    # we limit up to a given number
    c = 0
    for ref in urls:
        # TODO: we might check if we are calling the same 
        # domain instead of doing this at each iteration:
        time.sleep(REQUEST_DELAY)

        RELEVANCE_QUERY = "What type of vulnerability is it?"

        # Extract the text using "Trafilatura libary"
        filtered_chunks, chunks = get_filtered_content_from_url(ref, RELEVANCE_QUERY,  6, filter_with_cross_encoder)

        extracted = '\n\n'.join(filtered_chunks)

        print("Extracted chars:",len(extracted))
        if not extracted:
            continue

        summary = summarize_reference(extracted, SUMMARIZER_MODEL)

        print("Summary length:",len(summary))

        reference_objs.append({
            "url": ref,
            "chunks" : chunks,
            "filtered_chunks" : filtered_chunks,
            "extracted_text": extracted,
            "summary": summary
        })
        
        if summary:
            c += 1
        if  c >= NOT_NONE_REF_MAX or len(reference_objs) >= REF_MAX:
            break

    summarized_references = [r["summary"] for r in reference_objs]

    return {
        **state,
        "summarized_references": summarized_references,
        "_reference_objects": reference_objs  # for JSON logging
    }

def formatter(state: CVEClassifierState):
    nvd_desc = state["references"][0]
    # External summaries are secondary, providing technical depth
    if state["summarized_references"]:
        ref_sections = []
        tech_references = [t_ref for t_ref in state["summarized_references"] if t_ref]
        for i, x in enumerate(tech_references):
            ref_sections.append(f"[Technical Insight from Reference {i+1}]\n{x}")
        references_text = "\n\n".join(ref_sections)
    else:
        references_text = "No additional technical references provided."

    rag_text = f"""--- PRIMARY SOURCE: NVD DESCRIPTION ---
{nvd_desc}

--- SECONDARY SOURCES: TECHNICAL SUMMARIES ---
{references_text}
"""
    return {**state, "rag": rag_text}

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
    
    try:
        structured_model = chat_model.with_structured_output(OUTPUT_SCHEMA)
        result = structured_model.invoke(query)
        return {**state, "output": result["labels"]}
    except Exception as e:
        print(f"Classification error: {e}")
        return {"labels": ["NONE"]}

pipeline = RunnableSequence(
    RunnableLambda(nvd_caller),
    RunnableLambda(summary_extractor),
    RunnableLambda(formatter),
    RunnableLambda(classifier),
)


if __name__ == "__main__":
    for i in range(NUMBER_OF_EVALUATIONS):
        os.chdir(os.path.dirname(__file__))
        os.chdir(os.path.pardir)
        print(f"Working directory : -{os.getcwd()}")

        run_id = datetime.now().strftime("%Y%m%d_%H%M%S_semantic_split")
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
        with open(output_file, "w") as f:
            json.dump(log, f, indent=2)

        print(f"Aggregated scores added to logs \n - {os.path.abspath(output_file)}")