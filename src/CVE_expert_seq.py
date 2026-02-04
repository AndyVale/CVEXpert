import os
import json

import random
from datetime import datetime
import langchain_core.runnables as lcr

from Definitions.const import CVE_TEST
from Definitions.config import CHAT_MODEL, SUMMARIZER_MODEL
from Definitions.labels import LABELS_DESCRIPTIONS, ALL_LABELS

from Graph.Nodes.nvd import nvd_caller
from Graph.Nodes.scrapers import extract_md_trafilatura
from Graph.Nodes.chunkers import semantic_chunker
from Graph.Nodes.filters import CosineFilterNode
from Graph.Nodes.summarizers import summarize_reference
from Graph.Nodes.evaluators import *
from Graph.Nodes.formatters import formatter
from Graph.Nodes.classifiers import classifier

REQUEST_DELAY = .5
random.seed(42)

"""def summary_extractor(state: CVEClassifierState):
    urls = state["references"][1:].copy()
    random.shuffle(urls)

    reference_objs = []

    # Since some CVEs has hundreds of references, 
    # we limit up to a given number
    c = 0
    for ref in urls:
        # domain instead of doing this at each iteration:
        time.sleep(REQUEST_DELAY)

        RELEVANCE_QUERY = "What type of vulnerability is it?"

        # Extract the text using "Trafilatura libary"
        filtered_chunks, chunks = [],[] #get_filtered_content_from_url(ref, RELEVANCE_QUERY,  6, filter_with_cross_encoder)

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
    }"""


if __name__ == "__main__":
    NUMBER_OF_EVALUATIONS = 4
    random.seed(42)

    cosine_filter = CosineFilterNode(
        query="What type of vulnerability is it?",
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        threshold=0.3
    )

    pipeline = (
        lcr.RunnableLambda(nvd_caller)
        | extract_md_trafilatura    
        | semantic_chunker
        | cosine_filter

    )

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