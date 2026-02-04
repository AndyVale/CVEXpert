import os
import json

import random
from datetime import datetime
import langchain_core.runnables as lcr

from Definitions.const import CVE_TEST
from Definitions.config import CHAT_MODEL, SUMMARIZER_MODEL, OPEN_BUTTON_TOKEN, VAST_HOST
from Definitions.labels import LABELS_DESCRIPTIONS, ALL_LABELS

from Graph.Nodes.nvd import nvd_caller
from Graph.Nodes.scrapers import extract_md_trafilatura
from Graph.Nodes.chunkers import semantic_chunker
from Graph.Nodes.filters import CosineFilterNode
from Graph.Nodes.summarizers import ReferenceSummarizerNode
from Graph.Nodes.evaluators import *
from Graph.Nodes.formatters import formatter
from Graph.Nodes.classifiers import classifier

REQUEST_DELAY = .5
random.seed(42)

if __name__ == "__main__":
    NUMBER_OF_EVALUATIONS = 4
    random.seed(42)

    cosine_filter = CosineFilterNode(
        query="What type of vulnerability is it?",
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        threshold=0.3
    )

    summarizer = ReferenceSummarizerNode(
        model_name=SUMMARIZER_MODEL,
        api_key=OPEN_BUTTON_TOKEN,
        base_url=VAST_HOST,
        labels_descriptions=LABELS_DESCRIPTIONS,
    )

    pipeline = (
        lcr.RunnableLambda(nvd_caller)
        | extract_md_trafilatura    
        | semantic_chunker
        | cosine_filter
        | summarizer
        | classifier
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
            predicted_labels = state["cve_labels"]

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