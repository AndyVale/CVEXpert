import os
import json

import random
from datetime import datetime
import langchain_core.runnables as lcr
from langchain_openai import OpenAIEmbeddings

from Definitions.const import CVE_TEST
from Definitions.config import CHAT_MODEL, CHAT_MODEL_TEMP, SUMMARIZER_MODEL, EMBEDDING_MODEL, OPEN_BUTTON_TOKEN, OPEN_BUTTON_TOKEN2, VAST_IP_PORT, VAST_IP_PORT2
from Definitions.labels import LABELS_DESCRIPTIONS, ALL_LABELS

from Graph.Nodes.nvd import nvd_caller
from Graph.Nodes.scrapers import extract_md_trafilatura
from Graph.Nodes.chunkers import SemanticChunkerNode
from Graph.Nodes.filters import CosineFilterNode
from Graph.Nodes.summarizers import ReferenceSummarizerNode
from Graph.Nodes.evaluators import *
from Graph.Nodes.formatters import formatter
from Graph.Nodes.classifiers import CVEClassifierNode

if __name__ == "__main__":
    NUMBER_OF_EVALUATIONS = 4
    random.seed(42)
    VAST_HOST = f"http://{VAST_IP_PORT}/v1"
    VAST_HOST2 = f"http://{VAST_IP_PORT2}/v1"

    print(VAST_HOST, VAST_HOST2)
    # Initialize the embedding model externally
    embedding_model_instance = OpenAIEmbeddings(
        model=EMBEDDING_MODEL, 
        api_key=OPEN_BUTTON_TOKEN2,
        base_url=VAST_HOST2,
    )

    # Inject the model instance into the node
    semantic_chunker = SemanticChunkerNode(
        embed_model=embedding_model_instance
    )

    cosine_filter = CosineFilterNode(
        query="What type of vulnerability is it?",
        embed_model=embedding_model_instance,
        threshold=0.2
    )

    summarizer = ReferenceSummarizerNode(
        model_name=SUMMARIZER_MODEL,
        api_key=OPEN_BUTTON_TOKEN,
        base_url=VAST_HOST,
        labels_descriptions=LABELS_DESCRIPTIONS,
    )

    classifier = CVEClassifierNode(
        model_name=CHAT_MODEL,
        api_key=OPEN_BUTTON_TOKEN,
        base_url=VAST_HOST,
        temperature=CHAT_MODEL_TEMP,
        labels_descriptions=LABELS_DESCRIPTIONS
    )

    pipeline = (
        lcr.RunnableLambda(nvd_caller)
        | extract_md_trafilatura    
        | semantic_chunker
        | cosine_filter
        | summarizer
        | formatter
        | classifier
    )

    for i in range(NUMBER_OF_EVALUATIONS):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        log_dir = os.path.join(os.path.dirname(base_dir), "logs")
        os.makedirs(log_dir, exist_ok=True)

        run_id = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        output_file = os.path.join(log_dir, f"run_{run_id}.json")

        log = {
            "pipeline_metadata": {
                "run_id": run_id,
                "iteration": i + 1,
                "models": {
                    "chat_model": CHAT_MODEL,
                    "summarizer_model": SUMMARIZER_MODEL,
                    "embedding_model": "all-MiniLM-L6-v2"
                },
                "labels_schema": LABELS_DESCRIPTIONS
            },
            "cves": {},
            "aggregated_scores": {}
        }

        all_y_true = []
        all_y_pred = []

        for cve, expected_labels in CVE_TEST.items():
            print(f"--- Analyzing {cve} ---")
            
            state = pipeline.invoke({"cve_id": cve})
            
            predicted_labels = state["cve_labels"]

            individual_scores = compute_individual_scores(expected_labels, predicted_labels, ALL_LABELS)

            log["cves"][cve] = {
                # "nvd_description": state.get("nvd_description", ""),
                # "nvd_url_references": state.get("nvd_url_references", []),
                # "nvd_filtered_chunks": state.get("nvd_filtered_chunks", {}),
                # "summaries": state.get("summaries", {}), 
                "rag_input": state.get("rag", ""),
                "expected_labels": expected_labels,
                "classification_output": predicted_labels,
                "individual_scores": individual_scores
            }

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(log, f, indent=2)

            print(f"Log {os.path.abspath(output_file)} updated for {cve}")
            
            all_y_true.append(expected_labels)
            all_y_pred.append(predicted_labels)

        grouped_scores = compute_grouped_scores(all_y_true, all_y_pred, ALL_LABELS)
        log["aggregated_scores"] = grouped_scores
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(log, f, indent=2)

        print(f"\nEvaluation Run {run_id} completed.")
        print(f"Final log file: {os.path.abspath(output_file)}")