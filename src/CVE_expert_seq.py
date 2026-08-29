"""
Linear workflow to classify CVEs against list of labels.
"""

import os
import json
import random
import time
import concurrent.futures

from langchain.chat_models import init_chat_model
import langchain_core.runnables as lcr
from langchain_openai import OpenAIEmbeddings

from Definitions.const import CVE_TEST
from Definitions.config import CHAT_MODEL, CHAT_MODEL_TEMP, SUMMARIZER_MODEL, EMBEDDING_MODEL, OPEN_BUTTON_TOKEN_MODEL, OPEN_BUTTON_TOKEN_EMBEDDING, VAST_IP_PORT_MODEL, VAST_IP_PORT_EMBEDDING, validate_runtime_config
from Definitions.labels import LABELS_DESCRIPTIONS, ALL_LABELS

from Graph.Nodes.nvd import nvd_caller
from Graph.Nodes.scrapers import extract_md_trafilatura
from Graph.Nodes.chunkers import SemanticChunkerNode
from Graph.Nodes.filters import CosineFilterNode
from Graph.Nodes.summarizers import CVEAwareSummarizerNode
from Graph.Nodes.evaluators import *
from Graph.Nodes.formatters import formatter
from Graph.Nodes.classifiers import CVEClassifierNode
from Graph.errors import PipelineStageError


def _serialize_pipeline_error(error, cve_id):
    if isinstance(error, PipelineStageError):
        return error.to_dict(), str(error)

    details = {
        "stage": "pipeline",
        "cve_id": cve_id,
        "error_type": type(error).__name__,
        "message": "Unexpected pipeline failure",
    }
    safe_message = (
        f"pipeline stage failed for {cve_id}: "
        f"Unexpected pipeline failure ({details['error_type']})"
    )
    return details, safe_message

def run_evaluation(args):
    """
    Worker function to run a single evaluation iteration.
    Exception handling is applied per-CVE to ensure the run continues even if one fails.
    """
    RUN_N, pipeline_instance, pipeline_names = args
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(os.path.dirname(base_dir), "logs")
    
    # Create a unique folder for this pipeline configuration
    run_id_str = '_'.join(pipeline_names)
    run_folder = os.path.join(log_dir, f"LOG_GPT_NORANDAware")
    os.makedirs(run_folder, exist_ok=True)
    
    output_file = os.path.join(run_folder, f"RUN_{RUN_N}.json")

    print(f"[Run {RUN_N}] Starting. Log: {os.path.basename(output_file)}")

    log = {
        "pipeline_metadata": {
            "run_id": run_id_str,
            "RUN_N": RUN_N + 1,
            "pipeline_structure": pipeline_names, # Fixed variable name usage
            "models": {
                "chat_model": CHAT_MODEL,
                "summarizer_model": SUMMARIZER_MODEL,
                "embedding_model": EMBEDDING_MODEL
            },
            "labels_schema": LABELS_DESCRIPTIONS
        },
        "cves": {},
        "aggregated_scores": {}
    }

    all_y_true = []
    all_y_pred = []
    # Shuffle to avoid NVD error of too many requests in a row
    cve_shuffled = random.sample(list(CVE_TEST.items()), len(CVE_TEST))
    for cve, expected_labels in cve_shuffled:
        print(f"[Run {RUN_N}] --- Analyzing {cve} ---")
        
        try:
            t = time.time()
            state = pipeline_instance.invoke({"cve_id": cve})
            t = time.time() - t
            predicted_labels = state["cve_labels"]
            individual_scores = compute_individual_scores(expected_labels, predicted_labels, ALL_LABELS)
            pipeline_warnings = list(state.get("pipeline_warnings", []))
            status = "degraded" if pipeline_warnings else "success"

            log["cves"][cve] = {
                "status": status,
                "pipeline_warnings": pipeline_warnings,
                "nvd_description": state.get("nvd_description", ""),
                "nvd_references_pages": state.get("nvd_references_pages", {}),
                "nvd_references_chunks": state.get("nvd_references_chunks", {}),
                "nvd_filtered_chunks": state.get("nvd_filtered_chunks", {}),
                "summaries": state.get("summaries", {}), 
                "rag_input": state.get("rag", ""),
                "expected_labels": expected_labels,
                "classification_output": predicted_labels,
                "required_time":t, # optional
                "labels_motivation": state.get("labels_motivation", []), # optional
                "labels_confidence": state.get("labels_confidence", []), # optional
                "individual_scores": individual_scores
            }
            
            all_y_true.append(expected_labels)
            all_y_pred.append(predicted_labels)

        except Exception as error:
            error_details, error_msg = _serialize_pipeline_error(error, cve)
            print(f"[Run {RUN_N}] ERROR on {cve}: {error_msg}")
            
            log["cves"][cve] = {
                "status": "error",
                "pipeline_warnings": [],
                "error": error_details,
                "error_message": error_msg,
                "expected_labels": expected_labels,
                "classification_output": ["ERROR"]
            }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(log, f, indent=2)

        print(f"[Run {RUN_N}] Log updated for {cve}")

    aggregation_complete = True
    if all_y_true and all_y_pred:
        try:
            log["aggregated_scores"] = compute_grouped_scores(
                all_y_true,
                all_y_pred,
                ALL_LABELS,
            )
        except Exception as e:
            print(f"[Run {RUN_N}] Error computing aggregated scores: {e}")
            aggregation_complete = False
            log["aggregated_scores"] = {
                "error": "Aggregate metric computation failed",
                "error_type": type(e).__name__,
            }
    else:
        log["aggregated_scores"] = {"note": "No successful predictions to aggregate."}

    statuses = [entry["status"] for entry in log["cves"].values()]
    total = len(CVE_TEST)
    scored = len(all_y_true)
    successful = statuses.count("success")
    degraded = statuses.count("degraded")
    failed = statuses.count("error")
    log["aggregated_scores"].update(
        {
            "total": total,
            "scored": scored,
            "successful": successful,
            "degraded": degraded,
            "failed": failed,
            "complete": (
                aggregation_complete
                and failed == 0
                and scored == total
            ),
        }
    )
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2)

    print(f"\n[Run {RUN_N}] COMPLETED. File: {os.path.abspath(output_file)}")
    return f"Finished: Run {RUN_N}"
    
if __name__ == "__main__":
    validate_runtime_config(require_embedding=True)
    NUMBER_OF_EVALUATIONS = 8
    random.seed(42)
    VAST_HOST = f"http://{VAST_IP_PORT_MODEL}/v1"
    VAST_HOST_EMBEDDING = f"http://{VAST_IP_PORT_EMBEDDING}/v1"

    print(f"Chat Host: {VAST_HOST}")
    print(f"Embedding Host: {VAST_HOST_EMBEDDING}")

    # Initialize the embedding model externally
    embedding_model_instance = OpenAIEmbeddings(
        model=EMBEDDING_MODEL, 
        api_key=OPEN_BUTTON_TOKEN_EMBEDDING,
        base_url=VAST_HOST_EMBEDDING,
    )

    # Inject the model instance into the node
    semantic_chunker = SemanticChunkerNode(
        embed_model=embedding_model_instance
    )

    cosine_filter = CosineFilterNode(
        query="What type of vulnerability is it?",
        embed_model=embedding_model_instance,
        threshold=0.6
    )

    summarizer_llm = init_chat_model(
        model=SUMMARIZER_MODEL,
        model_provider="openai",
        api_key=OPEN_BUTTON_TOKEN_MODEL,
        base_url=VAST_HOST,
    )

    summarizer = CVEAwareSummarizerNode(
        model=summarizer_llm,
        labels_descriptions=LABELS_DESCRIPTIONS,
    )

    classifier_llm = init_chat_model(
        model=CHAT_MODEL,
        model_provider="openai",
        api_key=OPEN_BUTTON_TOKEN_MODEL,
        base_url=VAST_HOST,
        temperature=CHAT_MODEL_TEMP,
    )

    classifier = CVEClassifierNode(
        model=classifier_llm,
        labels_descriptions=LABELS_DESCRIPTIONS,
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

    pipeline_component_names = []
    for step in pipeline.steps:
        if hasattr(step, 'func'):
            target = step.func
            if hasattr(target, '__name__'):
                pipeline_component_names.append(target.__name__)
            else:
                pipeline_component_names.append(target.__class__.__name__)

    print(f"Pipeline Components: {pipeline_component_names}")

    print(f"Starting {NUMBER_OF_EVALUATIONS} evaluations in parallel...")
    
    tasks_args = [
        (i, pipeline, pipeline_component_names) 
        for i in range(NUMBER_OF_EVALUATIONS)
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=NUMBER_OF_EVALUATIONS) as executor:
        future_to_iter = {
            executor.submit(run_evaluation, arg): arg[0] 
            for arg in tasks_args
        }
        
        for future in concurrent.futures.as_completed(future_to_iter):
            iter_idx = future_to_iter[future]
            try:
                result = future.result()
                print(f"Main Thread: {result}")
            except Exception as exc:
                print(f"Main Thread: Iteration {iter_idx} generated an exception: {exc}")

    print("All evaluations finished.")
