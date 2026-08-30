"""
Test linear workflow to classify CVEs against list of labels.
"""

import os
import json
import random
import time
import concurrent.futures

from langchain.chat_models import init_chat_model
import langchain_core.runnables as lcr
from Definitions.const import CVE_TEST
from Definitions.config import read_api_key, validate_runtime_config
from Definitions.labels import LABELS_DESCRIPTIONS, ALL_LABELS

from Graph.Nodes.util import StateFromFileLoader

from Graph.Nodes.summarizers import CVEAwareSummarizerNode, ReferenceSummarizerNode
from Graph.Nodes.evaluators import *
from Graph.Nodes.formatters import formatter
from Graph.Nodes.classifiers import CVEClassifierNode, CVESelfConsistentClassifierNode

def run_evaluation(args):
    """
    Worker function to run a single evaluation iteration.
    Exception handling is applied per-CVE to ensure the run continues even if one fails.
    """
    RUN_N, pipeline_instance, pipeline_names, runtime_config = args
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(os.path.dirname(base_dir), "logs")
    
    # Create a unique folder for this pipeline configuration
    run_id_str = '_'.join(pipeline_names)
    run_folder = os.path.join(log_dir, f"LOG_GPTSelfCons0.8")
    os.makedirs(run_folder, exist_ok=True)
    
    output_file = os.path.join(run_folder, f"RUN_{RUN_N}.json")

    print(f"[Run {RUN_N}] Starting. Log: {os.path.basename(output_file)}")

    log = {
        "pipeline_metadata": {
            "run_id": run_id_str,
            "RUN_N": RUN_N + 1,
            "pipeline_structure": pipeline_names, # Fixed variable name usage
            "models": runtime_config.model_metadata,
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

            log["cves"][cve] = {
                "status": "success",
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

        except Exception as e:
            error_msg = str(e)
            print(f"[Run {RUN_N}] ERROR on {cve}: {error_msg}")
            
            log["cves"][cve] = {
                "status": "error",
                "error_message": error_msg,
                "expected_labels": expected_labels,
                "classification_output": ["ERROR"]
            }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(log, f, indent=2)

        print(f"[Run {RUN_N}] Log updated for {cve}")

    if all_y_true and all_y_pred:
        try:
            grouped_scores = compute_grouped_scores(all_y_true, all_y_pred, ALL_LABELS)
            log["aggregated_scores"] = grouped_scores
        except Exception as e:
            print(f"[Run {RUN_N}] Error computing aggregated scores: {e}")
            log["aggregated_scores"] = {"error": str(e)}
    else:
        log["aggregated_scores"] = {"note": "No successful predictions to aggregate."}
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2)

    print(f"\n[Run {RUN_N}] COMPLETED. File: {os.path.abspath(output_file)}")
    return f"Finished: Run {RUN_N}"
        
if __name__ == "__main__":
    runtime_config = validate_runtime_config(require_embedding=False)
    PARALLEL_EXECUTION = 8
    random.seed(42)
    LOG_FILE_PATH = "/home/andyvale/Documents/cvexpert/logs/OLD_LOGS/LOG_GPT_NORANDAware/RUN_0.json"

    print(f"Chat Host: {runtime_config.chat.base_url}")
    chat_api_key = read_api_key(runtime_config.chat.api_key_env)

    state_loader = StateFromFileLoader(
        file_path=LOG_FILE_PATH,
        fields_to_load=[
            "nvd_description", 
            "nvd_url_references",
            "nvd_filtered_chunks" 
        ]
    )

    summarizer_llm = init_chat_model(
        model=runtime_config.chat.summarizer_model,
        model_provider="openai",
        api_key=chat_api_key,
        base_url=runtime_config.chat.base_url,
        temperature=runtime_config.chat.summarizer_temperature,
    )

    summarizer = CVEAwareSummarizerNode(
        model=summarizer_llm,
        labels_descriptions=LABELS_DESCRIPTIONS,
    )

    classifier_llm = init_chat_model(
        model=runtime_config.chat.classifier_model,
        model_provider="openai",
        api_key=chat_api_key,
        base_url=runtime_config.chat.base_url,
        temperature=runtime_config.chat.classifier_temperature,
    )

    classifier = CVESelfConsistentClassifierNode(
        model=classifier_llm,
        labels_descriptions=LABELS_DESCRIPTIONS,
        total_runs=5
    )

    pipeline = (
        lcr.RunnableLambda(state_loader)
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

    print(f"Starting {PARALLEL_EXECUTION} evaluations in parallel...")
    
    tasks_args = [
        (i, pipeline, pipeline_component_names, runtime_config)
        for i in range(PARALLEL_EXECUTION)
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=PARALLEL_EXECUTION) as executor:
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
