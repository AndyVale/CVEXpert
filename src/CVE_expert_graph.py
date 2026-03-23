"""
Non-Linear workflow to classify CVEs against a tree structure of labels using LangGraph.
Runs in parallel to speed up evaluations.
"""

import os
import json
import random
import time
import concurrent.futures

from langchain.chat_models import init_chat_model
from langgraph.graph import StateGraph, START, END

from Definitions.const import CVE_TEST
from Definitions.config import (
    CHAT_MODEL, CHAT_MODEL_TEMP, SUMMARIZER_MODEL, 
    OPEN_BUTTON_TOKEN_MODEL, VAST_IP_PORT_MODEL
)
from Definitions.labels import VULNERABILITY_TREE, ALL_LABELS, FLATTEN_TREE, ALL_TREE_LABELS
from Graph.state import CVEClassifierState

# Import nodes
from Graph.Nodes.util import StateFromFileLoader
from Graph.Nodes.summarizers import CVEAwareSummarizerNode
from Graph.Nodes.evaluators import compute_individual_scores, compute_grouped_scores
from Graph.Nodes.formatters import formatter
from Graph.Nodes.classifiers import HierarchicalClassifierNode
from Definitions.prompts import get_cve_aware_summarizer_prompt, get_hierarchical_classifier_prompt

def run_evaluation(args):
    """
    Worker function to run a single evaluation iteration.
    Exception handling is applied per-CVE to ensure the run continues even if one fails.
    """
    RUN_N, pipeline_instance, pipeline_names = args
    local_rng = random.Random(42 + RUN_N)
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(os.path.dirname(base_dir), "logs")
    
    # Create a unique folder for this pipeline configuration
    run_id_str = '_'.join(pipeline_names)
    run_folder = os.path.join(log_dir, f"GraphGPTTEST")
    os.makedirs(run_folder, exist_ok=True)
    
    output_file = os.path.join(run_folder, f"RUN_{RUN_N}.json")

    print(f"[Run {RUN_N}] Starting. Log: {os.path.basename(output_file)}")

    log = {
        "pipeline_metadata": {
            "run_id": run_id_str,
            "RUN_N": RUN_N + 1,
            "pipeline_structure": pipeline_names, 
            "models": {
                "chat_model": CHAT_MODEL,
                "summarizer_model": SUMMARIZER_MODEL
            },
            "labels_schema": VULNERABILITY_TREE # Log the tree instead of flat labels
        },
        "cves": {},
        "aggregated_scores": {}
    }

    all_y_true = []
    all_y_pred =[]
    # Shuffle to avoid NVD error of too many requests in a row
    cve_shuffled = local_rng.sample(list(CVE_TEST.items()), len(CVE_TEST))
    
    for cve, expected_labels in cve_shuffled:
        print(f"[Run {RUN_N}] --- Analyzing {cve} ---")
        
        try:
            t = time.time()
            
            # Initialize the LangGraph state properly
            initial_state = {
                "cve_id": cve,
                "cve_labels":[],
                "new_labels":[], 
                "labels_motivation": {},
                "labels_confidence": {}
            }
            
            state = pipeline_instance.invoke(initial_state)
            t = time.time() - t
            
            predicted_labels = state.get("cve_labels",[])
            individual_scores = compute_individual_scores(expected_labels, predicted_labels, ALL_TREE_LABELS)

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
                "required_time": t,
                "labels_motivation": state.get("labels_motivation", {}),
                "labels_confidence": state.get("labels_confidence", {}),
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

def should_continue(state: CVEClassifierState):
    """
    Decides if the classification process needs another step.
    If 'new_labels' are produced and have children in the tree, we continue.
    """
    queue = state.get("new_labels",[])
    if queue:
        return "classify_step"
    return END

if __name__ == "__main__":
    NUMBER_OF_EVALUATIONS = 15
    random.seed(42)
    VAST_HOST = f"http://{VAST_IP_PORT_MODEL}/v1"
    LOG_FILE_PATH = "/home/andyvale/Documents/cvexpert/logs/OLD_LOGS/oldold/LOG_GPT_NORANDAware/RUN_0.json"
    
    print(f"Chat Host: {VAST_HOST}")

    # --- 1. Initialize Models ---
    summarizer_llm = init_chat_model(
        model=SUMMARIZER_MODEL,
        model_provider="openai",
        api_key=OPEN_BUTTON_TOKEN_MODEL,
        base_url=VAST_HOST,
    )

    classifier_llm = init_chat_model(
        model=CHAT_MODEL,
        model_provider="openai",
        api_key=OPEN_BUTTON_TOKEN_MODEL,
        base_url=VAST_HOST,
        temperature=CHAT_MODEL_TEMP,
    )

    # --- 2. Initialize Nodes ---
    state_loader = StateFromFileLoader(
        file_path=LOG_FILE_PATH,
        fields_to_load=[
            "nvd_description", 
            "nvd_url_references",
            "nvd_filtered_chunks" 
        ]
    )

    classifier_node = HierarchicalClassifierNode(
        model=classifier_llm,
        full_label_tree=VULNERABILITY_TREE,
        flatten_tree=FLATTEN_TREE,
        prompt_func=get_hierarchical_classifier_prompt
    )

    summarizer_node = CVEAwareSummarizerNode(
        model=summarizer_llm,
        labels_descriptions=FLATTEN_TREE,
        prompt_func=get_cve_aware_summarizer_prompt
    )
    
    # --- 3. Build the LangGraph Workflow ---
    workflow = StateGraph(CVEClassifierState)

    workflow.add_node("load_state", state_loader)
    workflow.add_edge(START, "load_state")

    workflow.add_node("summarize", summarizer_node)
    workflow.add_edge("load_state", "summarize")
    
    workflow.add_node("format", formatter)
    workflow.add_edge("summarize", "format")
    
    workflow.add_node("classify_step", classifier_node)
    workflow.add_edge("format", "classify_step")

    workflow.add_conditional_edges(
        "classify_step",
        should_continue,
        {
            "classify_step": "classify_step",
            END: END
        }
    )

    app = workflow.compile()

    # Define explicit pipeline names since StateGraph does not have a .steps attribute
    pipeline_component_names =[
        "StateFromFileLoader",
        "CVEAwareSummarizerNode",
        "formatter",
        "HierarchicalClassifierNode"
    ]

    print(f"Pipeline Components: {pipeline_component_names}")
    print(f"Starting {NUMBER_OF_EVALUATIONS} evaluations in parallel...")
    
    # --- 4. Parallel Execution ---
    tasks_args =[
        (i, app, pipeline_component_names) 
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