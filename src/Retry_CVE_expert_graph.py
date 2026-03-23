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
from Definitions.labels import VULNERABILITY_TREE, ALL_TREE_LABELS, FLATTEN_TREE
from Graph.state import CVEClassifierState

# Import nodes
from Graph.Nodes.util import StateFromFileLoader
from Graph.Nodes.summarizers import CVEAwareSummarizerNode
from Graph.Nodes.evaluators import compute_individual_scores, compute_grouped_scores
from Graph.Nodes.formatters import formatter
from Graph.Nodes.classifiers import CVEClassifierNode
from Definitions.prompts import get_cve_classifier_prompt_hierarchical, get_cve_aware_summarizer_prompt

def run_evaluation(args):
    """
    Worker function to run a single evaluation iteration.
    Exception handling is applied per-CVE to ensure the run continues even if one fails.
    """
    RUN_N, pipeline_instance, pipeline_names = args
    local_rng = random.Random(42 + RUN_N)
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(os.path.dirname(base_dir), "logs")
    
    run_id_str = '_'.join(pipeline_names)
    run_folder = os.path.join(log_dir, "HIERARCHICAL_RETRY2")
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
            "labels_schema": VULNERABILITY_TREE
        },
        "cves": {},
        "aggregated_scores": {}
    }

    all_y_true = []
    all_y_pred =[]
    
    cve_shuffled = local_rng.sample(list(CVE_TEST.items()), len(CVE_TEST))
    
    for cve, expected_labels in cve_shuffled:
        print(f"[Run {RUN_N}] --- Analyzing {cve} ---")
        
        try:
            t = time.time()
            
            initial_state = {
                "cve_id": cve,
                "cve_labels":[],
                "labels_motivation": {},
                "labels_confidence": {}
            }
            
            state = pipeline_instance.invoke(initial_state)
            t = time.time() - t
            
            predicted_labels = state.get("cve_labels",[])
            
            # Use ALL_TREE_LABELS for accurate metric calculation
            individual_scores = compute_individual_scores(expected_labels, predicted_labels, ALL_TREE_LABELS)

            log["cves"][cve] = {
                "status": "success",
                "nvd_description": state.get("nvd_description", ""),
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
            # Use ALL_TREE_LABELS for accurate aggregated scores
            grouped_scores = compute_grouped_scores(all_y_true, all_y_pred, ALL_TREE_LABELS)
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

from langgraph.graph import END

def should_continue(state: CVEClassifierState, label_tree: dict):
    """
    Validates if the predicted labels form valid hierarchical paths from the roots.
    If any labels remain unconsumed, the hierarchy was violated and the step is re-iterated.
    """
    predicted_labels = state.get("cve_labels", [])
    
    if not predicted_labels or predicted_labels == ["NONE"]:
        return END
        
    labels_to_consume = set(predicted_labels)
    
    def consume_tree(current_tree):
        for node_name, node_data in current_tree.items():
            if node_name in labels_to_consume:
                labels_to_consume.remove(node_name)
                # Proceed in depth ONLY if the parent label was found and removed
                children = node_data.get("children", {})
                if children:
                    consume_tree(children)

    # Start consumption from the roots of the provided tree
    consume_tree(label_tree)
    
    # If the set is not empty, there are orphaned children
    if len(labels_to_consume) > 0:
        print(f"Hierarchy validation failed. Orphaned labels found: {labels_to_consume}. Retrying classification...")
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

    # Pass the ALL_TREE_LABELS imported from Definitions.labels
    classifier_node = CVEClassifierNode(
        model=classifier_llm,
        full_label_tree=VULNERABILITY_TREE,
        all_tree_labels=ALL_TREE_LABELS,
        prompt_func=get_cve_classifier_prompt_hierarchical
    )

    # Pass the pre-computed FLATTEN_TREE directly
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

    # Use the validation function to loop if the hierarchy is broken
    workflow.add_conditional_edges(
        "classify_step",
        lambda state: should_continue(state, VULNERABILITY_TREE),
        {
            "classify_step": "classify_step",
            END: END
        }
    )

    app = workflow.compile()

    pipeline_component_names =[
        "StateFromFileLoader",
        "CVEAwareSummarizerNode",
        "formatter",
        "CVEClassifierNode_Hierarchical_Validation"
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