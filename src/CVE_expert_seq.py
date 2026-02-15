import os
import json
import random
from datetime import datetime
import concurrent.futures

from langchain.chat_models import init_chat_model
import langchain_core.runnables as lcr
from langchain_openai import OpenAIEmbeddings

from Definitions.const import CVE_TEST
from Definitions.config import CHAT_MODEL, CHAT_MODEL_TEMP, SUMMARIZER_MODEL, EMBEDDING_MODEL, OPEN_BUTTON_TOKEN, OPEN_BUTTON_TOKEN_EMBEDDING, VAST_IP_PORT, VAST_IP_EMBEDDING
from Definitions.labels import LABELS_DESCRIPTIONS, ALL_LABELS

from Graph.Nodes.nvd import nvd_caller
from Graph.Nodes.scrapers import extract_md_trafilatura
from Graph.Nodes.chunkers import SemanticChunkerNode
from Graph.Nodes.filters import CosineFilterNode
from Graph.Nodes.summarizers import ReferenceSummarizerNode, NoSummarizerNode
from Graph.Nodes.evaluators import *
from Graph.Nodes.formatters import formatter
from Graph.Nodes.classifiers import CVEClassifierNode

def run_evaluation(args):
    """
    Worker function to run a single evaluation iteration.
    Unpacks arguments to allow usage with ThreadPoolExecutor.map.
    """
    RUN_N, pipeline_instance = args
    
    # Setup paths inside the thread
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(os.path.dirname(base_dir), "logs")

    # Unique filename per run
    run_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    os.makedirs(os.path.join(log_dir, f"run_{run_id}"), exist_ok=True)
    output_file = os.path.join(log_dir, f"run_{run_id}", f"run_{run_id}_iter_{RUN_N}.json")

    print(f"[Run {RUN_N}] Starting. Log: {os.path.basename(output_file)}")

    log = {
        "pipeline_metadata": {
            "run_id": run_id,
            "RUN_N": RUN_N + 1,
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

    for cve, expected_labels in CVE_TEST.items():
        print(f"[Iter {RUN_N}] --- Analyzing {cve} ---")
        
        # Invoke the pipeline
        state = pipeline_instance.invoke({"cve_id": cve})
        
        predicted_labels = state["cve_labels"]

        individual_scores = compute_individual_scores(expected_labels, predicted_labels, ALL_LABELS)

        log["cves"][cve] = {
            "nvd_description": state.get("nvd_description", ""),
            "nvd_filtered_chunks": state.get("nvd_filtered_chunks", {}),
            "summaries": state.get("summaries", {}), 
            "rag_input": state.get("rag", ""),
            "expected_labels": expected_labels,
            "classification_output": predicted_labels,
            "individual_scores": individual_scores
        }

        # --- KEY REQUIREMENT: Log update inside the loop ---
        # This saves the file after every single CVE is processed
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(log, f, indent=2)

        print(f"[Iter {RUN_N}] Log updated for {cve}")
        
        all_y_true.append(expected_labels)
        all_y_pred.append(predicted_labels)

    # Final aggregation after all CVEs in this iteration are done
    grouped_scores = compute_grouped_scores(all_y_true, all_y_pred, ALL_LABELS)
    log["aggregated_scores"] = grouped_scores
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2)

    print(f"\n[Iter {RUN_N}] Evaluation Run completed.\nFinal log file: {os.path.abspath(output_file)}")

if __name__ == "__main__":
    NUMBER_OF_EVALUATIONS = 2
    random.seed(42)
    VAST_HOST = f"http://{VAST_IP_PORT}/v1"
    VAST_HOST_EMBEDDING = f"http://{VAST_IP_EMBEDDING}/v1"

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
        api_key=OPEN_BUTTON_TOKEN,
        base_url=VAST_HOST,
    )

    summarizer = NoSummarizerNode() 
    #ReferenceSummarizerNode(
    #    model=summarizer_llm,
    #    labels_descriptions=LABELS_DESCRIPTIONS,
    #)

    classifier_llm = init_chat_model(
        model=CHAT_MODEL,
        model_provider="openai",
        api_key=OPEN_BUTTON_TOKEN,
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

    print(f"Starting {NUMBER_OF_EVALUATIONS} evaluations in parallel...")
    
    # Prepare arguments: list of (iteration_index, pipeline_object)
    # We pass the pipeline object to the worker function
    tasks = [(i, pipeline) for i in range(NUMBER_OF_EVALUATIONS)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=NUMBER_OF_EVALUATIONS) as executor:
        executor.map(run_evaluation, tasks)