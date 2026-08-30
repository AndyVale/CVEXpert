"""
Linear workflow to classify CVEs against list of labels.
"""

import os
import json
import time
from functools import partial

from langchain.chat_models import init_chat_model
import langchain_core.runnables as lcr
from langchain_openai import OpenAIEmbeddings
from openai import DefaultHttpxClient

from Definitions.const import CVE_TEST
from Definitions.config import RuntimeConfig, validate_runtime_config
from Definitions.labels import LABELS_DESCRIPTIONS, ALL_LABELS

from Graph.Nodes.nvd import nvd_caller
from Graph.Nodes.scrapers import extract_md_trafilatura
from Graph.Nodes.chunkers import SemanticChunkerNode
from Graph.Nodes.filters import CosineFilterNode
from Graph.Nodes.summarizers import CVEAwareSummarizerNode
from Graph.Nodes.evaluators import compute_grouped_scores, compute_individual_scores
from Graph.Nodes.formatters import formatter
from Graph.Nodes.classifiers import CVEClassifierNode
from Graph.errors import PipelineStageError
from Graph.request_pacing import MinimumIntervalPacer


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

def run_evaluation(
    pipeline_instance,
    pipeline_names,
    runtime_config: RuntimeConfig,
    run_number: int | None = None,
):
    """Run one ordered benchmark pass while isolating failures per CVE."""

    if run_number is None:
        run_number = runtime_config.evaluation.run_number

    run_id_str = '_'.join(pipeline_names)
    run_folder = runtime_config.evaluation.resolved_log_directory()
    os.makedirs(run_folder, exist_ok=True)

    output_file = run_folder / f"RUN_{run_number}.json"

    print(f"[Run {run_number}] Starting. Log: {output_file.name}")

    log = {
        "pipeline_metadata": {
            "run_id": run_id_str,
            "RUN_N": run_number + 1,
            "pipeline_structure": pipeline_names, # Fixed variable name usage
            "models": runtime_config.model_metadata,
            "labels_schema": LABELS_DESCRIPTIONS
        },
        "cves": {},
        "aggregated_scores": {}
    }

    all_y_true = []
    all_y_pred = []
    for cve, expected_labels in CVE_TEST.items():
        print(f"[Run {run_number}] --- Analyzing {cve} ---")
        
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
            print(f"[Run {run_number}] ERROR on {cve}: {error_msg}")
            
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

        print(f"[Run {run_number}] Log updated for {cve}")

    aggregation_complete = True
    if all_y_true and all_y_pred:
        try:
            log["aggregated_scores"] = compute_grouped_scores(
                all_y_true,
                all_y_pred,
                ALL_LABELS,
            )
        except Exception as e:
            print(f"[Run {run_number}] Error computing aggregated scores: {e}")
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

    print(f"\n[Run {run_number}] COMPLETED. File: {output_file.resolve()}")
    return f"Finished: Run {run_number}"


def build_pipeline(runtime_config: RuntimeConfig):
    """Construct the configured live linear pipeline after validation."""

    print(f"Chat Host: {runtime_config.chat.base_url}")
    print(f"Embedding Host: {runtime_config.embedding.base_url}")

    embedding_http_client = DefaultHttpxClient(
        event_hooks={
            "request": [
                MinimumIntervalPacer(
                    runtime_config.embedding.request_delay_seconds
                )
            ]
        }
    )

    embedding_model_instance = OpenAIEmbeddings(
        model=runtime_config.embedding.model,
        api_key=runtime_config.embedding.api_key,
        base_url=runtime_config.embedding.base_url,
        http_client=embedding_http_client,
        check_embedding_ctx_length=(
            runtime_config.embedding.check_embedding_ctx_length
        ),
    )

    semantic_chunker = SemanticChunkerNode(
        embed_model=embedding_model_instance,
        breakpoint_threshold_type=(
            runtime_config.semantic_chunker.breakpoint_threshold_type
        ),
        breakpoint_threshold_amount=(
            runtime_config.semantic_chunker.breakpoint_threshold_amount
        ),
    )

    cosine_filter = CosineFilterNode(
        query=runtime_config.cosine_filter.query,
        embed_model=embedding_model_instance,
        threshold=runtime_config.cosine_filter.threshold,
    )

    chat_http_client = DefaultHttpxClient(
        event_hooks={
            "request": [
                MinimumIntervalPacer(runtime_config.chat.request_delay_seconds)
            ]
        }
    )

    summarizer_llm = init_chat_model(
        model=runtime_config.chat.summarizer_model,
        model_provider="openai",
        api_key=runtime_config.chat.api_key,
        base_url=runtime_config.chat.base_url,
        temperature=runtime_config.chat.summarizer_temperature,
        http_client=chat_http_client,
    )

    summarizer = CVEAwareSummarizerNode(
        model=summarizer_llm,
        labels_descriptions=LABELS_DESCRIPTIONS,
    )

    classifier_llm = init_chat_model(
        model=runtime_config.chat.classifier_model,
        model_provider="openai",
        api_key=runtime_config.chat.api_key,
        base_url=runtime_config.chat.base_url,
        temperature=runtime_config.chat.classifier_temperature,
        http_client=chat_http_client,
    )

    classifier = CVEClassifierNode(
        model=classifier_llm,
        labels_descriptions=LABELS_DESCRIPTIONS,
    )

    configured_nvd_caller = partial(
        nvd_caller,
        base_url=runtime_config.nvd.base_url,
        timeout_seconds=runtime_config.nvd.timeout_seconds,
    )
    configured_nvd_caller.__name__ = nvd_caller.__name__
    configured_scraper = partial(
        extract_md_trafilatura,
        max_pages=runtime_config.references.max_pages,
    )
    configured_scraper.__name__ = extract_md_trafilatura.__name__

    pipeline = (
        lcr.RunnableLambda(configured_nvd_caller)
        | configured_scraper
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
    return pipeline, pipeline_component_names


def main():
    """Build the live pipeline and run the benchmark exactly once."""

    runtime_config = validate_runtime_config()
    pipeline, pipeline_component_names = build_pipeline(runtime_config)
    return run_evaluation(pipeline, pipeline_component_names, runtime_config)


if __name__ == "__main__":
    main()
