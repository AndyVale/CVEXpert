"""
Linear workflow to classify CVEs against list of labels.
"""

import argparse
import os
import json
import time
import requests
import httpx
from datetime import datetime, timezone
from collections.abc import Sequence
from functools import partial
from pathlib import Path
from uuid import uuid4

from langchain.chat_models import init_chat_model
import langchain_core.runnables as lcr
from langchain_openai import OpenAIEmbeddings
from openai import DefaultHttpxClient

from Definitions.config import CONFIG_PATH, RuntimeConfig, validate_runtime_config
from Definitions.fixtures import (
    Benchmark,
    BenchmarkCase,
    FixtureError,
    Taxonomy,
    load_benchmark,
    load_taxonomy,
    normalize_cve_id,
)

from Graph.Nodes.nvd import nvd_caller
from Graph.Nodes.scrapers import extract_md_trafilatura
from Graph.Nodes.chunkers import SemanticChunkerNode
from Graph.Nodes.filters import CosineFilterNode
from Graph.Nodes.summarizers import CVEAwareSummarizerNode
from Graph.Nodes.evaluators import compute_grouped_scores, compute_individual_scores
from Graph.Nodes.formatters import formatter
from Graph.Nodes.classifiers import CVEClassifierNode
from Graph.errors import PipelineStageError
from Graph.model_requests import RepositoryRetryEmbeddings
from Graph.request_pacing import MinimumIntervalPacer
from Graph.resilience import RetryPolicy
from Graph.reporting import (
    configure_console,
    get_logger,
    render_benchmark_results,
    render_runtime_config,
    report_error,
)
from Graph.stage_timing import StageTimingCallback


LOGGER = get_logger("runner")


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

def _write_log(output_file: Path, log: dict) -> None:
    with open(output_file, "w", encoding="utf-8") as handle:
        json.dump(log, handle, indent=2)


def _run_cases(
    pipeline_instance,
    pipeline_names: list[str],
    runtime_config: RuntimeConfig,
    taxonomy: Taxonomy,
    cases: Sequence[BenchmarkCase | str],
    output_file: Path,
    *,
    benchmark: Benchmark | None = None,
    run_number: int | None = None,
):
    """Persist each result while isolating failures to individual CVEs."""

    run_folder = runtime_config.evaluation.resolved_log_directory()
    os.makedirs(run_folder, exist_ok=True)
    mode = "benchmark" if benchmark is not None else "classification"
    run_label = f"[Run {run_number}]" if benchmark is not None else "[Classification]"
    LOGGER.info("%s Starting. Log: %s", run_label, output_file)

    metadata = {
        "run_id": "_".join(pipeline_names),
        "mode": mode,
        "pipeline_structure": pipeline_names,
        "models": runtime_config.model_metadata,
        "taxonomy_name": taxonomy.name,
        "taxonomy_file": str(taxonomy.source_path),
        "taxonomy_sha256": taxonomy.fingerprint,
        "labels_schema": taxonomy.descriptions,
    }
    if benchmark is not None:
        metadata["RUN_N"] = run_number + 1
        metadata["expected_classification_file"] = str(benchmark.source_path)
    log = {"pipeline_metadata": metadata, "cves": {}}
    if benchmark is not None:
        log["aggregated_scores"] = {}

    all_y_true: list[list[str]] = []
    all_y_pred: list[list[str]] = []
    for case in cases:
        cve_id = case.cve_id if isinstance(case, BenchmarkCase) else case
        expected = list(case.labels) if isinstance(case, BenchmarkCase) else None
        case_metadata = (
            {
                "expected_labels": expected,
                "rationale": case.rationale,
                "sources": list(case.sources),
            }
            if isinstance(case, BenchmarkCase)
            else {}
        )
        LOGGER.info("%s Analyzing %s", run_label, cve_id)
        stage_timer = StageTimingCallback(pipeline_names)
        try:
            started = time.time()
            if isinstance(pipeline_instance, lcr.RunnableSequence):
                state = pipeline_instance.invoke(
                    {"cve_id": cve_id}, config={"callbacks": [stage_timer]}
                )
            else:
                state = pipeline_instance.invoke({"cve_id": cve_id})
            elapsed = time.time() - started
            predicted = state["cve_labels"]
            warnings = list(state.get("pipeline_warnings", []))
            status = "degraded" if warnings else "success"
            entry = {
                "status": status,
                "pipeline_warnings": warnings,
                "nvd_description": state.get("nvd_description", ""),
                "nvd_references_pages": state.get("nvd_references_pages", {}),
                "nvd_references_chunks": state.get("nvd_references_chunks", {}),
                "nvd_filtered_chunks": state.get("nvd_filtered_chunks", {}),
                "summaries": state.get("summaries", {}),
                "rag_input": state.get("rag", ""),
                "classification_output": predicted,
                "required_time": elapsed,
                "labels_motivation": state.get("labels_motivation", []),
                "labels_confidence": state.get("labels_confidence", []),
                **case_metadata,
            }
            if state.get("reference_focus"):
                entry["reference_focus"] = state["reference_focus"]
            if stage_timer.records:
                entry["stage_timings"] = stage_timer.records
            if expected is not None:
                entry["individual_scores"] = compute_individual_scores(
                    expected, predicted, taxonomy.all_labels
                )
                all_y_true.append(expected)
                all_y_pred.append(predicted)
            log["cves"][cve_id] = entry
            LOGGER.info(
                "%s %s finished: status=%s labels=%s duration=%.2fs",
                run_label,
                cve_id,
                status,
                predicted,
                elapsed,
            )
        except Exception as error:
            details, safe_message = _serialize_pipeline_error(error, cve_id)
            technical_error = (
                error.original_error if isinstance(error, PipelineStageError) else error
            )
            report_error(LOGGER, f"{run_label} {safe_message}", technical_error)
            error_entry = {
                "status": "error",
                "pipeline_warnings": [],
                "error": details,
                "error_message": safe_message,
                "classification_output": ["ERROR"],
                **case_metadata,
            }
            if stage_timer.records:
                error_entry["stage_timings"] = stage_timer.records
            log["cves"][cve_id] = error_entry
        _write_log(output_file, log)
        LOGGER.debug("%s Log updated for %s", run_label, cve_id)

    statuses = [entry["status"] for entry in log["cves"].values()]
    successful = statuses.count("success")
    degraded = statuses.count("degraded")
    failed = statuses.count("error")
    if benchmark is not None:
        aggregation_complete = True
        if all_y_true:
            try:
                log["aggregated_scores"] = compute_grouped_scores(
                    all_y_true, all_y_pred, taxonomy.all_labels
                )
            except Exception as error:
                report_error(LOGGER, f"{run_label} Aggregate metric computation failed", error)
                aggregation_complete = False
                log["aggregated_scores"] = {
                    "error": "Aggregate metric computation failed",
                    "error_type": type(error).__name__,
                }
        else:
            log["aggregated_scores"] = {"note": "No successful predictions to aggregate."}
        log["aggregated_scores"].update(
            {
                "total": len(cases),
                "scored": len(all_y_true),
                "successful": successful,
                "degraded": degraded,
                "failed": failed,
                "complete": aggregation_complete and failed == 0 and len(all_y_true) == len(cases),
            }
        )
        _write_log(output_file, log)
        LOGGER.info(
            "\n%s",
            render_benchmark_results(log["cves"], log["aggregated_scores"]),
        )

    LOGGER.info(
        "%s Completed: successful=%s degraded=%s failed=%s file=%s",
        run_label,
        successful,
        degraded,
        failed,
        output_file.resolve(),
    )
    return f"Finished: Run {run_number}" if benchmark is not None else "Finished: Classification"


def run_evaluation(
    pipeline_instance,
    pipeline_names: list[str],
    runtime_config: RuntimeConfig,
    taxonomy: Taxonomy,
    benchmark: Benchmark,
    run_number: int | None = None,
):
    """Score the selected benchmark cases in their requested order."""

    if benchmark.taxonomy_sha256 != taxonomy.fingerprint:
        raise FixtureError("Benchmark does not match the selected taxonomy")
    if run_number is None:
        run_number = runtime_config.evaluation.run_number
    output_file = runtime_config.evaluation.resolved_log_directory() / f"RUN_{run_number}.json"
    return _run_cases(
        pipeline_instance,
        pipeline_names,
        runtime_config,
        taxonomy,
        benchmark.cases,
        output_file,
        benchmark=benchmark,
        run_number=run_number,
    )


def run_classification(
    pipeline_instance,
    pipeline_names: list[str],
    runtime_config: RuntimeConfig,
    taxonomy: Taxonomy,
    cve_ids: Sequence[str],
):
    """Classify explicit CVEs without ground-truth scoring."""

    normalized_ids = [normalize_cve_id(cve_id) for cve_id in cve_ids]
    if not normalized_ids or len(normalized_ids) != len(set(normalized_ids)):
        raise FixtureError("Classification requires unique CVE IDs")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output_file = (
        runtime_config.evaluation.resolved_log_directory()
        / f"CLASSIFY_{stamp}_{uuid4().hex[:8]}.json"
    )
    return _run_cases(
        pipeline_instance,
        pipeline_names,
        runtime_config,
        taxonomy,
        normalized_ids,
        output_file,
    )


def build_pipeline(runtime_config: RuntimeConfig, taxonomy: Taxonomy):
    """Construct the configured live linear pipeline after validation."""

    LOGGER.debug("Constructing embedding client and linear pipeline")

    retry_settings = runtime_config.resilience
    embedding_settings = runtime_config.embedding
    embedding_timeout = httpx.Timeout(
        connect=embedding_settings.connect_timeout_seconds,
        read=embedding_settings.read_timeout_seconds,
        write=embedding_settings.write_timeout_seconds,
        pool=embedding_settings.pool_timeout_seconds,
    )
    embedding_http_client = DefaultHttpxClient(timeout=embedding_timeout)

    raw_embedding_model = OpenAIEmbeddings(
        model=embedding_settings.model,
        api_key=embedding_settings.api_key,
        base_url=embedding_settings.base_url,
        http_client=embedding_http_client,
        check_embedding_ctx_length=embedding_settings.check_embedding_ctx_length,
        max_retries=0,
        timeout=embedding_timeout,
    )
    embedding_model_instance = RepositoryRetryEmbeddings(
        raw_embedding_model,
        model_name=embedding_settings.model,
        retry_policy=RetryPolicy(
            max_attempts=embedding_settings.max_attempts,
            initial_backoff_seconds=retry_settings.initial_backoff_seconds,
            max_backoff_seconds=retry_settings.max_backoff_seconds,
            max_retry_after_seconds=retry_settings.max_retry_after_seconds,
        ),
        pacer=MinimumIntervalPacer(embedding_settings.request_delay_seconds),
    )

    semantic_chunker = SemanticChunkerNode(
        embed_model=embedding_model_instance,
        breakpoint_threshold_type=(
            runtime_config.semantic_chunker.breakpoint_threshold_type
        ),
        breakpoint_threshold_amount=(
            runtime_config.semantic_chunker.breakpoint_threshold_amount
        ),
        max_chunks_per_reference=(
            runtime_config.semantic_chunker.max_chunks_per_reference
        ),
        max_chunks_per_cve=runtime_config.semantic_chunker.max_chunks_per_cve,
    )

    cosine_filter = CosineFilterNode(
        query=runtime_config.cosine_filter.query,
        embed_model=embedding_model_instance,
        threshold=runtime_config.cosine_filter.threshold,
    )

    chat_settings = runtime_config.chat
    chat_timeout = httpx.Timeout(
        connect=chat_settings.connect_timeout_seconds,
        read=chat_settings.read_timeout_seconds,
        write=chat_settings.write_timeout_seconds,
        pool=chat_settings.pool_timeout_seconds,
    )
    chat_http_client = DefaultHttpxClient(timeout=chat_timeout)
    chat_pacer = MinimumIntervalPacer(chat_settings.request_delay_seconds)

    summarizer_llm = init_chat_model(
        model=chat_settings.summarizer_model,
        model_provider="openai",
        api_key=chat_settings.api_key,
        base_url=chat_settings.base_url,
        temperature=chat_settings.summarizer_temperature,
        http_client=chat_http_client,
        timeout=chat_timeout,
        max_retries=0,
        max_tokens=runtime_config.summarization.max_output_tokens,
        include_response_headers=True,
    )

    summarizer = CVEAwareSummarizerNode(
        model=summarizer_llm,
        labels_descriptions=taxonomy.root_descriptions,
        model_name=chat_settings.summarizer_model,
        retry_policy=RetryPolicy(
            max_attempts=runtime_config.summarization.max_attempts,
            initial_backoff_seconds=retry_settings.initial_backoff_seconds,
            max_backoff_seconds=retry_settings.max_backoff_seconds,
            max_retry_after_seconds=retry_settings.max_retry_after_seconds,
        ),
        request_pacer=chat_pacer,
        max_input_tokens=runtime_config.summarization.max_input_tokens,
        max_output_tokens=runtime_config.summarization.max_output_tokens,
        structured_repair_attempts=(
            runtime_config.summarization.structured_repair_attempts
        ),
    )

    classifier_llm = init_chat_model(
        model=chat_settings.classifier_model,
        model_provider="openai",
        api_key=chat_settings.api_key,
        base_url=chat_settings.base_url,
        temperature=chat_settings.classifier_temperature,
        http_client=chat_http_client,
        timeout=chat_timeout,
        max_retries=0,
        max_tokens=runtime_config.classification.max_output_tokens,
        include_response_headers=True,
    )

    classifier = CVEClassifierNode(
        model=classifier_llm,
        taxonomy=taxonomy,
        max_input_tokens=runtime_config.classification.max_input_tokens,
        model_name=chat_settings.classifier_model,
        retry_policy=RetryPolicy(
            max_attempts=runtime_config.classification.max_attempts,
            initial_backoff_seconds=retry_settings.initial_backoff_seconds,
            max_backoff_seconds=retry_settings.max_backoff_seconds,
            max_retry_after_seconds=retry_settings.max_retry_after_seconds,
        ),
        request_pacer=chat_pacer,
        max_output_tokens=runtime_config.classification.max_output_tokens,
        structured_repair_attempts=(
            runtime_config.classification.structured_repair_attempts
        ),
    )

    nvd_session = requests.Session()
    configured_nvd_caller = partial(
        nvd_caller,
        base_url=runtime_config.nvd.base_url,
        timeout_seconds=runtime_config.nvd.timeout_seconds,
        connect_timeout_seconds=runtime_config.nvd.connect_timeout_seconds,
        retry_policy=RetryPolicy(
            max_attempts=runtime_config.nvd.max_attempts,
            initial_backoff_seconds=retry_settings.initial_backoff_seconds,
            max_backoff_seconds=retry_settings.max_backoff_seconds,
            max_retry_after_seconds=retry_settings.max_retry_after_seconds,
        ),
        session=nvd_session,
        api_key=runtime_config.nvd.api_key,
        request_pacer=MinimumIntervalPacer(
            runtime_config.nvd.request_delay_seconds
        ),
    )
    configured_nvd_caller.__name__ = nvd_caller.__name__
    configured_scraper = partial(
        extract_md_trafilatura,
        max_pages=runtime_config.references.max_pages,
        max_attempts=runtime_config.references.max_attempts,
        connect_timeout_seconds=runtime_config.references.connect_timeout_seconds,
        read_timeout_seconds=runtime_config.references.read_timeout_seconds,
        max_redirects=runtime_config.references.max_redirects,
        max_bytes_per_reference=runtime_config.references.max_bytes_per_reference,
        max_bytes_per_cve=runtime_config.references.max_bytes_per_cve,
        max_extracted_chars_per_reference=(
            runtime_config.references.max_extracted_chars_per_reference
        ),
        max_extracted_chars_per_cve=(
            runtime_config.references.max_extracted_chars_per_cve
        ),
        retry_policy=RetryPolicy(
            max_attempts=runtime_config.references.max_attempts,
            initial_backoff_seconds=retry_settings.initial_backoff_seconds,
            max_backoff_seconds=retry_settings.max_backoff_seconds,
            max_retry_after_seconds=retry_settings.max_retry_after_seconds,
        ),
        request_pacer=MinimumIntervalPacer(0.0),
        session=requests.Session(),
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

    LOGGER.debug("Pipeline components: %s", " -> ".join(pipeline_component_names))
    return pipeline, pipeline_component_names


def main(
    *,
    verbose: bool = False,
    benchmark: bool = False,
    cve_ids: Sequence[str] = (),
):
    """Build one live pipeline for the requested CVEs, optionally with scoring."""

    if not cve_ids:
        raise ValueError("Provide one or more CVE IDs")
    normalized_ids = [normalize_cve_id(cve_id) for cve_id in cve_ids]
    if len(normalized_ids) != len(set(normalized_ids)):
        raise FixtureError("Duplicate CVE IDs are not allowed")

    configure_console(verbose=verbose)
    runtime_config = validate_runtime_config()
    taxonomy = load_taxonomy(runtime_config.fixtures.resolved_taxonomy_file())
    selected_benchmark = None
    if benchmark:
        expected_path = runtime_config.fixtures.resolved_expected_classification_file()
        if expected_path is None:
            raise FixtureError(
                "--benchmark requires [fixtures].expected_classification_file"
            )
        selected_benchmark = load_benchmark(expected_path, taxonomy).select(normalized_ids)
    configure_console(
        verbose=verbose,
        sensitive_values=(
            runtime_config.chat.api_key,
            runtime_config.embedding.api_key,
            runtime_config.nvd.api_key or "",
        ),
    )
    if verbose:
        LOGGER.debug(
            "\n%s",
            render_runtime_config(
                runtime_config,
                config_path=CONFIG_PATH,
                cve_count=(
                    len(selected_benchmark.cases)
                    if selected_benchmark is not None
                    else len(normalized_ids)
                ),
            ),
        )
    pipeline, pipeline_component_names = build_pipeline(runtime_config, taxonomy)
    if selected_benchmark is not None:
        return run_evaluation(
            pipeline,
            pipeline_component_names,
            runtime_config,
            taxonomy,
            selected_benchmark,
        )
    return run_classification(
        pipeline,
        pipeline_component_names,
        runtime_config,
        taxonomy,
        normalized_ids,
    )


def cli(argv: Sequence[str] | None = None) -> int:
    """Run the command-line entry point with concise top-level failures."""

    parser = argparse.ArgumentParser(
        description="Classify CVEs, optionally scoring them against configured expected classifications.",
    )
    parser.add_argument(
        "cve_ids",
        metavar="CVE-ID",
        nargs="*",
        help="one or more CVE IDs to classify",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="score the requested CVEs against the JSON selected in config.toml",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show the effective configuration and detailed stage summaries",
    )
    args = parser.parse_args(argv)
    if not args.cve_ids:
        parser.error("provide one or more CVE IDs")
    configure_console(verbose=args.verbose)

    try:
        main(
            verbose=args.verbose,
            benchmark=args.benchmark,
            cve_ids=args.cve_ids,
        )
    except KeyboardInterrupt:
        LOGGER.error("ERROR Pipeline interrupted by the user")
        return 130
    except Exception as error:
        report_error(LOGGER, "Pipeline setup or execution failed", error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
