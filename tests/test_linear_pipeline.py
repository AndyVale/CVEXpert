from contextlib import redirect_stderr
from dataclasses import replace
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Definitions.config import (
    ChatSettings,
    ClassificationSettings,
    CosineFilterSettings,
    EmbeddingSettings,
    EvaluationSettings,
    FixtureSettings,
    NvdSettings,
    ReferenceSettings,
    RuntimeConfig,
    SemanticChunkerSettings,
)
from Definitions.fixtures import Benchmark, BenchmarkCase, Taxonomy, TaxonomyLabel
from Graph.errors import PipelineStageError
from Graph.Nodes.evaluators import compute_grouped_scores, compute_individual_scores
from Graph.Nodes.formatters import formatter
from Graph.Nodes.util import StateFromFileLoader

import CVE_expert_seq


TEST_TAXONOMY = Taxonomy(
    name="Test mechanisms",
    labels=(
        TaxonomyLabel("XSS", "Cross-site scripting", "Browser script execution"),
        TaxonomyLabel("SQLi", "SQL injection", "SQL syntax injection"),
    ),
    fingerprint="test-fingerprint",
    source_path=Path("/tmp/test-taxonomy.json"),
)
ALL_LABELS = TEST_TAXONOMY.all_labels


def make_benchmark(expected: dict[str, list[str]]) -> Benchmark:
    return Benchmark(
        cases=tuple(
            BenchmarkCase(cve_id, tuple(labels), f"Why {cve_id}", ("https://source.test",))
            for cve_id, labels in expected.items()
        ),
        source_path=Path("/tmp/expected.json"),
        taxonomy_sha256=TEST_TAXONOMY.fingerprint,
    )


def make_runtime_config(log_directory: str) -> RuntimeConfig:
    return RuntimeConfig(
        chat=ChatSettings(
            base_url="https://chat.example.test/v1",
            api_key="chat-token",
            classifier_model="classifier-model",
            classifier_temperature=0.0,
            summarizer_model="summarizer-model",
            summarizer_temperature=0.0,
            request_delay_seconds=4.2,
        ),
        embedding=EmbeddingSettings(
            base_url="https://embedding.example.test/v1",
            api_key="embedding-token",
            model="embedding-model",
            request_delay_seconds=0.7,
            check_embedding_ctx_length=False,
        ),
        nvd=NvdSettings(
            base_url="https://nvd.example.test/cves/2.0",
            timeout_seconds=20.0,
            request_delay_seconds=6.1,
        ),
        references=ReferenceSettings(max_pages=10),
        semantic_chunker=SemanticChunkerSettings(
            breakpoint_threshold_type="percentile",
            breakpoint_threshold_amount=25.0,
        ),
        cosine_filter=CosineFilterSettings(
            query="relevance query",
            threshold=0.6,
        ),
        fixtures=FixtureSettings(
            taxonomy_file="fixtures/flat/taxonomy.json",
            expected_classification_file="fixtures/flat/expected-classification.json",
        ),
        classification=ClassificationSettings(max_input_tokens=12000),
        evaluation=EvaluationSettings(
            log_directory=log_directory,
            run_number=0,
        ),
    )


class FakePipeline:
    def __init__(self, states):
        self.states = states
        self.invocations = []

    def invoke(self, state):
        cve_id = state["cve_id"]
        self.invocations.append(cve_id)
        result = self.states[cve_id]
        if isinstance(result, BaseException):
            raise result
        return {"cve_id": cve_id, **result}


class FakeEmbeddingsClient:
    def embed_query(self, _query):
        return [1.0, 0.0]

    def embed_documents(self, documents):
        return [[1.0, 0.0] for _document in documents]


class FakeChatClient:
    def with_structured_output(self, _schema):
        return self


class EvaluatorTests(unittest.TestCase):
    def test_individual_exact_match_scores_one(self):
        scores = compute_individual_scores(["XSS"], ["XSS"], ALL_LABELS)

        self.assertEqual(
            scores,
            {"accuracy": 1.0, "precision": 1.0, "recall": 1.0, "f1": 1.0},
        )

    def test_grouped_scores_cover_multiple_cves(self):
        scores = compute_grouped_scores(
            [["XSS"], ["SQLi"]],
            [["XSS"], ["SQLi"]],
            ALL_LABELS,
        )

        self.assertEqual(scores["accuracy"], 1.0)
        self.assertEqual(scores["precision"], 1.0)
        self.assertEqual(scores["recall"], 1.0)
        self.assertEqual(scores["f1"], 1.0)

    def test_empty_prediction_scores_zero_without_metric_failure(self):
        scores = compute_individual_scores(["XSS"], [], ALL_LABELS)

        self.assertEqual(
            scores,
            {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1": 0.0},
        )

    def test_exact_match_accuracy_counts_complete_label_sets(self):
        scores = compute_grouped_scores(
            [["XSS"], ["SQLi"]],
            [["XSS"], ["XSS", "SQLi"]],
            ALL_LABELS,
        )

        self.assertEqual(scores["accuracy"], 0.5)
        self.assertEqual(scores["recall"], 1.0)
        self.assertLess(scores["precision"], 1.0)


class FormatterTests(unittest.TestCase):
    def test_formatter_combines_nvd_and_reference_summaries(self):
        state = formatter(
            {
                "cve_id": "CVE-TEST-1",
                "nvd_description": "Primary description",
                "summaries": {
                    "https://example.test/one": "First insight",
                    "https://example.test/two": "Second insight",
                },
            }
        )

        self.assertIn("Primary description", state["rag"])
        self.assertIn("[Technical Insight from Reference 1]", state["rag"])
        self.assertIn("First insight", state["rag"])
        self.assertIn("Second insight", state["rag"])

    def test_formatter_supports_nvd_only_context(self):
        state = formatter(
            {
                "cve_id": "CVE-TEST-1",
                "nvd_description": "Primary description",
                "summaries": {},
            }
        )

        self.assertIn("No additional technical references provided.", state["rag"])


class StateLoaderTests(unittest.TestCase):
    def test_loader_restores_selected_successful_fields(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "run.json"
            log_path.write_text(
                json.dumps(
                    {
                        "cves": {
                            "CVE-TEST-1": {
                                "status": "success",
                                "nvd_description": "Cached description",
                                "nvd_filtered_chunks": {"url": ["chunk"]},
                                "classification_output": ["XSS"],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            loader = StateFromFileLoader(
                str(log_path),
                fields_to_load=["nvd_description", "nvd_filtered_chunks"],
            )
            state = loader({"cve_id": "CVE-TEST-1"})

        self.assertEqual(state["nvd_description"], "Cached description")
        self.assertEqual(state["nvd_filtered_chunks"], {"url": ["chunk"]})
        self.assertNotIn("classification_output", state)


class RunnerTests(unittest.TestCase):
    def test_build_pipeline_uses_provider_neutral_toml_settings(self):
        runtime_config = make_runtime_config("logs/test-run")
        embeddings_client = FakeEmbeddingsClient()
        chat_client = FakeChatClient()
        embedding_http_client = object()
        chat_http_client = object()

        with (
            patch.object(
                CVE_expert_seq,
                "DefaultHttpxClient",
                side_effect=[embedding_http_client, chat_http_client],
            ) as http_client_factory,
            patch.object(
                CVE_expert_seq,
                "OpenAIEmbeddings",
                return_value=embeddings_client,
            ) as embeddings_factory,
            patch.object(
                CVE_expert_seq,
                "init_chat_model",
                return_value=chat_client,
            ) as chat_factory,
        ):
            pipeline, component_names = CVE_expert_seq.build_pipeline(runtime_config, TEST_TAXONOMY)

        embeddings_factory.assert_called_once_with(
            model="embedding-model",
            api_key="embedding-token",
            base_url="https://embedding.example.test/v1",
            http_client=embedding_http_client,
            check_embedding_ctx_length=False,
        )
        self.assertEqual(
            [call.kwargs for call in chat_factory.call_args_list],
            [
                {
                    "model": "summarizer-model",
                    "model_provider": "openai",
                    "api_key": "chat-token",
                    "base_url": "https://chat.example.test/v1",
                    "temperature": 0.0,
                    "http_client": chat_http_client,
                },
                {
                    "model": "classifier-model",
                    "model_provider": "openai",
                    "api_key": "chat-token",
                    "base_url": "https://chat.example.test/v1",
                    "temperature": 0.0,
                    "http_client": chat_http_client,
                },
            ],
        )
        self.assertEqual(http_client_factory.call_count, 2)
        embedding_pacer = http_client_factory.call_args_list[0].kwargs[
            "event_hooks"
        ]["request"][0]
        chat_pacer = http_client_factory.call_args_list[1].kwargs[
            "event_hooks"
        ]["request"][0]
        self.assertEqual(embedding_pacer.minimum_interval_seconds, 0.7)
        self.assertEqual(chat_pacer.minimum_interval_seconds, 4.2)
        nvd_arguments = pipeline.steps[0].func.keywords
        self.assertEqual(
            nvd_arguments["base_url"],
            "https://nvd.example.test/cves/2.0",
        )
        self.assertEqual(nvd_arguments["timeout_seconds"], 20.0)
        self.assertEqual(
            nvd_arguments["request_pacer"].minimum_interval_seconds,
            6.1,
        )
        self.assertEqual(pipeline.steps[1].func.keywords, {"max_pages": 10})
        self.assertEqual(
            pipeline.steps[4].func.labels_descriptions,
            TEST_TAXONOMY.root_descriptions,
        )
        self.assertIs(pipeline.steps[6].func.taxonomy, TEST_TAXONOMY)
        self.assertEqual(
            component_names,
            [
                "nvd_caller",
                "extract_md_trafilatura",
                "SemanticChunkerNode",
                "CosineFilterNode",
                "CVEAwareSummarizerNode",
                "formatter",
                "CVEClassifierNode",
            ],
        )

    def test_successful_run_writes_expected_artifacts_and_scores(self):
        test_cves = {"CVE-TEST-1": ["XSS"]}
        pipeline = FakePipeline(
            {
                "CVE-TEST-1": {
                    "nvd_description": "Description",
                    "nvd_references_pages": {},
                    "nvd_references_chunks": {},
                    "nvd_filtered_chunks": {},
                    "summaries": {},
                    "rag": "Context",
                    "cve_labels": ["XSS"],
                }
            }
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output_directory = Path(temp_dir) / "logs" / "test-run"
            runtime_config = make_runtime_config(str(output_directory))
            result = CVE_expert_seq.run_evaluation(
                pipeline,
                ["FakePipeline"],
                runtime_config,
                TEST_TAXONOMY,
                make_benchmark(test_cves),
                run_number=0,
            )

            output_path = output_directory / "RUN_0.json"
            log = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(result, "Finished: Run 0")
        self.assertEqual(pipeline.invocations, ["CVE-TEST-1"])
        self.assertEqual(log["cves"]["CVE-TEST-1"]["status"], "success")
        self.assertEqual(
            log["cves"]["CVE-TEST-1"]["classification_output"],
            ["XSS"],
        )
        self.assertEqual(log["aggregated_scores"]["f1"], 1.0)
        self.assertEqual(log["aggregated_scores"]["accuracy"], 1.0)
        self.assertEqual(log["pipeline_metadata"]["taxonomy_sha256"], "test-fingerprint")
        self.assertEqual(log["cves"]["CVE-TEST-1"]["rationale"], "Why CVE-TEST-1")
        self.assertEqual(log["cves"]["CVE-TEST-1"]["sources"], ["https://source.test"])

    def test_benchmark_log_and_scores_cover_only_requested_subset(self):
        benchmark = make_benchmark({
            "CVE-2024-0001": ["XSS"],
            "CVE-2024-0002": ["SQLi"],
            "CVE-2024-0003": ["XSS"],
        }).select(["CVE-2024-0003", "CVE-2024-0002"])
        pipeline = FakePipeline({
            "CVE-2024-0003": {"cve_labels": ["XSS"]},
            "CVE-2024-0002": {"cve_labels": ["XSS"]},
        })

        with tempfile.TemporaryDirectory() as temp_dir:
            CVE_expert_seq.run_evaluation(
                pipeline, ["FakePipeline"], make_runtime_config(temp_dir),
                TEST_TAXONOMY, benchmark,
            )
            log = json.loads((Path(temp_dir) / "RUN_0.json").read_text(encoding="utf-8"))

        self.assertEqual(pipeline.invocations, ["CVE-2024-0003", "CVE-2024-0002"])
        self.assertEqual(list(log["cves"]), pipeline.invocations)
        self.assertEqual(log["aggregated_scores"]["total"], 2)
        self.assertEqual(log["aggregated_scores"]["scored"], 2)
        self.assertEqual(log["aggregated_scores"]["accuracy"], 0.5)
        self.assertEqual(log["cves"]["CVE-2024-0002"]["individual_scores"]["accuracy"], 0.0)

    def test_run_reports_degraded_and_terminal_error_coverage(self):
        test_cves = {
            "CVE-SUCCESS": ["XSS"],
            "CVE-DEGRADED": ["SQLi"],
            "CVE-ERROR": ["XSS"],
        }
        warning = {
            "stage": "scrape",
            "source": "https://failed.example.test",
            "error_type": "TimeoutError",
            "message": "Reference download or text extraction failed",
        }
        pipeline = FakePipeline(
            {
                "CVE-SUCCESS": {
                    "nvd_description": "Description",
                    "summaries": {},
                    "rag": "Context",
                    "cve_labels": ["XSS"],
                },
                "CVE-DEGRADED": {
                    "nvd_description": "Description",
                    "summaries": {"url": "Usable evidence"},
                    "rag": "Context with usable evidence",
                    "cve_labels": ["SQLi"],
                    "pipeline_warnings": [warning],
                },
                "CVE-ERROR": PipelineStageError(
                    stage="nvd",
                    cve_id="CVE-ERROR",
                    error=TimeoutError("upstream details"),
                    safe_message="NVD request or response parsing failed",
                ),
            }
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output_directory = Path(temp_dir) / "logs" / "test-run"
            runtime_config = make_runtime_config(str(output_directory))
            CVE_expert_seq.run_evaluation(
                pipeline,
                ["FakePipeline"],
                runtime_config,
                TEST_TAXONOMY,
                make_benchmark(test_cves),
                run_number=0,
            )

            output_path = output_directory / "RUN_0.json"
            log = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(log["cves"]["CVE-SUCCESS"]["status"], "success")
        self.assertEqual(pipeline.invocations, list(test_cves))
        self.assertEqual(log["cves"]["CVE-DEGRADED"]["status"], "degraded")
        self.assertEqual(
            log["cves"]["CVE-DEGRADED"]["pipeline_warnings"],
            [warning],
        )
        terminal_entry = log["cves"]["CVE-ERROR"]
        self.assertEqual(terminal_entry["status"], "error")
        self.assertEqual(terminal_entry["classification_output"], ["ERROR"])
        self.assertEqual(terminal_entry["error"]["stage"], "nvd")
        self.assertIn("error_message", terminal_entry)
        self.assertEqual(
            log["aggregated_scores"],
            {
                "accuracy": 1.0,
                "precision": 1.0,
                "recall": 1.0,
                "f1": 1.0,
                "total": 3,
                "scored": 2,
                "successful": 1,
                "degraded": 1,
                "failed": 1,
                "complete": False,
            },
        )

    def test_classification_mode_writes_distinct_unscored_logs(self):
        pipeline = FakePipeline({
            "CVE-2024-0001": {"nvd_description": "Description", "cve_labels": ["XSS"]}
        })
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_config = make_runtime_config(temp_dir)
            first = CVE_expert_seq.run_classification(
                pipeline, ["FakePipeline"], runtime_config, TEST_TAXONOMY,
                ["CVE-2024-0001"],
            )
            second = CVE_expert_seq.run_classification(
                pipeline, ["FakePipeline"], runtime_config, TEST_TAXONOMY,
                ["CVE-2024-0001"],
            )
            output_paths = list(Path(temp_dir).glob("CLASSIFY_*.json"))
            logs = [json.loads(path.read_text(encoding="utf-8")) for path in output_paths]

        self.assertEqual(first, "Finished: Classification")
        self.assertEqual(second, "Finished: Classification")
        self.assertEqual(len(output_paths), 2)
        for log in logs:
            self.assertEqual(log["pipeline_metadata"]["mode"], "classification")
            self.assertNotIn("aggregated_scores", log)
            entry = log["cves"]["CVE-2024-0001"]
            self.assertEqual(entry["classification_output"], ["XSS"])
            self.assertNotIn("expected_labels", entry)
            self.assertNotIn("individual_scores", entry)

    def test_runner_rejects_mismatched_benchmark_before_writing_log(self):
        wrong = replace(
            make_benchmark({"CVE-2024-0001": ["XSS"]}),
            taxonomy_sha256="wrong",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime_config = make_runtime_config(temp_dir)
            with self.assertRaisesRegex(ValueError, "does not match"):
                CVE_expert_seq.run_evaluation(
                    FakePipeline({}), ["FakePipeline"], runtime_config,
                    TEST_TAXONOMY, wrong,
                )
            self.assertEqual(list(Path(temp_dir).iterdir()), [])

    def test_main_builds_and_runs_one_evaluation(self):
        pipeline = FakePipeline({})
        runtime_config = make_runtime_config("logs/test-run")
        benchmark = make_benchmark({"CVE-2024-0001": ["XSS"]})
        with (
            patch.object(CVE_expert_seq, "configure_console"),
            patch.object(
                CVE_expert_seq,
                "validate_runtime_config",
                return_value=runtime_config,
            ) as validate,
            patch.object(CVE_expert_seq, "load_taxonomy", return_value=TEST_TAXONOMY) as load_taxonomy,
            patch.object(CVE_expert_seq, "load_benchmark", return_value=benchmark) as load_benchmark,
            patch.object(
                CVE_expert_seq,
                "build_pipeline",
                return_value=(pipeline, ["FakePipeline"]),
            ) as build,
            patch.object(
                CVE_expert_seq,
                "run_evaluation",
                return_value="Finished: Run 0",
            ) as run,
        ):
            result = CVE_expert_seq.main(benchmark=True, cve_ids=["CVE-2024-0001"])

        validate.assert_called_once_with()
        load_taxonomy.assert_called_once_with(runtime_config.fixtures.resolved_taxonomy_file())
        load_benchmark.assert_called_once_with(
            runtime_config.fixtures.resolved_expected_classification_file(), TEST_TAXONOMY
        )
        build.assert_called_once_with(runtime_config, TEST_TAXONOMY)
        run.assert_called_once_with(
            pipeline,
            ["FakePipeline"],
            runtime_config,
            TEST_TAXONOMY,
            benchmark,
        )
        self.assertEqual(result, "Finished: Run 0")
        self.assertFalse(hasattr(CVE_expert_seq, "concurrent"))

    def test_main_renders_configuration_only_in_verbose_mode(self):
        pipeline = FakePipeline({})
        runtime_config = make_runtime_config("logs/test-run")
        benchmark = make_benchmark({"CVE-2024-0001": ["XSS"]})
        with (
            patch.object(CVE_expert_seq, "configure_console"),
            patch.object(
                CVE_expert_seq,
                "validate_runtime_config",
                return_value=runtime_config,
            ),
            patch.object(CVE_expert_seq, "load_taxonomy", return_value=TEST_TAXONOMY),
            patch.object(CVE_expert_seq, "load_benchmark", return_value=benchmark),
            patch.object(
                CVE_expert_seq,
                "build_pipeline",
                return_value=(pipeline, ["FakePipeline"]),
            ),
            patch.object(
                CVE_expert_seq,
                "run_evaluation",
                return_value="Finished: Run 0",
            ),
            patch.object(
                CVE_expert_seq,
                "render_runtime_config",
                return_value="CONFIG TABLE",
            ) as render_config,
        ):
            CVE_expert_seq.main(verbose=False, benchmark=True, cve_ids=["CVE-2024-0001"])
            render_config.assert_not_called()

            CVE_expert_seq.main(verbose=True, benchmark=True, cve_ids=["CVE-2024-0001"])
            render_config.assert_called_once()

    def test_main_classifies_explicit_ids_without_loading_configured_benchmark(self):
        runtime_config = make_runtime_config("logs/test-run")
        pipeline = FakePipeline({})
        with (
            patch.object(CVE_expert_seq, "configure_console"),
            patch.object(CVE_expert_seq, "validate_runtime_config", return_value=runtime_config),
            patch.object(CVE_expert_seq, "load_taxonomy", return_value=TEST_TAXONOMY),
            patch.object(CVE_expert_seq, "load_benchmark") as load_benchmark,
            patch.object(CVE_expert_seq, "build_pipeline", return_value=(pipeline, ["FakePipeline"])),
            patch.object(CVE_expert_seq, "run_classification", return_value="Finished: Classification") as run,
        ):
            result = CVE_expert_seq.main(cve_ids=["cve-2024-0001"])

        self.assertEqual(result, "Finished: Classification")
        load_benchmark.assert_not_called()
        run.assert_called_once_with(
            pipeline, ["FakePipeline"], runtime_config, TEST_TAXONOMY,
            ["CVE-2024-0001"],
        )

    def test_main_requires_dataset_path_for_benchmark_before_client_creation(self):
        runtime_config = make_runtime_config("logs/test-run")
        runtime_config = replace(runtime_config, fixtures=FixtureSettings(
            taxonomy_file="fixtures/flat/taxonomy.json",
            expected_classification_file=None,
        ))
        with (
            patch.object(CVE_expert_seq, "validate_runtime_config", return_value=runtime_config),
            patch.object(CVE_expert_seq, "load_taxonomy", return_value=TEST_TAXONOMY),
            patch.object(CVE_expert_seq, "build_pipeline") as build,
            self.assertRaisesRegex(ValueError, "expected_classification_file"),
        ):
            CVE_expert_seq.main(benchmark=True, cve_ids=["CVE-2024-0001"])
        build.assert_not_called()

    def test_main_rejects_missing_expected_cve_before_client_creation(self):
        runtime_config = make_runtime_config("logs/test-run")
        benchmark = make_benchmark({"CVE-2024-0001": ["XSS"]})
        with (
            patch.object(CVE_expert_seq, "validate_runtime_config", return_value=runtime_config),
            patch.object(CVE_expert_seq, "load_taxonomy", return_value=TEST_TAXONOMY),
            patch.object(CVE_expert_seq, "load_benchmark", return_value=benchmark),
            patch.object(CVE_expert_seq, "build_pipeline") as build,
            self.assertRaisesRegex(ValueError, "CVE-2024-0002"),
        ):
            CVE_expert_seq.main(
                benchmark=True, cve_ids=["CVE-2024-0001", "CVE-2024-0002"]
            )
        build.assert_not_called()

    def test_main_benchmarks_only_requested_cases_in_cli_order(self):
        runtime_config = make_runtime_config("logs/test-run")
        benchmark = make_benchmark({
            "CVE-2024-0001": ["XSS"],
            "CVE-2024-0002": ["SQLi"],
            "CVE-2024-0003": ["XSS"],
        })
        pipeline = FakePipeline({})
        with (
            patch.object(CVE_expert_seq, "configure_console"),
            patch.object(CVE_expert_seq, "validate_runtime_config", return_value=runtime_config),
            patch.object(CVE_expert_seq, "load_taxonomy", return_value=TEST_TAXONOMY),
            patch.object(CVE_expert_seq, "load_benchmark", return_value=benchmark),
            patch.object(CVE_expert_seq, "build_pipeline", return_value=(pipeline, ["FakePipeline"])),
            patch.object(CVE_expert_seq, "run_evaluation") as run,
        ):
            CVE_expert_seq.main(
                benchmark=True, cve_ids=["CVE-2024-0003", "CVE-2024-0001"]
            )

        selected = run.call_args.args[4]
        self.assertEqual(
            [case.cve_id for case in selected.cases],
            ["CVE-2024-0003", "CVE-2024-0001"],
        )
        self.assertEqual(selected.source_path, benchmark.source_path)
        self.assertEqual(selected.taxonomy_sha256, benchmark.taxonomy_sha256)

    def test_main_rejects_duplicate_cve_ids_before_loading_config(self):
        with (
            patch.object(CVE_expert_seq, "validate_runtime_config") as validate,
            self.assertRaisesRegex(ValueError, "Duplicate CVE IDs"),
        ):
            CVE_expert_seq.main(cve_ids=["CVE-2024-0001", "cve-2024-0001"])
        validate.assert_not_called()

    def test_cli_passes_verbose_flag_to_main(self):
        with patch.object(CVE_expert_seq, "main") as main:
            exit_code = CVE_expert_seq.cli(["--verbose", "--benchmark", "CVE-2024-0001"])

        self.assertEqual(exit_code, 0)
        main.assert_called_once_with(verbose=True, benchmark=True, cve_ids=["CVE-2024-0001"])

    def test_cli_passes_explicit_cve_ids_to_classification_mode(self):
        with patch.object(CVE_expert_seq, "main") as main:
            exit_code = CVE_expert_seq.cli(["CVE-2024-0001", "CVE-2024-0002"])
        self.assertEqual(exit_code, 0)
        main.assert_called_once_with(
            verbose=False,
            benchmark=False,
            cve_ids=["CVE-2024-0001", "CVE-2024-0002"],
        )

    def test_cli_requires_cve_ids_with_or_without_benchmark(self):
        for args in ([], ["--benchmark"]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    CVE_expert_seq.cli(args)
            self.assertEqual(raised.exception.code, 2)

    def test_cli_reports_top_level_error_without_traceback(self):
        stream = io.StringIO()
        with patch.object(
            CVE_expert_seq,
            "main",
            side_effect=RuntimeError("short technical detail"),
        ), redirect_stderr(stream):
            exit_code = CVE_expert_seq.cli(["--benchmark", "CVE-2024-0001"])

        self.assertEqual(exit_code, 1)
        self.assertIn("RuntimeError: short technical detail", stream.getvalue())
        self.assertNotIn("Traceback", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
