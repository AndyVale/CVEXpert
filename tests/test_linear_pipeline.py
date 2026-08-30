import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Definitions.config import (
    ChatSettings,
    CosineFilterSettings,
    EmbeddingSettings,
    EvaluationSettings,
    NvdSettings,
    ReferenceSettings,
    RuntimeConfig,
    SemanticChunkerSettings,
)
from Definitions.labels import ALL_LABELS
from Graph.errors import PipelineStageError
from Graph.Nodes.evaluators import compute_grouped_scores, compute_individual_scores
from Graph.Nodes.formatters import formatter
from Graph.Nodes.util import StateFromFileLoader

import CVE_expert_seq


def make_runtime_config(log_directory: str) -> RuntimeConfig:
    return RuntimeConfig(
        chat=ChatSettings(
            base_url="https://chat.example.test/v1",
            api_key_env="CHAT_SECRET",
            classifier_model="classifier-model",
            classifier_temperature=0.0,
            summarizer_model="summarizer-model",
            summarizer_temperature=0.0,
        ),
        embedding=EmbeddingSettings(
            base_url="https://embedding.example.test/v1",
            api_key_env="EMBEDDING_SECRET",
            model="embedding-model",
        ),
        nvd=NvdSettings(
            base_url="https://nvd.example.test/cves/2.0",
            timeout_seconds=20.0,
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
            {"precision": 1.0, "recall": 1.0, "f1": 1.0},
        )

    def test_grouped_scores_cover_multiple_cves(self):
        scores = compute_grouped_scores(
            [["XSS"], ["SQLi"]],
            [["XSS"], ["SQLi"]],
            ALL_LABELS,
        )

        self.assertEqual(scores["precision"], 1.0)
        self.assertEqual(scores["recall"], 1.0)
        self.assertEqual(scores["f1"], 1.0)

    def test_empty_prediction_scores_zero_without_metric_failure(self):
        scores = compute_individual_scores(["XSS"], [], ALL_LABELS)

        self.assertEqual(
            scores,
            {"precision": 0.0, "recall": 0.0, "f1": 0.0},
        )


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

        def secret_for(variable_name):
            return {
                "CHAT_SECRET": "chat-token",
                "EMBEDDING_SECRET": "embedding-token",
            }[variable_name]

        with (
            patch.object(
                CVE_expert_seq,
                "read_api_key",
                side_effect=secret_for,
            ) as read_secret,
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
            pipeline, component_names = CVE_expert_seq.build_pipeline(runtime_config)

        self.assertEqual(
            [call.args[0] for call in read_secret.call_args_list],
            ["CHAT_SECRET", "EMBEDDING_SECRET"],
        )
        embeddings_factory.assert_called_once_with(
            model="embedding-model",
            api_key="embedding-token",
            base_url="https://embedding.example.test/v1",
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
                },
                {
                    "model": "classifier-model",
                    "model_provider": "openai",
                    "api_key": "chat-token",
                    "base_url": "https://chat.example.test/v1",
                    "temperature": 0.0,
                },
            ],
        )
        self.assertEqual(
            pipeline.steps[0].func.keywords,
            {
                "base_url": "https://nvd.example.test/cves/2.0",
                "timeout_seconds": 20.0,
            },
        )
        self.assertEqual(pipeline.steps[1].func.keywords, {"max_pages": 10})
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
            with patch.object(CVE_expert_seq, "CVE_TEST", test_cves):
                result = CVE_expert_seq.run_evaluation(
                    pipeline,
                    ["FakePipeline"],
                    runtime_config,
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
            with patch.object(CVE_expert_seq, "CVE_TEST", test_cves):
                CVE_expert_seq.run_evaluation(
                    pipeline,
                    ["FakePipeline"],
                    runtime_config,
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

    def test_main_builds_and_runs_one_evaluation(self):
        pipeline = FakePipeline({})
        runtime_config = make_runtime_config("logs/test-run")
        with (
            patch.object(
                CVE_expert_seq,
                "validate_runtime_config",
                return_value=runtime_config,
            ) as validate,
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
            result = CVE_expert_seq.main()

        validate.assert_called_once_with(require_embedding=True)
        build.assert_called_once_with(runtime_config)
        run.assert_called_once_with(
            pipeline,
            ["FakePipeline"],
            runtime_config,
        )
        self.assertEqual(result, "Finished: Run 0")
        self.assertFalse(hasattr(CVE_expert_seq, "concurrent"))


if __name__ == "__main__":
    unittest.main()
