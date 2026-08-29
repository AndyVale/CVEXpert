import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Definitions import config
from Definitions.labels import ALL_LABELS
from Graph.Nodes.evaluators import compute_grouped_scores, compute_individual_scores
from Graph.Nodes.formatters import formatter
from Graph.Nodes.util import StateFromFileLoader

import CVE_expert_seq


class RuntimeConfigurationTests(unittest.TestCase):
    def test_dotenv_path_is_anchored_to_repository_root(self):
        expected_path = Path(config.__file__).resolve().parents[2] / ".env"

        self.assertEqual(config.DOTENV_PATH, expected_path)

    def test_live_validation_requires_chat_and_embedding_settings(self):
        settings = {
            "VAST_IP_PORT_MODEL": "chat.test:8000",
            "OPEN_BUTTON_TOKEN_MODEL": "chat-token",
            "VAST_IP_PORT_EMBEDDING": None,
            "OPEN_BUTTON_TOKEN_EMBEDDING": " ",
        }

        with (
            patch.multiple(config, **settings),
            self.assertRaises(config.RuntimeConfigurationError) as raised,
        ):
            config.validate_runtime_config(require_embedding=True)

        self.assertEqual(
            raised.exception.missing_variables,
            ("VAST_IP_PORT_EMBEDDING", "OPEN_BUTTON_TOKEN_EMBEDDING"),
        )
        self.assertNotIn("chat-token", str(raised.exception))

    def test_replay_validation_requires_only_chat_settings(self):
        settings = {
            "VAST_IP_PORT_MODEL": "chat.test:8000",
            "OPEN_BUTTON_TOKEN_MODEL": "chat-token",
            "VAST_IP_PORT_EMBEDDING": None,
            "OPEN_BUTTON_TOKEN_EMBEDDING": None,
        }

        with patch.multiple(config, **settings):
            config.validate_runtime_config(require_embedding=False)

    def test_missing_chat_settings_fail_in_all_modes(self):
        settings = {
            "VAST_IP_PORT_MODEL": None,
            "OPEN_BUTTON_TOKEN_MODEL": "",
            "VAST_IP_PORT_EMBEDDING": "embedding.test:8001",
            "OPEN_BUTTON_TOKEN_EMBEDDING": "embedding-token",
        }

        with (
            patch.multiple(config, **settings),
            self.assertRaises(config.RuntimeConfigurationError) as raised,
        ):
            config.validate_runtime_config(require_embedding=False)

        self.assertEqual(
            raised.exception.missing_variables,
            ("VAST_IP_PORT_MODEL", "OPEN_BUTTON_TOKEN_MODEL"),
        )


class FakePipeline:
    def __init__(self, states):
        self.states = states
        self.invocations = []

    def invoke(self, state):
        cve_id = state["cve_id"]
        self.invocations.append(cve_id)
        return {"cve_id": cve_id, **self.states[cve_id]}


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
            fake_module_path = Path(temp_dir) / "src" / "CVE_expert_seq.py"
            fake_module_path.parent.mkdir()
            with (
                patch.object(CVE_expert_seq, "__file__", str(fake_module_path)),
                patch.object(CVE_expert_seq, "CVE_TEST", test_cves),
                patch.object(
                    CVE_expert_seq.random,
                    "sample",
                    return_value=list(test_cves.items()),
                ),
            ):
                result = CVE_expert_seq.run_evaluation(
                    (0, pipeline, ["FakePipeline"])
                )

            output_path = (
                Path(temp_dir)
                / "logs"
                / "LOG_GPT_NORANDAware"
                / "RUN_0.json"
            )
            log = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(result, "Finished: Run 0")
        self.assertEqual(pipeline.invocations, ["CVE-TEST-1"])
        self.assertEqual(log["cves"]["CVE-TEST-1"]["status"], "success")
        self.assertEqual(
            log["cves"]["CVE-TEST-1"]["classification_output"],
            ["XSS"],
        )
        self.assertEqual(log["aggregated_scores"]["f1"], 1.0)


if __name__ == "__main__":
    unittest.main()
