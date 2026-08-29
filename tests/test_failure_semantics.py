import unittest
from unittest.mock import patch

from Graph.errors import PipelineStageError
from Graph.Nodes.classifiers import (
    CVEClassifierNode,
    CVEConfidenceClassifierNode,
    CVENoRagClassifierNode,
    CVESelfConsistentClassifierNode,
)
from Graph.Nodes.filters import CosineFilterNode
from Graph.Nodes.formatters import formatter
from Graph.Nodes.nvd import nvd_caller


LABELS = {"XSS": "Cross-site scripting", "SQLi": "SQL injection"}


class StubModel:
    def __init__(self, responses):
        self.responses = list(responses)
        self.schema = None

    def with_structured_output(self, schema):
        self.schema = schema
        return self

    def invoke(self, _prompt):
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class StubResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FailingDocumentEmbeddings:
    def embed_query(self, _query):
        return [1.0, 0.0]

    def embed_documents(self, _documents):
        raise RuntimeError("embedding endpoint unavailable")


class PipelineStageErrorTests(unittest.TestCase):
    def test_error_details_are_structured_and_safe(self):
        error = PipelineStageError(
            stage="nvd",
            cve_id="CVE-TEST-1",
            error=TimeoutError("sensitive upstream details"),
            safe_message="NVD request failed",
        )

        self.assertEqual(
            error.to_dict(),
            {
                "stage": "nvd",
                "cve_id": "CVE-TEST-1",
                "error_type": "TimeoutError",
                "message": "NVD request failed",
            },
        )
        self.assertNotIn("sensitive upstream details", str(error))


class NvdFailureTests(unittest.TestCase):
    def test_request_failure_raises_stage_error(self):
        with (
            patch("Graph.Nodes.nvd.requests.get", side_effect=TimeoutError("timeout")),
            self.assertRaises(PipelineStageError) as raised,
        ):
            nvd_caller({"cve_id": "CVE-TEST-1"})

        self.assertEqual(raised.exception.stage, "nvd")
        self.assertEqual(raised.exception.cve_id, "CVE-TEST-1")
        self.assertEqual(raised.exception.error_type, "TimeoutError")

    def test_response_parsing_failure_raises_stage_error(self):
        response = StubResponse({"vulnerabilities": []})
        with (
            patch("Graph.Nodes.nvd.requests.get", return_value=response),
            self.assertRaises(PipelineStageError) as raised,
        ):
            nvd_caller({"cve_id": "CVE-TEST-2"})

        self.assertEqual(raised.exception.stage, "nvd")
        self.assertEqual(raised.exception.error_type, "IndexError")


class FormatterFailureTests(unittest.TestCase):
    def test_missing_formatter_input_raises_stage_error(self):
        with self.assertRaises(PipelineStageError) as raised:
            formatter({"cve_id": "CVE-TEST-1", "nvd_description": "Description"})

        self.assertEqual(raised.exception.stage, "format")


class FilterFailureTests(unittest.TestCase):
    def test_embedding_failure_raises_stage_error(self):
        node = CosineFilterNode(
            embed_model=FailingDocumentEmbeddings(),
            query="query",
            threshold=0.6,
        )

        with self.assertRaises(PipelineStageError) as raised:
            node(
                {
                    "cve_id": "CVE-TEST-1",
                    "nvd_references_chunks": {"https://example.test": ["chunk"]},
                }
            )

        self.assertEqual(raised.exception.stage, "filter")
        self.assertEqual(raised.exception.error_type, "RuntimeError")


class ClassifierFailureTests(unittest.TestCase):
    def test_active_classifier_propagates_model_failure(self):
        node = CVEClassifierNode(StubModel([RuntimeError("model failed")]), LABELS)

        with self.assertRaises(PipelineStageError) as raised:
            node({"cve_id": "CVE-TEST-1", "rag": "Evidence"})

        self.assertEqual(raised.exception.stage, "classify")
        self.assertEqual(raised.exception.error_type, "RuntimeError")

    def test_active_classifier_rejects_invalid_label_outputs(self):
        invalid_responses = {
            "empty": {"labels": []},
            "unknown": {"labels": ["UNKNOWN"]},
            "duplicate": {"labels": ["XSS", "XSS"]},
            "mixed_none": {"labels": ["NONE", "XSS"]},
        }

        for case_name, response in invalid_responses.items():
            with self.subTest(case_name=case_name):
                node = CVEClassifierNode(StubModel([response]), LABELS)
                with self.assertRaises(PipelineStageError):
                    node({"cve_id": "CVE-TEST-1", "rag": "Evidence"})

    def test_valid_none_is_a_successful_classification(self):
        node = CVEClassifierNode(StubModel([{"labels": ["NONE"]}]), LABELS)

        state = node({"cve_id": "CVE-TEST-1", "rag": "Evidence"})

        self.assertEqual(state["cve_labels"], ["NONE"])

    def test_no_rag_variant_accepts_valid_none(self):
        model = StubModel([{"labels": ["NONE"]}])
        node = CVENoRagClassifierNode(model, LABELS)

        state = node({"cve_id": "CVE-TEST-1"})

        self.assertEqual(state["cve_labels"], ["NONE"])
        self.assertIn("NONE", model.schema["properties"]["labels"]["items"]["enum"])

    def test_confidence_variant_rejects_empty_output(self):
        node = CVEConfidenceClassifierNode(
            StubModel([{"classifications": []}]),
            LABELS,
        )

        with self.assertRaises(PipelineStageError):
            node({"cve_id": "CVE-TEST-1", "rag": "Evidence"})

    def test_self_consistency_rejects_none_mixed_across_runs(self):
        node = CVESelfConsistentClassifierNode(
            StubModel(
                [
                    {"classifications": [{"label": "NONE", "motivation": "None"}]},
                    {"classifications": [{"label": "XSS", "motivation": "Evidence"}]},
                ]
            ),
            LABELS,
            total_runs=2,
        )

        with self.assertRaises(PipelineStageError):
            node({"cve_id": "CVE-TEST-1", "rag": "Evidence"})


if __name__ == "__main__":
    unittest.main()
