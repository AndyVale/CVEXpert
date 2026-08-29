import unittest
from unittest.mock import patch

from Graph.Nodes.chunkers import RecursiveCharacterChunkerNode
from Graph.Nodes.scrapers import extract_md_trafilatura
from Graph.Nodes.summarizers import CVEAwareSummarizerNode


class StubModel:
    def __init__(self, responses):
        self.responses = list(responses)

    def with_structured_output(self, _schema):
        return self

    def invoke(self, _prompt):
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class ReferenceWarningTests(unittest.TestCase):
    def test_failed_scrape_records_warning_and_keeps_successful_reference(self):
        urls = ["https://failed.example.test", "https://usable.example.test"]

        def fetch(url):
            return None if url == urls[0] else "downloaded page"

        with (
            patch("Graph.Nodes.scrapers.trafilatura.fetch_url", side_effect=fetch),
            patch(
                "Graph.Nodes.scrapers.trafilatura.extract",
                return_value="Usable page text",
            ),
        ):
            state = extract_md_trafilatura(
                {"cve_id": "CVE-TEST-1", "nvd_url_references": urls}
            )

        self.assertEqual(
            state["nvd_references_pages"],
            {"https://usable.example.test": "Usable page text"},
        )
        self.assertEqual(len(state["pipeline_warnings"]), 1)
        self.assertEqual(state["pipeline_warnings"][0]["stage"], "scrape")
        self.assertEqual(state["pipeline_warnings"][0]["source"], urls[0])

    def test_failed_chunk_records_warning_and_keeps_successful_reference(self):
        node = RecursiveCharacterChunkerNode()

        def split(text):
            if text == "bad page":
                raise ValueError("cannot split")
            return ["usable chunk"]

        with patch.object(node.splitter, "split_text", side_effect=split):
            state = node(
                {
                    "cve_id": "CVE-TEST-1",
                    "nvd_references_pages": {
                        "https://failed.example.test": "bad page",
                        "https://usable.example.test": "good page",
                    },
                }
            )

        self.assertEqual(
            state["nvd_references_chunks"]["https://usable.example.test"],
            ["usable chunk"],
        )
        self.assertEqual(state["nvd_references_chunks"]["https://failed.example.test"], [])
        self.assertEqual(state["pipeline_warnings"][0]["stage"], "chunk")

    def test_failed_summary_records_warning_and_keeps_successful_reference(self):
        node = CVEAwareSummarizerNode(
            StubModel(
                [
                    RuntimeError("model failed"),
                    {"is_cve_related": True, "summary": "Usable technical evidence"},
                ]
            ),
            {"XSS": "Cross-site scripting"},
        )

        state = node(
            {
                "cve_id": "CVE-TEST-1",
                "nvd_description": "Description",
                "nvd_filtered_chunks": {
                    "https://failed.example.test": ["failed evidence"],
                    "https://usable.example.test": ["usable evidence"],
                },
            }
        )

        self.assertEqual(
            state["summaries"],
            {"https://usable.example.test": "Usable technical evidence"},
        )
        self.assertEqual(state["pipeline_warnings"][0]["stage"], "summarize")


if __name__ == "__main__":
    unittest.main()
