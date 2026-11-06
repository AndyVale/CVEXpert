import unittest
from pathlib import Path

from Definitions.config import REPOSITORY_ROOT
from Definitions.fixtures import Taxonomy, TaxonomyLabel, load_taxonomy
from Graph.Nodes.classifiers import CVEClassifierNode
from Graph.errors import PipelineStageError


class RecordingModel:
    def __init__(self, responses):
        self.responses = list(responses)
        self.schemas = []
        self.prompts = []

    def with_structured_output(self, schema):
        self.schemas.append(schema)
        return self

    def invoke(self, prompt):
        self.prompts.append(prompt)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


TAXONOMY = Taxonomy(
    name="Nested test",
    labels=(
        TaxonomyLabel("Parent", "Parent family", "Parent mechanism " * 15),
        TaxonomyLabel("Child", "Specific child", "Child mechanism " * 15, "Parent"),
        TaxonomyLabel("Other", "Other family", "Other mechanism " * 15),
    ),
    fingerprint="test",
    source_path=Path("/tmp/taxonomy.json"),
)
STATE = {"cve_id": "CVE-2024-0001", "rag": "Technical CVE evidence"}


def one_label_budget() -> int:
    node = CVEClassifierNode(RecordingModel([]), TAXONOMY, 12000)
    return max(
        node._estimated_input_tokens(STATE["cve_id"], STATE["rag"], [label])
        for label in TAXONOMY.labels
    )


class TaxonomyClassifierTests(unittest.TestCase):
    def test_groups_fit_budget_and_prune_ancestor_across_calls(self):
        model = RecordingModel(
            [{"labels": ["Parent"]}, {"labels": ["Child"]}, {"labels": ["no_matching_label"]}]
        )
        node = CVEClassifierNode(model, TAXONOMY, one_label_budget())
        groups = node._groups(STATE["cve_id"], STATE["rag"])
        self.assertEqual([[label.id for label in group] for group in groups], [
            ["Parent"], ["Child"], ["Other"]
        ])
        self.assertTrue(all(
            node._estimated_input_tokens(STATE["cve_id"], STATE["rag"], group)
            <= node.max_input_tokens
            for group in groups
        ))

        result = node(STATE)

        self.assertEqual(result["cve_labels"], ["Child"])
        self.assertEqual(len(model.prompts), 3)
        self.assertIn("Parent (Parent family)", model.prompts[1])
        self.assertEqual(
            model.schemas[1]["properties"]["labels"]["items"]["enum"],
            ["Child", "no_matching_label", "not_enough_information"],
        )

    def test_all_groups_none_yields_one_none(self):
        model = RecordingModel([{"labels": ["no_matching_label"]}] * 3)
        node = CVEClassifierNode(model, TAXONOMY, one_label_budget())

        self.assertEqual(node(STATE)["cve_labels"], ["no_matching_label"])

    def test_group_failure_is_terminal(self):
        model = RecordingModel([{"labels": ["no_matching_label"]}, RuntimeError("failed")])
        node = CVEClassifierNode(model, TAXONOMY, one_label_budget())

        with self.assertRaises(PipelineStageError) as raised:
            node(STATE)
        self.assertEqual(raised.exception.stage, "classify")
        self.assertEqual(len(model.prompts), 2)

    def test_evidence_too_large_fails_before_any_model_call(self):
        model = RecordingModel([])
        node = CVEClassifierNode(model, TAXONOMY, 10)

        with self.assertRaises(PipelineStageError) as raised:
            node(STATE)
        self.assertIn("budget", str(raised.exception.original_error))
        self.assertEqual(model.prompts, [])

    def test_supplied_hybrid_set_splits_under_example_budget(self):
        root = REPOSITORY_ROOT / "fixtures"
        flat = load_taxonomy(root / "flat/taxonomy.json")
        hybrid = load_taxonomy(root / "hybrid/taxonomy.json")
        flat_node = CVEClassifierNode(RecordingModel([]), flat, 12000)
        hybrid_node = CVEClassifierNode(RecordingModel([]), hybrid, 12000)

        self.assertEqual(len(flat_node._groups(STATE["cve_id"], STATE["rag"])), 1)
        self.assertGreater(len(hybrid_node._groups(STATE["cve_id"], STATE["rag"])), 1)


if __name__ == "__main__":
    unittest.main()
