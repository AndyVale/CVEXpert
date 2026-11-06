import unittest
from test_classifier_taxonomy import RecordingModel, TAXONOMY, STATE, one_label_budget
from Graph.Nodes.classifiers import CVEClassifierNode, _validate_labels
from Graph.errors import PipelineStageError

class OutcomeTests(unittest.TestCase):
    def classify(self, labels):
        return CVEClassifierNode(RecordingModel([{'labels': x} for x in labels]), TAXONOMY, one_label_budget())(STATE)

    def test_uncertainty_and_positive(self):
        for middle, expected in [('not_enough_information', ['not_enough_information']), ('Child', ['Child'])]:
            result = self.classify([['not_enough_information'], [middle], ['no_matching_label']])
            self.assertEqual(result['cve_labels'], expected)
            self.assertFalse(result['classification_assessment_complete'])
            self.assertEqual(len(result['classification_groups']), 3)

    def test_complete_negative(self):
        result = self.classify([['no_matching_label']]*3)
        self.assertEqual(result['cve_labels'], ['no_matching_label'])
        self.assertTrue(result['classification_assessment_complete'])

    def test_invalid_and_legacy(self):
        allowed = TAXONOMY.all_labels
        for labels in [[], ['NONE'], ['not_enough_information','Child'], ['not_enough_information','no_matching_label'], ['not_enough_information']*2]:
            with self.assertRaises(ValueError):
                _validate_labels(labels, allowed)

    def test_partial_failure(self):
        node = CVEClassifierNode(RecordingModel([{'labels':['Child']}, RuntimeError('failed')]), TAXONOMY, one_label_budget())
        # First group cannot select Child; use its actual candidate.
        node.model.responses[0] = {'labels':['Parent']}
        with self.assertRaises(PipelineStageError) as caught:
            node(STATE)
        self.assertFalse(caught.exception.partial_state['classification_assessment_complete'])
        self.assertEqual(len(caught.exception.partial_state['classification_groups']), 1)
