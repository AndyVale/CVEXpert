import unittest

from Definitions.const import CVE_TEST
from Definitions.labels import ALL_LABELS


class CveFixtureTests(unittest.TestCase):
    def test_expected_labels_are_valid_nonempty_and_unique(self):
        allowed_labels = set(ALL_LABELS)

        for cve_id, expected_labels in CVE_TEST.items():
            with self.subTest(cve_id=cve_id):
                self.assertTrue(expected_labels)
                self.assertEqual(len(expected_labels), len(set(expected_labels)))
                self.assertLessEqual(set(expected_labels), allowed_labels)

    def test_none_is_mutually_exclusive(self):
        for cve_id, expected_labels in CVE_TEST.items():
            with self.subTest(cve_id=cve_id):
                if "NONE" in expected_labels:
                    self.assertEqual(expected_labels, ["NONE"])


if __name__ == "__main__":
    unittest.main()
