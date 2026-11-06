import json
import tempfile
import unittest
from pathlib import Path

from Definitions.config import REPOSITORY_ROOT
from Definitions.fixtures import FixtureError, load_benchmark, load_taxonomy


FIXTURE_ROOT = REPOSITORY_ROOT / "fixtures"


class JsonFixtureTests(unittest.TestCase):
    def test_all_supplied_pairs_load_with_expected_counts_and_provenance(self):
        for variant, label_count in (
            ("flat", 9),
            ("hierarchical", 39),
            ("hybrid", 84),
        ):
            with self.subTest(variant=variant):
                directory = FIXTURE_ROOT / variant
                taxonomy = load_taxonomy(directory / "taxonomy.json")
                benchmark = load_benchmark(
                    directory / "expected-classification.json", taxonomy
                )

                self.assertEqual(len(taxonomy.labels), label_count)
                self.assertEqual(len(benchmark.cases), 50)
                self.assertEqual(len({case.cve_id for case in benchmark.cases}), 50)
                self.assertEqual(benchmark.taxonomy_sha256, taxonomy.fingerprint)
                self.assertEqual(benchmark.cases[0].cve_id, "CVE-2021-27103")
                self.assertTrue(benchmark.cases[0].rationale)
                self.assertTrue(benchmark.cases[0].sources)
                self.assertTrue(set(taxonomy.root_descriptions) <= set(taxonomy.descriptions))

    def test_hierarchy_paths_and_most_specific_cases_are_valid(self):
        for variant in ("hierarchical", "hybrid"):
            with self.subTest(variant=variant):
                directory = FIXTURE_ROOT / variant
                taxonomy = load_taxonomy(directory / "taxonomy.json")
                benchmark = load_benchmark(
                    directory / "expected-classification.json", taxonomy
                )
                self.assertTrue(any(label.parent for label in taxonomy.labels))
                for case in benchmark.cases:
                    for label in case.labels:
                        if label != "no_matching_label":
                            self.assertFalse(
                                set(taxonomy.ancestors_of(label)) & set(case.labels)
                            )

    def test_benchmark_selects_requested_cases_and_ignores_unrequested_cases(self):
        for variant in ("flat", "hierarchical", "hybrid"):
            with self.subTest(variant=variant):
                directory = FIXTURE_ROOT / variant
                taxonomy = load_taxonomy(directory / "taxonomy.json")
                benchmark = load_benchmark(
                    directory / "expected-classification.json", taxonomy
                )
                requested = [benchmark.cases[2].cve_id, benchmark.cases[0].cve_id]

                selected = benchmark.select(requested)

                self.assertEqual([case.cve_id for case in selected.cases], requested)
                self.assertEqual(selected.cases[0], benchmark.cases[2])
                self.assertEqual(selected.source_path, benchmark.source_path)
                self.assertEqual(len(benchmark.cases), 50)

                with self.assertRaisesRegex(FixtureError, "CVE-2099-9999"):
                    benchmark.select([requested[0], "CVE-2099-9999"])

    def test_rejects_unknown_parent_and_cycles(self):
        base = {
            "name": "Test",
            "hierarchy_policy": "most_specific",
            "labels": [
                {"id": "A", "name": "A", "description": "A definition", "parent": "B"},
                {"id": "B", "name": "B", "description": "B definition"},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "taxonomy.json"
            base["labels"][0]["parent"] = "missing"
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaisesRegex(FixtureError, "Unknown parent"):
                load_taxonomy(path)

            base["labels"][0]["parent"] = "B"
            base["labels"][1]["parent"] = "A"
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaisesRegex(FixtureError, "Cyclic"):
                load_taxonomy(path)

    def test_rejects_duplicate_ids_and_unsupported_hierarchy_policy(self):
        payload = {
            "name": "Test",
            "hierarchy_policy": "most_specific",
            "labels": [
                {"id": "A", "name": "A", "description": "First"},
                {"id": "A", "name": "A again", "description": "Second"},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "taxonomy.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(FixtureError, "Duplicate taxonomy ID"):
                load_taxonomy(path)

            payload["labels"].pop()
            payload["hierarchy_policy"] = "include_ancestors"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(FixtureError, "most_specific"):
                load_taxonomy(path)

    def test_rejects_mismatched_taxonomy_fingerprint(self):
        flat = FIXTURE_ROOT / "flat"
        taxonomy = load_taxonomy(flat / "taxonomy.json")
        source = json.loads((flat / "expected-classification.json").read_text())
        source["taxonomy_sha256"] = "wrong"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "expected.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaisesRegex(FixtureError, "do not match"):
                load_benchmark(path, taxonomy)

    def test_rejects_duplicate_and_ancestor_descendant_expected_labels(self):
        taxonomy = load_taxonomy(FIXTURE_ROOT / "hierarchical" / "taxonomy.json")
        payload = {
            "schema_version": 1,
            "taxonomy_sha256": taxonomy.fingerprint,
            "cases": [
                {"cve_id": "CVE-2024-0001", "labels": ["InterpreterInjection"]},
                {"cve_id": "CVE-2024-0001", "labels": ["SSRF"]},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "expected.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(FixtureError, "Duplicate expected CVE"):
                load_benchmark(path, taxonomy)

            payload["cases"] = [
                {
                    "cve_id": "CVE-2024-0001",
                    "labels": ["InterpreterInjection", "QueryInjection"],
                }
            ]
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(FixtureError, "ancestor and descendant"):
                load_benchmark(path, taxonomy)

    def test_rejects_unknown_expected_label_and_mixed_none(self):
        taxonomy = load_taxonomy(FIXTURE_ROOT / "flat" / "taxonomy.json")
        payload = {
            "schema_version": 1,
            "taxonomy_sha256": taxonomy.fingerprint,
            "cases": [{"cve_id": "CVE-2024-0001", "labels": ["unknown"]}],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "expected.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(FixtureError, "unsupported labels"):
                load_benchmark(path, taxonomy)

            payload["cases"][0]["labels"] = ["no_matching_label", "AccessControl"]
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(FixtureError, "combines no_matching_label"):
                load_benchmark(path, taxonomy)


if __name__ == "__main__":
    unittest.main()
