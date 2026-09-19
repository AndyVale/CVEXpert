import unittest
from unittest.mock import patch

from Graph.Nodes.chunkers import SemanticChunkerNode
from Graph.reference_focus import focus_broad_cve_reference


TARGET = "CVE-2020-14864"


def broad_reference() -> str:
    other_ids = " ".join(f"CVE-2024-{index:04d}" for index in range(1000, 1120))
    return (
        f"Acknowledgment: {TARGET} with author details.\n"
        + other_ids
        + "\nIrrelevant catalog text. " * 3000
        + f"\nVulnerability table row: {TARGET} affects the installation component."
    )


class ReferenceFocusTests(unittest.TestCase):
    def test_large_multi_cve_index_keeps_target_contexts(self):
        page = broad_reference()

        focused = focus_broad_cve_reference(page, TARGET)

        self.assertLess(len(focused), len(page) // 5)
        self.assertEqual(focused.count(TARGET), 2)
        self.assertIn("Acknowledgment:", focused)
        self.assertIn("Vulnerability table row:", focused)
        self.assertNotIn("Irrelevant catalog text. " * 100, focused)

    def test_large_single_cve_analysis_and_index_without_target_are_preserved(self):
        technical_page = f"{TARGET} details. " + "technical analysis. " * 3500
        index_without_target = broad_reference().replace(TARGET, "CVE-2020-99999")

        self.assertIs(focus_broad_cve_reference(technical_page, TARGET), technical_page)
        self.assertIs(focus_broad_cve_reference(index_without_target, TARGET), index_without_target)

    def test_semantic_chunker_keeps_original_page_and_splits_focused_text(self):
        page = broad_reference()
        node = SemanticChunkerNode(embed_model=object())

        with patch.object(node.splitter, "split_text", side_effect=lambda text: [text]) as split:
            result = node({
                "cve_id": TARGET,
                "nvd_references_pages": {"https://example.test/advisory": page},
            })

        focused = split.call_args.args[0]
        self.assertLess(len(focused), len(page) // 5)
        self.assertEqual(result["nvd_references_pages"]["https://example.test/advisory"], page)
        self.assertEqual(result["nvd_references_chunks"]["https://example.test/advisory"], [focused])
        self.assertEqual(
            result["reference_focus"]["https://example.test/advisory"],
            {"original_chars": len(page), "focused_chars": len(focused)},
        )


if __name__ == "__main__":
    unittest.main()
