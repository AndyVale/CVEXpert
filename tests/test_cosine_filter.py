import unittest

from Graph.errors import PipelineStageError
from Graph.Nodes.filters import CosineFilterNode


class StubEmbeddings:
    def __init__(self, query_embedding, document_embeddings):
        self.query_embedding = query_embedding
        self.document_embeddings = document_embeddings

    def embed_query(self, _query):
        return self.query_embedding

    def embed_documents(self, _documents):
        return self.document_embeddings


class CosineFilterTests(unittest.TestCase):
    def test_similarity_is_independent_of_embedding_magnitude(self):
        node = CosineFilterNode(
            embed_model=StubEmbeddings(
                query_embedding=[2.0, 0.0],
                document_embeddings=[
                    [0.4, 0.0],
                    [0.4, 100.0],
                ],
            ),
            query="query",
            threshold=0.6,
        )

        state = node(
            {
                "cve_id": "CVE-TEST-1",
                "nvd_references_chunks": {
                    "https://example.test": ["aligned", "large but off-axis"],
                },
            }
        )

        self.assertEqual(
            state["nvd_filtered_chunks"]["https://example.test"],
            ["aligned", "..."],
        )

    def test_zero_document_vector_is_treated_as_no_similarity(self):
        node = CosineFilterNode(
            embed_model=StubEmbeddings(
                query_embedding=[1.0, 0.0],
                document_embeddings=[[0.0, 0.0], [3.0, 0.0]],
            ),
            query="query",
            threshold=0.6,
        )

        state = node(
            {
                "cve_id": "CVE-TEST-1",
                "nvd_references_chunks": {
                    "https://example.test": ["zero vector", "aligned"],
                },
            }
        )

        self.assertEqual(
            state["nvd_filtered_chunks"]["https://example.test"],
            ["...", "aligned"],
        )

    def test_zero_query_vector_is_rejected_during_construction(self):
        with self.assertRaisesRegex(ValueError, "zero vector"):
            CosineFilterNode(
                embed_model=StubEmbeddings(
                    query_embedding=[0.0, 0.0],
                    document_embeddings=[],
                ),
                query="query",
                threshold=0.6,
            )

    def test_embedding_dimension_mismatch_is_a_filter_stage_error(self):
        node = CosineFilterNode(
            embed_model=StubEmbeddings(
                query_embedding=[1.0, 0.0],
                document_embeddings=[[1.0, 0.0, 0.0]],
            ),
            query="query",
            threshold=0.6,
        )

        with self.assertRaises(PipelineStageError) as raised:
            node(
                {
                    "cve_id": "CVE-TEST-1",
                    "nvd_references_chunks": {
                        "https://example.test": ["chunk"],
                    },
                }
            )

        self.assertEqual(raised.exception.stage, "filter")
        self.assertEqual(raised.exception.error_type, "ValueError")

    def test_embedding_count_mismatch_is_a_filter_stage_error(self):
        node = CosineFilterNode(
            embed_model=StubEmbeddings(
                query_embedding=[1.0, 0.0],
                document_embeddings=[[1.0, 0.0]],
            ),
            query="query",
            threshold=0.6,
        )

        with self.assertRaises(PipelineStageError):
            node(
                {
                    "cve_id": "CVE-TEST-1",
                    "nvd_references_chunks": {
                        "https://example.test": ["one", "two"],
                    },
                }
            )


if __name__ == "__main__":
    unittest.main()
