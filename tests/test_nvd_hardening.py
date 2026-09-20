from __future__ import annotations

import unittest
from unittest.mock import Mock

from Graph.errors import PipelineStageError
from Graph.Nodes.nvd import nvd_caller
from Graph.resilience import RetryPolicy


def response(payload):
    value = Mock()
    value.status_code = 200
    value.headers = {"x-request-id": "request-1"}
    value.json.return_value = payload
    value.raise_for_status.return_value = None
    return value


class NvdHardeningTests(unittest.TestCase):
    def test_selects_matching_record_english_description_and_deduplicates_urls(self):
        payload = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2024-9999", "descriptions": []}},
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "descriptions": [
                            {"lang": "it", "value": "Descrizione"},
                            {"lang": "en", "value": " English description "},
                        ],
                        "references": [
                            {
                                "url": "HTTPS://Example.COM:443/advisory#details",
                                "tags": ["Vendor Advisory"],
                            },
                            {
                                "url": "https://example.com/advisory",
                                "tags": ["Technical Description"],
                            },
                            {"tags": ["Exploit"]},
                            "not-an-object",
                        ],
                    }
                },
            ]
        }
        session = Mock()
        session.get.return_value = response(payload)

        state = nvd_caller(
            {"cve_id": "CVE-2024-0001"},
            base_url="https://nvd.example.test/cves/2.0",
            timeout_seconds=20,
            connect_timeout_seconds=5,
            request_pacer=lambda: 0.0,
            retry_policy=RetryPolicy(max_attempts=1),
            session=session,
            api_key="nvd-secret",
        )

        self.assertEqual(state["nvd_description"], "English description")
        self.assertEqual(state["nvd_url_references"], ["https://example.com/advisory"])
        self.assertEqual(len(state["pipeline_warnings"]), 2)
        session.get.assert_called_once_with(
            "https://nvd.example.test/cves/2.0",
            params={"cveId": "CVE-2024-0001"},
            headers={"apiKey": "nvd-secret"},
            timeout=(5, 20),
        )

    def test_non_english_or_mismatched_response_is_terminal(self):
        payloads = [
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-0001",
                            "descriptions": [{"lang": "it", "value": "Solo italiano"}],
                            "references": [],
                        }
                    }
                ]
            },
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-9999",
                            "descriptions": [{"lang": "en", "value": "Wrong record"}],
                            "references": [],
                        }
                    }
                ]
            },
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                session = Mock()
                session.get.return_value = response(payload)
                with self.assertRaises(PipelineStageError) as raised:
                    nvd_caller(
                        {"cve_id": "CVE-2024-0001"},
                        base_url="https://nvd.example.test/cves/2.0",
                        timeout_seconds=20,
                        request_pacer=lambda: 0.0,
                        session=session,
                    )
                self.assertEqual(raised.exception.error_type, "ValueError")
                self.assertEqual(raised.exception.partial_state["cve_id"], "CVE-2024-0001")


if __name__ == "__main__":
    unittest.main()
