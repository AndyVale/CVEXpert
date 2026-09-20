from __future__ import annotations

import socket
import unittest
from unittest.mock import Mock, patch

import requests

from Graph.Nodes.scrapers import (
    ReferencePolicyError,
    _download_reference,
    extract_md_trafilatura,
)
from Graph.resilience import RetryPolicy
from Graph.url_safety import UnsafeUrlError, normalize_http_url, validate_public_http_url


def public_resolver(host, port, **_kwargs):
    address = "127.0.0.1" if host == "127.0.0.1" else "93.184.216.34"
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]


class FakeResponse:
    def __init__(self, *, status=200, headers=None, chunks=()):
        self.status_code = status
        self.headers = dict(headers or {})
        self._chunks = list(chunks)
        self.closed = False

    def raise_for_status(self):
        if self.status_code >= 400:
            error = requests.HTTPError(f"status {self.status_code}")
            error.response = self
            raise error

    def iter_content(self, chunk_size):
        self.chunk_size = chunk_size
        yield from self._chunks

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


class UrlSafetyTests(unittest.TestCase):
    def test_normalization_strips_fragment_and_default_port(self):
        self.assertEqual(
            normalize_http_url("HTTPS://Example.COM:443/advisory#fragment"),
            "https://example.com/advisory",
        )

    def test_unsafe_scheme_credentials_and_private_address_are_rejected(self):
        for value in (
            "file:///etc/passwd",
            "https://user:pass@example.com/",
            "http://127.0.0.1/",
        ):
            with self.subTest(value=value), self.assertRaises(UnsafeUrlError):
                validate_public_http_url(value, resolver=public_resolver)


class ReferenceDownloadTests(unittest.TestCase):
    def _download(self, session, **overrides):
        arguments = {
            "source_id": "reference-001",
            "session": session,
            "resolver": public_resolver,
            "retry_policy": RetryPolicy(max_attempts=1),
            "request_pacer": lambda: 0.0,
            "connect_timeout_seconds": 10.0,
            "read_timeout_seconds": 30.0,
            "max_redirects": 5,
            "max_bytes": 20,
        }
        arguments.update(overrides)
        return _download_reference("https://example.com/start", **arguments)

    def test_download_uses_explicit_timeout_and_supported_content_type(self):
        response = FakeResponse(
            headers={"Content-Type": "text/html; charset=utf-8", "Content-Length": "4"},
            chunks=[b"page"],
        )
        session = FakeSession([response])

        self.assertEqual(self._download(session), b"page")
        self.assertEqual(
            session.calls[0],
            (
                "https://example.com/start",
                {"allow_redirects": False, "stream": True, "timeout": (10.0, 30.0)},
            ),
        )
        self.assertTrue(response.closed)

    def test_redirect_to_private_address_is_rejected_before_second_request(self):
        redirect = FakeResponse(status=302, headers={"Location": "http://127.0.0.1/admin"})
        session = FakeSession([redirect])
        with self.assertRaises(UnsafeUrlError):
            self._download(session)
        self.assertEqual(len(session.calls), 1)
        self.assertTrue(redirect.closed)

    def test_content_type_declared_size_and_streamed_size_are_bounded(self):
        cases = [
            FakeResponse(headers={"Content-Type": "application/pdf"}, chunks=[b"data"]),
            FakeResponse(
                headers={"Content-Type": "text/plain", "Content-Length": "21"},
                chunks=[b"small"],
            ),
            FakeResponse(headers={"Content-Type": "text/plain"}, chunks=[b"a" * 21]),
        ]
        for response in cases:
            with self.subTest(headers=response.headers):
                with self.assertRaises(ReferencePolicyError):
                    self._download(FakeSession([response]))
                self.assertTrue(response.closed)

    def test_extracted_text_is_truncated_with_warning(self):
        response = FakeResponse(
            headers={"Content-Type": "text/plain"}, chunks=[b"downloaded"]
        )
        session = FakeSession([response])
        with (
            patch("Graph.Nodes.scrapers.trafilatura.extract", return_value="abcdefghij"),
            patch("Graph.Nodes.scrapers.report_warning") as report_warning,
        ):
            state = extract_md_trafilatura(
                {
                    "cve_id": "CVE-2024-0001",
                    "nvd_url_references": ["https://example.com/start"],
                },
                max_pages=1,
                max_extracted_chars_per_reference=5,
                max_extracted_chars_per_cve=20,
                session=session,
                resolver=public_resolver,
            )

        self.assertTrue(state["nvd_references_pages"]["https://example.com/start"].startswith("abcde"))
        self.assertEqual(state["pipeline_warnings"][0]["message"], "Extracted reference text was truncated")
        report_warning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
