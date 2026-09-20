"""Bounded, trust-aware reference download and Markdown extraction."""

from __future__ import annotations

from collections.abc import Callable
import socket
from urllib.parse import urljoin

import requests
import trafilatura
from tqdm import tqdm

from Graph.audit import BudgetExceeded, request_scope
from Graph.errors import PipelineStageError, make_pipeline_warning
from Graph.reporting import get_logger, report_warning
from Graph.resilience import RetryPolicy, execute_with_retry
from Graph.state import CVEClassifierState
from Graph.url_safety import validate_public_http_url


LOGGER = get_logger("scrape")
ALLOWED_CONTENT_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "text/plain",
    "text/markdown",
    "application/xml",
    "text/xml",
}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class ReferencePolicyError(ValueError):
    """A reference violates a bounded download or content policy."""


def _download_reference(
    url: str,
    *,
    source_id: str,
    session: requests.Session,
    resolver: Callable[..., list[tuple]],
    retry_policy: RetryPolicy,
    request_pacer: Callable[[], float],
    connect_timeout_seconds: float,
    read_timeout_seconds: float,
    max_redirects: int,
    max_bytes: int,
) -> bytes:
    current_url = validate_public_http_url(url, resolver=resolver)
    for redirect_count in range(max_redirects + 1):
        def fetch():
            response = session.get(
                current_url,
                allow_redirects=False,
                stream=True,
                timeout=(connect_timeout_seconds, read_timeout_seconds),
            )
            if response.status_code not in REDIRECT_STATUSES:
                response.raise_for_status()
            return response

        with request_scope(stage="scrape", operation="download", source=source_id):
            response = execute_with_retry(
                fetch,
                policy=retry_policy,
                pacer=request_pacer,
            )
        try:
            if response.status_code in REDIRECT_STATUSES:
                if redirect_count >= max_redirects:
                    raise ReferencePolicyError("Reference redirect limit exceeded")
                location = response.headers.get("Location")
                if not location:
                    raise ReferencePolicyError("Reference redirect is missing Location")
                current_url = validate_public_http_url(
                    urljoin(current_url, location), resolver=resolver
                )
                continue

            content_type = response.headers.get("Content-Type", "")
            media_type = content_type.split(";", 1)[0].strip().lower()
            if media_type not in ALLOWED_CONTENT_TYPES:
                raise ReferencePolicyError("Reference content type is not supported")
            raw_length = response.headers.get("Content-Length")
            if raw_length:
                try:
                    declared_length = int(raw_length)
                except ValueError as error:
                    raise ReferencePolicyError("Reference Content-Length is invalid") from error
                if declared_length < 0 or declared_length > max_bytes:
                    raise ReferencePolicyError("Reference exceeds the download byte limit")

            body = bytearray()
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                if len(body) + len(chunk) > max_bytes:
                    raise ReferencePolicyError("Reference exceeds the download byte limit")
                body.extend(chunk)
            if not body:
                raise ValueError("Reference download returned no content")
            return bytes(body)
        finally:
            response.close()

    raise ReferencePolicyError("Reference redirect limit exceeded")


def _append_warning(
    warnings: list,
    *,
    source: str,
    error: BaseException,
    safe_message: str,
) -> None:
    warning = make_pipeline_warning(
        stage="scrape",
        source=source,
        error=error,
        safe_message=safe_message,
    )
    warnings.append(warning)
    report_warning(LOGGER, warning, error)


def extract_md_trafilatura(
    state: CVEClassifierState,
    *,
    max_pages: int,
    max_attempts: int = 1,
    connect_timeout_seconds: float = 10.0,
    read_timeout_seconds: float = 30.0,
    max_redirects: int = 5,
    max_bytes_per_reference: int = 5 * 1024 * 1024,
    max_bytes_per_cve: int = 20 * 1024 * 1024,
    max_extracted_chars_per_reference: int = 500_000,
    max_extracted_chars_per_cve: int = 2_000_000,
    retry_policy: RetryPolicy | None = None,
    request_pacer: Callable[[], float] = lambda: 0.0,
    session: requests.Session | None = None,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> CVEClassifierState:
    """Fetch ranked references within explicit network and content limits."""

    url_refs = state["nvd_url_references"].copy()
    pages_dict: dict[str, str] = {}
    warnings = list(state.get("pipeline_warnings", []))
    initial_warning_count = len(warnings)
    attempted = 0
    downloaded_bytes = 0
    extracted_chars = 0
    http_session = session or requests.Session()
    policy = retry_policy or RetryPolicy(max_attempts=max_attempts)
    LOGGER.debug(
        "Reference extraction started: candidates=%s successful-page-limit=%s",
        len(url_refs),
        max_pages,
    )

    for index, url_ref in enumerate(tqdm(url_refs, "Extracting references"), start=1):
        if len(pages_dict) >= max_pages:
            break
        remaining_bytes = max_bytes_per_cve - downloaded_bytes
        remaining_chars = max_extracted_chars_per_cve - extracted_chars
        if remaining_bytes <= 0 or remaining_chars <= 0:
            _append_warning(
                warnings,
                source=url_ref,
                error=ReferencePolicyError("CVE reference content budget exhausted"),
                safe_message="Remaining references were skipped after the CVE content limit",
            )
            break
        attempted += 1
        try:
            downloaded = _download_reference(
                url_ref,
                source_id=f"reference-{index:03d}",
                session=http_session,
                resolver=resolver,
                retry_policy=policy,
                request_pacer=request_pacer,
                connect_timeout_seconds=connect_timeout_seconds,
                read_timeout_seconds=read_timeout_seconds,
                max_redirects=max_redirects,
                max_bytes=min(max_bytes_per_reference, remaining_bytes),
            )
            downloaded_bytes += len(downloaded)
            text = trafilatura.extract(
                downloaded,
                url=url_ref,
                output_format="markdown",
                favor_recall=True,
            )
            if not isinstance(text, str) or not text.strip():
                raise ValueError("Reference extraction returned no text")
            text = text.strip()
            allowed_chars = min(max_extracted_chars_per_reference, remaining_chars)
            if len(text) > allowed_chars:
                marker = "\n\n[TRUNCATED BY CVEXPERT]"
                if allowed_chars > len(marker):
                    text = text[: allowed_chars - len(marker)].rstrip() + marker
                else:
                    text = text[:allowed_chars]
                _append_warning(
                    warnings,
                    source=url_ref,
                    error=ReferencePolicyError("Extracted reference exceeded character limit"),
                    safe_message="Extracted reference text was truncated",
                )
            pages_dict[url_ref] = text
            extracted_chars += len(text)
        except BudgetExceeded as error:
            raise PipelineStageError(
                stage="scrape",
                cve_id=state["cve_id"],
                error=error,
                safe_message="Reference acquisition budget exhausted",
                partial_state={
                    **state,
                    "nvd_references_pages": pages_dict,
                    "pipeline_warnings": warnings,
                },
            ) from error
        except Exception as error:
            _append_warning(
                warnings,
                source=url_ref,
                error=error,
                safe_message="Reference download or text extraction failed",
            )

    LOGGER.debug(
        "Reference extraction completed: attempted=%s extracted=%s bytes=%s chars=%s warnings=%s",
        attempted,
        len(pages_dict),
        downloaded_bytes,
        extracted_chars,
        len(warnings) - initial_warning_count,
    )
    return {
        **state,
        "nvd_references_pages": pages_dict,
        "pipeline_warnings": warnings,
    }
