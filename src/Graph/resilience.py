"""Bounded, observable retry handling for synchronous external requests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import random
import time
from typing import Any, Callable, TypeVar

import httpx
import openai
import requests

from Graph.audit import (
    current_execution_context,
    current_request_scope,
    utc_now,
)


T = TypeVar("T")
RETRYABLE_STATUSES = {408, 409, 425, 429}
RATE_LIMIT_HEADERS = {
    "x-ratelimit-limit-requests",
    "x-ratelimit-limit-tokens",
    "x-ratelimit-remaining-requests",
    "x-ratelimit-remaining-tokens",
    "x-ratelimit-reset-requests",
    "x-ratelimit-reset-tokens",
}


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    initial_backoff_seconds: float = 1.0
    max_backoff_seconds: float = 30.0
    max_retry_after_seconds: float = 30.0


def _status_code(error: BaseException) -> int | None:
    status = getattr(error, "status_code", None)
    if isinstance(status, int):
        return status
    response = getattr(error, "response", None)
    status = getattr(response, "status_code", None)
    return status if isinstance(status, int) else None


def _headers(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        raw = value.get("raw")
        if raw is not None:
            return _headers(raw)
        nested = value.get("headers")
        if hasattr(nested, "items"):
            return {str(key).lower(): str(item) for key, item in nested.items()}
    headers = getattr(value, "headers", None)
    if headers is None:
        response = getattr(value, "response", None)
        headers = getattr(response, "headers", None)
    if headers is None:
        return {}
    return {str(key).lower(): str(item) for key, item in headers.items()}


def _retry_after_seconds(error: BaseException) -> float | None:
    raw = _headers(error).get("retry-after")
    if raw is None:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(raw)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            return max(0.0, (retry_at - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None


def classify_error(error: BaseException) -> tuple[str, bool]:
    """Return a safe category and whether an error is transient."""

    status = _status_code(error)
    if status is not None:
        if status in RETRYABLE_STATUSES or 500 <= status <= 599:
            return f"http_{status}", True
        return f"http_{status}", False
    if isinstance(
        error,
        (
            TimeoutError,
            ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            httpx.TimeoutException,
            httpx.NetworkError,
            openai.APITimeoutError,
            openai.APIConnectionError,
        ),
    ):
        return "transport", True
    return type(error).__name__, False


def _response_metadata(value: Any) -> tuple[str | None, int | None, dict[str, str]]:
    if isinstance(value, dict) and value.get("raw") is not None:
        return _response_metadata(value["raw"])
    response_metadata = getattr(value, "response_metadata", None)
    if isinstance(response_metadata, dict):
        headers = _headers(response_metadata)
        request_id = headers.get("x-request-id")
        status = response_metadata.get("status_code")
        rate_limits = {key: headers[key] for key in RATE_LIMIT_HEADERS if key in headers}
        if request_id or isinstance(status, int) or rate_limits:
            return request_id, status if isinstance(status, int) else None, rate_limits
    direct_status = getattr(value, "status_code", None)
    response = value if isinstance(direct_status, int) else getattr(value, "response", value)
    headers = _headers(response)
    request_id = (
        getattr(value, "_request_id", None)
        or headers.get("x-request-id")
        or getattr(response, "id", None)
    )
    status = getattr(response, "status_code", None)
    rate_limits = {key: headers[key] for key in RATE_LIMIT_HEADERS if key in headers}
    return (
        str(request_id) if request_id else None,
        status if isinstance(status, int) else None,
        rate_limits,
    )


def execute_with_retry(
    operation: Callable[[], T],
    *,
    policy: RetryPolicy,
    pacer: Callable[[], float] | None = None,
    estimated_input_tokens: int = 0,
    estimated_output_tokens: int = 0,
    usage: Callable[[T], tuple[int, int] | None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    random_uniform: Callable[[float, float], float] = random.uniform,
) -> T:
    """Execute one logical request with repository-owned retry and telemetry."""

    if policy.max_attempts <= 0:
        raise ValueError("Retry max_attempts must be positive")
    scope = current_request_scope()
    context = current_execution_context()
    estimated_total = estimated_input_tokens + estimated_output_tokens

    for attempt in range(1, policy.max_attempts + 1):
        if context is not None:
            context.authorize_request(estimated_total)
        pacing_seconds = pacer() if pacer is not None else 0.0
        started_at = utc_now()
        started = clock()
        try:
            result = operation()
            provider_usage = usage(result) if usage is not None else None
            if provider_usage is None:
                input_tokens = estimated_input_tokens
                output_tokens = estimated_output_tokens
                usage_source = "estimate" if estimated_total else "unavailable"
                actual_total = estimated_total
            else:
                input_tokens, output_tokens = provider_usage
                actual_total = input_tokens + output_tokens
                usage_source = "provider"
                if context is not None:
                    context.reconcile_tokens(estimated_total, actual_total)
            request_id, status, rate_limits = _response_metadata(result)
            if context is not None:
                context.add_record(
                    {
                        **scope,
                        "attempt": attempt,
                        "started_at": started_at,
                        "latency_seconds": round(clock() - started, 3),
                        "pacing_seconds": round(pacing_seconds, 3),
                        "retry_delay_seconds": 0.0,
                        "status": "success",
                        "error_category": None,
                        "http_status": status,
                        "provider_request_id": request_id,
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens,
                        "total_tokens": actual_total,
                        "token_usage_source": usage_source,
                        "rate_limits": rate_limits,
                    }
                )
            return result
        except Exception as error:
            category, retryable = classify_error(error)
            retry_after = _retry_after_seconds(error)
            will_retry = retryable and attempt < policy.max_attempts
            if retry_after is not None and retry_after > policy.max_retry_after_seconds:
                will_retry = False
                category = "retry_after_exceeds_limit"
            delay = 0.0
            if will_retry:
                exponential_cap = min(
                    policy.max_backoff_seconds,
                    policy.initial_backoff_seconds * (2 ** (attempt - 1)),
                )
                delay = random_uniform(0.0, exponential_cap)
                if retry_after is not None:
                    delay = max(delay, retry_after)
                if context is not None and delay >= context.remaining_seconds():
                    will_retry = False
                    delay = 0.0
                    category = "retry_delay_exceeds_deadline"
            request_id, status, rate_limits = _response_metadata(error)
            if context is not None:
                context.add_record(
                    {
                        **scope,
                        "attempt": attempt,
                        "started_at": started_at,
                        "latency_seconds": round(clock() - started, 3),
                        "pacing_seconds": round(pacing_seconds, 3),
                        "retry_delay_seconds": round(delay, 3),
                        "status": "retrying" if will_retry else "error",
                        "error_category": category,
                        "http_status": status,
                        "provider_request_id": request_id,
                        "input_tokens": estimated_input_tokens,
                        "output_tokens": estimated_output_tokens,
                        "total_tokens": estimated_total,
                        "token_usage_source": "estimate" if estimated_total else "unavailable",
                        "rate_limits": rate_limits,
                    }
                )
            if not will_retry:
                raise
            sleep(delay)

    raise AssertionError("Retry loop exited unexpectedly")
