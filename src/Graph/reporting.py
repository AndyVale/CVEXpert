"""Tqdm-safe, secret-conscious console reporting for the linear pipeline."""

from __future__ import annotations

import logging
import os
import re
import shutil
import sys
import textwrap
from collections.abc import Iterable, Mapping, Sequence
from numbers import Real
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit, urlunsplit

from tqdm import tqdm


LOGGER_NAME = "cvexpert"
ANSI_YELLOW = "\033[33m"
ANSI_RED = "\033[31m"
ANSI_RESET = "\033[0m"
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
_HTML_ERROR_PATTERN = re.compile(r"<!doctype\s+html|<html(?:\s|>)", re.IGNORECASE)


def get_logger(component: str | None = None) -> logging.Logger:
    """Return the project logger or one of its component children."""

    return logging.getLogger(
        LOGGER_NAME if not component else f"{LOGGER_NAME}.{component}"
    )


def sanitize_url(value: str) -> str:
    """Remove credentials, query parameters, and fragments from a displayed URL."""

    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return value

        hostname = parsed.hostname
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        try:
            port = f":{parsed.port}" if parsed.port is not None else ""
        except ValueError:
            port = ""
        return urlunsplit((parsed.scheme, f"{hostname}{port}", parsed.path, "", ""))
    except (TypeError, ValueError):
        return value


def _sanitize_urls_in_text(value: str) -> str:
    return _URL_PATTERN.sub(lambda match: sanitize_url(match.group(0)), value)


def _collapse_whitespace(value: str) -> str:
    return " ".join(value.split())


def _shorten_console_line(value: str) -> str:
    terminal_width = shutil.get_terminal_size(fallback=(160, 24)).columns
    width = max(40, terminal_width)
    collapsed = _collapse_whitespace(value)
    if len(collapsed) <= width:
        return collapsed
    return f"{collapsed[:width - 3].rstrip()}..."


def _extract_provider_message(error: BaseException) -> str:
    body = getattr(error, "body", None)
    if isinstance(body, Mapping):
        error_body = body.get("error", body)
        if isinstance(error_body, Mapping):
            message = error_body.get("message")
            if isinstance(message, str) and message.strip():
                return message
        message = body.get("message")
        if isinstance(message, str) and message.strip():
            return message
    return str(error)


def concise_exception(error: BaseException) -> str:
    """Return one short technical line without dumping a full response payload."""

    error_type = type(error).__name__
    status_code = getattr(error, "status_code", None)
    prefix = error_type
    if isinstance(status_code, int):
        prefix += f" (HTTP {status_code})"

    message = _collapse_whitespace(_extract_provider_message(error))
    message = _sanitize_urls_in_text(message)
    if _HTML_ERROR_PATTERN.search(message):
        message = "Upstream service returned an HTML error page"
    if not message:
        message = "No additional diagnostic detail"

    detail = _shorten_console_line(message)
    return f"{prefix}: {detail}"


class _RedactingFormatter(logging.Formatter):
    def __init__(self, sensitive_values: Iterable[str]) -> None:
        super().__init__("%(message)s")
        self._sensitive_values = tuple(
            value for value in sensitive_values if isinstance(value, str) and value
        )

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        for value in self._sensitive_values:
            message = message.replace(value, "<redacted>")
        return _sanitize_urls_in_text(message)


class TqdmConsoleHandler(logging.Handler):
    """Write log records without corrupting active tqdm progress bars."""

    def __init__(
        self,
        *,
        stream: TextIO | None = None,
        use_color: bool | None = None,
    ) -> None:
        super().__init__()
        self.stream = stream if stream is not None else sys.stderr
        if use_color is None:
            is_terminal = bool(getattr(self.stream, "isatty", lambda: False)())
            use_color = is_terminal and "NO_COLOR" not in os.environ
        self.use_color = use_color

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
            if self.use_color and record.levelno >= logging.ERROR:
                message = f"{ANSI_RED}{message}{ANSI_RESET}"
            elif self.use_color and record.levelno >= logging.WARNING:
                message = f"{ANSI_YELLOW}{message}{ANSI_RESET}"
            tqdm.write(message, file=self.stream)
        except Exception:
            self.handleError(record)


class _ConsoleModeFilter(logging.Filter):
    """Hide recoverable warnings in normal mode while retaining INFO and ERROR."""

    def __init__(self, *, verbose: bool) -> None:
        super().__init__()
        self.verbose = verbose

    def filter(self, record: logging.LogRecord) -> bool:
        return (
            self.verbose
            or record.levelno < logging.WARNING
            or record.levelno >= logging.ERROR
        )


def configure_console(
    *,
    verbose: bool,
    sensitive_values: Iterable[str] = (),
    stream: TextIO | None = None,
    use_color: bool | None = None,
) -> logging.Logger:
    """Configure the project logger for one CLI or programmatic run."""

    logger = get_logger()
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    handler = TqdmConsoleHandler(stream=stream, use_color=use_color)
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler.addFilter(_ConsoleModeFilter(verbose=verbose))
    handler.setFormatter(_RedactingFormatter(sensitive_values))
    logger.addHandler(handler)
    return logger


def report_warning(
    logger: logging.Logger,
    warning: Mapping[str, str],
    error: BaseException,
) -> None:
    """Print one recoverable warning with short technical context."""

    source = warning.get("source", "unknown source")
    if source.startswith(("http://", "https://")):
        source = sanitize_url(source)
    logger.warning(
        _shorten_console_line(
            "WARNING "
            f"[{warning.get('stage', 'pipeline')}] "
            f"{concise_exception(error)} — "
            f"{warning.get('message', 'Recoverable pipeline failure')} — "
            f"source={source}"
        )
    )


def report_error(
    logger: logging.Logger,
    message: str,
    error: BaseException,
) -> None:
    """Print one terminal error with short technical context."""

    logger.error(
        _shorten_console_line(f"ERROR {message} — {concise_exception(error)}")
    )


def _render_table(rows: list[tuple[str, str, str]]) -> str:
    headers = ("Section", "Setting", "Value")
    all_rows = [headers, *rows]
    widths = [max(len(row[index]) for row in all_rows) for index in range(3)]

    def render_row(row: tuple[str, str, str]) -> str:
        return " | ".join(
            value.ljust(widths[index]) for index, value in enumerate(row)
        )

    divider = "-+-".join("-" * width for width in widths)
    return "\n".join(
        ["Runtime configuration", render_row(headers), divider]
        + [render_row(row) for row in rows]
    )


def render_runtime_config(
    runtime_config: Any,
    *,
    config_path: str | Path,
    cve_count: int,
) -> str:
    """Render all effective non-secret settings as an aligned table."""

    rows = [
        ("runtime", "config file", str(Path(config_path).resolve())),
        ("runtime", "verbosity", "verbose"),
        ("runtime", "selected CVEs", str(cve_count)),
        ("chat", "endpoint", sanitize_url(runtime_config.chat.base_url)),
        ("chat", "API key", "configured"),
        ("chat", "classifier model", runtime_config.chat.classifier_model),
        (
            "chat",
            "classifier temperature",
            str(runtime_config.chat.classifier_temperature),
        ),
        ("chat", "summarizer model", runtime_config.chat.summarizer_model),
        (
            "chat",
            "summarizer temperature",
            str(runtime_config.chat.summarizer_temperature),
        ),
        (
            "chat",
            "request delay (s)",
            str(runtime_config.chat.request_delay_seconds),
        ),
        ("embedding", "endpoint", sanitize_url(runtime_config.embedding.base_url)),
        ("embedding", "API key", "configured"),
        ("embedding", "model", runtime_config.embedding.model),
        (
            "embedding",
            "request delay (s)",
            str(runtime_config.embedding.request_delay_seconds),
        ),
        (
            "embedding",
            "context-length check",
            str(runtime_config.embedding.check_embedding_ctx_length),
        ),
        ("nvd", "endpoint", sanitize_url(runtime_config.nvd.base_url)),
        ("nvd", "timeout (s)", str(runtime_config.nvd.timeout_seconds)),
        (
            "nvd",
            "request delay (s)",
            str(runtime_config.nvd.request_delay_seconds),
        ),
        ("references", "maximum pages", str(runtime_config.references.max_pages)),
        (
            "semantic chunker",
            "threshold type",
            runtime_config.semantic_chunker.breakpoint_threshold_type,
        ),
        (
            "semantic chunker",
            "threshold amount",
            str(runtime_config.semantic_chunker.breakpoint_threshold_amount),
        ),
        ("cosine filter", "query", runtime_config.cosine_filter.query),
        ("cosine filter", "threshold", str(runtime_config.cosine_filter.threshold)),
        (
            "fixtures",
            "taxonomy",
            str(runtime_config.fixtures.resolved_taxonomy_file()),
        ),
        (
            "fixtures",
            "expected cases",
            str(runtime_config.fixtures.resolved_expected_classification_file() or "not configured"),
        ),
        (
            "classification",
            "maximum input tokens",
            str(runtime_config.classification.max_input_tokens),
        ),
        (
            "evaluation",
            "log directory",
            str(runtime_config.evaluation.resolved_log_directory()),
        ),
        ("evaluation", "run number", str(runtime_config.evaluation.run_number)),
    ]
    return _render_table(rows)


def _render_wrapped_table(
    headers: tuple[str, ...],
    rows: list[tuple[str, ...]],
    width_limits: tuple[int, ...],
) -> str:
    """Render an aligned table while wrapping potentially long label cells."""

    if len(headers) != len(width_limits):
        raise ValueError("Table headers and width limits must have the same length")
    normalized_rows = [
        tuple(_collapse_whitespace(str(value)) for value in row) for row in rows
    ]
    if any(len(row) != len(headers) for row in normalized_rows):
        raise ValueError("Every table row must match the header width")

    all_rows = [headers, *normalized_rows]
    widths = tuple(
        min(max(len(row[index]) for row in all_rows), width_limits[index])
        for index in range(len(headers))
    )

    def wrap_cell(value: str, width: int) -> list[str]:
        return textwrap.wrap(
            value,
            width=width,
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""]

    def render_row(row: tuple[str, ...]) -> list[str]:
        wrapped = [wrap_cell(value, widths[index]) for index, value in enumerate(row)]
        height = max(len(cell) for cell in wrapped)
        return [
            " | ".join(
                wrapped[index][line].ljust(widths[index])
                if line < len(wrapped[index])
                else " " * widths[index]
                for index in range(len(headers))
            )
            for line in range(height)
        ]

    divider = "-+-".join("-" * width for width in widths)
    rendered = [*render_row(headers), divider]
    for row in normalized_rows:
        rendered.extend(render_row(row))
    return "\n".join(rendered)


def _labels_cell(value: Any) -> str:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        labels = [str(label) for label in value]
        return ", ".join(labels) if labels else "—"
    return "—"


def _score_cell(scores: Mapping[str, Any], name: str) -> str:
    value = scores.get(name)
    if isinstance(value, Real) and not isinstance(value, bool):
        return f"{float(value):.3f}"
    return "—"


def render_benchmark_results(
    cves: Mapping[str, Mapping[str, Any]],
    aggregate_scores: Mapping[str, Any],
) -> str:
    """Render per-CVE label comparisons, scores, and aggregate coverage."""

    score_names = ("accuracy", "precision", "recall", "f1")
    rows: list[tuple[str, ...]] = []
    for cve_id, entry in cves.items():
        individual_scores = entry.get("individual_scores", {})
        if not isinstance(individual_scores, Mapping):
            individual_scores = {}
        rows.append(
            (
                cve_id,
                str(entry.get("status", "unknown")),
                _labels_cell(entry.get("expected_labels")),
                _labels_cell(entry.get("classification_output")),
                *(_score_cell(individual_scores, name) for name in score_names),
            )
        )

    scored = aggregate_scores.get("scored", 0)
    total = aggregate_scores.get("total", len(cves))
    rows.append(
        (
            "AGGREGATE",
            f"{scored}/{total} scored",
            "—",
            "—",
            *(_score_cell(aggregate_scores, name) for name in score_names),
        )
    )
    table = _render_wrapped_table(
        (
            "CVE",
            "Status",
            "Expected labels",
            "Predicted labels",
            "Accuracy",
            "Precision",
            "Recall",
            "F1",
        ),
        rows,
        (20, 14, 32, 32, 8, 9, 6, 5),
    )
    complete = "yes" if aggregate_scores.get("complete") is True else "no"
    coverage = (
        "Coverage: "
        f"successful={aggregate_scores.get('successful', 0)} "
        f"degraded={aggregate_scores.get('degraded', 0)} "
        f"failed={aggregate_scores.get('failed', 0)} "
        f"scored={scored}/{total} complete={complete}"
    )
    return "\n".join(
        [
            "Benchmark results",
            "Accuracy is exact label-set match; precision, recall, and F1 are micro averaged.",
            table,
            coverage,
        ]
    )


get_logger().addHandler(logging.NullHandler())
