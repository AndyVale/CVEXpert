"""Typed, repository-rooted runtime configuration for the linear pipeline."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import math
from pathlib import Path
import tomllib
from urllib.parse import urlparse

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = REPOSITORY_ROOT / "config.toml"
CONFIG_EXAMPLE_PATH = REPOSITORY_ROOT / "config.example.toml"


@dataclass(frozen=True)
class ChatSettings:
    """Shared OpenAI-compatible chat endpoint and stage-specific models."""

    base_url: str
    api_key: str = field(repr=False)
    classifier_model: str
    classifier_temperature: float
    summarizer_model: str
    summarizer_temperature: float
    request_delay_seconds: float
    connect_timeout_seconds: float = 10.0
    read_timeout_seconds: float = 60.0
    write_timeout_seconds: float = 60.0
    pool_timeout_seconds: float = 10.0


@dataclass(frozen=True)
class EmbeddingSettings:
    """OpenAI-compatible embedding endpoint configuration."""

    base_url: str
    api_key: str = field(repr=False)
    model: str
    request_delay_seconds: float
    check_embedding_ctx_length: bool
    max_attempts: int = 3
    connect_timeout_seconds: float = 10.0
    read_timeout_seconds: float = 60.0
    write_timeout_seconds: float = 60.0
    pool_timeout_seconds: float = 10.0


@dataclass(frozen=True)
class NvdSettings:
    """NVD request settings currently honored by the pipeline."""

    base_url: str
    timeout_seconds: float
    request_delay_seconds: float
    api_key: str | None = field(default=None, repr=False)
    max_attempts: int = 3
    connect_timeout_seconds: float = 5.0


@dataclass(frozen=True)
class ReferenceSettings:
    """Reference acquisition limits."""

    max_pages: int
    max_attempts: int = 3
    connect_timeout_seconds: float = 10.0
    read_timeout_seconds: float = 30.0
    max_redirects: int = 5
    max_bytes_per_reference: int = 5 * 1024 * 1024
    max_bytes_per_cve: int = 20 * 1024 * 1024
    max_extracted_chars_per_reference: int = 500_000
    max_extracted_chars_per_cve: int = 2_000_000


@dataclass(frozen=True)
class SemanticChunkerSettings:
    """Parameters passed to LangChain's semantic chunker."""

    breakpoint_threshold_type: str
    breakpoint_threshold_amount: float
    max_chunks_per_reference: int = 256
    max_chunks_per_cve: int = 1024


@dataclass(frozen=True)
class CosineFilterSettings:
    """Query and threshold used to select reference chunks."""

    query: str
    threshold: float


@dataclass(frozen=True)
class FixtureSettings:
    """Selected JSON taxonomy and optional benchmark cases."""

    taxonomy_file: str
    expected_classification_file: str | None

    def resolved_taxonomy_file(self, repository_root: Path = REPOSITORY_ROOT) -> Path:
        path = Path(self.taxonomy_file).expanduser()
        return path if path.is_absolute() else repository_root / path

    def resolved_expected_classification_file(
        self, repository_root: Path = REPOSITORY_ROOT
    ) -> Path | None:
        if self.expected_classification_file is None:
            return None
        path = Path(self.expected_classification_file).expanduser()
        return path if path.is_absolute() else repository_root / path


@dataclass(frozen=True)
class ClassificationSettings:
    """Approximate classifier input budget per model call."""

    max_input_tokens: int
    max_attempts: int = 3
    structured_repair_attempts: int = 1
    max_output_tokens: int = 512


@dataclass(frozen=True)
class SummarizationSettings:
    """Summarizer retry, repair, and model-input limits."""

    max_attempts: int = 3
    structured_repair_attempts: int = 1
    max_input_tokens: int = 12_000
    max_output_tokens: int = 768


@dataclass(frozen=True)
class ResilienceSettings:
    """Backoff behavior shared by all synchronous request policies."""

    initial_backoff_seconds: float = 1.0
    max_backoff_seconds: float = 30.0
    max_retry_after_seconds: float = 30.0


@dataclass(frozen=True)
class BudgetSettings:
    """Request, token, and cooperative wall-clock limits."""

    max_requests_per_cve: int = 100
    max_tokens_per_cve: int = 250_000
    max_cve_seconds: float = 600.0
    max_requests_per_run: int = 5_000
    max_tokens_per_run: int = 10_000_000
    max_run_seconds: float = 21_600.0


@dataclass(frozen=True)
class EvaluationSettings:
    """Benchmark artifact settings."""

    log_directory: str
    run_number: int

    def resolved_log_directory(self, repository_root: Path = REPOSITORY_ROOT) -> Path:
        path = Path(self.log_directory).expanduser()
        return path if path.is_absolute() else repository_root / path


@dataclass(frozen=True)
class RuntimeConfig:
    """Complete configuration for one pipeline run."""

    chat: ChatSettings
    embedding: EmbeddingSettings
    nvd: NvdSettings
    references: ReferenceSettings
    semantic_chunker: SemanticChunkerSettings
    cosine_filter: CosineFilterSettings
    fixtures: FixtureSettings
    classification: ClassificationSettings
    evaluation: EvaluationSettings
    summarization: SummarizationSettings = field(default_factory=SummarizationSettings)
    resilience: ResilienceSettings = field(default_factory=ResilienceSettings)
    budgets: BudgetSettings = field(default_factory=BudgetSettings)

    @property
    def model_metadata(self) -> dict[str, str]:
        return {
            "chat_model": self.chat.classifier_model,
            "summarizer_model": self.chat.summarizer_model,
            "embedding_model": self.embedding.model,
        }


class RuntimeConfigurationError(ValueError):
    """Raised when the local TOML configuration is unavailable or invalid."""


def _configuration_error(message: str) -> RuntimeConfigurationError:
    return RuntimeConfigurationError(f"Invalid runtime configuration: {message}")


def _require_table(
    data: Mapping[str, object],
    name: str,
    allowed_keys: set[str],
) -> Mapping[str, object]:
    value = data.get(name)
    if not isinstance(value, dict):
        raise _configuration_error(f"[{name}] must be present and must be a table")

    unknown_keys = sorted(set(value) - allowed_keys)
    if unknown_keys:
        raise _configuration_error(
            f"[{name}] contains unknown setting(s): {', '.join(unknown_keys)}"
        )
    return value


def _optional_table(
    data: Mapping[str, object],
    name: str,
    allowed_keys: set[str],
) -> Mapping[str, object]:
    if name not in data:
        return {}
    return _require_table(data, name, allowed_keys)


def _require_string(table: Mapping[str, object], table_name: str, key: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _configuration_error(f"[{table_name}].{key} must be a non-empty string")
    return value.strip()


def _optional_string(
    table: Mapping[str, object], table_name: str, key: str
) -> str | None:
    if key not in table:
        return None
    return _require_string(table, table_name, key)


def _optional_number(
    table: Mapping[str, object], table_name: str, key: str, default: float
) -> float:
    if key not in table:
        return default
    return _require_number(table, table_name, key)


def _optional_integer(
    table: Mapping[str, object], table_name: str, key: str, default: int
) -> int:
    if key not in table:
        return default
    return _require_integer(table, table_name, key)


def _positive_number(value: float, setting_name: str) -> float:
    if not math.isfinite(value) or value <= 0:
        raise _configuration_error(f"{setting_name} must be a finite number greater than zero")
    return value


def _positive_integer(value: int, setting_name: str) -> int:
    if value <= 0:
        raise _configuration_error(f"{setting_name} must be greater than zero")
    return value


def _non_negative_integer(value: int, setting_name: str) -> int:
    if value < 0:
        raise _configuration_error(f"{setting_name} must be non-negative")
    return value


def _require_number(table: Mapping[str, object], table_name: str, key: str) -> float:
    value = table.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _configuration_error(f"[{table_name}].{key} must be a number")
    return float(value)


def _require_integer(table: Mapping[str, object], table_name: str, key: str) -> int:
    value = table.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _configuration_error(f"[{table_name}].{key} must be an integer")
    return value


def _require_boolean(table: Mapping[str, object], table_name: str, key: str) -> bool:
    value = table.get(key)
    if not isinstance(value, bool):
        raise _configuration_error(f"[{table_name}].{key} must be a boolean")
    return value


def _validate_url(value: str, setting_name: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise _configuration_error(
            f"{setting_name} must be a complete http:// or https:// URL"
        )
    return value


def _parse_runtime_config(data: Mapping[str, object]) -> RuntimeConfig:
    expected_tables = {
        "chat",
        "embedding",
        "nvd",
        "references",
        "semantic_chunker",
        "cosine_filter",
        "fixtures",
        "classification",
        "evaluation",
        "summarization",
        "resilience",
        "budgets",
    }
    unknown_tables = sorted(set(data) - expected_tables)
    if unknown_tables:
        raise _configuration_error(
            f"unknown top-level table(s): {', '.join(unknown_tables)}"
        )

    chat_data = _require_table(
        data,
        "chat",
        {
            "base_url",
            "api_key",
            "classifier_model",
            "classifier_temperature",
            "summarizer_model",
            "summarizer_temperature",
            "request_delay_seconds",
            "connect_timeout_seconds",
            "read_timeout_seconds",
            "write_timeout_seconds",
            "pool_timeout_seconds",
        },
    )
    embedding_data = _require_table(
        data,
        "embedding",
        {
            "base_url",
            "api_key",
            "model",
            "request_delay_seconds",
            "check_embedding_ctx_length",
            "max_attempts",
            "connect_timeout_seconds",
            "read_timeout_seconds",
            "write_timeout_seconds",
            "pool_timeout_seconds",
        },
    )
    nvd_data = _require_table(
        data,
        "nvd",
        {
            "base_url",
            "timeout_seconds",
            "request_delay_seconds",
            "api_key",
            "max_attempts",
            "connect_timeout_seconds",
        },
    )
    reference_data = _require_table(
        data,
        "references",
        {
            "max_pages",
            "max_attempts",
            "connect_timeout_seconds",
            "read_timeout_seconds",
            "max_redirects",
            "max_bytes_per_reference",
            "max_bytes_per_cve",
            "max_extracted_chars_per_reference",
            "max_extracted_chars_per_cve",
        },
    )
    chunker_data = _require_table(
        data,
        "semantic_chunker",
        {
            "breakpoint_threshold_type",
            "breakpoint_threshold_amount",
            "max_chunks_per_reference",
            "max_chunks_per_cve",
        },
    )
    filter_data = _require_table(data, "cosine_filter", {"query", "threshold"})
    fixture_data = _require_table(
        data,
        "fixtures",
        {"taxonomy_file", "expected_classification_file"},
    )
    classification_data = _require_table(
        data,
        "classification",
        {
            "max_input_tokens",
            "max_attempts",
            "structured_repair_attempts",
            "max_output_tokens",
        },
    )
    evaluation_data = _require_table(
        data,
        "evaluation",
        {"log_directory", "run_number"},
    )
    summarization_data = _optional_table(
        data,
        "summarization",
        {
            "max_attempts",
            "structured_repair_attempts",
            "max_input_tokens",
            "max_output_tokens",
        },
    )
    resilience_data = _optional_table(
        data,
        "resilience",
        {
            "initial_backoff_seconds",
            "max_backoff_seconds",
            "max_retry_after_seconds",
        },
    )
    budgets_data = _optional_table(
        data,
        "budgets",
        {
            "max_requests_per_cve",
            "max_tokens_per_cve",
            "max_cve_seconds",
            "max_requests_per_run",
            "max_tokens_per_run",
            "max_run_seconds",
        },
    )

    classifier_temperature = _require_number(
        chat_data,
        "chat",
        "classifier_temperature",
    )
    summarizer_temperature = _require_number(
        chat_data,
        "chat",
        "summarizer_temperature",
    )
    if classifier_temperature < 0 or summarizer_temperature < 0:
        raise _configuration_error("chat temperatures must be greater than or equal to zero")

    chat_request_delay = _require_number(
        chat_data,
        "chat",
        "request_delay_seconds",
    )
    embedding_request_delay = _require_number(
        embedding_data,
        "embedding",
        "request_delay_seconds",
    )
    if not math.isfinite(chat_request_delay) or chat_request_delay < 0:
        raise _configuration_error(
            "[chat].request_delay_seconds must be a finite number greater than or equal to zero"
        )
    if not math.isfinite(embedding_request_delay) or embedding_request_delay < 0:
        raise _configuration_error(
            "[embedding].request_delay_seconds must be a finite number greater than or equal to zero"
        )

    nvd_timeout = _require_number(nvd_data, "nvd", "timeout_seconds")
    if nvd_timeout <= 0:
        raise _configuration_error("[nvd].timeout_seconds must be greater than zero")
    nvd_request_delay = _require_number(
        nvd_data,
        "nvd",
        "request_delay_seconds",
    )
    if not math.isfinite(nvd_request_delay) or nvd_request_delay < 0:
        raise _configuration_error(
            "[nvd].request_delay_seconds must be a finite number greater than or equal to zero"
        )

    max_pages = _require_integer(reference_data, "references", "max_pages")
    if max_pages <= 0:
        raise _configuration_error("[references].max_pages must be greater than zero")

    threshold_type = _require_string(
        chunker_data,
        "semantic_chunker",
        "breakpoint_threshold_type",
    )
    supported_threshold_types = {
        "percentile",
        "standard_deviation",
        "interquartile",
        "gradient",
    }
    if threshold_type not in supported_threshold_types:
        raise _configuration_error(
            "[semantic_chunker].breakpoint_threshold_type must be one of: "
            + ", ".join(sorted(supported_threshold_types))
        )

    threshold_amount = _require_number(
        chunker_data,
        "semantic_chunker",
        "breakpoint_threshold_amount",
    )
    if threshold_amount < 0:
        raise _configuration_error(
            "[semantic_chunker].breakpoint_threshold_amount must be non-negative"
        )

    cosine_threshold = _require_number(filter_data, "cosine_filter", "threshold")
    if not -1 <= cosine_threshold <= 1:
        raise _configuration_error("[cosine_filter].threshold must be between -1 and 1")

    run_number = _require_integer(evaluation_data, "evaluation", "run_number")
    if run_number < 0:
        raise _configuration_error("[evaluation].run_number must be non-negative")
    max_input_tokens = _require_integer(
        classification_data, "classification", "max_input_tokens"
    )
    if max_input_tokens <= 0:
        raise _configuration_error("[classification].max_input_tokens must be positive")

    def positive_optional_number(
        table: Mapping[str, object], table_name: str, key: str, default: float
    ) -> float:
        return _positive_number(
            _optional_number(table, table_name, key, default),
            f"[{table_name}].{key}",
        )

    def positive_optional_integer(
        table: Mapping[str, object], table_name: str, key: str, default: int
    ) -> int:
        return _positive_integer(
            _optional_integer(table, table_name, key, default),
            f"[{table_name}].{key}",
        )

    chat_timeouts = {
        key: positive_optional_number(chat_data, "chat", key, default)
        for key, default in {
            "connect_timeout_seconds": 10.0,
            "read_timeout_seconds": 60.0,
            "write_timeout_seconds": 60.0,
            "pool_timeout_seconds": 10.0,
        }.items()
    }
    embedding_timeouts = {
        key: positive_optional_number(embedding_data, "embedding", key, default)
        for key, default in {
            "connect_timeout_seconds": 10.0,
            "read_timeout_seconds": 60.0,
            "write_timeout_seconds": 60.0,
            "pool_timeout_seconds": 10.0,
        }.items()
    }
    embedding_max_attempts = positive_optional_integer(
        embedding_data, "embedding", "max_attempts", 3
    )
    nvd_max_attempts = positive_optional_integer(nvd_data, "nvd", "max_attempts", 3)
    nvd_connect_timeout = positive_optional_number(
        nvd_data, "nvd", "connect_timeout_seconds", 5.0
    )

    reference_defaults = ReferenceSettings(max_pages=max_pages)
    reference_values = {
        "max_attempts": positive_optional_integer(
            reference_data, "references", "max_attempts", reference_defaults.max_attempts
        ),
        "connect_timeout_seconds": positive_optional_number(
            reference_data,
            "references",
            "connect_timeout_seconds",
            reference_defaults.connect_timeout_seconds,
        ),
        "read_timeout_seconds": positive_optional_number(
            reference_data,
            "references",
            "read_timeout_seconds",
            reference_defaults.read_timeout_seconds,
        ),
        "max_redirects": _non_negative_integer(
            _optional_integer(
                reference_data,
                "references",
                "max_redirects",
                reference_defaults.max_redirects,
            ),
            "[references].max_redirects",
        ),
    }
    for key in (
        "max_bytes_per_reference",
        "max_bytes_per_cve",
        "max_extracted_chars_per_reference",
        "max_extracted_chars_per_cve",
    ):
        reference_values[key] = positive_optional_integer(
            reference_data, "references", key, getattr(reference_defaults, key)
        )
    if reference_values["max_bytes_per_cve"] < reference_values["max_bytes_per_reference"]:
        raise _configuration_error(
            "[references].max_bytes_per_cve must be at least max_bytes_per_reference"
        )
    if (
        reference_values["max_extracted_chars_per_cve"]
        < reference_values["max_extracted_chars_per_reference"]
    ):
        raise _configuration_error(
            "[references].max_extracted_chars_per_cve must be at least "
            "max_extracted_chars_per_reference"
        )

    chunk_limits = {
        "max_chunks_per_reference": positive_optional_integer(
            chunker_data, "semantic_chunker", "max_chunks_per_reference", 256
        ),
        "max_chunks_per_cve": positive_optional_integer(
            chunker_data, "semantic_chunker", "max_chunks_per_cve", 1024
        ),
    }
    if chunk_limits["max_chunks_per_cve"] < chunk_limits["max_chunks_per_reference"]:
        raise _configuration_error(
            "[semantic_chunker].max_chunks_per_cve must be at least max_chunks_per_reference"
        )

    summarization_settings = SummarizationSettings(
        max_attempts=positive_optional_integer(
            summarization_data, "summarization", "max_attempts", 3
        ),
        structured_repair_attempts=_non_negative_integer(
            _optional_integer(
                summarization_data,
                "summarization",
                "structured_repair_attempts",
                1,
            ),
            "[summarization].structured_repair_attempts",
        ),
        max_input_tokens=positive_optional_integer(
            summarization_data, "summarization", "max_input_tokens", 12_000
        ),
        max_output_tokens=positive_optional_integer(
            summarization_data, "summarization", "max_output_tokens", 768
        ),
    )
    classification_settings = ClassificationSettings(
        max_input_tokens=max_input_tokens,
        max_attempts=positive_optional_integer(
            classification_data, "classification", "max_attempts", 3
        ),
        structured_repair_attempts=_non_negative_integer(
            _optional_integer(
                classification_data,
                "classification",
                "structured_repair_attempts",
                1,
            ),
            "[classification].structured_repair_attempts",
        ),
        max_output_tokens=positive_optional_integer(
            classification_data, "classification", "max_output_tokens", 512
        ),
    )
    resilience_settings = ResilienceSettings(
        initial_backoff_seconds=positive_optional_number(
            resilience_data, "resilience", "initial_backoff_seconds", 1.0
        ),
        max_backoff_seconds=positive_optional_number(
            resilience_data, "resilience", "max_backoff_seconds", 30.0
        ),
        max_retry_after_seconds=positive_optional_number(
            resilience_data, "resilience", "max_retry_after_seconds", 30.0
        ),
    )
    if resilience_settings.max_backoff_seconds < resilience_settings.initial_backoff_seconds:
        raise _configuration_error(
            "[resilience].max_backoff_seconds must be at least initial_backoff_seconds"
        )
    budget_settings = BudgetSettings(
        max_requests_per_cve=positive_optional_integer(
            budgets_data, "budgets", "max_requests_per_cve", 100
        ),
        max_tokens_per_cve=positive_optional_integer(
            budgets_data, "budgets", "max_tokens_per_cve", 250_000
        ),
        max_cve_seconds=positive_optional_number(
            budgets_data, "budgets", "max_cve_seconds", 600.0
        ),
        max_requests_per_run=positive_optional_integer(
            budgets_data, "budgets", "max_requests_per_run", 5_000
        ),
        max_tokens_per_run=positive_optional_integer(
            budgets_data, "budgets", "max_tokens_per_run", 10_000_000
        ),
        max_run_seconds=positive_optional_number(
            budgets_data, "budgets", "max_run_seconds", 21_600.0
        ),
    )
    if budget_settings.max_requests_per_run < budget_settings.max_requests_per_cve:
        raise _configuration_error(
            "[budgets].max_requests_per_run must be at least max_requests_per_cve"
        )
    if budget_settings.max_tokens_per_run < budget_settings.max_tokens_per_cve:
        raise _configuration_error(
            "[budgets].max_tokens_per_run must be at least max_tokens_per_cve"
        )

    return RuntimeConfig(
        chat=ChatSettings(
            base_url=_validate_url(
                _require_string(chat_data, "chat", "base_url"),
                "[chat].base_url",
            ),
            api_key=_require_string(chat_data, "chat", "api_key"),
            classifier_model=_require_string(
                chat_data,
                "chat",
                "classifier_model",
            ),
            classifier_temperature=classifier_temperature,
            summarizer_model=_require_string(
                chat_data,
                "chat",
                "summarizer_model",
            ),
            summarizer_temperature=summarizer_temperature,
            request_delay_seconds=chat_request_delay,
            **chat_timeouts,
        ),
        embedding=EmbeddingSettings(
            base_url=_validate_url(
                _require_string(embedding_data, "embedding", "base_url"),
                "[embedding].base_url",
            ),
            api_key=_require_string(embedding_data, "embedding", "api_key"),
            model=_require_string(embedding_data, "embedding", "model"),
            request_delay_seconds=embedding_request_delay,
            check_embedding_ctx_length=_require_boolean(
                embedding_data,
                "embedding",
                "check_embedding_ctx_length",
            ),
            max_attempts=embedding_max_attempts,
            **embedding_timeouts,
        ),
        nvd=NvdSettings(
            base_url=_validate_url(
                _require_string(nvd_data, "nvd", "base_url"),
                "[nvd].base_url",
            ),
            timeout_seconds=nvd_timeout,
            request_delay_seconds=nvd_request_delay,
            api_key=_optional_string(nvd_data, "nvd", "api_key"),
            max_attempts=nvd_max_attempts,
            connect_timeout_seconds=nvd_connect_timeout,
        ),
        references=ReferenceSettings(max_pages=max_pages, **reference_values),
        semantic_chunker=SemanticChunkerSettings(
            breakpoint_threshold_type=threshold_type,
            breakpoint_threshold_amount=threshold_amount,
            **chunk_limits,
        ),
        cosine_filter=CosineFilterSettings(
            query=_require_string(filter_data, "cosine_filter", "query"),
            threshold=cosine_threshold,
        ),
        fixtures=FixtureSettings(
            taxonomy_file=_require_string(fixture_data, "fixtures", "taxonomy_file"),
            expected_classification_file=_optional_string(
                fixture_data, "fixtures", "expected_classification_file"
            ),
        ),
        classification=classification_settings,
        evaluation=EvaluationSettings(
            log_directory=_require_string(
                evaluation_data,
                "evaluation",
                "log_directory",
            ),
            run_number=run_number,
        ),
        summarization=summarization_settings,
        resilience=resilience_settings,
        budgets=budget_settings,
    )


def load_runtime_config(
    config_path: str | Path | None = None,
) -> RuntimeConfig:
    """Load and validate the ignored local TOML configuration."""

    path = Path(config_path) if config_path is not None else CONFIG_PATH
    if not path.is_file():
        hint = " Copy config.example.toml to config.toml and edit it."
        raise RuntimeConfigurationError(f"Configuration file not found: {path}.{hint}")

    try:
        with path.open("rb") as config_file:
            data = tomllib.load(config_file)
    except tomllib.TOMLDecodeError as error:
        raise RuntimeConfigurationError(
            f"Invalid TOML in configuration file {path}: {error}"
        ) from error

    return _parse_runtime_config(data)


def validate_runtime_config(
    config_path: str | Path | None = None,
) -> RuntimeConfig:
    """Compatibility wrapper returning the validated runtime configuration."""

    return load_runtime_config(config_path)
