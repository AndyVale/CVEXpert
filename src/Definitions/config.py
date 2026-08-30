"""Typed, repository-rooted runtime configuration for the linear pipeline."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import tomllib
from urllib.parse import urlparse

from dotenv import load_dotenv


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = REPOSITORY_ROOT / "config.toml"
CONFIG_EXAMPLE_PATH = REPOSITORY_ROOT / "config.example.toml"
DOTENV_PATH = REPOSITORY_ROOT / ".env"


@dataclass(frozen=True)
class ChatSettings:
    """Shared OpenAI-compatible chat endpoint and stage-specific models."""

    base_url: str
    api_key_env: str
    classifier_model: str
    classifier_temperature: float
    summarizer_model: str
    summarizer_temperature: float


@dataclass(frozen=True)
class EmbeddingSettings:
    """OpenAI-compatible embedding endpoint configuration."""

    base_url: str
    api_key_env: str
    model: str


@dataclass(frozen=True)
class NvdSettings:
    """NVD request settings currently honored by the pipeline."""

    base_url: str
    timeout_seconds: float


@dataclass(frozen=True)
class ReferenceSettings:
    """Reference acquisition limits."""

    max_pages: int


@dataclass(frozen=True)
class SemanticChunkerSettings:
    """Parameters passed to LangChain's semantic chunker."""

    breakpoint_threshold_type: str
    breakpoint_threshold_amount: float


@dataclass(frozen=True)
class CosineFilterSettings:
    """Query and threshold used to select reference chunks."""

    query: str
    threshold: float


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
    """Complete non-secret configuration for one pipeline run."""

    chat: ChatSettings
    embedding: EmbeddingSettings
    nvd: NvdSettings
    references: ReferenceSettings
    semantic_chunker: SemanticChunkerSettings
    cosine_filter: CosineFilterSettings
    evaluation: EvaluationSettings

    @property
    def model_metadata(self) -> dict[str, str]:
        return {
            "chat_model": self.chat.classifier_model,
            "summarizer_model": self.chat.summarizer_model,
            "embedding_model": self.embedding.model,
        }


class RuntimeConfigurationError(ValueError):
    """Raised when TOML settings or referenced secrets are unavailable."""

    def __init__(
        self,
        message: str,
        *,
        missing_variables: tuple[str, ...] = (),
    ):
        self.missing_variables = missing_variables
        super().__init__(message)


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


def _require_string(table: Mapping[str, object], table_name: str, key: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _configuration_error(f"[{table_name}].{key} must be a non-empty string")
    return value.strip()


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
        "evaluation",
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
            "api_key_env",
            "classifier_model",
            "classifier_temperature",
            "summarizer_model",
            "summarizer_temperature",
        },
    )
    embedding_data = _require_table(
        data,
        "embedding",
        {"base_url", "api_key_env", "model"},
    )
    nvd_data = _require_table(data, "nvd", {"base_url", "timeout_seconds"})
    reference_data = _require_table(data, "references", {"max_pages"})
    chunker_data = _require_table(
        data,
        "semantic_chunker",
        {"breakpoint_threshold_type", "breakpoint_threshold_amount"},
    )
    filter_data = _require_table(data, "cosine_filter", {"query", "threshold"})
    evaluation_data = _require_table(
        data,
        "evaluation",
        {"log_directory", "run_number"},
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

    nvd_timeout = _require_number(nvd_data, "nvd", "timeout_seconds")
    if nvd_timeout <= 0:
        raise _configuration_error("[nvd].timeout_seconds must be greater than zero")

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

    return RuntimeConfig(
        chat=ChatSettings(
            base_url=_validate_url(
                _require_string(chat_data, "chat", "base_url"),
                "[chat].base_url",
            ),
            api_key_env=_require_string(chat_data, "chat", "api_key_env"),
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
        ),
        embedding=EmbeddingSettings(
            base_url=_validate_url(
                _require_string(embedding_data, "embedding", "base_url"),
                "[embedding].base_url",
            ),
            api_key_env=_require_string(
                embedding_data,
                "embedding",
                "api_key_env",
            ),
            model=_require_string(embedding_data, "embedding", "model"),
        ),
        nvd=NvdSettings(
            base_url=_validate_url(
                _require_string(nvd_data, "nvd", "base_url"),
                "[nvd].base_url",
            ),
            timeout_seconds=nvd_timeout,
        ),
        references=ReferenceSettings(max_pages=max_pages),
        semantic_chunker=SemanticChunkerSettings(
            breakpoint_threshold_type=threshold_type,
            breakpoint_threshold_amount=threshold_amount,
        ),
        cosine_filter=CosineFilterSettings(
            query=_require_string(filter_data, "cosine_filter", "query"),
            threshold=cosine_threshold,
        ),
        evaluation=EvaluationSettings(
            log_directory=_require_string(
                evaluation_data,
                "evaluation",
                "log_directory",
            ),
            run_number=run_number,
        ),
    )


def _validate_secret_environment(
    config: RuntimeConfig,
    *,
    require_embedding: bool,
    environ: Mapping[str, str],
) -> None:
    required_variables = [config.chat.api_key_env]
    if require_embedding:
        required_variables.append(config.embedding.api_key_env)

    missing_variables = tuple(
        variable_name
        for variable_name in dict.fromkeys(required_variables)
        if not environ.get(variable_name, "").strip()
    )
    if missing_variables:
        raise RuntimeConfigurationError(
            "Missing required environment variables: " + ", ".join(missing_variables),
            missing_variables=missing_variables,
        )


def load_runtime_config(
    config_path: str | Path | None = None,
    *,
    require_embedding: bool = True,
    environ: Mapping[str, str] | None = None,
) -> RuntimeConfig:
    """Load TOML configuration and validate its referenced secret variables."""

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

    config = _parse_runtime_config(data)

    if environ is None:
        load_dotenv(dotenv_path=DOTENV_PATH, override=False)
        environment: Mapping[str, str] = os.environ
    else:
        environment = environ

    _validate_secret_environment(
        config,
        require_embedding=require_embedding,
        environ=environment,
    )
    return config


def read_api_key(
    variable_name: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Read one already-validated secret without placing it in TOML or logs."""

    environment = os.environ if environ is None else environ
    value = environment.get(variable_name, "")
    if not value.strip():
        raise RuntimeConfigurationError(
            f"Missing required environment variables: {variable_name}",
            missing_variables=(variable_name,),
        )
    return value


def validate_runtime_config(
    require_embedding: bool = True,
    config_path: str | Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> RuntimeConfig:
    """Compatibility wrapper returning the validated runtime configuration."""

    return load_runtime_config(
        config_path,
        require_embedding=require_embedding,
        environ=environ,
    )
