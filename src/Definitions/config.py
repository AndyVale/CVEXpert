import os
from pathlib import Path

from dotenv import load_dotenv


REF_MAX = 10
NOT_NONE_REF_MAX = 5

CHAT_MODEL = "openai/gpt-oss-20b"
CHAT_MODEL_TEMP = 0.0

SUMMARIZER_MODEL = "openai/gpt-oss-20b"  # "mistralai/Ministral-3-3B-Instruct-2512"
SUMMARIZER_MODEL_TEMP = 0.0

EMBEDDING_MODEL = "Qwen/Qwen3-Embedding-4B"

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DOTENV_PATH = REPOSITORY_ROOT / ".env"

load_dotenv(dotenv_path=DOTENV_PATH)

VAST_IP_PORT_MODEL = os.getenv("VAST_IP_PORT_MODEL")
VAST_IP_PORT_EMBEDDING = os.getenv("VAST_IP_PORT_EMBEDDING")

OPEN_BUTTON_TOKEN_MODEL = os.getenv("OPEN_BUTTON_TOKEN_MODEL")
OPEN_BUTTON_TOKEN_EMBEDDING = os.getenv("OPEN_BUTTON_TOKEN_EMBEDDING")


class RuntimeConfigurationError(ValueError):
    """Raised when required endpoint configuration is unavailable."""

    def __init__(self, missing_variables: list[str]):
        self.missing_variables = tuple(missing_variables)
        missing_names = ", ".join(self.missing_variables)
        super().__init__(f"Missing required environment variables: {missing_names}")


def validate_runtime_config(require_embedding: bool = True) -> None:
    """Validate endpoint settings before constructing model clients.

    Replay runs use only the chat endpoint and can set ``require_embedding`` to
    ``False``. Error details intentionally contain variable names but never
    credential values.
    """

    required_settings = {
        "VAST_IP_PORT_MODEL": VAST_IP_PORT_MODEL,
        "OPEN_BUTTON_TOKEN_MODEL": OPEN_BUTTON_TOKEN_MODEL,
    }
    if require_embedding:
        required_settings.update(
            {
                "VAST_IP_PORT_EMBEDDING": VAST_IP_PORT_EMBEDDING,
                "OPEN_BUTTON_TOKEN_EMBEDDING": OPEN_BUTTON_TOKEN_EMBEDDING,
            }
        )

    missing_variables = [
        name
        for name, value in required_settings.items()
        if value is None or not str(value).strip()
    ]
    if missing_variables:
        raise RuntimeConfigurationError(missing_variables)
