import tempfile
import tomllib
import unittest
from pathlib import Path

from Definitions import config


VALID_CONFIG = """
[chat]
base_url = "https://chat.example.test/v1/openai/"
api_key_env = "CHAT_SECRET"
classifier_model = "classifier-model"
classifier_temperature = 0.0
summarizer_model = "summarizer-model"
summarizer_temperature = 0.0

[embedding]
base_url = "https://embedding.example.test/v1"
api_key_env = "EMBEDDING_SECRET"
model = "embedding-model"

[nvd]
base_url = "https://nvd.example.test/cves/2.0"
timeout_seconds = 12.5

[references]
max_pages = 7

[semantic_chunker]
breakpoint_threshold_type = "percentile"
breakpoint_threshold_amount = 25.0

[cosine_filter]
query = "CVE-specific relevance query"
threshold = 0.6

[evaluation]
log_directory = "logs/test-run"
run_number = 3
"""


class RuntimeConfigurationTests(unittest.TestCase):
    def _write_config(self, directory: str, content: str = VALID_CONFIG) -> Path:
        path = Path(directory) / "config.toml"
        path.write_text(content, encoding="utf-8")
        return path

    def test_loads_repository_specific_settings_and_preserves_full_urls(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._write_config(temp_dir)
            settings = config.load_runtime_config(
                path,
                environ={
                    "CHAT_SECRET": "chat-token",
                    "EMBEDDING_SECRET": "embedding-token",
                },
            )

        self.assertEqual(
            settings.chat.base_url,
            "https://chat.example.test/v1/openai/",
        )
        self.assertEqual(settings.chat.classifier_model, "classifier-model")
        self.assertEqual(settings.embedding.model, "embedding-model")
        self.assertEqual(settings.nvd.timeout_seconds, 12.5)
        self.assertEqual(settings.references.max_pages, 7)
        self.assertEqual(settings.evaluation.run_number, 3)
        self.assertNotIn("chat-token", repr(settings))
        self.assertNotIn("embedding-token", repr(settings))

    def test_live_validation_requires_chat_and_embedding_secrets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._write_config(temp_dir)
            with self.assertRaises(config.RuntimeConfigurationError) as raised:
                config.load_runtime_config(
                    path,
                    environ={"CHAT_SECRET": "chat-token"},
                )

        self.assertEqual(
            raised.exception.missing_variables,
            ("EMBEDDING_SECRET",),
        )
        self.assertNotIn("chat-token", str(raised.exception))

    def test_replay_validation_can_omit_embedding_secret(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._write_config(temp_dir)
            settings = config.load_runtime_config(
                path,
                require_embedding=False,
                environ={"CHAT_SECRET": "chat-token"},
            )

        self.assertEqual(settings.embedding.api_key_env, "EMBEDDING_SECRET")

    def test_missing_chat_secret_fails_in_all_modes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._write_config(temp_dir)
            with self.assertRaises(config.RuntimeConfigurationError) as raised:
                config.load_runtime_config(
                    path,
                    require_embedding=False,
                    environ={},
                )

        self.assertEqual(raised.exception.missing_variables, ("CHAT_SECRET",))

    def test_unknown_setting_is_rejected_instead_of_silently_ignored(self):
        invalid_config = VALID_CONFIG.replace(
            'run_number = 3',
            'run_number = 3\nunsupported_option = true',
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._write_config(temp_dir, invalid_config)
            with self.assertRaisesRegex(
                config.RuntimeConfigurationError,
                "unsupported_option",
            ):
                config.load_runtime_config(
                    path,
                    environ={
                        "CHAT_SECRET": "chat-token",
                        "EMBEDDING_SECRET": "embedding-token",
                    },
                )

    def test_invalid_endpoint_url_is_rejected(self):
        invalid_config = VALID_CONFIG.replace(
            'base_url = "https://chat.example.test/v1/openai/"',
            'base_url = "chat.example.test:8000"',
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._write_config(temp_dir, invalid_config)
            with self.assertRaisesRegex(
                config.RuntimeConfigurationError,
                "complete http:// or https:// URL",
            ):
                config.load_runtime_config(
                    path,
                    environ={
                        "CHAT_SECRET": "chat-token",
                        "EMBEDDING_SECRET": "embedding-token",
                    },
                )

    def test_missing_config_points_to_the_tracked_template(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_path = Path(temp_dir) / "config.toml"
            with self.assertRaisesRegex(
                config.RuntimeConfigurationError,
                "config.example.toml",
            ):
                config.load_runtime_config(missing_path, environ={})

    def test_tracked_example_is_valid_toml_and_contains_no_secret_values(self):
        with config.CONFIG_EXAMPLE_PATH.open("rb") as example_file:
            example = tomllib.load(example_file)

        self.assertEqual(example["chat"]["api_key_env"], "CVEXPERT_CHAT_API_KEY")
        self.assertEqual(
            example["embedding"]["api_key_env"],
            "CVEXPERT_EMBEDDING_API_KEY",
        )
        self.assertNotIn("api_key", example["chat"])
        self.assertNotIn("api_key", example["embedding"])

    def test_default_paths_are_anchored_to_the_repository_root(self):
        expected_root = Path(config.__file__).resolve().parents[2]

        self.assertEqual(config.REPOSITORY_ROOT, expected_root)
        self.assertEqual(config.CONFIG_PATH, expected_root / "config.toml")
        self.assertEqual(config.DOTENV_PATH, expected_root / ".env")


if __name__ == "__main__":
    unittest.main()
