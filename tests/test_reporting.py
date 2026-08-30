import io
import logging
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from Graph.reporting import (
    ANSI_RED,
    ANSI_YELLOW,
    concise_exception,
    configure_console,
    get_logger,
    render_runtime_config,
    report_error,
    report_warning,
)


class FakeAPIError(RuntimeError):
    status_code = 429
    body = {
        "error": {
            "message": (
                "Quota exceeded for the configured embedding model.\n"
                "Please retry after a short delay without dumping this entire payload."
            )
        }
    }


class FakeBatchError(RuntimeError):
    status_code = 400
    body = {
        "error": {
            "message": (
                "* BatchEmbedContentsRequest.requests: at most 100 requests "
                "can be in one batch"
            )
        }
    }


class FakeTerminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def make_runtime_config():
    return SimpleNamespace(
        chat=SimpleNamespace(
            base_url="https://chat-user:chat-password@chat.example.test/v1?token=hidden",
            api_key="chat-secret",
            classifier_model="classifier-model",
            classifier_temperature=0.0,
            summarizer_model="summarizer-model",
            summarizer_temperature=0.0,
            request_delay_seconds=4.2,
        ),
        embedding=SimpleNamespace(
            base_url="https://embedding.example.test/v1?api_key=hidden",
            api_key="embedding-secret",
            model="embedding-model",
            request_delay_seconds=0.7,
            check_embedding_ctx_length=False,
        ),
        nvd=SimpleNamespace(
            base_url="https://nvd.example.test/cves/2.0?key=hidden",
            timeout_seconds=20.0,
            request_delay_seconds=6.1,
        ),
        references=SimpleNamespace(max_pages=10),
        semantic_chunker=SimpleNamespace(
            breakpoint_threshold_type="percentile",
            breakpoint_threshold_amount=25.0,
        ),
        cosine_filter=SimpleNamespace(
            query="What type of vulnerability is it?",
            threshold=0.6,
        ),
        evaluation=SimpleNamespace(
            resolved_log_directory=lambda: Path("/tmp/test-logs"),
            run_number=0,
        ),
    )


class ReportingTests(unittest.TestCase):
    def tearDown(self):
        configure_console(verbose=False, stream=io.StringIO(), use_color=False)

    def test_normal_mode_keeps_lifecycle_and_errors_but_hides_detail_and_warnings(self):
        stream = io.StringIO()
        logger = configure_console(verbose=False, stream=stream, use_color=False)

        logger.debug("stage details")
        logger.info("run started")
        logger.warning("warning detail")
        logger.error("error detail")

        output = stream.getvalue()
        self.assertNotIn("stage details", output)
        self.assertIn("run started", output)
        self.assertNotIn("warning detail", output)
        self.assertIn("error detail", output)

    def test_verbose_mode_uses_tqdm_write_and_colors_problems(self):
        stream = io.StringIO()
        logger = configure_console(verbose=True, stream=stream, use_color=True)

        with patch("Graph.reporting.tqdm.write") as tqdm_write:
            logger.debug("stage details")
            logger.warning("warning detail")
            logger.error("error detail")

        messages = [call.args[0] for call in tqdm_write.call_args_list]
        self.assertEqual(tqdm_write.call_count, 3)
        self.assertIn("stage details", messages[0])
        self.assertTrue(messages[1].startswith(ANSI_YELLOW))
        self.assertTrue(messages[2].startswith(ANSI_RED))
        self.assertTrue(all(call.kwargs["file"] is stream for call in tqdm_write.call_args_list))

    def test_no_color_environment_disables_ansi_output(self):
        stream = FakeTerminal()
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            logger = configure_console(verbose=True, stream=stream)

        logger.warning("warning detail")

        self.assertNotIn("\033[", stream.getvalue())

    def test_console_redacts_secrets_and_url_parameters(self):
        stream = io.StringIO()
        logger = configure_console(
            verbose=True,
            sensitive_values=("chat-secret", "embedding-secret"),
            stream=stream,
            use_color=False,
        )

        logger.error(
            "credentials chat-secret embedding-secret endpoint "
            "https://user:password@example.test/v1?api_key=hidden"
        )

        output = stream.getvalue()
        self.assertNotIn("chat-secret", output)
        self.assertNotIn("embedding-secret", output)
        self.assertNotIn("password", output)
        self.assertNotIn("api_key", output)
        self.assertIn("https://example.test/v1", output)

    def test_concise_exception_is_single_line_and_technical(self):
        detail = concise_exception(FakeAPIError("fallback message"))

        self.assertNotIn("\n", detail)
        self.assertIn("FakeAPIError (HTTP 429)", detail)
        self.assertIn("Quota exceeded", detail)
        self.assertNotIn("{'error'", detail)

    def test_short_terminal_messages_prioritize_provider_diagnostics(self):
        stream = io.StringIO()
        logger = configure_console(verbose=True, stream=stream, use_color=False)
        warning = {
            "stage": "chunk",
            "message": "Semantic chunking failed",
            "source": "https://example.test/reference?token=hidden",
        }

        with patch(
            "Graph.reporting.shutil.get_terminal_size",
            return_value=os.terminal_size((80, 24)),
        ):
            report_warning(logger, warning, FakeAPIError("fallback message"))
            report_error(logger, "filter stage failed for CVE-TEST", FakeAPIError())

        lines = stream.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(all("FakeAPIError (HTTP 429)" in line for line in lines))
        self.assertTrue(all("Quota exceeded" in line for line in lines))

    def test_long_provider_token_is_preserved_when_line_is_shortened(self):
        stream = io.StringIO()
        logger = configure_console(verbose=True, stream=stream, use_color=False)
        warning = {
            "stage": "chunk",
            "message": "Semantic chunking failed",
            "source": "https://example.test/reference",
        }

        with patch(
            "Graph.reporting.shutil.get_terminal_size",
            return_value=os.terminal_size((80, 24)),
        ):
            report_warning(logger, warning, FakeBatchError())

        self.assertIn("BatchEmbedContentsRequest", stream.getvalue())

    def test_configuration_table_contains_features_but_not_secrets(self):
        table = render_runtime_config(
            make_runtime_config(),
            config_path="config.toml",
            cve_count=20,
        )

        self.assertIn("Runtime configuration", table)
        self.assertIn("classifier-model", table)
        self.assertIn("embedding-model", table)
        self.assertIn("request delay (s)", table)
        self.assertIn("6.1", table)
        self.assertIn("benchmark CVEs", table)
        self.assertIn("configured", table)
        self.assertNotIn("chat-secret", table)
        self.assertNotIn("embedding-secret", table)
        self.assertNotIn("chat-password", table)
        self.assertNotIn("api_key", table)
        self.assertNotIn("token=hidden", table)

    def test_project_logger_children_share_the_configured_handler(self):
        stream = io.StringIO()
        configure_console(verbose=True, stream=stream, use_color=False)

        get_logger("stage").debug("shared handler")

        self.assertIn("shared handler", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
