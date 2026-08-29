from typing import Any


class PipelineStageError(RuntimeError):
    """A terminal failure tied to one CVE pipeline stage."""

    def __init__(
        self,
        *,
        stage: str,
        cve_id: str,
        error: BaseException,
        safe_message: str,
    ):
        self.stage = stage
        self.cve_id = cve_id
        self.error_type = type(error).__name__
        self.safe_message = safe_message
        super().__init__(
            f"{stage} stage failed for {cve_id}: "
            f"{safe_message} ({self.error_type})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Return safe, JSON-serializable failure details."""

        return {
            "stage": self.stage,
            "cve_id": self.cve_id,
            "error_type": self.error_type,
            "message": self.safe_message,
        }
