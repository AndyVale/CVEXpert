"""Capture top-level linear pipeline stage durations without recording inputs."""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler


class StageTimingCallback(BaseCallbackHandler):
    """Measure direct children of a RunnableSequence for one CVE."""

    def __init__(self, stage_names: Sequence[str]) -> None:
        self.stage_names = stage_names
        self.records: list[dict[str, str | float]] = []
        self._root_run_id: UUID | None = None
        self._started: dict[UUID, tuple[dict[str, str | float], float]] = {}

    def on_chain_start(
        self,
        serialized: dict[str, Any] | None,
        inputs: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        if parent_run_id is None:
            self._root_run_id = run_id
        elif parent_run_id == self._root_run_id:
            index = len(self.records)
            if index >= len(self.stage_names):
                return
            record: dict[str, str | float] = {
                "stage": self.stage_names[index],
                "seconds": 0.0,
                "status": "running",
            }
            self.records.append(record)
            self._started[run_id] = (record, time.perf_counter())

    def _finish(self, run_id: UUID, status: str) -> None:
        started = self._started.pop(run_id, None)
        if started is None:
            return
        record, start_time = started
        record["seconds"] = round(time.perf_counter() - start_time, 3)
        record["status"] = status

    def on_chain_end(self, outputs: Any, *, run_id: UUID, **kwargs: Any) -> None:
        self._finish(run_id, "success")

    def on_chain_error(
        self, error: BaseException, *, run_id: UUID, **kwargs: Any
    ) -> None:
        self._finish(run_id, "error")
