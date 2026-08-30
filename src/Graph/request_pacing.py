"""Thread-safe minimum-interval pacing for synchronous HTTP requests."""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from threading import Lock
from typing import Any


class MinimumIntervalPacer:
    """Ensure consecutive request starts are separated by a minimum interval."""

    def __init__(
        self,
        minimum_interval_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if (
            not math.isfinite(minimum_interval_seconds)
            or minimum_interval_seconds < 0
        ):
            raise ValueError(
                "minimum_interval_seconds must be a finite, non-negative number"
            )

        self.minimum_interval_seconds = minimum_interval_seconds
        self._clock = clock
        self._sleep = sleep
        self._lock = Lock()
        self._last_request_started_at: float | None = None

    def __call__(self, _request: Any = None) -> None:
        """Wait as needed before allowing the next HTTP request to start."""

        with self._lock:
            now = self._clock()
            if self._last_request_started_at is not None:
                elapsed = now - self._last_request_started_at
                remaining = self.minimum_interval_seconds - elapsed
                if remaining > 0:
                    self._sleep(remaining)
                    now = self._clock()

            self._last_request_started_at = now
