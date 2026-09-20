"""Per-request telemetry and cooperative request/token/time budgets."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import time
from threading import Lock
from typing import Any, Iterator


def estimate_tokens(text: str) -> int:
    """Return the project's conservative provider-neutral token estimate."""

    return math.ceil(1.2 * len(text.encode("utf-8")) / 3)


class BudgetExceeded(RuntimeError):
    """A CVE or run request, token, or wall-clock budget was exhausted."""

    def __init__(self, scope: str, budget: str):
        self.scope = scope
        self.budget = budget
        super().__init__(f"{scope} {budget} budget exhausted")


@dataclass(frozen=True)
class BudgetCaps:
    max_requests: int
    max_tokens: int
    max_seconds: float


@dataclass
class _BudgetCounter:
    caps: BudgetCaps
    clock: Any = time.monotonic
    started_at: float = field(init=False)
    requests: int = 0
    tokens: int = 0
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        self.started_at = self.clock()

    def remaining_seconds(self) -> float:
        return self.caps.max_seconds - (self.clock() - self.started_at)

    def check_time(self, scope: str) -> None:
        if self.remaining_seconds() <= 0:
            raise BudgetExceeded(scope, "time")

    def reserve_request(self, scope: str, estimated_tokens: int) -> None:
        with self._lock:
            self.check_time(scope)
            if self.requests + 1 > self.caps.max_requests:
                raise BudgetExceeded(scope, "request")
            if self.tokens + estimated_tokens > self.caps.max_tokens:
                raise BudgetExceeded(scope, "token")
            self.requests += 1
            self.tokens += estimated_tokens

    def reconcile_tokens(self, scope: str, estimated: int, actual: int) -> None:
        with self._lock:
            self.tokens += actual - estimated
            if self.tokens > self.caps.max_tokens:
                raise BudgetExceeded(scope, "token")

    def snapshot(self) -> dict[str, int | float]:
        return {
            "requests": self.requests,
            "tokens": self.tokens,
            "elapsed_seconds": round(self.clock() - self.started_at, 3),
            "max_requests": self.caps.max_requests,
            "max_tokens": self.caps.max_tokens,
            "max_seconds": self.caps.max_seconds,
        }


@dataclass
class RunBudget:
    counter: _BudgetCounter

    @classmethod
    def create(cls, caps: BudgetCaps, *, clock: Any = time.monotonic) -> RunBudget:
        return cls(_BudgetCounter(caps, clock=clock))


@dataclass
class ExecutionContext:
    """Mutable telemetry for one CVE plus a shared run budget."""

    cve_id: str
    cve_counter: _BudgetCounter
    run_budget: RunBudget
    records: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        cve_id: str,
        cve_caps: BudgetCaps,
        run_budget: RunBudget,
        *,
        clock: Any = time.monotonic,
    ) -> ExecutionContext:
        return cls(cve_id, _BudgetCounter(cve_caps, clock=clock), run_budget)

    def remaining_seconds(self) -> float:
        return min(
            self.cve_counter.remaining_seconds(),
            self.run_budget.counter.remaining_seconds(),
        )

    def check_time(self) -> None:
        self.run_budget.counter.check_time("run")
        self.cve_counter.check_time("CVE")

    def authorize_request(self, estimated_tokens: int = 0) -> None:
        self.run_budget.counter.reserve_request("run", estimated_tokens)
        try:
            self.cve_counter.reserve_request("CVE", estimated_tokens)
        except Exception:
            # Keep the shared run ledger conservative when a CVE cap rejects work.
            raise

    def reconcile_tokens(self, estimated: int, actual: int) -> None:
        self.run_budget.counter.reconcile_tokens("run", estimated, actual)
        self.cve_counter.reconcile_tokens("CVE", estimated, actual)

    def add_record(self, record: dict[str, Any]) -> None:
        self.records.append(record)

    def budget_snapshot(self) -> dict[str, Any]:
        return {
            "cve": self.cve_counter.snapshot(),
            "run": self.run_budget.counter.snapshot(),
        }

    def aggregate(self) -> dict[str, Any]:
        totals: dict[str, Any] = {
            "requests": len(self.records),
            "retries": sum(1 for record in self.records if record.get("attempt", 1) > 1),
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "estimated_token_records": 0,
            "pacing_seconds": 0.0,
            "retry_delay_seconds": 0.0,
            "latency_seconds": 0.0,
            "by_stage": {},
        }
        for record in self.records:
            stage = str(record.get("stage", "unknown"))
            stage_totals = totals["by_stage"].setdefault(
                stage,
                {"requests": 0, "retries": 0, "tokens": 0, "latency_seconds": 0.0},
            )
            stage_totals["requests"] += 1
            if record.get("attempt", 1) > 1:
                stage_totals["retries"] += 1
            for key in ("input_tokens", "output_tokens", "total_tokens"):
                value = int(record.get(key) or 0)
                totals[key] += value
                if key == "total_tokens":
                    stage_totals["tokens"] += value
            if record.get("token_usage_source") == "estimate":
                totals["estimated_token_records"] += 1
            for key in ("pacing_seconds", "retry_delay_seconds", "latency_seconds"):
                value = float(record.get(key) or 0.0)
                totals[key] += value
                if key == "latency_seconds":
                    stage_totals["latency_seconds"] += value
        for key in ("pacing_seconds", "retry_delay_seconds", "latency_seconds"):
            totals[key] = round(totals[key], 3)
        for values in totals["by_stage"].values():
            values["latency_seconds"] = round(values["latency_seconds"], 3)
        return totals


_CURRENT_CONTEXT: ContextVar[ExecutionContext | None] = ContextVar(
    "cvexpert_execution_context", default=None
)
_CURRENT_SCOPE: ContextVar[dict[str, str | None]] = ContextVar(
    "cvexpert_request_scope",
    default={"stage": "unknown", "operation": "request", "source": None, "model": None},
)


@contextmanager
def bind_execution_context(context: ExecutionContext) -> Iterator[ExecutionContext]:
    token = _CURRENT_CONTEXT.set(context)
    try:
        yield context
    finally:
        _CURRENT_CONTEXT.reset(token)


@contextmanager
def request_scope(
    *, stage: str, operation: str, source: str | None = None, model: str | None = None
) -> Iterator[None]:
    token = _CURRENT_SCOPE.set(
        {"stage": stage, "operation": operation, "source": source, "model": model}
    )
    try:
        yield
    finally:
        _CURRENT_SCOPE.reset(token)


def current_execution_context() -> ExecutionContext | None:
    return _CURRENT_CONTEXT.get()


def current_request_scope() -> dict[str, str | None]:
    return dict(_CURRENT_SCOPE.get())


def mark_last_request_invalid(error_category: str) -> None:
    """Mark the latest successful transport attempt as an invalid model result."""

    context = current_execution_context()
    if context is None or not context.records:
        return
    record = context.records[-1]
    if record.get("status") == "success":
        record["status"] = "invalid_output"
        record["error_category"] = error_category


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
