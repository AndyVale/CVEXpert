from __future__ import annotations

import unittest

import requests

from Graph.audit import (
    BudgetCaps,
    BudgetExceeded,
    ExecutionContext,
    RunBudget,
    bind_execution_context,
    request_scope,
)
from Graph.resilience import RetryPolicy, classify_error, execute_with_retry


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class ResponseError(requests.HTTPError):
    def __init__(self, status, headers=None):
        response = requests.Response()
        response.status_code = status
        response.headers.update(headers or {})
        super().__init__(f"status {status}", response=response)


class RetryTests(unittest.TestCase):
    def _context(self, clock):
        run = RunBudget.create(BudgetCaps(20, 20_000, 100), clock=clock)
        return ExecutionContext.create(
            "CVE-2024-0001", BudgetCaps(10, 10_000, 50), run, clock=clock
        )

    def test_transient_failure_retries_and_records_attempts(self):
        clock = FakeClock()
        context = self._context(clock)
        responses = [ResponseError(503), "ok"]

        def operation():
            response = responses.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response

        with (
            bind_execution_context(context),
            request_scope(stage="classify", operation="model", model="test-model"),
        ):
            result = execute_with_retry(
                operation,
                policy=RetryPolicy(max_attempts=3),
                estimated_input_tokens=10,
                estimated_output_tokens=5,
                sleep=clock.sleep,
                clock=clock,
                random_uniform=lambda _low, high: high,
            )

        self.assertEqual(result, "ok")
        self.assertEqual([record["status"] for record in context.records], ["retrying", "success"])
        self.assertEqual(context.records[0]["retry_delay_seconds"], 1.0)
        self.assertEqual(context.aggregate()["requests"], 2)
        self.assertEqual(context.aggregate()["retries"], 1)

    def test_permanent_error_is_not_retried(self):
        calls = 0

        def operation():
            nonlocal calls
            calls += 1
            raise ResponseError(401)

        with self.assertRaises(ResponseError):
            execute_with_retry(operation, policy=RetryPolicy(max_attempts=3))
        self.assertEqual(calls, 1)

    def test_retry_after_over_limit_is_not_retried(self):
        calls = 0

        def operation():
            nonlocal calls
            calls += 1
            raise ResponseError(429, {"Retry-After": "60"})

        with self.assertRaises(ResponseError):
            execute_with_retry(
                operation,
                policy=RetryPolicy(max_attempts=3, max_retry_after_seconds=30),
            )
        self.assertEqual(calls, 1)

    def test_error_classification_distinguishes_transient_and_permanent(self):
        self.assertEqual(classify_error(ResponseError(500)), ("http_500", True))
        self.assertEqual(classify_error(ResponseError(404)), ("http_404", False))
        self.assertEqual(classify_error(TimeoutError()), ("transport", True))
        self.assertFalse(classify_error(ValueError())[1])


class BudgetTests(unittest.TestCase):
    def test_request_and_token_caps_are_enforced(self):
        clock = FakeClock()
        run = RunBudget.create(BudgetCaps(3, 100, 100), clock=clock)
        context = ExecutionContext.create(
            "CVE-2024-0001", BudgetCaps(1, 20, 50), run, clock=clock
        )
        context.authorize_request(10)
        with self.assertRaises(BudgetExceeded) as raised:
            context.authorize_request(1)
        self.assertEqual(raised.exception.budget, "request")

    def test_deadline_prevents_request(self):
        clock = FakeClock()
        run = RunBudget.create(BudgetCaps(3, 100, 100), clock=clock)
        context = ExecutionContext.create(
            "CVE-2024-0001", BudgetCaps(3, 100, 2), run, clock=clock
        )
        clock.value = 2.1
        with self.assertRaises(BudgetExceeded) as raised:
            context.authorize_request()
        self.assertEqual(raised.exception.budget, "time")


if __name__ == "__main__":
    unittest.main()
