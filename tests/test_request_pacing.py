import math
import unittest

from Graph.request_pacing import MinimumIntervalPacer


class FakeTime:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleep_calls: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleep_calls.append(seconds)
        self.now += seconds


class MinimumIntervalPacerTests(unittest.TestCase):
    def test_first_request_is_immediate_and_later_requests_are_spaced(self):
        fake_time = FakeTime()
        pacer = MinimumIntervalPacer(
            1.0,
            clock=fake_time.monotonic,
            sleep=fake_time.sleep,
        )

        pacer()
        fake_time.now = 0.25
        pacer()
        fake_time.now = 2.0
        pacer()

        self.assertEqual(fake_time.sleep_calls, [0.75])

    def test_zero_interval_disables_waiting(self):
        fake_time = FakeTime()
        pacer = MinimumIntervalPacer(
            0.0,
            clock=fake_time.monotonic,
            sleep=fake_time.sleep,
        )

        pacer()
        pacer()

        self.assertEqual(fake_time.sleep_calls, [])

    def test_invalid_intervals_are_rejected(self):
        for invalid_interval in (-0.1, math.inf, math.nan):
            with self.subTest(invalid_interval=invalid_interval):
                with self.assertRaises(ValueError):
                    MinimumIntervalPacer(invalid_interval)


if __name__ == "__main__":
    unittest.main()
