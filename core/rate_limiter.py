#!/usr/bin/env python3
"""Token bucket + adaptive rate limiter."""
import time
import threading


class RateLimiter:
    def __init__(self, rate_per_second):
        self.rate = max(1, rate_per_second)
        self.tokens = float(rate_per_second)
        self.last_time = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_time
            self.last_time = now
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            if self.tokens < 1:
                time.sleep((1 - self.tokens) / self.rate)
                self.tokens = 0
            else:
                self.tokens -= 1


class AdaptiveRateLimiter(RateLimiter):
    """Rate limiter that adapts based on 429/503 responses."""

    def __init__(self, initial_rate=150):
        super().__init__(initial_rate)
        self.base_rate = initial_rate
        self.min_rate = 5
        self.recent_429 = 0
        self.recent_total = 0

    def report_response(self, status_code):
        with self.lock:
            self.recent_total += 1
            if status_code in (429, 503):
                self.recent_429 += 1
                self.rate = max(self.min_rate, self.rate // 2)
            if self.recent_total >= 20:
                if self.recent_429 == 0:
                    self.rate = min(self.base_rate, int(self.rate * 1.5))
                self.recent_429 = 0
                self.recent_total = 0