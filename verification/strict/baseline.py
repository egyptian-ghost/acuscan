#!/usr/bin/env python3
"""
Baseline Profiler
=================
Captures N baseline responses to establish what "normal" looks like.
Uses statistical analysis to detect real anomalies.

Key concepts:
  - Baseline fingerprint: hash + length + timing + headers
  - Differential analysis: compare candidate response to baseline set
  - Anomaly score: 0.0 (identical) → 1.0 (completely different)
  - Robust: filters out timing noise, random tokens, CSRF tokens
"""
import re
import time
import hashlib
import statistics
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from difflib import SequenceMatcher


@dataclass
class BaselineSample:
    """A single baseline response."""
    status: int
    length: int
    body_hash: str
    body_text: str
    elapsed_ms: float
    headers: Dict[str, str] = field(default_factory=dict)
    volatile_tokens: List[str] = field(default_factory=list)


@dataclass
class DiffResult:
    """Result of differential analysis."""
    anomaly_score: float        # 0.0 = identical, 1.0 = completely different
    status_changed: bool
    length_delta: int
    length_delta_pct: float
    body_similarity: float      # 0.0 = different, 1.0 = identical
    timing_delta_ms: float
    timing_anomalous: bool
    matched_indicators: List[str] = field(default_factory=list)
    is_anomalous: bool = False
    reason: str = ""

    def to_dict(self) -> Dict:
        return {
            "anomaly_score": round(self.anomaly_score, 3),
            "status_changed": self.status_changed,
            "length_delta": self.length_delta,
            "length_delta_pct": round(self.length_delta_pct, 2),
            "body_similarity": round(self.body_similarity, 3),
            "timing_delta_ms": round(self.timing_delta_ms, 2),
            "timing_anomalous": self.timing_anomalous,
            "matched_indicators": self.matched_indicators,
            "is_anomalous": self.is_anomalous,
            "reason": self.reason,
        }


class BaselineProfiler:
    """
    Captures baseline responses and provides differential analysis.

    Usage:
        profiler = BaselineProfiler(http_client)
        profiler.capture(url, param, method="GET", samples=5)
        result = profiler.compare(candidate_response)
        if result.is_anomalous:
            # investigate
    """

    # Regex to find volatile tokens (random session IDs, CSRF, timestamps)
    VOLATILE_PATTERNS = [
        r'name="csrf[_-]?token"\s+value="([^"]+)"',
        r'name="authenticity_token"\s+value="([^"]+)"',
        r'_token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        r'session[_-]?id["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
        r'\b[0-9]{10,13}\b',  # Unix timestamps
    ]

    def __init__(self, http_client, config=None):
        self.http = http_client
        self.config = config or {}
        self.samples: List[BaselineSample] = []
        self._url = None
        self._param = None
        self._method = None
        self._form_data = None

    # ═══════════════════════════════════════════════════════════════════
    #  Baseline capture
    # ═══════════════════════════════════════════════════════════════════

    def capture(self, url: str, param: str, method: str = "GET",
               form_data: Dict = None, samples: int = 5) -> bool:
        """
        Capture baseline samples by sending neutral values.
        Returns True if enough samples captured.
        """
        self.samples = []
        self._url = url
        self._param = param
        self._method = method
        self._form_data = form_data

        neutral_values = ["1", "test", "abc", "123", "aaa", "xyz"]

        for i in range(samples):
            value = neutral_values[i % len(neutral_values)]
            exchange = self._inject(value)

            if not exchange or exchange.response_status == 0:
                continue

            sample = BaselineSample(
                status=exchange.response_status,
                length=len(exchange.response_body or ""),
                body_hash=hashlib.md5(
                    (exchange.response_body or "").encode()
                ).hexdigest(),
                body_text=exchange.response_body or "",
                elapsed_ms=exchange.response_time_ms or 0.0,
                headers=dict(exchange.response_headers or {}),
            )
            # Extract volatile tokens
            sample.volatile_tokens = self._extract_volatile(sample.body_text)
            self.samples.append(sample)

            time.sleep(0.1)  # Small delay between samples

        return len(self.samples) >= 3

    def _inject(self, payload: str):
        """Inject a value and get the response."""
        try:
            if self._method.upper() == "GET":
                return self.http.inject_get(self._url, self._param, payload)
            else:
                return self.http.inject_post(
                    self._url, self._param, payload, self._form_data
                )
        except Exception:
            return None

    # ═══════════════════════════════════════════════════════════════════
    #  Differential analysis
    # ═══════════════════════════════════════════════════════════════════

    def compare(self, exchange) -> DiffResult:
        """
        Compare a candidate response against baseline samples.
        Returns DiffResult with anomaly_score and is_anomalous flag.
        """
        if not self.samples or not exchange or exchange.response_status == 0:
            return DiffResult(
                anomaly_score=1.0, status_changed=False,
                length_delta=0, length_delta_pct=0,
                body_similarity=0, timing_delta_ms=0,
                timing_anomalous=False, is_anomalous=False,
                reason="no_baseline",
            )

        # Dominant baseline status (most common)
        statuses = [s.status for s in self.samples]
        dominant_status = max(set(statuses), key=statuses.count)
        status_changed = exchange.response_status != dominant_status

        # Length analysis
        baseline_lengths = [s.length for s in self.samples]
        median_length = statistics.median(baseline_lengths)
        candidate_length = len(exchange.response_body or "")
        length_delta = candidate_length - median_length
        length_delta_pct = (abs(length_delta) / max(median_length, 1)) * 100

        # Body similarity — compare against each sample, take best match
        candidate_body = exchange.response_body or ""
        best_similarity = 0.0
        for sample in self.samples:
            # Normalize volatile tokens before comparing
            normalized_baseline = self._normalize_body(sample.body_text)
            normalized_candidate = self._normalize_body(candidate_body)
            sim = self._compute_similarity(normalized_baseline,
                                          normalized_candidate)
            if sim > best_similarity:
                best_similarity = sim

        # Timing analysis
        baseline_times = [s.elapsed_ms for s in self.samples]
        median_time = statistics.median(baseline_times)
        candidate_time = exchange.response_time_ms or 0.0
        timing_delta = candidate_time - median_time
        timing_anomalous = timing_delta > 3000  # >3s = suspicious

        # Overall anomaly score
        anomaly_score = 0.0
        if status_changed:
            anomaly_score += 0.4
        if length_delta_pct > 30:
            anomaly_score += min(0.3, length_delta_pct / 100)
        if best_similarity < 0.7:
            anomaly_score += (1 - best_similarity) * 0.3

        anomaly_score = min(1.0, anomaly_score)

        # Is it anomalous?
        # Anomalous if: status changed OR body significantly different
        # (NOT if only length changed slightly)
        is_anomalous = (
            status_changed or
            (best_similarity < 0.85 and length_delta_pct > 20)
        )

        reason = ""
        if status_changed:
            reason = f"status changed: {dominant_status} → {exchange.response_status}"
        elif best_similarity < 0.5:
            reason = f"body very different (similarity {best_similarity:.2f})"
        elif best_similarity < 0.85:
            reason = f"body somewhat different (similarity {best_similarity:.2f})"

        return DiffResult(
            anomaly_score=anomaly_score,
            status_changed=status_changed,
            length_delta=length_delta,
            length_delta_pct=length_delta_pct,
            body_similarity=best_similarity,
            timing_delta_ms=timing_delta,
            timing_anomalous=timing_anomalous,
            is_anomalous=is_anomalous,
            reason=reason,
        )

    # ═══════════════════════════════════════════════════════════════════
    #  Helpers
    # ═══════════════════════════════════════════════════════════════════

    def _extract_volatile(self, text: str) -> List[str]:
        """Find volatile tokens that change between requests."""
        tokens = []
        for pattern in self.VOLATILE_PATTERNS:
            for m in re.finditer(pattern, text):
                if m.groups():
                    tokens.append(m.group(1))
                else:
                    tokens.append(m.group(0))
        return tokens[:50]

    def _normalize_body(self, text: str) -> str:
        """Remove volatile tokens from body for stable comparison."""
        if not text:
            return ""
        # Remove all found volatile tokens
        all_volatile = set()
        for sample in self.samples:
            all_volatile.update(sample.volatile_tokens)
        for token in all_volatile:
            if token and len(token) > 5:
                text = text.replace(token, "__VOLATILE__")
        # Remove whitespace variations
        text = re.sub(r'\s+', ' ', text)
        # Remove long hex strings (likely hashes)
        text = re.sub(r'\b[a-f0-9]{32,}\b', '__HASH__', text, flags=re.I)
        return text

    def _compute_similarity(self, a: str, b: str) -> float:
        """Compute similarity between two strings (0.0 - 1.0)."""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        # Use SequenceMatcher for accurate ratio
        # But limit size for performance
        if len(a) > 20000:
            a = a[:20000]
        if len(b) > 20000:
            b = b[:20000]
        return SequenceMatcher(None, a, b).ratio()

    def get_baseline_stats(self) -> Dict:
        """Get baseline statistics for reporting."""
        if not self.samples:
            return {}
        lengths = [s.length for s in self.samples]
        times = [s.elapsed_ms for s in self.samples]
        return {
            "sample_count": len(self.samples),
            "median_length": int(statistics.median(lengths)),
            "min_length": min(lengths),
            "max_length": max(lengths),
            "length_stddev": round(statistics.pstdev(lengths), 2),
            "median_time_ms": round(statistics.median(times), 2),
            "dominant_status": max(
                set(s.status for s in self.samples),
                key=lambda s: [x.status for x in self.samples].count(s)
            ),
        }