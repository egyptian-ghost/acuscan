#!/usr/bin/env python3
"""
Strict Verification Engine
==========================
Orchestrates StrictVerifier classes with baseline profiling and
independent validation.

A finding is CONFIRMED only if:
  1. Baseline captured successfully (≥3 samples)
  2. At least one candidate triggers the primary detector
  3. At least N independent validators pass
  4. Combined confidence ≥ threshold
"""
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Callable

from .baseline import BaselineProfiler
from .validators import IndependentValidators, ValidationResult


@dataclass
class StrictConfig:
    """Configuration for strict verification."""
    min_validators: int = 2          # Need ≥2 independent validators
    min_confidence: float = 0.8      # Average confidence threshold
    baseline_samples: int = 5         # How many baseline responses to capture
    max_payloads: int = 15           # Limit payloads tried per vuln
    verbose: bool = False
    abort_on_first_confirm: bool = True
    baseline_similarity_threshold: float = 0.85


@dataclass
class StrictResult:
    """Result of strict verification."""
    confirmed: bool
    confidence: float
    passed_validators: List[str] = field(default_factory=list)
    all_validations: List[Dict] = field(default_factory=list)
    extracted_info: Dict = field(default_factory=dict)
    baseline_stats: Dict = field(default_factory=dict)
    reason: str = ""

    def to_dict(self) -> Dict:
        return {
            "confirmed": self.confirmed,
            "confidence": round(self.confidence, 3),
            "passed_validators": self.passed_validators,
            "all_validations": self.all_validations,
            "extracted_info": self.extracted_info,
            "baseline_stats": self.baseline_stats,
            "reason": self.reason,
        }


class StrictVerifier:
    """
    Base class for strict verifiers.

    Subclasses implement:
        get_baseline_targets() -> (url, param, method, form_data)
        primary_detect(context) -> Optional[Dict]  # Returns context if matched
        build_validators(context) -> IndependentValidators
    """

    NAME = "unnamed"
    VULN_TYPE = "unknown"
    DEFAULT_SEVERITY = "medium"

    def __init__(self, http_client, config: StrictConfig = None):
        self.http = http_client
        self.config = config or StrictConfig()
        self.profiler: Optional[BaselineProfiler] = None

    # ═══════════════════════════════════════════════════════════════════
    #  Public API
    # ═══════════════════════════════════════════════════════════════════

    def verify(self, url: str, param: str, method: str = "GET",
               form_data: Dict = None) -> StrictResult:
        """
        Main verification method.
        Returns StrictResult with confirmed=False if not verified.
        """
        # Step 1: Capture baseline
        self.profiler = BaselineProfiler(self.http, self.config.__dict__)
        ok = self.profiler.capture(
            url, param, method, form_data,
            samples=self.config.baseline_samples,
        )
        if not ok:
            return StrictResult(
                confirmed=False, confidence=0.0,
                reason="Could not capture baseline (≥3 samples required)",
            )

        # Step 2: Try payloads, look for primary detection
        detected = self._try_payloads(url, param, method, form_data)

        if not detected:
            return StrictResult(
                confirmed=False, confidence=0.0,
                baseline_stats=self.profiler.get_baseline_stats(),
                reason="No payload triggered primary detection",
            )

        # Step 3: Run independent validators
        validators = self.build_validators(detected)
        if not validators:
            return StrictResult(
                confirmed=False, confidence=0.0,
                baseline_stats=self.profiler.get_baseline_stats(),
                reason="No validators available",
            )

        result = validators.run(detected)

        return StrictResult(
            confirmed=result["confirmed"],
            confidence=result["avg_confidence"],
            passed_validators=result["passing_validators"],
            all_validations=result["all_results"],
            extracted_info=result["extracted"],
            baseline_stats=self.profiler.get_baseline_stats(),
            reason=(
                f"{result['passed_count']}/{result['required_count']} "
                f"validators passed"
            ),
        )

    # ═══════════════════════════════════════════════════════════════════
    #  Abstract methods
    # ═══════════════════════════════════════════════════════════════════

    def _try_payloads(self, url: str, param: str, method: str,
                     form_data: Dict) -> Optional[Dict]:
        """Try payloads and return context if primary detection triggers."""
        raise NotImplementedError

    def build_validators(self, context: Dict) -> Optional[IndependentValidators]:
        """Build the validators for this vuln type."""
        raise NotImplementedError

    # ═══════════════════════════════════════════════════════════════════
    #  Helper: inject payload
    # ═══════════════════════════════════════════════════════════════════

    def _inject(self, url: str, param: str, payload: str,
               method: str = "GET", form_data: Dict = None):
        """Inject a payload."""
        try:
            if method.upper() == "GET":
                return self.http.inject_get(url, param, payload)
            return self.http.inject_post(url, param, payload, form_data)
        except Exception:
            return None