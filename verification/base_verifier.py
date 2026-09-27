#!/usr/bin/env python3
"""
Base Verifier
=============
Abstract base for all vulnerability verifiers.
Provides helpers for:
  - Step management (start/finish with timing)
  - Evidence accumulation
  - Finding construction
"""
import time
from abc import ABC, abstractmethod
from typing import Optional, List, Dict

from .models import (
    VerifiedFinding, VerificationStep,
    VerificationEvidence, HTTPExchange,
)


class BaseVerifier(ABC):
    """Base class for vulnerability verifiers."""

    # Subclasses MUST override these
    VULN_TYPE = "unknown"
    VULN_TITLE = "Unknown Vulnerability"
    DEFAULT_SEVERITY = "medium"
    DEFAULT_CWE = ""
    DEFAULT_CVSS = 0.0
    DEFAULT_CVSS_VECTOR = ""
    DEFAULT_REMEDIATION = ""

    def __init__(self, http_client, config=None):
        self.http = http_client
        self.config = config or {}
        self.steps: List[VerificationStep] = []
        self.timeline: List[Dict] = []

    # ═══════════════════════════════════════════════════════════════════════
    #  Abstract API
    # ═══════════════════════════════════════════════════════════════════════

    @abstractmethod
    def verify(self, url: str, param: str, method: str = "GET",
              form_data: Dict = None) -> Optional[VerifiedFinding]:
        """
        Verify if the vulnerability exists.

        Returns:
            VerifiedFinding if vulnerable AND verified
            None otherwise
        """
        pass

    # ═══════════════════════════════════════════════════════════════════════
    #  Step helpers
    # ═══════════════════════════════════════════════════════════════════════

    def start_step(self, name: str, description: str,
                  stage: str = "detection") -> VerificationStep:
        step = VerificationStep(
            name=name,
            description=description,
            stage=stage,
            status="pending",
        )
        # Attach internal timer (not serialized)
        step._start_time = time.time()
        step._timeline_start = time.time()
        return step

    def finish_step(self, step: VerificationStep, status: str,
                   payload: str = "", details: str = "",
                   evidence: List[VerificationEvidence] = None):
        step.status = status
        step.payload = payload
        step.details = details
        if evidence:
            step.evidence.extend(evidence)
        if hasattr(step, '_start_time'):
            step.duration_ms = (time.time() - step._start_time) * 1000
        self.timeline.append({
            "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "stage": step.stage, "step": step.name, "status": status,
            "duration_ms": round(step.duration_ms, 2), "details": details,
        })
        self.steps.append(step)

    # ═══════════════════════════════════════════════════════════════════════
    #  Finding builder
    # ═══════════════════════════════════════════════════════════════════════

    def build_finding(self, url: str, param: str,
                     confidence: float,
                     description: str,
                     methods: List[str] = None,
                     extracted_info: Dict = None,
                     key_exchange: HTTPExchange = None,
                     severity: str = None,
                     title: str = None,
                     impact: str = "",
                     remediation: str = "") -> VerifiedFinding:
        """Build a VerifiedFinding from accumulated steps."""
        all_evidence = []
        for step in self.steps:
            all_evidence.extend(step.evidence)

        return VerifiedFinding(
            title=title or self.VULN_TITLE,
            vuln_type=self.VULN_TYPE,
            severity=severity or self.DEFAULT_SEVERITY,
            url=url,
            parameter=param,
            verified=True,
            confidence=confidence,
            verification_methods=methods or [s.name for s in self.steps
                                            if s.status == "passed"],
            description=description,
            impact=impact,
            remediation=remediation or self.DEFAULT_REMEDIATION,
            cwe=self.DEFAULT_CWE,
            cvss_score=self.DEFAULT_CVSS,
            cvss_vector=self.DEFAULT_CVSS_VECTOR,
            steps=list(self.steps),
            all_evidence=all_evidence,
            extracted_info=extracted_info or {},
            key_exchange=key_exchange,
            reproduction={
                "method": getattr(key_exchange, "method", "GET") if key_exchange else "GET",
                "url": url, "parameter": param,
                "payload": next((e.payload for e in all_evidence if e.payload), ""),
                "steps": [s.name for s in self.steps if s.status == "passed"],
            },
            verification_timeline=list(self.timeline),
        )

    # ═══════════════════════════════════════════════════════════════════════
    #  Common helpers
    # ═══════════════════════════════════════════════════════════════════════

    def inject(self, url, param, payload, method="GET", form_data=None,
              content_type=None) -> HTTPExchange:
        """Inject a payload according to the method."""
        if method.upper() == "GET":
            return self.http.inject_get(url, param, payload)
        return self.http.inject_post(
            url, param, payload, form_data, method=method,
            content_type=content_type,
        )

    def response_contains(self, exchange: HTTPExchange, needle: str) -> bool:
        """Check if response contains a substring."""
        if not exchange or not exchange.response_body:
            return False
        return needle in exchange.response_body