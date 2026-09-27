#!/usr/bin/env python3
"""
Verification Data Models
========================
Structured models for verification results, evidence, and HTTP exchanges.

Every verified finding carries:
  - Full verification steps (multi-stage)
  - Evidence with raw HTTP exchanges
  - Confidence score
  - Extracted data (proof of exploit)
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
import json


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP Exchange (Request + Response)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HTTPExchange:
    """
    Represents one complete HTTP request/response pair.
    Includes raw request/response reconstruction for UI display.
    """
    method: str = "GET"
    url: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_time_ms: float = 0.0
    timestamp: str = field(default_factory=_utc_now)

    def raw_request(self) -> str:
        """Reconstruct the raw HTTP request as it was sent."""
        try:
            from urllib.parse import urlparse
            p = urlparse(self.url)
            path = p.path or "/"
            if p.query:
                path += "?" + p.query
            host = p.netloc

            lines = [f"{self.method} {path} HTTP/1.1"]
            headers = dict(self.request_headers or {})
            headers.setdefault("Host", host)
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
            if self.request_body:
                lines.append("")
                lines.append(str(self.request_body))
            return "\n".join(lines)
        except Exception:
            return f"{self.method} {self.url}"

    def raw_response(self) -> str:
        """Reconstruct the raw HTTP response."""
        lines = [f"HTTP/1.1 {self.response_status}"]
        for k, v in (self.response_headers or {}).items():
            lines.append(f"{k}: {v}")
        if self.response_body:
            lines.append("")
            body = self.response_body
            if len(body) > 15000:
                body = body[:15000] + "\n... [truncated]"
            lines.append(body)
        return "\n".join(lines)

    def to_dict(self) -> Dict:
        return {
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers or {},
            "request_body": self.request_body or "",
            "raw_request": self.raw_request(),
            "response_status": self.response_status,
            "response_headers": self.response_headers or {},
            "response_body": (self.response_body[:15000]
                             if self.response_body else ""),
            "raw_response": self.raw_response(),
            "response_time_ms": round(self.response_time_ms or 0, 2),
            "timestamp": self.timestamp,
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  Verification Evidence
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class VerificationEvidence:
    """
    A single piece of evidence supporting a finding.
    Always includes the full HTTP exchange that produced it.
    """
    type: str                    # "error_message" | "timing" | "oast_callback" | "db_extract" | ...
    title: str                   # Human-readable title
    description: str = ""        # Detailed explanation
    payload: str = ""            # The payload used
    extracted_data: Dict = field(default_factory=dict)
    exchange: Optional[HTTPExchange] = None
    confidence: float = 0.0      # 0.0 - 1.0
    raw_match: str = ""          # Raw match text from response

    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "payload": self.payload,
            "extracted_data": self.extracted_data or {},
            "exchange": self.exchange.to_dict() if self.exchange else None,
            "confidence": self.confidence,
            "raw_match": self.raw_match,
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  Verification Step (single test)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class VerificationStep:
    """
    One stage in the multi-stage verification.
    Statuses: pending | passed | failed | error
    Stages:   detection | confirmation | extraction
    """
    name: str = ""
    description: str = ""
    stage: str = "detection"
    status: str = "pending"
    payload: str = ""
    evidence: List[VerificationEvidence] = field(default_factory=list)
    details: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "stage": self.stage,
            "status": self.status,
            "payload": self.payload,
            "evidence": [e.to_dict() for e in self.evidence],
            "details": self.details,
            "duration_ms": round(self.duration_ms or 0, 2),
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  Verified Finding (final result)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class VerifiedFinding:
    """
    A fully verified vulnerability.
    Only produced if verification succeeded with confidence >= threshold.
    """
    # Core identification
    title: str = ""
    vuln_type: str = ""          # SQLi | XSS | RCE | LFI | SSRF | ...
    severity: str = "medium"
    url: str = ""
    parameter: str = ""

    # Verification info
    verified: bool = True
    confidence: float = 0.0
    verification_methods: List[str] = field(default_factory=list)

    # Description
    description: str = ""
    impact: str = ""
    remediation: str = ""

    # Identifiers
    cve: str = ""
    cwe: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""

    # Evidence & steps
    steps: List[VerificationStep] = field(default_factory=list)
    all_evidence: List[VerificationEvidence] = field(default_factory=list)
    extracted_info: Dict = field(default_factory=dict)

    # Primary confirmation exchange
    key_exchange: Optional[HTTPExchange] = None

    # Verification 2.0 metadata
    reproduction: Dict = field(default_factory=dict)
    verification_timeline: List[Dict] = field(default_factory=list)

    # Metadata
    timestamp: str = field(default_factory=_utc_now)
    scan_id: str = ""

    def to_dict(self) -> Dict:
        return {
            "title": self.title,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "verified": self.verified,
            "confidence": self.confidence,
            "verification_methods": self.verification_methods,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "cve": self.cve,
            "cwe": self.cwe,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "steps": [s.to_dict() for s in self.steps],
            "all_evidence": [e.to_dict() for e in self.all_evidence],
            "extracted_info": self.extracted_info or {},
            "reproduction": self.reproduction or {},
            "verification_timeline": self.verification_timeline or [],
            "key_exchange": (self.key_exchange.to_dict()
                            if self.key_exchange else None),
            "timestamp": self.timestamp,
            "scan_id": self.scan_id,
        }

    def to_finding_dict(self) -> Dict:
        """Convert to Finding-shaped dict (for compatibility with old scanner)."""
        primary_evidence = self.all_evidence[0] if self.all_evidence else None

        return {
            "name": self.title,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "detail": self.description,
            "evidence": (primary_evidence.raw_match if primary_evidence else ""),
            "cve": self.cve,
            "cwe": self.cwe,
            "cvss": str(self.cvss_score),
            "cvss_vector": self.cvss_vector,
            "category": "Verified",
            "check_name": self.vuln_type,
            "payload": (primary_evidence.payload if primary_evidence else ""),
            "confidence": self.confidence,
            "verification_methods": self.verification_methods,
            "verification_steps": [s.to_dict() for s in self.steps],
            "all_evidence": [e.to_dict() for e in self.all_evidence],
            "extracted_info": self.extracted_info or {},
            "reproduction": self.reproduction or {},
            "verification_timeline": self.verification_timeline or [],
            "request": (self.key_exchange.raw_request()
                       if self.key_exchange else ""),
            "response": (self.key_exchange.raw_response()
                        if self.key_exchange else ""),
            "verified": self.verified,
            "remediation": self.remediation,
        }