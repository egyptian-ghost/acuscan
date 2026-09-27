#!/usr/bin/env python3
"""
Finding class
=============
Represents a single discovered (and possibly verified) vulnerability.
Every Finding carries:
  - Basic metadata (name, severity, url, param)
  - Evidence and payload
  - Verification info (confidence, methods, steps)
  - Extracted data (proof of exploit)
  - Full HTTP request/response
"""
import threading
from datetime import datetime, timezone

from core.utils import truncate


class Finding:
    """Represents a single vulnerability finding."""

    _counter = 0
    _lock = threading.Lock()

    def __init__(self, name, severity, url, detail="", vuln_ref="",
                 evidence="", cve="", cwe="", cvss="", tags="",
                 category="", check_name="", request=None, response=None,
                 payload="", confidence=0.0, verification_methods=None,
                 verification_steps=None, all_evidence=None,
                 extracted_info=None, cvss_vector="", remediation="",
                 parameter="", verified=False):
        with Finding._lock:
            Finding._counter += 1
            self.id = Finding._counter

        self.name = name
        self.severity = (severity or "info").lower()
        self.url = url
        self.detail = detail
        self.vuln_ref = vuln_ref
        self.evidence = truncate(evidence, 500)
        self.cve = cve or ""
        self.cwe = cwe or ""
        self.cvss = cvss or ""
        self.cvss_vector = cvss_vector or ""
        self.tags = tags or ""
        self.category = category or ""
        self.check_name = check_name or ""
        self.request = request
        self.response = response
        self.payload = payload or ""
        self.confidence = float(confidence or 0.0)
        self.verification_methods = verification_methods or []
        self.verification_steps = verification_steps or []
        self.all_evidence = all_evidence or []
        self.extracted_info = extracted_info or {}
        self.remediation = remediation or ""
        self.parameter = parameter or ""
        self.verified = bool(verified)
        self.timestamp = datetime.now(timezone.utc).isoformat()

    # ═══════════════════════════════════════════════════════════════════════
    #  Serialization
    # ═══════════════════════════════════════════════════════════════════════

    def to_dict(self):
        """Full dict for JSON / API."""
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "detail": self.detail,
            "vuln_ref": self.vuln_ref,
            "evidence": self.evidence,
            "cve": self.cve,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "cvss_vector": self.cvss_vector,
            "tags": self.tags,
            "category": self.category,
            "check_name": self.check_name,
            "payload": self.payload,
            "confidence": self.confidence,
            "verification_methods": self.verification_methods,
            "verification_steps": self.verification_steps,
            "all_evidence": self.all_evidence,
            "extracted_info": self.extracted_info,
            "remediation": self.remediation,
            "verified": self.verified,
            "request": self.request,
            "response": self.response,
            "timestamp": self.timestamp,
        }

    def to_storage_dict(self):
        """Dict compatible with storage.add_finding()."""
        return {
            "name": self.name,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "detail": self.detail,
            "evidence": self.evidence,
            "cve": self.cve,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "cvss_vector": self.cvss_vector,
            "category": self.category,
            "check_name": self.check_name,
            "payload": self.payload,
            "confidence": self.confidence,
            "verification_methods": self.verification_methods,
            "verification_steps": self.verification_steps,
            "all_evidence": self.all_evidence,
            "extracted_info": self.extracted_info,
            "remediation": self.remediation,
            "request": self.request,
            "response": self.response,
            "verified": self.verified,
        }

    @classmethod
    def from_verified_dict(cls, fd, url, param):
        """Create a Finding from a VerifierBridge dict."""
        return cls(
            name=fd.get("name", ""),
            severity=fd.get("severity", "info"),
            url=url,
            parameter=param,
            detail=fd.get("detail", ""),
            evidence=fd.get("evidence", ""),
            cve=fd.get("cve", ""),
            cwe=fd.get("cwe", ""),
            cvss=fd.get("cvss", ""),
            cvss_vector=fd.get("cvss_vector", ""),
            category=fd.get("category", "Verified"),
            check_name=fd.get("check_name", ""),
            payload=fd.get("payload", ""),
            confidence=fd.get("confidence", 0.0),
            verification_methods=fd.get("verification_methods", []),
            verification_steps=fd.get("verification_steps", []),
            all_evidence=fd.get("all_evidence", []),
            extracted_info=fd.get("extracted_info", {}),
            remediation=fd.get("remediation", ""),
            request=fd.get("request"),
            response=fd.get("response"),
            verified=fd.get("verified", True),
        )

    def __repr__(self):
        return f"Finding({self.severity}: {self.name} @ {self.url})"