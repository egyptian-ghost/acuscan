#!/usr/bin/env python3
"""
Independent Validators
======================
Multiple orthogonal validation methods. A finding is only confirmed
if ≥2 independent validators agree.

Validators:
  1. TimingValidator       — detects sleep/time-based injection
  2. ContentValidator      — checks for specific content patterns
  3. ReflectionValidator   — checks unescaped reflection
  4. DifferentialValidator — response differs from baseline
  5. ErrorValidator        — specific error signatures
  6. StructuralValidator   — HTML/XML structure changes
  7. OASTValidator         — out-of-band callback
  8. ArithmeticValidator   — computed values in response
  9. FileContentValidator  — known file signatures
  10. SemanticValidator    — semantic meaning of extracted data
"""
import re
import time
import statistics
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable

from .baseline import BaselineProfiler, DiffResult


@dataclass
class ValidationResult:
    """Result of a single validator."""
    validator_name: str
    passed: bool
    confidence: float           # 0.0 - 1.0
    evidence: str
    extracted: Dict = field(default_factory=dict)
    raw_match: str = ""
    exchange: Any = None

    def to_dict(self) -> Dict:
        return {
            "validator": self.validator_name,
            "passed": self.passed,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "extracted": self.extracted,
            "raw_match": self.raw_match[:500] if self.raw_match else "",
        }


class ValidationMethod(ABC):
    """Base class for all validation methods."""

    NAME = "unnamed"
    DESCRIPTION = ""

    @abstractmethod
    def validate(self, context: Dict) -> Optional[ValidationResult]:
        """
        Validate the given context.
        Returns ValidationResult if validator was applicable and ran,
        None if the validator doesn't apply.
        """
        pass


# ═══════════════════════════════════════════════════════════════════════════════
#  1. TimingValidator — detects time-based injections
# ═══════════════════════════════════════════════════════════════════════════════

class TimingValidator(ValidationMethod):
    """Detects significant timing delays after injection."""

    NAME = "timing"
    DESCRIPTION = "Measures response time for sleep payloads"

    def __init__(self, threshold_ms: float = 3000):
        self.threshold_ms = threshold_ms

    def validate(self, ctx: Dict) -> Optional[ValidationResult]:
        baseline_ms = ctx.get("baseline_time_ms", 0)
        candidate_ms = ctx.get("candidate_time_ms", 0)
        expected_delay_s = ctx.get("expected_delay_s", 5)

        if not baseline_ms or not candidate_ms:
            return None

        delta = candidate_ms - baseline_ms
        expected_ms = expected_delay_s * 1000

        # Must be at least 70% of expected delay
        passed = delta > max(self.threshold_ms, expected_ms * 0.7)

        # Confidence based on how close to expected
        if passed:
            ratio = delta / expected_ms
            confidence = min(1.0, max(0.7, 1.0 - abs(ratio - 1.0) * 0.5))
        else:
            confidence = 0.0

        return ValidationResult(
            validator_name=self.NAME,
            passed=passed,
            confidence=confidence,
            evidence=(
                f"Baseline: {baseline_ms:.0f}ms, "
                f"Candidate: {candidate_ms:.0f}ms, "
                f"Delta: {delta:.0f}ms "
                f"(expected ~{expected_ms:.0f}ms)"
            ),
            extracted={
                "baseline_ms": round(baseline_ms, 2),
                "candidate_ms": round(candidate_ms, 2),
                "delta_ms": round(delta, 2),
            },
            exchange=ctx.get("candidate_exchange"),
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  2. ContentValidator — checks for specific content patterns
# ═══════════════════════════════════════════════════════════════════════════════

class ContentValidator(ValidationMethod):
    """Checks for specific content patterns in response."""

    NAME = "content"
    DESCRIPTION = "Matches specific content patterns"

    def __init__(self, patterns: List[str], extractor: Callable = None,
                 case_sensitive: bool = False):
        """
        Args:
            patterns: List of regex patterns
            extractor: Optional function to extract data from matched groups
            case_sensitive: If False, uses re.IGNORECASE
        """
        self.patterns = patterns
        self.extractor = extractor
        flags = 0 if case_sensitive else re.IGNORECASE
        self.compiled = [re.compile(p, flags) for p in patterns]

    def validate(self, ctx: Dict) -> Optional[ValidationResult]:
        body = ctx.get("candidate_body", "")
        if not body:
            return None

        for i, (pattern, rx) in enumerate(zip(self.patterns, self.compiled)):
            m = rx.search(body)
            if m:
                extracted = {}
                if self.extractor:
                    try:
                        extracted = self.extractor(m, body)
                    except Exception:
                        pass
                if not extracted and m.groups():
                    # Default: use group(1) as "match"
                    extracted = {"match": m.group(1)}

                return ValidationResult(
                    validator_name=self.NAME,
                    passed=True,
                    confidence=0.9,
                    evidence=f"Pattern matched: {pattern[:80]}",
                    extracted=extracted,
                    raw_match=m.group(0)[:500],
                    exchange=ctx.get("candidate_exchange"),
                )
        return ValidationResult(
            validator_name=self.NAME,
            passed=False,
            confidence=0.0,
            evidence=f"No pattern matched ({len(self.patterns)} patterns tried)",
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  3. ReflectionValidator — checks for unescaped reflection
# ═══════════════════════════════════════════════════════════════════════════════

class ReflectionValidator(ValidationMethod):
    """Checks if a payload is reflected UNESCAPED in the response."""

    NAME = "reflection"
    DESCRIPTION = "Checks for unescaped reflection"

    def __init__(self, escape_indicators: List[str] = None):
        # Characters that indicate the reflection was escaped
        self.escape_indicators = escape_indicators or [
            "&lt;", "&gt;", "&quot;", "&amp;", "&#60;", "&#62;",
            "&#x3c;", "&#x3e;", "&apos;", "&#39;",
        ]

    def validate(self, ctx: Dict) -> Optional[ValidationResult]:
        body = ctx.get("candidate_body", "")
        payload = ctx.get("payload", "")

        if not body or not payload:
            return None

        if payload not in body:
            return ValidationResult(
                validator_name=self.NAME,
                passed=False,
                confidence=0.0,
                evidence="Payload not reflected",
            )

        # Find context around payload
        idx = body.find(payload)
        context = body[max(0, idx - 100):min(len(body), idx + len(payload) + 100)]

        # Check if escaped
        escaped = any(ind in context for ind in self.escape_indicators)

        # Confidence: high if reflected AND not escaped
        if not escaped:
            return ValidationResult(
                validator_name=self.NAME,
                passed=True,
                confidence=0.95,
                evidence=f"Payload reflected UNESCAPED in context",
                raw_match=context[:500],
                exchange=ctx.get("candidate_exchange"),
            )
        else:
            return ValidationResult(
                validator_name=self.NAME,
                passed=False,
                confidence=0.0,
                evidence=f"Payload reflected but ESCAPED",
                raw_match=context[:500],
            )


# ═══════════════════════════════════════════════════════════════════════════════
#  4. DifferentialValidator — checks response differential
# ═══════════════════════════════════════════════════════════════════════════════

class DifferentialValidator(ValidationMethod):
    """Uses BaselineProfiler to detect anomalies."""

    NAME = "differential"
    DESCRIPTION = "Compares to baseline for anomalies"

    def __init__(self, profiler: BaselineProfiler, min_anomaly_score: float = 0.5):
        self.profiler = profiler
        self.min_anomaly_score = min_anomaly_score

    def validate(self, ctx: Dict) -> Optional[ValidationResult]:
        candidate_exchange = ctx.get("candidate_exchange")
        if not candidate_exchange:
            return None

        diff = self.profiler.compare(candidate_exchange)

        passed = diff.is_anomalous and diff.anomaly_score >= self.min_anomaly_score

        return ValidationResult(
            validator_name=self.NAME,
            passed=passed,
            confidence=min(1.0, diff.anomaly_score),
            evidence=diff.reason or f"Anomaly score: {diff.anomaly_score:.2f}",
            extracted={
                "anomaly_score": round(diff.anomaly_score, 3),
                "body_similarity": round(diff.body_similarity, 3),
                "status_changed": diff.status_changed,
            },
            exchange=candidate_exchange,
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  5. ErrorValidator — specific error signatures
# ═══════════════════════════════════════════════════════════════════════════════

class ErrorValidator(ValidationMethod):
    """Checks for specific error messages from the response."""

    NAME = "error_signature"
    DESCRIPTION = "Matches DBMS/framework error signatures"

    def __init__(self, signatures: List[str]):
        """
        Args:
            signatures: List of regex patterns for error signatures
        """
        self.signatures = signatures
        self.compiled = [re.compile(p, re.IGNORECASE | re.DOTALL)
                        for p in signatures]

    def validate(self, ctx: Dict) -> Optional[ValidationResult]:
        body = ctx.get("candidate_body", "")
        if not body:
            return None

        for sig, rx in zip(self.signatures, self.compiled):
            m = rx.search(body)
            if m:
                return ValidationResult(
                    validator_name=self.NAME,
                    passed=True,
                    confidence=0.95,
                    evidence=f"Error signature matched",
                    raw_match=m.group(0)[:500],
                    exchange=ctx.get("candidate_exchange"),
                )
        return ValidationResult(
            validator_name=self.NAME,
            passed=False,
            confidence=0.0,
            evidence="No error signature matched",
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  6. StructuralValidator — HTML/XML structure analysis
# ═══════════════════════════════════════════════════════════════════════════════

class StructuralValidator(ValidationMethod):
    """Checks for structural changes in HTML/XML."""

    NAME = "structure"
    DESCRIPTION = "Detects structural changes in HTML/XML"

    def validate(self, ctx: Dict) -> Optional[ValidationResult]:
        baseline_body = ctx.get("baseline_body", "")
        candidate_body = ctx.get("candidate_body", "")
        marker = ctx.get("marker", "")

        if not marker or not candidate_body:
            return None

        # Find marker position
        idx = candidate_body.find(marker)
        if idx == -1:
            return ValidationResult(
                validator_name=self.NAME,
                passed=False,
                confidence=0.0,
                evidence="Marker not found",
            )

        # Check if marker is inside a <script> tag
        before = candidate_body[:idx]
        last_script_open = before.lower().rfind("<script")
        last_script_close = before.lower().rfind("</script")
        in_script = last_script_open > last_script_close

        # Check if marker is inside an HTML attribute
        last_lt = before.rfind("<")
        last_gt = before.rfind(">")
        in_tag = last_lt > last_gt

        if in_script:
            return ValidationResult(
                validator_name=self.NAME,
                passed=True,
                confidence=0.9,
                evidence="Payload is inside <script> block",
                extracted={"context": "script"},
                exchange=ctx.get("candidate_exchange"),
            )
        elif in_tag:
            # Check if inside attribute value
            tag_content = before[last_lt:]
            if '"' in tag_content or "'" in tag_content:
                return ValidationResult(
                    validator_name=self.NAME,
                    passed=True,
                    confidence=0.75,
                    evidence="Payload is inside attribute value",
                    extracted={"context": "attribute"},
                    exchange=ctx.get("candidate_exchange"),
                )
        return ValidationResult(
            validator_name=self.NAME,
            passed=False,
            confidence=0.0,
            evidence="Payload not in executable context",
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  7. OASTValidator — out-of-band callback
# ═══════════════════════════════════════════════════════════════════════════════

class OASTValidator(ValidationMethod):
    """Checks for out-of-band callback from OAST server."""

    NAME = "oast_callback"
    DESCRIPTION = "Verifies out-of-band interaction"

    def __init__(self, oast_client, poll_timeout: int = 10):
        self.oast = oast_client
        self.poll_timeout = poll_timeout

    def validate(self, ctx: Dict) -> Optional[ValidationResult]:
        if not self.oast:
            return None

        token = ctx.get("oast_token")
        if not token:
            return None

        interactions = self.oast.poll(token, timeout=self.poll_timeout)
        if not interactions:
            return ValidationResult(
                validator_name=self.NAME,
                passed=False,
                confidence=0.0,
                evidence=f"No OAST callback within {self.poll_timeout}s",
            )

        first = interactions[0]
        return ValidationResult(
            validator_name=self.NAME,
            passed=True,
            confidence=0.98,
            evidence=(
                f"Out-of-band callback received from "
                f"{first.get('source_ip', 'unknown')} "
                f"({len(interactions)} interaction(s))"
            ),
            extracted={
                "source_ip": first.get("source_ip"),
                "user_agent": first.get("user_agent", ""),
                "path": first.get("path", ""),
                "interaction_count": len(interactions),
            },
            exchange=ctx.get("candidate_exchange"),
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  8. ArithmeticValidator — computed values
# ═══════════════════════════════════════════════════════════════════════════════

class ArithmeticValidator(ValidationMethod):
    """Verifies arithmetic computation in response."""

    NAME = "arithmetic"
    DESCRIPTION = "Verifies computed values appear in response"

    def validate(self, ctx: Dict) -> Optional[ValidationResult]:
        body = ctx.get("candidate_body", "")
        expected = ctx.get("expected_result", "")
        payload = ctx.get("payload", "")

        if not body or not expected:
            return None

        # Must find the expected result in the body
        if expected not in body:
            return ValidationResult(
                validator_name=self.NAME,
                passed=False,
                confidence=0.0,
                evidence=f"Expected result '{expected}' not in response",
            )

        # Ensure the raw payload is NOT in the body (would be a false positive)
        if payload and payload in body:
            return ValidationResult(
                validator_name=self.NAME,
                passed=False,
                confidence=0.0,
                evidence="Payload appears in body instead of computed result",
            )

        # Find the context around the result
        idx = body.find(expected)
        context = body[max(0, idx - 50):min(len(body), idx + len(expected) + 50)]

        return ValidationResult(
            validator_name=self.NAME,
            passed=True,
            confidence=0.98,
            evidence=f"Computed result '{expected}' found in response",
            raw_match=context,
            extracted={"computed_value": expected},
            exchange=ctx.get("candidate_exchange"),
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  9. FileContentValidator — known file signatures
# ═══════════════════════════════════════════════════════════════════════════════

class FileContentValidator(ValidationMethod):
    """Validates known file contents (e.g., /etc/passwd format)."""

    NAME = "file_content"
    DESCRIPTION = "Validates known file contents"

    def __init__(self, file_signatures: Dict[str, List[str]]):
        """
        Args:
            file_signatures: {filename: [regex patterns]}
        """
        self.signatures = {
            fname: [re.compile(p, re.MULTILINE) for p in pats]
            for fname, pats in file_signatures.items()
        }

    def validate(self, ctx: Dict) -> Optional[ValidationResult]:
        body = ctx.get("candidate_body", "")
        target_file = ctx.get("target_file", "")

        if not body:
            return None

        # If specific file requested, only check that
        files_to_check = [target_file] if target_file else list(self.signatures.keys())

        for fname in files_to_check:
            if fname not in self.signatures:
                continue
            for pattern in self.signatures[fname]:
                m = pattern.search(body)
                if m:
                    # Extract a sample
                    idx = m.start()
                    sample = body[max(0, idx - 20):min(len(body), idx + 200)]
                    return ValidationResult(
                        validator_name=self.NAME,
                        passed=True,
                        confidence=0.98,
                        evidence=f"Content matches {fname} structure",
                        raw_match=m.group(0)[:500],
                        extracted={
                            "file": fname,
                            "sample": sample[:300],
                        },
                        exchange=ctx.get("candidate_exchange"),
                    )

        return ValidationResult(
            validator_name=self.NAME,
            passed=False,
            confidence=0.0,
            evidence="No known file content matched",
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  10. SemanticValidator — semantic validation of extracted data
# ═══════════════════════════════════════════════════════════════════════════════

class SemanticValidator(ValidationMethod):
    """
    Semantic validation: ensures extracted data makes sense.

    Example: For SQLi, `database=html` is invalid (html is not a DB name)
    For AWS metadata, `AccessKeyId` must be followed by a real key pattern
    """

    NAME = "semantic"
    DESCRIPTION = "Validates extracted data is semantically meaningful"

    # Things that are NEVER valid DB names
    INVALID_DB_NAMES = {
        "html", "css", "js", "javascript", "php", "the", "and", "or",
        "null", "true", "false", "yes", "no", "select", "from", "where",
    }

    # Valid database name: alphanumeric + underscore, 3-64 chars, not a keyword
    DB_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,63}$")

    # AWS credentials
    AWS_KEY_ID_PATTERN = re.compile(r"^AKIA[0-9A-Z]{16}$")
    AWS_SECRET_PATTERN = re.compile(r"^[A-Za-z0-9/+=]{40}$")

    def validate(self, ctx: Dict) -> Optional[ValidationResult]:
        extracted = ctx.get("extracted", {})
        vuln_type = ctx.get("vuln_type", "")

        if not extracted:
            return None

        # SQLi semantic check
        if "sql" in vuln_type.lower():
            db = extracted.get("database", "")
            version = extracted.get("version", "")

            # Check database name validity
            if db:
                if db.lower() in self.INVALID_DB_NAMES:
                    return ValidationResult(
                        validator_name=self.NAME,
                        passed=False,
                        confidence=0.0,
                        evidence=f"Invalid DB name: '{db}' is not a valid database name",
                    )
                if not self.DB_NAME_PATTERN.match(db):
                    return ValidationResult(
                        validator_name=self.NAME,
                        passed=False,
                        confidence=0.0,
                        evidence=f"Invalid DB name format: '{db}'",
                    )

            # Check version validity — must be X.Y.Z
            if version:
                if not re.match(r"^\d+\.\d+(\.\d+)?", version):
                    return ValidationResult(
                        validator_name=self.NAME,
                        passed=False,
                        confidence=0.0,
                        evidence=f"Invalid version format: '{version}'",
                    )

            if db or version:
                return ValidationResult(
                    validator_name=self.NAME,
                    passed=True,
                    confidence=0.9,
                    evidence=f"Semantically valid DB info",
                    extracted={"database": db, "version": version},
                )

        # AWS metadata check
        if "cloud" in vuln_type.lower() or "metadata" in vuln_type.lower():
            access_key = extracted.get("AccessKeyId", "")
            secret_key = extracted.get("SecretAccessKey", "")

            if access_key and not self.AWS_KEY_ID_PATTERN.match(access_key):
                return ValidationResult(
                    validator_name=self.NAME,
                    passed=False,
                    confidence=0.0,
                    evidence=f"Invalid AWS AccessKeyId format",
                )
            if secret_key and not self.AWS_SECRET_PATTERN.match(secret_key):
                return ValidationResult(
                    validator_name=self.NAME,
                    passed=False,
                    confidence=0.0,
                    evidence=f"Invalid AWS SecretAccessKey format",
                )
            if access_key or secret_key:
                return ValidationResult(
                    validator_name=self.NAME,
                    passed=True,
                    confidence=0.98,
                    evidence=f"Valid AWS credentials extracted",
                )

        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  IndependentValidators — runs multiple validators
# ═══════════════════════════════════════════════════════════════════════════════

class IndependentValidators:
    """
    Runs multiple independent validators.

    A vulnerability is only confirmed if:
      - At least N validators passed
      - The combined confidence ≥ threshold
    """

    def __init__(self, validators: List[ValidationMethod],
                 min_validators: int = 2,
                 min_confidence: float = 0.8):
        self.validators = validators
        self.min_validators = min_validators
        self.min_confidence = min_confidence

    def run(self, context: Dict) -> Dict:
        """
        Run all validators on the context.
        Returns aggregated result.
        """
        results = []
        passed_count = 0
        all_extracted = {}
        combined_confidence = 0.0
        passing_names = []

        for v in self.validators:
            try:
                result = v.validate(context)
                if result is None:
                    continue
                results.append(result)
                if result.passed:
                    passed_count += 1
                    passing_names.append(result.validator_name)
                    if result.extracted:
                        all_extracted.update(result.extracted)
                    combined_confidence += result.confidence
            except Exception:
                continue

        # Average confidence across passing validators
        avg_confidence = (combined_confidence / passed_count
                        if passed_count > 0 else 0.0)

        # Confirmed if enough validators passed AND confidence is high
        confirmed = (
            passed_count >= self.min_validators and
            avg_confidence >= self.min_confidence
        )

        return {
            "confirmed": confirmed,
            "passed_count": passed_count,
            "required_count": self.min_validators,
            "avg_confidence": round(avg_confidence, 3),
            "passing_validators": passing_names,
            "extracted": all_extracted,
            "all_results": [r.to_dict() for r in results],
        }