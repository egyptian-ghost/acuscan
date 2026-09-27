#!/usr/bin/env python3
"""
Verifier Integration Bridge
============================
Bridges scanner.py (old API) with the modular verification engine.
Converts VerifiedFinding → Finding-compatible dicts.
"""
import threading
from typing import Dict, List

from .engine import VerificationEngine
from .models import VerifiedFinding


class VerifierBridge:
    """Bridge for scanner integration."""

    def __init__(self, http_client, config):
        self.http_client = http_client
        self.config = config
        self.engine = None
        self.lock = threading.Lock()
        self._init_engine()

    def _init_engine(self):
        try:
            verifier_config = {
                "timeout": self.config.get("timeout", 15),
                "follow_redirects": self.config.get("follow_redirects", True),
                "verbose": self.config.get("verbose", False),
                "_oast": self.config.get("_oast"),
                "verification_workers": int(self.config.get("verification_workers", 6)),
                "browser_xss": bool(self.config.get("browser_xss", True)),
            }
            self.engine = VerificationEngine(self.http_client, verifier_config)
        except Exception as e:
            if self.config.get("verbose"):
                print(f"[VerifierBridge] Init failed: {e}")
            self.engine = None

    def is_available(self) -> bool:
        return self.engine is not None

    def verify_param(self, url: str, param: str,
                    method: str = "GET",
                    form_data: Dict = None,
                    verifier_names: List[str] = None) -> List[Dict]:
        """
        Verify a URL parameter.
        Returns list of Finding-shaped dicts.
        """
        if not self.engine:
            return []
        try:
            results = self.engine.verify_url_param(
                url, param, method=method,
                form_data=form_data,
                verifier_names=verifier_names,
            )
            return [self._verified_to_dict(rf, url, param) for rf in results]
        except Exception:
            if self.config.get("verbose"):
                import traceback
                traceback.print_exc()
            return []

    def verify_url(self, url: str, params: List[str],
                  method: str = "GET",
                  form_data: Dict = None,
                  max_workers: int = 5) -> List[Dict]:
        """Verify all params of a URL."""
        if not self.engine:
            return []
        try:
            results = self.engine.verify_url_all_params(
                url, params, method=method,
                form_data=form_data, max_workers=max_workers,
            )
            out = []
            for rf in results:
                out.append(self._verified_to_dict(rf, url, rf.parameter or ""))
            # Once-per-URL checks: CORS, GraphQL, API schema, JWT exposure, headers.
            out.extend(self.verify_surface(url))
            return out
        except Exception:
            if self.config.get("verbose"):
                import traceback
                traceback.print_exc()
            return []

    def verify_surface(self, url: str) -> List[Dict]:
        if not self.engine:
            return []
        try:
            results = self.engine.verify_url_surface(url)
            return [self._verified_to_dict(r, url, "") for r in results]
        except Exception:
            if self.config.get("verbose"):
                import traceback; traceback.print_exc()
            return []

    def get_stats(self) -> Dict:
        if not self.engine:
            return {"tests_run": 0, "confirmed": 0, "rejected": 0,
                   "extracted_info": 0}
        return self.engine.get_stats()

    # ═══════════════════════════════════════════════════════════════════════
    #  Conversion
    # ═══════════════════════════════════════════════════════════════════════

    def _verified_to_dict(self, rf: VerifiedFinding,
                         url: str, param: str) -> Dict:
        """Convert VerifiedFinding to a dict compatible with scanner."""
        request_raw = ""
        response_raw = ""
        if rf.key_exchange:
            request_raw = rf.key_exchange.raw_request()
            response_raw = rf.key_exchange.raw_response()

        primary_payload = ""
        for ev in rf.all_evidence:
            if ev.payload:
                primary_payload = ev.payload
                break

        # Serialize steps and evidence
        steps_serialized = []
        for s in rf.steps:
            steps_serialized.append({
                "name": s.name,
                "description": s.description,
                "stage": s.stage,
                "status": s.status,
                "payload": s.payload,
                "details": s.details,
                "duration_ms": s.duration_ms,
                "evidence": [e.to_dict() for e in s.evidence],
            })

        evidence_serialized = [e.to_dict() for e in rf.all_evidence]

        primary_evidence = rf.all_evidence[0] if rf.all_evidence else None

        return {
            "name": rf.title,
            "severity": rf.severity,
            "url": url,
            "parameter": param,
            "detail": rf.description,
            "evidence": (primary_evidence.raw_match
                        if primary_evidence else ""),
            "cve": rf.cve,
            "cwe": rf.cwe,
            "cvss": str(rf.cvss_score),
            "cvss_vector": rf.cvss_vector,
            "category": "Verified",
            "check_name": rf.vuln_type,
            "payload": primary_payload,
            "confidence": rf.confidence,
            "verification_methods": rf.verification_methods,
            "verification_steps": steps_serialized,
            "all_evidence": evidence_serialized,
            "extracted_info": rf.extracted_info or {},
            "request": request_raw,
            "response": response_raw,
            "verified": rf.verified,
            "reproduction": rf.reproduction or {},
            "verification_timeline": rf.verification_timeline or [],
            "remediation": rf.remediation,
        }