#!/usr/bin/env python3
"""Markdown report."""
from collections import Counter
from datetime import datetime

from core.config import VERSION
from core.colors import SEVERITY_ORDER


def write_markdown_report(filepath, targets, findings):
    sev_counts = Counter(f.severity for f in findings)
    sorted_f = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.name),
    )

    lines = []
    lines.append(f"# AcuScan v{VERSION} — Scan Report\n")
    lines.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Targets:** {len(targets)}  ")
    lines.append(f"**Total Findings:** {len(findings)}\n")

    verified = sum(1 for f in findings if getattr(f, "verified", False))
    if verified:
        lines.append(f"**Verified:** {verified}\n")

    lines.append("## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"| {sev.upper()} | {sev_counts.get(sev, 0)} |")
    lines.append("")
    lines.append("## Findings\n")

    for i, f in enumerate(sorted_f, 1):
        lines.append(f"### {i}. [{f.severity.upper()}] {f.name}\n")
        lines.append(f"- **URL:** `{f.url}`")
        if getattr(f, "parameter", ""):
            lines.append(f"- **Parameter:** `{f.parameter}`")
        if getattr(f, "confidence", 0):
            lines.append(f"- **Confidence:** {f.confidence:.0%}")
        if getattr(f, "verified", False):
            lines.append("- **Verified:** ✅ Yes")
        if getattr(f, "category", ""):
            lines.append(f"- **Category:** {f.category}")
        if f.detail:
            lines.append(f"- **Detail:** {f.detail}")
        if getattr(f, "evidence", ""):
            lines.append(f"- **Evidence:** `{f.evidence}`")
        if getattr(f, "payload", ""):
            lines.append(f"- **Payload:** `{f.payload}`")
        if getattr(f, "cve", ""):
            lines.append(f"- **CVE:** {f.cve}")
        if getattr(f, "cwe", ""):
            lines.append(f"- **CWE:** {f.cwe}")
        if getattr(f, "extracted_info", None):
            lines.append("- **Extracted:**")
            for k, v in f.extracted_info.items():
                lines.append(f"  - `{k}`: `{str(v)[:200]}`")
        lines.append("")

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))