#!/usr/bin/env python3
"""Plain text report."""
from collections import defaultdict
from datetime import datetime

from core.config import VERSION
from core.colors import SEVERITY_ORDER


def write_text_report(filepath, targets, findings):
    """Write a plain-text report."""
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity] += 1

    sorted_f = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.name, f.url),
    )

    lines = []
    w = lines.append
    w("=" * 90)
    w(f"  AcuScan v{VERSION} - Scan Report")
    w("=" * 90)
    w("")
    w(f"  Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    w(f"  Targets: {len(targets)}")
    for t in targets:
        w(f"           {t}")
    w("")
    w(f"  Total Findings: {len(findings)}")
    verified_count = sum(1 for f in findings if getattr(f, "verified", False))
    if verified_count:
        w(f"  Verified:       {verified_count}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = sev_counts.get(sev, 0)
        if cnt:
            w(f"    {sev.upper():>10s}: {cnt}")
    w("")
    w("-" * 90)

    for i, f in enumerate(sorted_f, 1):
        w("")
        w(f"  [{i:04d}] {f.severity.upper()} - {f.name}")
        w("  " + "─" * 70)
        w(f"  URL:       {f.url}")
        if getattr(f, "parameter", ""):
            w(f"  Parameter: {f.parameter}")
        if getattr(f, "category", ""):
            w(f"  Category:  {f.category}")
        if getattr(f, "confidence", 0):
            w(f"  Confidence: {f.confidence:.0%}")
        if getattr(f, "verified", False):
            w(f"  Verified:  YES")
        if f.detail:
            w(f"  Detail:    {f.detail}")
        if getattr(f, "evidence", ""):
            w(f"  Evidence:  {f.evidence}")
        if getattr(f, "cve", ""):
            w(f"  CVE:       {f.cve}")
        if getattr(f, "cwe", ""):
            w(f"  CWE:       {f.cwe}")
        if getattr(f, "payload", ""):
            w(f"  Payload:   {f.payload}")
        if getattr(f, "verification_methods", None):
            w(f"  Verified by: {', '.join(f.verification_methods)}")
        if getattr(f, "extracted_info", None):
            for k, v in f.extracted_info.items():
                w(f"  Extracted [{k}]: {str(v)[:200]}")
        w(f"  Time:      {f.timestamp}")

    w("")
    w("=" * 90)

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))