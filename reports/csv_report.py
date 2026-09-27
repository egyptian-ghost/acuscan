#!/usr/bin/env python3
"""CSV report."""
import csv


def write_csv_report(filepath, findings):
    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([
            "ID", "Severity", "Confidence", "Verified", "Name", "URL",
            "Parameter", "Detail", "Evidence", "CVE", "CWE",
            "Payload", "Category", "Check",
        ])
        for f in findings:
            w.writerow([
                f.id,
                f.severity,
                f"{getattr(f, 'confidence', 0):.2f}",
                "yes" if getattr(f, "verified", False) else "no",
                f.name,
                f.url,
                getattr(f, "parameter", ""),
                f.detail,
                getattr(f, "evidence", ""),
                getattr(f, "cve", ""),
                getattr(f, "cwe", ""),
                getattr(f, "payload", ""),
                getattr(f, "category", ""),
                getattr(f, "check_name", ""),
            ])