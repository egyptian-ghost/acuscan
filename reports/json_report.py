#!/usr/bin/env python3
"""JSON report."""
import json
from collections import Counter
from datetime import datetime

from core.config import VERSION


def write_json_report(filepath, targets, findings):
    data = {
        "scanner": f"AcuScan v{VERSION}",
        "scan_time": datetime.utcnow().isoformat(),
        "targets": targets,
        "summary": {
            "total": len(findings),
            "verified": sum(1 for f in findings if getattr(f, "verified", False)),
            "by_severity": dict(Counter(f.severity for f in findings)),
        },
        "findings": [f.to_dict() for f in findings],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)