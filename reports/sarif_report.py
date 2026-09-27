#!/usr/bin/env python3
"""SARIF 2.1.0 report (for GitHub code scanning, etc.)."""
import json

from core.config import VERSION


def write_sarif_report(filepath, findings):
    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }

    results = []
    for f in findings:
        result = {
            "ruleId": getattr(f, "check_name", "") or f.name,
            "level": level_map.get(f.severity, "none"),
            "message": {"text": f.detail or f.name},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.url},
                }
            }],
        }
        if getattr(f, "cwe", ""):
            result["taxa"] = [{"id": f.cwe}]
        results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AcuScan",
                    "version": VERSION,
                    "informationUri": "https://github.com/",
                    "rules": [],
                }
            },
            "results": results,
        }],
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)