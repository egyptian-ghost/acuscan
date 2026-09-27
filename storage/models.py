"""Data classes for storage records."""
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict


@dataclass
class FindingRecord:
    id: Optional[int] = None
    scan_id: Optional[int] = None
    name: str = ""
    severity: str = "info"
    url: str = ""
    parameter: str = ""
    detail: str = ""
    evidence: str = ""
    confidence: float = 0.0
    cve: str = ""
    cwe: str = ""
    cvss: float = 0.0
    cvss_vector: str = ""
    category: str = ""
    check_name: str = ""
    payload: str = ""
    verification_methods: List[str] = field(default_factory=list)
    verification_steps: List[Dict] = field(default_factory=list)
    all_evidence: List[Dict] = field(default_factory=list)
    extracted_info: Dict = field(default_factory=dict)
    request_raw: str = ""
    response_raw: str = ""
    remediation: str = ""
    verified: bool = False


@dataclass
class ScanRecord:
    id: Optional[int] = None
    scan_uuid: str = ""
    targets: List[str] = field(default_factory=list)
    config: Dict = field(default_factory=dict)
    status: str = "pending"
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: float = 0.0
    request_count: int = 0
    error_count: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    verified_count: int = 0