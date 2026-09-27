"""AcuScan Web UI API routes."""
from .scans import scans_bp
from .findings import findings_bp
from .verification import verification_bp
from .auth_api import auth_bp
from .upload import upload_bp
from .dashboard import dashboard_bp
from .schedules import schedules_bp
from .scans_detail import scans_detail_bp

__all__ = [
    "scans_bp",
    "findings_bp",
    "verification_bp",
    "auth_bp",
    "upload_bp",
    "dashboard_bp",
    "schedules_bp",
    "scans_detail_bp",
]