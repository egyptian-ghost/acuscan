"""Web UI routes."""
from .auth import auth_bp
from .scans import scans_bp
from .findings import findings_bp
from .verification import verification_bp
from .upload import upload_bp
from .dashboard import dashboard_bp
from .schedules import schedules_bp

__all__ = [
    "auth_bp", "scans_bp", "findings_bp", "verification_bp",
    "upload_bp", "dashboard_bp", "schedules_bp",
]