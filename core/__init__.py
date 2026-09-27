"""AcuScan Core — configuration, colors, utils, rate limiting."""
from .config import (
    VERSION, SCRIPT_DIR, DEFAULT_DB_PATH, PLUGINS_DIR,
    DEFAULT_UA, DEFAULT_ARCHIVE_PREFIX, IS_WINDOWS,
)
from .colors import C, SEVERITY_COLORS, SEVERITY_ICONS, SEVERITY_ORDER, BANNER
from .utils import (
    normalize_url, safe_url_join, is_clean_path, truncate,
    compile_regex, luhn_check,
)

__all__ = [
    "VERSION", "SCRIPT_DIR", "DEFAULT_DB_PATH", "PLUGINS_DIR",
    "DEFAULT_UA", "DEFAULT_ARCHIVE_PREFIX", "IS_WINDOWS",
    "C", "SEVERITY_COLORS", "SEVERITY_ICONS", "SEVERITY_ORDER", "BANNER",
    "normalize_url", "safe_url_join", "is_clean_path", "truncate",
    "compile_regex", "luhn_check",
]