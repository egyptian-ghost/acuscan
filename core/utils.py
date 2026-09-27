#!/usr/bin/env python3
"""
AcuScan utility functions v6.5.4
================================
Fixed:
  - normalize_url preserves PATH (was stripping it)
  - Added get_base_domain() helper
  - Added expand_scan_targets() for scan scope logic
"""
import os
import re
import hashlib
import string
import random
from urllib.parse import urlparse, urljoin


# ═══════════════════════════════════════════════════════════════════════════════
#  URL utilities
# ═══════════════════════════════════════════════════════════════════════════════

def normalize_url(url):
    """
    Normalize URL while PRESERVING path.

    Examples:
      http://127.0.0.1/3/v3/   → http://127.0.0.1/3/v3
      example.com              → http://example.com
      https://x.com/admin/     → https://x.com/admin
      http://x.com/            → http://x.com
    """
    if not url:
        return ""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    path = parsed.path.rstrip('/')
    if path and path != "":
        return f"{parsed.scheme}://{parsed.netloc}{path}"
    return f"{parsed.scheme}://{parsed.netloc}"


def get_base_domain(url):
    """
    Get scheme://netloc without path.
    http://127.0.0.1/3/v3  → http://127.0.0.1
    """
    if not url:
        return ""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def expand_scan_targets(url, scope="domain"):
    """
    Expand a target URL into a list of URLs to scan based on scope.

    Args:
        url: target URL (may contain path)
        scope: one of:
            "path"    → only the given path (default)
            "domain"  → only the base domain
            "both"    → path first, then domain

    Returns:
        list of URL strings to scan (in order)

    Examples:
        expand_scan_targets("http://x.com/3/v3", "path")   → ["http://x.com/3/v3"]
        expand_scan_targets("http://x.com/3/v3", "domain") → ["http://x.com"]
        expand_scan_targets("http://x.com/3/v3", "both")   → ["http://x.com/3/v3", "http://x.com"]
    """
    normalized = normalize_url(url)
    base_domain = get_base_domain(url)

    if scope == "path":
        return [normalized]
    elif scope == "domain":
        return [base_domain]
    elif scope == "both":
        # Path first, then domain (dedupe if same)
        targets = [normalized]
        if base_domain != normalized:
            targets.append(base_domain)
        return targets
    else:
        # Default: path only
        return [normalized]


def safe_url_join(base, path):
    """Safely join base URL with path."""
    if not path:
        return base
    if path.startswith(('http://', 'https://')):
        return path
    if not path.startswith('/'):
        path = '/' + path
    parsed = urlparse(base)
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def is_clean_path(path):
    """Filter out JavaScript code fragments that were mis-extracted as URLs."""
    if not path or not isinstance(path, str):
        return False
    if not path.startswith('/'):
        return False
    bad = ['"', "'", '+', '(', ')', '{', '}', '==', '!=', ';', '\\',
           'function', 'var ', 'if ', '&&', '||', 'return ',
           '.get', '.push', 'http.', 'new ', 'undefined',
           '\\n', '\\r', '\\t', 'RegExp']
    for b in bad:
        if b in path:
            return False
    if len(path) > 200:
        return False
    if re.search(r'[*?|<>]{2,}', path):
        return False
    return True


def truncate(text, maxlen=80):
    """Truncate text for display."""
    if not text:
        return ""
    text = str(text).replace('\n', ' ').replace('\r', '')
    return text[:maxlen-3] + "..." if len(text) > maxlen else text


def compile_regex(pattern, flags_str=""):
    """Compile a JavaScript regex pattern to Python."""
    try:
        py_flags = 0
        if 'i' in flags_str:
            py_flags |= re.IGNORECASE
        if 's' in flags_str:
            py_flags |= re.DOTALL
        if 'm' in flags_str:
            py_flags |= re.MULTILINE
        return re.compile(pattern, py_flags)
    except re.error:
        return None


def luhn_check(num_str):
    """Validate credit card number with Luhn algorithm."""
    try:
        digits = [int(d) for d in num_str if d.isdigit()]
        if len(digits) < 13:
            return False
        total = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0
    except Exception:
        return False


def random_token(length=16, hex_only=True):
    """Generate a random token."""
    if hex_only:
        return hashlib.md5(os.urandom(8)).hexdigest()[:length]
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choices(chars, k=length))