#!/usr/bin/env python3
"""AcuScan utility functions."""
import os
import re
import hashlib
import string
import random
from urllib.parse import urlparse, urljoin


def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def safe_url_join(base, path):
    if not path:
        return base
    if path.startswith(('http://', 'https://')):
        return path
    if not path.startswith('/'):
        path = '/' + path
    parsed = urlparse(base)
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def is_clean_path(path):
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
    if not text:
        return ""
    text = str(text).replace('\n', ' ').replace('\r', '')
    return text[:maxlen-3] + "..." if len(text) > maxlen else text


def compile_regex(pattern, flags_str=""):
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
    if hex_only:
        return hashlib.md5(os.urandom(8)).hexdigest()[:length]
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choices(chars, k=length))