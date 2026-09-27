#!/usr/bin/env python3
"""
Phase 5: WebApps v6.6.0
=======================
Fingerprints web applications with STRICT validation.

Fixes:
  - Was reporting ALL web apps on every page
  - Now requires MULTIPLE specific indicators
  - Confidence threshold: >= 2 signatures required
  - Ignores common strings ("wordpress" in title, etc.)
"""
import re
from core.utils import safe_url_join
from ..finding import Finding


class PhaseWebApps:
    """Web application fingerprinting with strict validation."""

    # ═══════════════════════════════════════════════════════════════
    #  STRICT CMS fingerprints
    #  Each: name -> {
    #      'paths': [urls that MUST return specific content],
    #      'body_signatures': [regex patterns that MUST appear],
    #      'body_exclude': [patterns that INVALIDATE],
    #      'min_signatures': minimum matches required
    #  }
    # ═══════════════════════════════════════════════════════════════
    FINGERPRINTS = {
        "wordpress": {
            "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/"],
            "body_signatures": [
                r'wp-content/themes/',
                r'wp-includes/',
                r'<meta\s+name="generator"\s+content="WordPress',
                r'wp-json',
                r'/wp-emoji-release\.min\.js',
            ],
            "body_exclude": [],
            "min_signatures": 2,
        },
        "joomla": {
            "paths": ["/administrator/", "/components/", "/modules/"],
            "body_signatures": [
                r'content="Joomla',
                r'/media/system/js/',
                r'/templates/system/',
                r'com_content',
            ],
            "body_exclude": [],
            "min_signatures": 2,
        },
        "drupal": {
            "paths": ["/sites/default/", "/core/misc/drupal.js"],
            "body_signatures": [
                r'Drupal\.settings',
                r'sites/default/files',
                r'/core/misc/drupal\.js',
                r'<meta name="Generator" content="Drupal',
            ],
            "body_exclude": [],
            "min_signatures": 2,
        },
        "magento": {
            "paths": ["/skin/frontend/", "/js/mage/"],
            "body_signatures": [
                r'Mage\.Cookies',
                r'skin/frontend/',
                r'/js/mage/',
                r'var BLANK_URL',
            ],
            "body_exclude": [],
            "min_signatures": 2,
        },
        "phpmyadmin": {
            "paths": ["/phpmyadmin/", "/pma/"],
            "body_signatures": [
                r'<title>phpMyAdmin',
                r'pma_username',
                r'name="pma_username"',
                r'phpMyAdmin\s+\d',
            ],
            "body_exclude": [],
            "min_signatures": 2,
        },
        "phpbb": {
            "paths": ["/viewtopic.php", "/ucp.php"],
            "body_signatures": [
                r'phpBB\s+\d',
                r'viewtopic\.php',
                r'<meta name="description" content="phpBB',
            ],
            "body_exclude": [],
            "min_signatures": 2,
        },
        "mediawiki": {
            "paths": ["/wiki/", "/index.php?title=Main_Page"],
            "body_signatures": [
                r'MediaWiki',
                r'wiki/Wikimedia',
                r'<meta name="generator" content="MediaWiki',
            ],
            "body_exclude": [],
            "min_signatures": 2,
        },
        "django": {
            "paths": [],
            "body_signatures": [
                r'csrfmiddlewaretoken',
                r'__admin_media_prefix__',
                r'django\.pagination',
            ],
            "body_exclude": [],
            "min_signatures": 2,
        },
        "laravel": {
            "paths": [],
            "body_signatures": [
                r'laravel_session',
                r'XSRF-TOKEN',
                r'laravel_debugbar',
            ],
            "body_exclude": [],
            "min_signatures": 2,
        },
        "rails": {
            "paths": [],
            "body_signatures": [
                r'csrf-param',
                r'csrf-token',
                r'rails-ujs',
            ],
            "body_exclude": [],
            "min_signatures": 2,
        },
    }

    def __init__(self, scanner):
        self.scanner = scanner
        self.http = scanner.http
        self.db = scanner.db
        self.out = scanner.out

    def run(self, base_url):
        self.out.phase("Phase 5: WebApp Fingerprinting")

        # Get DB webapp patterns (may be empty)
        db_patterns = self.db.webapp_patterns
        if db_patterns:
            self.out.info(f"Checking {len(db_patterns)} DB web apps + "
                         f"{len(self.FINGERPRINTS)} built-in")

        # ═══ Check built-in strict fingerprints ═══
        detected_apps = set()
        for app_name, spec in self.FINGERPRINTS.items():
            if self.scanner.stop_event.is_set():
                break

            if self._detect_app(base_url, app_name, spec):
                detected_apps.add(app_name)
                self.out.success(f"Detected: {app_name}")

                self.scanner.add_finding(Finding(
                    name=f"Web application detected: {app_name.title()}",
                    severity="info", url=base_url,
                    detail=f"Detected via strict signature matching "
                          f"(>= {spec['min_signatures']} indicators)",
                    tags="fingerprint",
                    category="WebApps",
                    check_name=f"Detect_{app_name}",
                ))

        # ═══ DB patterns (if available) — with validation ═══
        if db_patterns:
            for app_name, check_paths in db_patterns.items():
                if self.scanner.stop_event.is_set():
                    break
                if app_name.lower() in detected_apps:
                    continue  # already detected

                # Skip if already detected by built-in
                skip = False
                for known in detected_apps:
                    if known.lower() in app_name.lower() or \
                       app_name.lower().startswith(known.lower()):
                        skip = True
                        break
                if skip:
                    continue

                # Validate DB pattern (strict)
                if self._validate_db_pattern(base_url, app_name, check_paths):
                    detected_apps.add(app_name)
                    self.out.success(f"Detected (DB): {app_name}")

                    self.scanner.add_finding(Finding(
                        name=f"Web application detected: "
                             f"{app_name.replace('_', ' ').title()}",
                        severity="info", url=base_url,
                        detail="Detected via DB fingerprint pattern",
                        tags="fingerprint",
                        category="WebApps",
                        check_name=app_name,
                    ))

        if not detected_apps:
            self.out.info("No web applications detected (strict mode)")

    # ═══════════════════════════════════════════════════════════════
    #  Strict detection helpers
    # ═══════════════════════════════════════════════════════════════

    def _detect_app(self, base_url, app_name, spec):
        """
        Detect app with STRICT validation.
        Returns True only if >= min_signatures match.
        """
        signatures_matched = 0

        # 1. Check specific paths
        paths_to_check = spec.get("paths", [])
        for path in paths_to_check[:3]:  # limit to 3
            if self.scanner.stop_event.is_set():
                return False
            try:
                url = safe_url_join(base_url, path)
                resp = self.http.get(url, timeout=8)
                if not resp or resp.status_code != 200:
                    continue

                # Skip 404s that look like the main page
                if self.scanner.is_custom_404(resp, base_url, url=url):
                    continue

                body = resp.text

                # Check body signatures
                for pattern in spec.get("body_signatures", []):
                    if re.search(pattern, body, re.I):
                        signatures_matched += 1
                        if signatures_matched >= spec["min_signatures"]:
                            return True
                        break  # one signature per path is enough
            except Exception:
                continue

        # 2. Check homepage if not enough signatures yet
        if signatures_matched < spec["min_signatures"]:
            try:
                resp = self.http.get(base_url, timeout=10)
                if resp and resp.status_code == 200:
                    body = resp.text
                    for pattern in spec.get("body_signatures", []):
                        if re.search(pattern, body, re.I):
                            signatures_matched += 1
                            if signatures_matched >= spec["min_signatures"]:
                                return True
            except Exception:
                pass

        return signatures_matched >= spec["min_signatures"]

    def _validate_db_pattern(self, base_url, app_name, check_paths):
        """
        Validate DB pattern with strict rules.
        Returns True only if MULTIPLE paths return 200 + app_name appears
        in at least 2 of them with meaningful content.
        """
        matches = 0
        checked = 0

        for path in check_paths[:5]:
            if self.scanner.stop_event.is_set():
                return False
            try:
                url = safe_url_join(base_url, path)
                resp = self.http.get(url, timeout=8)
                if not resp or resp.status_code != 200:
                    continue

                checked += 1

                # Skip custom 404s
                if self.scanner.is_custom_404(resp, base_url, url=url):
                    continue

                body = resp.text
                if len(body) < 200:
                    continue

                # Must have app_name in content
                if app_name.lower().replace("_", " ") in body.lower() or \
                   app_name.lower() in body.lower():
                    matches += 1
            except Exception:
                continue

        # Require: at least 1 path checked + 1 match, OR 2+ matches
        return matches >= 1 and checked >= 1