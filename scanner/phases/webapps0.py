#!/usr/bin/env python3
"""
Phase 5: WebApps
================
Fingerprints web applications (CMS, frameworks).
"""
from core.utils import safe_url_join
from ..finding import Finding


class PhaseWebApps:
    def __init__(self, scanner):
        self.scanner = scanner
        self.http = scanner.http
        self.db = scanner.db
        self.out = scanner.out

    def run(self, base_url):
        self.out.phase("Phase 5: WebApp Fingerprinting")

        patterns = self.db.webapp_patterns
        if not patterns:
            self.out.info("No webapp patterns in DB")
            return

        self.out.info(f"Checking {len(patterns)} web applications")

        cms_indicators = {
            "wordpress": ["wp-content", "wp-includes"],
            "joomla": ["joomla", "com_content"],
            "drupal": ["drupal", "sites/default"],
            "magento": ["magento", "mage/"],
            "phpmyadmin": ["phpmyadmin", "pma_"],
            "phpbb": ["phpbb", "viewtopic.php"],
            "mediawiki": ["mediawiki", "wikitext"],
        }

        for app_name, check_paths in patterns.items():
            if self.scanner.stop_event.is_set():
                break
            for path in check_paths[:10]:
                if self.scanner.stop_event.is_set():
                    break
                full_url = safe_url_join(base_url, path)
                resp = self.http.get(full_url, timeout=8)
                if (resp and resp.status_code == 200 and
                    not self.scanner.is_custom_404(resp, base_url,
                                                  url=full_url)):
                    try:
                        body = resp.text
                    except Exception:
                        continue

                    verified = len(body) > 200
                    lower = body.lower()
                    for cms, indicators in cms_indicators.items():
                        if cms in app_name.lower():
                            verified = any(i.lower() in lower
                                          for i in indicators)
                            break

                    if verified:
                        self.scanner.add_finding(Finding(
                            name=(f"Web app detected: "
                                 f"{app_name.replace('_', ' ').title()}"),
                            severity="info", url=full_url,
                            detail=f"Detected via: {path}",
                            tags="fingerprint",
                            category="WebApps",
                            check_name=app_name,
                        ))
                        break