#!/usr/bin/env python3
"""
Example Plugins
===============
Ready-to-use example plugins that come with AcuScan.
"""
import os
from core.config import PLUGINS_DIR


def create_example_plugin():
    """Write an example plugin file to plugins dir."""
    os.makedirs(PLUGINS_DIR, exist_ok=True)
    example_code = '''"""
Example AcuScan Plugin
======================
This plugin demonstrates how to write custom checks.
"""
from scanner import PluginBase
from scanner.finding import Finding
from core.utils import safe_url_join


class AdminPanelChecker(PluginBase):
    name = "admin_panel_checker"
    description = "Checks for exposed admin panels"
    severity = "high"
    author = "AcuScan Team"
    version = "1.0"
    tags = ["admin", "exposure"]

    ADMIN_PATHS = [
        "/admin", "/admin/", "/administrator", "/admin.php",
        "/wp-admin", "/wp-login.php", "/manager/html",
        "/phpmyadmin", "/pma", "/adminer.php",
    ]

    def scan(self, target_url, http_client, scanner):
        findings = []
        for path in self.ADMIN_PATHS:
            if scanner.stop_event.is_set():
                break
            url = safe_url_join(target_url, path)
            resp = http_client.get(url, timeout=8)
            if not resp or resp.status_code != 200:
                continue
            if scanner.is_custom_404(resp, target_url, url=url):
                continue
            ext = '.' + path.rsplit('.', 1)[-1] if '.' in path else ''
            if scanner.looks_like_rewrite(resp, ext):
                continue
            findings.append(Finding(
                name=f"Exposed admin panel: {path}",
                severity=self.severity, url=url,
                detail=f"HTTP 200, {len(resp.text)} bytes",
                category=self.category, check_name=self.name,
            ))
        return findings


class SecurityTxtChecker(PluginBase):
    name = "security_txt_checker"
    description = "Checks for security.txt file"
    severity = "info"
    author = "AcuScan Team"
    version = "1.0"
    tags = ["recon"]

    def scan(self, target_url, http_client, scanner):
        findings = []
        for path in ["/.well-known/security.txt", "/security.txt"]:
            url = safe_url_join(target_url, path)
            resp = http_client.get(url, timeout=8)
            if (resp and resp.status_code == 200 and
                "contact:" in resp.text.lower()):
                findings.append(Finding(
                    name="security.txt found",
                    severity=self.severity, url=url,
                    detail="Security contact info available",
                    category=self.category, check_name=self.name,
                ))
        return findings
'''
    path = os.path.join(PLUGINS_DIR, "example_plugins.py")
    if not os.path.exists(path):
        with open(path, 'w', encoding='utf-8') as f:
            f.write(example_code)
    return path