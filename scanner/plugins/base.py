#!/usr/bin/env python3
"""
Plugin Base
===========
Base class for custom check plugins.

Example:
    class MyPlugin(PluginBase):
        name = "my_check"
        description = "Checks for X"
        severity = "high"

        def scan(self, target_url, http_client, scanner):
            findings = []
            resp = http_client.get(target_url + "/admin")
            if resp and resp.status_code == 200:
                findings.append(Finding(...))
            return findings
"""


class PluginBase:
    name = "unnamed_plugin"
    description = ""
    severity = "info"
    author = "unknown"
    version = "1.0"
    enabled = True
    tags = []
    category = "custom"

    def __init__(self, config=None):
        self.config = config or {}
        self.findings = []
        self.scanner = None

    def setup(self, scanner):
        """Called before scan()."""
        self.scanner = scanner

    def scan(self, target_url, http_client, scanner):
        """Override: return list of Finding objects."""
        return []

    def on_finding(self, finding):
        self.findings.append(finding)

    def teardown(self):
        """Called after scan completes."""
        pass

    def get_metadata(self):
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "author": self.author,
            "version": self.version,
            "tags": self.tags,
            "category": self.category,
        }