#!/usr/bin/env python3
"""
Plugin Loader
=============
Discovers and loads PluginBase subclasses from a directory.
"""
import os
import re
import sys
import importlib.util
from typing import List, Dict

from .base import PluginBase


class PluginLoader:
    def __init__(self, plugins_dir=None, config=None):
        from core.config import PLUGINS_DIR
        self.plugins_dir = plugins_dir or PLUGINS_DIR
        self.config = config or {}
        self.plugins: List[PluginBase] = []
        self.errors: List[str] = []
        self.loaded_modules = {}

    def discover(self) -> List[Dict]:
        """Discover plugins without loading them."""
        if not os.path.isdir(self.plugins_dir):
            return []
        discovered = []
        for fname in sorted(os.listdir(self.plugins_dir)):
            if not fname.endswith('.py') or fname.startswith('_'):
                continue
            path = os.path.join(self.plugins_dir, fname)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read(2000)
                name_m = re.search(r'^\s*name\s*=\s*["\']([^"\']+)',
                                  content, re.M)
                desc_m = re.search(r'^\s*description\s*=\s*["\']([^"\']+)',
                                  content, re.M)
                sev_m = re.search(r'^\s*severity\s*=\s*["\']([^"\']+)',
                                 content, re.M)
                discovered.append({
                    "file": fname,
                    "path": path,
                    "name": name_m.group(1) if name_m else fname[:-3],
                    "description": desc_m.group(1) if desc_m else "",
                    "severity": sev_m.group(1) if sev_m else "info",
                })
            except Exception as e:
                self.errors.append(f"{fname}: {e}")
        return discovered

    def load_all(self) -> int:
        """Load all plugins. Returns count loaded."""
        if not os.path.isdir(self.plugins_dir):
            return 0

        # Ensure __init__.py
        init_file = os.path.join(self.plugins_dir, "__init__.py")
        if not os.path.exists(init_file):
            try:
                with open(init_file, 'w') as f:
                    f.write("# AcuScan plugins\n")
            except Exception:
                pass

        loaded = 0
        for fname in sorted(os.listdir(self.plugins_dir)):
            if not fname.endswith('.py') or fname.startswith('_'):
                continue
            path = os.path.join(self.plugins_dir, fname)
            try:
                module = self._load_module(path, fname[:-3])
                if not module:
                    continue
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and
                        issubclass(attr, PluginBase) and
                        attr is not PluginBase and
                        getattr(attr, 'enabled', True)):
                        instance = attr(self.config)
                        self.plugins.append(instance)
                        loaded += 1
            except Exception as e:
                self.errors.append(f"{fname}: {e}")
        return loaded

    def _load_module(self, path, name):
        """Load a plugin as part of the scanner.plugins package.

        Loading plugins with only their filename (e.g. ``example_plugins``)
        breaks plugins that use relative imports such as ``from .base import``.
        Give dynamically loaded modules a real package-qualified name so both
        relative and absolute imports work consistently.
        """
        module_name = f"scanner.plugins.{name}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if not spec or not spec.loader:
                return None

            module = importlib.util.module_from_spec(spec)
            module.__package__ = "scanner.plugins"
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            self.loaded_modules[name] = module
            return module
        except Exception as e:
            sys.modules.pop(module_name, None)
            self.errors.append(f"{name}: {e}")
            return None

    def run_all(self, target_url, http_client, scanner):
        """Run all loaded plugins."""
        all_findings = []
        for plugin in self.plugins:
            if scanner.stop_event.is_set():
                break
            try:
                plugin.setup(scanner)
                findings = plugin.scan(target_url, http_client, scanner)
                if findings:
                    for f in findings:
                        all_findings.append(f)
                        scanner.add_finding(f)
                        plugin.on_finding(f)
                plugin.teardown()
            except Exception as e:
                self.errors.append(f"{plugin.name}: {e}")
        return all_findings

    def list_plugins(self):
        return [p.get_metadata() for p in self.plugins]