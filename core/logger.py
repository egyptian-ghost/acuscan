#!/usr/bin/env python3
"""AcuScan logger."""
import sys
import json
import time
import threading
from datetime import datetime
from pathlib import Path


class ScanLogger:
    """Logs scanner events to file (JSON lines) for later analysis."""

    def __init__(self, log_file=None, verbose=False):
        self.log_file = log_file
        self.verbose = verbose
        self.lock = threading.Lock()
        self._fh = None
        if log_file:
            try:
                Path(log_file).parent.mkdir(parents=True, exist_ok=True)
                self._fh = open(log_file, 'a', encoding='utf-8')
            except Exception:
                self._fh = None

    def log(self, event_type, data):
        if not self._fh:
            return
        entry = {
            "ts": datetime.utcnow().isoformat(),
            "type": event_type,
            "data": data,
        }
        with self.lock:
            try:
                self._fh.write(json.dumps(entry, default=str) + "\n")
                self._fh.flush()
            except Exception:
                pass

    def close(self):
        if self._fh:
            try:
                self._fh.close()
            except Exception:
                pass