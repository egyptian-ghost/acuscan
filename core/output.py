#!/usr/bin/env python3
"""Console output formatter."""
import sys
import threading
from .colors import C, SEVERITY_COLORS, SEVERITY_ICONS
from .utils import truncate


class OutputFormatter:
    def __init__(self, no_color=False, silent=False):
        self.no_color = no_color
        self.silent = silent
        self.lock = threading.Lock()

    def _c(self, color, text):
        return text if self.no_color else f"{color}{text}{C.RST}"

    def banner(self):
        if self.silent:
            return
        if self.no_color:
            print("AcuScan v6.0")
            print("=" * 60)
        else:
            from .colors import BANNER
            print(BANNER)

    def info(self, msg):
        if not self.silent:
            with self.lock:
                print(f"  {self._c(C.GRY, '[')} {self._c(C.CYN, 'INF')} "
                      f"{self._c(C.GRY, ']')} {msg}")

    def warn(self, msg):
        if not self.silent:
            with self.lock:
                print(f"  {self._c(C.GRY, '[')} {self._c(C.YLW, 'WRN')} "
                      f"{self._c(C.GRY, ']')} {msg}")

    def error(self, msg):
        with self.lock:
            print(f"  {self._c(C.GRY, '[')} {self._c(C.RED, 'ERR')} "
                  f"{self._c(C.GRY, ']')} {msg}")

    def success(self, msg):
        if not self.silent:
            with self.lock:
                print(f"  {self._c(C.GRY, '[')} {self._c(C.BGRN, 'OK ')} "
                      f"{self._c(C.GRY, ']')} {msg}")

    def phase(self, name, desc=""):
        if not self.silent:
            with self.lock:
                line = f"\n  {self._c(C.BCYN, '━━━')} {self._c(C.BLD + C.WHT, name)}"
                if desc:
                    line += f" {self._c(C.GRY, f'({desc})')}"
                print(line)

    def progress(self, current, total, prefix=""):
        if self.silent:
            return
        with self.lock:
            pct = int(100 * current / total) if total > 0 else 0
            bar_len = 30
            filled = int(bar_len * current / total) if total > 0 else 0
            bar = "█" * filled + "░" * (bar_len - filled)
            color = C.GRN if pct == 100 else C.CYN
            sys.stdout.write(
                f"\r  {self._c(C.GRY, prefix)} "
                f"{self._c(color, bar)} "
                f"{self._c(C.WHT, f'{pct:3d}%')} "
                f"{self._c(C.GRY, f'({current}/{total})')}"
            )
            if current >= total:
                sys.stdout.write("\n")
            sys.stdout.flush()

    def finding(self, f):
        with self.lock:
            color = SEVERITY_COLORS.get(f.severity, C.WHT)
            icon = SEVERITY_ICONS.get(f.severity, "•")
            conf_str = ""
            if getattr(f, 'confidence', 0) > 0:
                conf_str = f" {self._c(C.GRY, f'[conf: {f.confidence:.0%}]')}"
            verified = ""
            if getattr(f, 'verified', False):
                verified = f" {self._c(C.BGRN, '✓ VERIFIED')}"
            print(f"  {icon} {self._c(color, f'[{f.severity.upper():>8s}]')} "
                  f"{self._c(C.WHT + C.BLD, f.name)}{conf_str}{verified}")
            print(f"     {self._c(C.GRY, '↳')} {self._c(C.GRY, f.url)}")
            if f.detail:
                print(f"     {self._c(C.GRY, '  ')} "
                      f"{self._c(C.DIM, truncate(f.detail, 100))}")
            if getattr(f, 'extracted_info', None):
                info_str = ", ".join(f"{k}={str(v)[:40]}"
                                    for k, v in list(f.extracted_info.items())[:3])
                print(f"     {self._c(C.BGRN, '  💎 Extracted:')} "
                      f"{self._c(C.GRN, info_str)}")
            if f.cve:
                print(f"     {self._c(C.GRY, '  CVE:')} "
                      f"{self._c(C.YLW, f.cve)}")

    def summary(self, findings, elapsed, requests_made, errors):
        if self.silent:
            return
        from collections import defaultdict
        counts = defaultdict(int)
        for f in findings:
            counts[f.severity] += 1

        print(f"\n  {self._c(C.BCYN, '═══')} "
              f"{self._c(C.BLD + C.WHT, 'Scan Summary')} "
              f"{self._c(C.BCYN, '═══')}")
        print()
        print(f"  {self._c(C.GRY, 'Duration:')}    {elapsed:.1f}s")
        print(f"  {self._c(C.GRY, 'Requests:')}    {requests_made}")
        print(f"  {self._c(C.GRY, 'Errors:')}      {errors}")
        print(f"  {self._c(C.GRY, 'Findings:')}    {len(findings)}")

        verified_count = sum(1 for f in findings if getattr(f, 'verified', False))
        if verified_count:
            print(f"  {self._c(C.BGRN, 'Verified:')}    {verified_count}")

        print()
        for sev in ["critical", "high", "medium", "low", "info"]:
            if counts[sev] > 0:
                color = SEVERITY_COLORS.get(sev, C.WHT)
                icon = SEVERITY_ICONS.get(sev, "•")
                bar = "█" * min(counts[sev], 50)
                print(f"  {icon} {self._c(color, f'{sev.upper():>8s}')} "
                      f"{self._c(color, bar)} {self._c(C.WHT, str(counts[sev]))}")
        print()