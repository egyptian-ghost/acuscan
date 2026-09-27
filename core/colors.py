#!/usr/bin/env python3
"""ANSI colors + severity metadata."""


class C:
    RST = "\033[0m"; BLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GRN = "\033[92m"; YLW = "\033[93m"
    BLU = "\033[94m"; MAG = "\033[95m"; CYN = "\033[96m"
    WHT = "\033[97m"; GRY = "\033[90m"
    BRED = "\033[1;91m"; BGRN = "\033[1;92m"; BYLW = "\033[1;93m"
    BBLU = "\033[1;94m"; BMAG = "\033[1;95m"; BCYN = "\033[1;96m"


SEVERITY_COLORS = {
    "critical": C.BRED, "high": C.RED, "medium": C.YLW,
    "low": C.BLU, "info": C.CYN,
}
SEVERITY_ICONS = {
    "critical": "🔴", "high": "🟠", "medium": "🟡",
    "low": "🔵", "info": "⚪",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

BANNER = f"""
{C.CYN}╔══════════════════════════════════════════════════════════════════╗
║  {C.WHT} █████   ██████ ██    ██ ███████  ██████  █████  ███    ██{C.CYN}    ║
║  {C.WHT}██   ██ ██      ██    ██ ██      ██      ██   ██ ████   ██{C.CYN}    ║
║  {C.WHT}███████ ██      ██    ██ ███████ ██      ███████ ██ ██  ██{C.CYN}    ║
║  {C.WHT}██   ██ ██      ██    ██      ██ ██      ██   ██ ██  ██ ██{C.CYN}    ║
║  {C.WHT}██   ██  ██████  ██████  ███████  ██████ ██   ██ ██   ████{C.CYN}    ║
║                                                                  ║
║  {C.GRN}AcuScan v6.0.0  {C.GRY}(c) tg:@Neoleads{C.CYN}                            ║
║  {C.GRY}Professional Web Vulnerability Scanner{C.CYN}                        ║
╚══════════════════════════════════════════════════════════════════╝{C.RST}
"""