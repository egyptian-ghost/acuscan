# AcuScan 6.8.0

## Web UI
- Web UI now registers the maintained `webui.api.scans` blueprint instead of the older duplicate implementation.
- Removed misleading `api.scans_detail` / `api.findings` startup probes.
- Target lists are deduplicated at input, storage, API and display layers.
- Duplicate pasted URLs differing only by trailing slash/case are collapsed.

## OAST
- OAST automatically searches a wider range of ports when the requested port is unavailable.
- Port availability checks now match the server bind address.
- Expected local Windows port-bind failures are quiet unless verbose mode is enabled.

## Crawler
- XML/XHTML responses are parsed with BeautifulSoup's XML parser when available.
- The previous XML-as-HTML warning is avoided without hiding unrelated warnings.
