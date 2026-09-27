# AcuScan 6.8.2

## Web UI stability
- Dedicated 404/405 handlers prevent routing errors from being logged as application crashes.
- API 404/405 responses are always JSON.
- Unexpected API exceptions remain JSON, preventing frontend `Unexpected token '<'` errors.
- Added `/favicon.ico`, `/robots.txt`, and `/healthz`.
- Updated visible version labels to 6.8.2.
- Unified internal module version banners.
