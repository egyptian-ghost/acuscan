# AcuScan 6.9.0 — Verification 2.0

- Separate HTTP/crawl concurrency from vulnerability verification workers.
- Added `--verification-workers` and `--no-browser-xss`.
- Verifiers run in parallel with fresh verifier instances per task.
- Added finding `confidence`, structured `reproduction`, and `verification_timeline`.
- Added once-per-URL surface checks for CORS, API schemas, GraphQL detection, JWT exposure, and security headers.
- Added optional Playwright browser confirmation for reflected/DOM XSS; static reflection alone is not promoted to confirmed XSS.
- Fixed verification package initializer to use the actual verifier modules shipped with the project.
- Preserved target-lock and single-scan protections from 6.8.x.

Browser XSS confirmation:
```bat
pip install playwright
playwright install chromium
```
