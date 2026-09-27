# AcuScan 6.8.1

## Hotfixes

- Fixed the `Storage.lock_target` / `unlock_target` / `unlock_targets` methods being placed outside the `Storage` class.
- Fixed `/api/scan` returning Flask's HTML 500 page when an internal exception occurred.
- Web UI now handles non-JSON API responses safely instead of showing `Unexpected token '<'`.
- Target-lock normalization now treats `https://Example.com/` and `example.com` consistently.
- Target locks remain protected against stale entries for up to two hours.
- Updated application version to `6.8.1`.
- Updated visible module version banners where applicable.

## Verification

- Python source compilation: passed.
- SQLite target-lock acquire/reject/release test: passed.
- Duplicate target lock test across URL scheme/case/trailing slash: passed.
- CLI `--version`: passed.
