# AcuScan 6.9.0

- Fixed missing scanner phase exports for BackupDiscoveryPhase and DirectoryBruteForcePhase.
- Fixed duplicate SQLite scan rows: Web UI jobs now own one canonical scan row and Scanner.scan() reuses it.
- Fixed target lock ownership by using the same scan UUID for the DB lock and ScanJob.
- Improved target canonicalization (scheme, host, default ports, path, query; fragments ignored).
- Terminal job failures are persisted as `failed` instead of leaving stale active rows.
- Target locks are always released in `finally`.
