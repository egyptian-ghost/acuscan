# AcuScan 6.7 — Maintenance & Security Update

## Fixed
- Added a working `--version` CLI option.
- Fixed dynamic plugin loading so plugins can use package-relative imports.
- Made TLS certificate verification enabled by default.
- Added `--insecure-tls` for authorized labs/self-signed targets.
- Removed unsafe `pickle` session persistence; sessions are now stored as JSON.
- Restored tuple HTTP Basic Auth values when loading JSON sessions.
- Applied best-effort owner-only permissions (`0600`) to saved session files on POSIX.
- Kept TLS behavior consistent across the main HTTP client, login tester, session manager, and per-folder checks.
- Updated the project version to `6.7.0`.

## Compatibility
Existing legacy pickle session files are intentionally not loaded automatically because deserializing untrusted pickle data can execute arbitrary code. Recreate the session file by logging in again.

## Validation
- All Python source files compile successfully.
- Generated example plugins load successfully through the plugin loader.
- Session JSON save/load round-trip passes.
- CLI `--version` and `--help` pass.

## Note
The Web UI requires the packages listed in `requirements.txt` (including Flask). The scan engine itself can be used without the Web UI dependencies where applicable.
