#!/usr/bin/env python3
"""
Backup & Sensitive File Discovery v1.0
=======================================
Professional-grade scanner for:
  - Backup files (with SITE-NAME variations!)
  - Config files
  - Database dumps
  - Source code archives
  - IDE/Editor temp files
  - Version control exposure
  - Package manager files

Examples of smart name generation:
  Site: https://example.com
  → example.com.bak
  → example_com.bak
  → example-backup.tar.gz
  → example.com-2024-01-01.sql
  → backup-example-20240101.zip
  → www.example.com.bak
  → index.php.bak
  → index.php~
  → .index.php.swp
"""
import re
import time
import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import safe_url_join
from ..finding import Finding


class BackupDiscoveryPhase:
    """Professional backup & sensitive file discovery."""

    # ═══════════════════════════════════════════════════════════════════════
    #  Backup file extensions with high-signal weights
    # ═══════════════════════════════════════════════════════════════════════
    BACKUP_EXTENSIONS = [
        # Classic backups
        ('.bak', 3), ('.backup', 3), ('.old', 3), ('.orig', 3),
        ('.original', 2), ('.save', 2), ('.sav', 2), ('.tmp', 2),
        ('.temp', 2), ('.copy', 2), ('.bkp', 3), ('.bk', 2),
        # Archives
        ('.zip', 4), ('.tar', 4), ('.tar.gz', 4), ('.tgz', 4),
        ('.tar.bz2', 4), ('.tbz', 3), ('.gz', 3), ('.rar', 4),
        ('.7z', 4), ('.war', 3), ('.jar', 3),
        # Dumps
        ('.sql', 5), ('.sql.gz', 5), ('.dump', 4), ('.mdb', 4),
        ('.db', 4), ('.sqlite', 4), ('.sqlite3', 4),
        # Source code
        ('.php~', 4), ('.asp~', 4), ('.jsp~', 4), ('.py~', 4),
        ('.rb~', 4), ('.js~', 4),
        # Editor temp files
        ('.swp', 3), ('.swo', 3), ('.swx', 3), ('.swpx', 3),
        ('.~', 3),
        # Distributables
        ('.dist', 2), ('.sample', 2), ('.example', 2), ('.default', 2),
    ]

    # ═══════════════════════════════════════════════════════════════════════
    #  Common backup filenames (independent of site name)
    # ═══════════════════════════════════════════════════════════════════════
    COMMON_BACKUP_NAMES = [
        "backup", "backups", "bak", "old", "old_backup",
        "site", "website", "website_backup", "site_backup",
        "www", "web", "web_backup", "www_backup",
        "data", "db", "database", "database_backup", "db_backup",
        "export", "dump", "sql_dump", "mysql_dump",
        "prod", "production", "staging", "dev", "development",
        "test", "testing", "old_site", "new_site", "archive",
        "root", "public", "public_html", "htdocs", "wwwroot",
        "2023", "2024", "2025",
    ]

    # ═══════════════════════════════════════════════════════════════════════
    #  Config / Sensitive files
    # ═══════════════════════════════════════════════════════════════════════
    SENSITIVE_FILES = [
        # Environment
        (".env", "high"), (".env.local", "high"), (".env.production", "critical"),
        (".env.backup", "critical"), (".env.old", "high"), (".env.save", "high"),
        (".env.example", "medium"), (".env.dist", "medium"),
        # Version control
        (".git/config", "critical"), (".git/HEAD", "high"),
        (".git/index", "medium"), (".git/logs/HEAD", "high"),
        (".svn/entries", "high"), (".svn/wc.db", "high"),
        (".hg/hgrc", "high"),
        # Config
        ("config.php", "high"), ("config.php.bak", "critical"),
        ("config.inc.php", "high"), ("configuration.php", "high"),
        ("wp-config.php", "critical"), ("wp-config.php.bak", "critical"),
        ("settings.php", "high"), ("settings.py", "high"),
        ("local_settings.py", "critical"), ("config.py", "high"),
        ("config.js", "high"), ("config.json", "high"),
        ("config.xml", "high"), ("config.yaml", "high"),
        ("config.yml", "high"), ("config.ini", "high"),
        ("database.yml", "high"), ("database.php", "high"),
        ("app.config", "medium"), ("web.config", "high"),
        (".htaccess", "medium"), (".htpasswd", "critical"),
        ("robots.txt", "info"), ("sitemap.xml", "info"),
        # Package managers
        ("composer.json", "low"), ("composer.lock", "low"),
        ("package.json", "low"), ("package-lock.json", "low"),
        ("yarn.lock", "low"), ("Gemfile", "low"), ("Gemfile.lock", "low"),
        ("requirements.txt", "low"), ("Pipfile", "low"),
        ("pom.xml", "low"), ("build.gradle", "low"),
        # CI/CD
        (".github/workflows/main.yml", "medium"),
        (".gitlab-ci.yml", "medium"), (".travis.yml", "medium"),
        ("Jenkinsfile", "medium"),
        # Docker
        ("Dockerfile", "low"), ("docker-compose.yml", "medium"),
        ("docker-compose.yaml", "medium"), (".dockerignore", "low"),
        # Cloud
        (".aws/credentials", "critical"), (".aws/config", "high"),
        ("credentials.json", "high"), ("service-account.json", "critical"),
        # SSH
        (".ssh/id_rsa", "critical"), (".ssh/id_rsa.pub", "medium"),
        (".ssh/authorized_keys", "high"), (".ssh/known_hosts", "medium"),
        # Logs
        ("error.log", "medium"), ("debug.log", "medium"),
        ("access.log", "medium"), ("app.log", "medium"),
        ("log.txt", "low"), ("logs/error.log", "medium"),
        # Database
        ("phpMyAdmin", "low"), ("pma", "low"),
        ("adminer.php", "medium"), ("adminer", "medium"),
        ("db.php", "high"), ("database.sql", "critical"),
        ("dump.sql", "critical"), ("backup.sql", "critical"),
        # Admin panels
        ("admin", "info"), ("admin.php", "info"),
        ("administrator", "info"), ("admin/login", "info"),
        # Info disclosure
        ("README.md", "low"), ("README.txt", "low"),
        ("CHANGELOG.md", "low"), ("CHANGELOG.txt", "low"),
        ("LICENSE", "low"), ("TODO.txt", "low"),
        (".DS_Store", "low"), ("Thumbs.db", "low"),
        ("phpinfo.php", "high"), ("info.php", "high"),
        ("test.php", "medium"), ("debug.php", "high"),
        # Web server status
        ("server-status", "medium"), ("server-info", "medium"),
        ("nginx_status", "medium"),
        # Backup directories
        ("backup/", "high"), ("backups/", "high"),
        ("old/", "medium"), ("archive/", "medium"),
        ("db_backups/", "high"), ("sql/", "medium"),
    ]

    # ═══════════════════════════════════════════════════════════════════════
    #  Content-Type validation for backup detection
    # ═══════════════════════════════════════════════════════════════════════
    DANGEROUS_CONTENT_TYPES = {
        'application/octet-stream',
        'application/x-gzip', 'application/gzip',
        'application/zip', 'application/x-zip',
        'application/x-tar', 'application/x-bzip2',
        'application/x-7z-compressed', 'application/x-rar',
        'application/sql', 'application/x-sql',
        'application/x-sqlite3',
        'application/java-archive',
        'application/x-httpd-php', 'application/x-php',
        'text/x-php',
    }

    # Magic bytes for detecting real archives
    MAGIC_BYTES = {
        b'PK\x03\x04': 'ZIP',
        b'PK\x05\x06': 'ZIP (empty)',
        b'PK\x07\x08': 'ZIP (spanned)',
        b'\x1f\x8b': 'GZIP',
        b'BZh': 'BZIP2',
        b'7z\xbc\xaf\x27\x1c': '7Z',
        b'Rar!\x1a\x07': 'RAR',
        b'SQLite format 3\x00': 'SQLite',
        b'-- MySQL dump': 'MySQL dump',
        b'-- PostgreSQL database dump': 'PostgreSQL dump',
        b'<?xml': 'XML (potential config)',
        b'#!': 'Shebang (script)',
    }

    def __init__(self, scanner):
        self.scanner = scanner
        self.http = scanner.http
        self.out = scanner.out
        self.config = scanner.config

    # ═══════════════════════════════════════════════════════════════════════
    #  PUBLIC
    # ═══════════════════════════════════════════════════════════════════════

    def run(self, base_url):
        self.out.phase("Backup & Sensitive File Discovery")

        parsed = urlparse(base_url)
        host = parsed.netloc
        path_prefix = parsed.path.rstrip("/")

        # ═══ Generate candidate URLs ═══
        candidates = []
        candidates.extend(self._build_sensitive_files(base_url, path_prefix))
        candidates.extend(self._build_backup_variants(base_url, host,
                                                      path_prefix))

        # Deduplicate
        seen = set()
        unique = []
        for c in candidates:
            if c["url"] not in seen:
                seen.add(c["url"])
                unique.append(c)

        self.out.info(
            f"Testing {len(unique)} candidates "
            f"({len([c for c in unique if c['type'] == 'backup'])} backup, "
            f"{len([c for c in unique if c['type'] == 'sensitive'])} sensitive)"
        )

        # ═══ Parallel check ═══
        total = len(unique)
        checked = [0]
        found = [0]
        lock = __import__("threading").Lock()

        def check_one(cand):
            if self.scanner.stop_event.is_set():
                return
            try:
                result = self._check_candidate(cand, base_url)
                if result:
                    with lock:
                        found[0] += 1
                        self._add_finding(result)
            except Exception:
                pass

            with lock:
                checked[0] += 1
                if checked[0] % 100 == 0 or checked[0] >= total:
                    self.out.progress(checked[0], total, "Backup")

        workers = min(self.config.get("concurrency", 25), 20)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(check_one, c) for c in unique]
            for f in as_completed(futures):
                if self.scanner.stop_event.is_set():
                    break

        self.out.progress(total, total, "Backup")
        if found[0]:
            self.out.success(f"Found {found[0]} backup/sensitive files")

    # ═══════════════════════════════════════════════════════════════════════
    #  GENERATORS
    # ═══════════════════════════════════════════════════════════════════════

    def _build_sensitive_files(self, base_url, path_prefix):
        """Sensitive files to check at root + path prefix."""
        result = []
        for filename, severity in self.SENSITIVE_FILES:
            result.append({
                "url": safe_url_join(base_url, "/" + filename),
                "type": "sensitive",
                "severity": severity,
                "reason": "Sensitive file",
                "filename": filename,
            })
        return result

    def _build_backup_variants(self, base_url, host, path_prefix):
        """
        Smart backup candidates based on SITE NAME.
        This is the key innovation — generates names from the site itself.
        """
        result = []
        host_clean = host.split(":")[0]

        # ═══ Extract site name variations ═══
        site_names = self._site_name_variations(host_clean)

        # ═══ Generate backup filenames from site names ═══
        date_variants = self._date_variants()
        archive_exts = ['.zip', '.tar.gz', '.tgz', '.rar', '.7z', '.sql',
                       '.sql.gz', '.dump']
        backup_exts = ['.bak', '.backup', '.old', '.orig', '.save', '.tmp']

        # ─── Filename templates ───
        filename_templates = []

        # "example.com.bak" etc.
        for name in site_names:
            for ext in backup_exts:
                filename_templates.append(f"{name}{ext}")
            for ext in archive_exts:
                filename_templates.append(f"{name}{ext}")

        # "backup-example-20240101.zip"
        for name in site_names:
            for d in date_variants:
                for sep in ['-', '_']:
                    for ext in archive_exts[:4]:
                        filename_templates.append(f"backup{sep}{name}{sep}{d}{ext}")
                        filename_templates.append(f"{name}{sep}backup{sep}{d}{ext}")
                        filename_templates.append(f"{name}{sep}{d}{ext}")

        # "example.com.sql.gz"
        for name in site_names:
            for ext in ['.sql', '.sql.gz', '.dump.sql']:
                filename_templates.append(f"{name}{ext}")

        # Only keep unique, avoid explosion
        filename_templates = list(dict.fromkeys(filename_templates))[:200]

        # ─── Build URLs ───
        prefixes = ["/", path_prefix + "/", "/backup/", "/backups/",
                   "/old/", "/archive/", "/db/", "/sql/",
                   "/database/", "/files/", "/download/",
                   "/wp-content/backups/", "/wp-content/uploads/"]

        for filename in filename_templates:
            for prefix in prefixes[:5]:  # top 5 prefixes
                url = safe_url_join(base_url, prefix + filename)
                result.append({
                    "url": url,
                    "type": "backup",
                    "severity": "high",
                    "reason": "Backup file with site name",
                    "filename": filename,
                })

        # ─── Common names + extensions ───
        for name in self.COMMON_BACKUP_NAMES:
            for ext in ['.zip', '.tar.gz', '.tgz', '.rar', '.7z',
                       '.sql', '.sql.gz', '.bak', '.tar']:
                for prefix in ["/", path_prefix + "/", "/backup/"]:
                    url = safe_url_join(base_url, prefix + name + ext)
                    result.append({
                        "url": url,
                        "type": "backup",
                        "severity": "high",
                        "reason": "Common backup name",
                        "filename": name + ext,
                    })

        # ─── Backup of specific files (index.php.bak, etc.) ───
        interesting_files = [
            "index.php", "index.html", "index.asp", "index.jsp",
            "config.php", "wp-config.php", "settings.php",
            "app.py", "main.py", "server.js",
        ]
        for fname in interesting_files:
            for ext in ['.bak', '.old', '.orig', '~', '.swp', '.backup',
                       '.save', '.tmp']:
                for prefix in ["/", path_prefix + "/"]:
                    url = safe_url_join(base_url, prefix + fname + ext)
                    result.append({
                        "url": url,
                        "type": "backup",
                        "severity": "critical",
                        "reason": f"Backup of {fname}",
                        "filename": fname + ext,
                    })

        return result

    def _site_name_variations(self, host):
        """
        Generate variations of the site name for backup filenames.

        Example: www.example.com →
          www.example.com
          example.com
          example_com
          example-com
          www_example_com
          example
          www-example-com
          www.example
        """
        variations = set()

        # Strip port
        host_clean = host.split(":")[0].lower()

        # Direct
        variations.add(host_clean)

        # Without www
        no_www = re.sub(r'^www\.', '', host_clean)
        variations.add(no_www)

        # Without TLD
        no_tld = no_www.split('.')[0] if '.' in no_www else no_www
        if no_tld and len(no_tld) >= 3:
            variations.add(no_tld)

        # Replace dots with underscore / hyphen
        variations.add(host_clean.replace('.', '_'))
        variations.add(host_clean.replace('.', '-'))
        variations.add(no_www.replace('.', '_'))
        variations.add(no_www.replace('.', '-'))

        # With www variants
        variations.add('www_' + no_www.replace('.', '_'))
        variations.add('www-' + no_www.replace('.', '-'))

        # Remove all separators
        variations.add(re.sub(r'[\-_.]', '', no_www))

        # Remove empty and very long
        variations = {v for v in variations if v and len(v) <= 50}

        return sorted(variations)[:15]

    def _date_variants(self):
        """Generate common date-based suffixes."""
        today = datetime.date.today()
        variants = []

        # Last 3 months
        for i in range(0, 90, 7):
            d = today - datetime.timedelta(days=i)
            variants.append(d.strftime("%Y%m%d"))
            variants.append(d.strftime("%Y-%m-%d"))
            variants.append(d.strftime("%d%m%Y"))

        # Common years
        current_year = today.year
        for y in range(current_year - 2, current_year + 1):
            variants.append(str(y))
            variants.append(f"{y}0101")
            variants.append(f"{y}1231")

        # Dedupe and limit
        return sorted(set(variants))[:15]

    # ═══════════════════════════════════════════════════════════════════════
    #  CHECKS
    # ═══════════════════════════════════════════════════════════════════════

    def _check_candidate(self, cand, base_url):
        """
        Fetch candidate and validate it's a REAL file (not soft 404).
        Returns Finding or None.
        """
        url = cand["url"]

        resp = self.http.get(url, timeout=8)
        if not resp or resp.status_code != 200:
            return None

        # ═══ Filter: custom 404 ═══
        if self.scanner.is_custom_404(resp, base_url, url=url):
            return None

        # ═══ Filter: URL rewrite ═══
        expected_ext = ""
        if '.' in url.split('?')[0]:
            expected_ext = '.' + url.split('?')[0].rsplit('.', 1)[-1]
        if expected_ext and self.scanner.looks_like_rewrite(resp, expected_ext):
            return None

        # ═══ Validate content ═══
        content_length = len(resp.content or b"")
        content_type = resp.headers.get("Content-Type", "").lower().split(";")[0].strip()
        body = resp.text or ""

        # ─── Filter: too small ───
        if content_length < 10:
            return None

        # ─── Detect magic bytes for archives ───
        magic = None
        try:
            first_bytes = resp.content[:16]
            for sig, name in self.MAGIC_BYTES.items():
                if first_bytes.startswith(sig):
                    magic = name
                    break
        except Exception:
            pass

        # ═══ Calculate confidence & severity ═══
        confidence = 0.5
        detected_as = "unknown"

        # ─── High confidence: magic bytes ───
        if magic:
            confidence = 0.95
            detected_as = magic

        # ─── High confidence: dangerous content type ───
        elif content_type in self.DANGEROUS_CONTENT_TYPES:
            confidence = 0.9
            detected_as = f"{content_type}"

        # ─── Medium: matches extension expectations ───
        elif expected_ext:
            ext_lower = expected_ext.lower()
            if ext_lower in ('.sql', '.dump', '.sql.gz') and \
               ("INSERT INTO" in body or "CREATE TABLE" in body or
                "mysqldump" in body.lower()):
                confidence = 0.95
                detected_as = "SQL dump content"
            elif ext_lower == '.env' and '=' in body and len(body) > 20:
                confidence = 0.9
                detected_as = "Environment file"
            elif ext_lower in ('.zip', '.tar', '.gz', '.tgz', '.rar', '.7z'):
                # Non-magic but correct extension
                if content_type not in ('text/html',):
                    confidence = 0.75
                    detected_as = f"Archive extension {ext_lower}"
                else:
                    return None  # HTML for archive ext = soft 404

        # ─── Config file: pattern matching ───
        if cand["type"] == "sensitive":
            filename = cand["filename"]
            if filename == ".env":
                if re.search(r'^[A-Z_]+=.+$', body, re.M):
                    confidence = 0.95
                    detected_as = "Environment variables"
            elif filename in ("wp-config.php", "config.php"):
                if re.search(r'define\s*\(|DB_PASSWORD|DB_NAME|\$db_', body):
                    confidence = 0.9
                    detected_as = "PHP config"
            elif "composer.json" in filename or "package.json" in filename:
                if re.search(r'"(name|version|dependencies)"\s*:', body):
                    confidence = 0.9
                    detected_as = "Package manifest"
            elif filename.endswith(".git/config"):
                if "[core]" in body and "repositoryformatversion" in body:
                    confidence = 0.98
                    detected_as = "Git config"
            elif filename == ".htpasswd":
                if re.search(r'^[\w\-\.]+:\$', body, re.M):
                    confidence = 0.95
                    detected_as = "htpasswd file"
            elif filename == ".ssh/id_rsa":
                if "PRIVATE KEY" in body:
                    confidence = 1.0
                    detected_as = "SSH private key"

        # ─── Reject if confidence too low ───
        if confidence < 0.7:
            return None

        # ═══ Determine final severity ═══
        severity = cand.get("severity", "medium")

        # Upgrade severity for critical findings
        if magic in ("MySQL dump", "PostgreSQL dump", "SQLite"):
            severity = "critical"
        elif magic in ("ZIP", "GZIP", "7Z", "RAR", "BZIP2"):
            severity = "high"
        elif detected_as == "SSH private key":
            severity = "critical"

        # ═══ Build evidence snippet ═══
        evidence_snippet = ""
        if magic:
            evidence_snippet = f"Magic bytes: {magic}"
        elif content_type != "text/html":
            evidence_snippet = f"Content-Type: {content_type}"

        # Show first 200 chars of body if it's text
        if not magic and content_type.startswith("text"):
            evidence_snippet = body[:200].replace("\n", " ")[:200]

        # ═══ Return finding ═══
        return {
            "name": f"{cand['reason']}: {cand['filename']}",
            "severity": severity,
            "url": url,
            "detail": (
                f"File accessible ({content_length} bytes). "
                f"Detected as: {detected_as}. "
                f"Confidence: {confidence:.0%}"
            ),
            "evidence": evidence_snippet[:200],
            "confidence": confidence,
            "category": "BackupDiscovery",
            "check_name": ("Sensitive_File" if cand["type"] == "sensitive"
                          else "Backup_File"),
            "cwe": "CWE-538" if cand["type"] == "sensitive" else "CWE-530",
            "tags": ("sensitive_file,info_disclosure"
                    if cand["type"] == "sensitive"
                    else "backup,info_disclosure"),
            "verified": True,
        }

    def _add_finding(self, finding_data):
        """Add a verified finding."""
        self.scanner.add_finding(Finding(
            name=finding_data["name"],
            severity=finding_data["severity"],
            url=finding_data["url"],
            detail=finding_data["detail"],
            evidence=finding_data["evidence"],
            confidence=finding_data["confidence"],
            cwe=finding_data["cwe"],
            tags=finding_data["tags"],
            category=finding_data["category"],
            check_name=finding_data["check_name"],
            verified=True,
        ))