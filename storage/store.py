#!/usr/bin/env python3
"""
AcuScan Storage Layer v6.9.0
==========================
Thread-safe SQLite storage with:
  - Scans, Findings, Evidence, Schedules, Users
  - Crawl Map (NEW)
  - Server Info (NEW)
  - Login Test Results (NEW)
"""
import os
import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Optional, List, Dict

from core.config import DEFAULT_STORAGE_DB
from .schema import SCHEMA


class Storage:
    def __init__(self, db_path=None):
        self.db_path = db_path or DEFAULT_STORAGE_DB
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.lock = threading.RLock()
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=30,
                              check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            self._ensure_columns(conn)

    def _ensure_columns(self, conn):
        """Add missing columns for schema migration."""
        try:
            cur = conn.execute("PRAGMA table_info(findings)")
            cols = {r[1] for r in cur.fetchall()}
            additions = [
                ("verification_steps", "TEXT"),
                ("all_evidence", "TEXT"),
                ("extracted_info", "TEXT"),
                ("request_raw", "TEXT"),
                ("response_raw", "TEXT"),
                ("verified", "INTEGER DEFAULT 0"),
            ]
            for name, typ in additions:
                if name not in cols:
                    conn.execute(f"ALTER TABLE findings ADD COLUMN {name} {typ}")

            cur = conn.execute("PRAGMA table_info(scans)")
            scols = {r[1] for r in cur.fetchall()}
            if "verified_count" not in scols:
                conn.execute(
                    "ALTER TABLE scans ADD COLUMN verified_count INTEGER DEFAULT 0"
                )
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════
    #  Scans
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _dedupe_targets(targets):
        """Return targets in original order without duplicates."""
        if not isinstance(targets, list):
            return []
        out = []
        seen = set()
        for value in targets:
            if value is None:
                continue
            value = str(value).strip()
            if not value:
                continue
            key = value.rstrip('/').lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(value)
        return out

    def create_scan(self, scan_uuid, targets, config):
        targets = self._dedupe_targets(targets)
        with self.lock, self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO scans (scan_uuid, targets, config, status, started_at)
                   VALUES (?, ?, ?, 'running', ?)""",
                (scan_uuid,
                 json.dumps(targets),
                 json.dumps(config, default=str),
                 datetime.now(timezone.utc).isoformat())
            )
            return cur.lastrowid

    def update_scan_status(self, scan_id, status, request_count=0,
                          error_count=0, totals=None, duration=None):
        with self.lock, self._connect() as conn:
            finished = (datetime.now(timezone.utc).isoformat()
                       if status in ('completed', 'failed', 'stopped')
                       else None)
            totals = totals or {}
            conn.execute(
                """UPDATE scans SET status=?, finished_at=?,
                   request_count=?, error_count=?, duration_seconds=?,
                   total_findings=?, critical_count=?, high_count=?,
                   medium_count=?, low_count=?, info_count=?,
                   verified_count=?
                   WHERE id=?""",
                (status, finished, request_count, error_count, duration,
                 totals.get('total', 0), totals.get('critical', 0),
                 totals.get('high', 0), totals.get('medium', 0),
                 totals.get('low', 0), totals.get('info', 0),
                 totals.get('verified', 0), scan_id)
            )

    def get_scan(self, scan_id):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?",
                             (scan_id,)).fetchone()
            if not row:
                return None
            return self._parse_scan_row(dict(row))

    def get_scan_by_uuid(self, scan_uuid):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE scan_uuid=?",
                             (scan_uuid,)).fetchone()
            if not row:
                return None
            return self._parse_scan_row(dict(row))

    def list_scans(self, limit=100, offset=0):
        """List scans — robust against missing columns."""
        with self._connect() as conn:
            try:
                cols_info = conn.execute("PRAGMA table_info(scans)").fetchall()
                existing_cols = {c[1] for c in cols_info}
            except Exception:
                existing_cols = set()

            wanted = [
                "id", "scan_uuid", "targets", "config", "status",
                "started_at", "finished_at", "duration_seconds",
                "request_count", "error_count", "total_findings",
                "critical_count", "high_count", "medium_count",
                "low_count", "info_count", "verified_count", "created_at",
            ]
            select_cols = [c for c in wanted if c in existing_cols]
            if not select_cols:
                return []

            query = (f"SELECT {', '.join(select_cols)} FROM scans "
                     f"ORDER BY id DESC LIMIT ? OFFSET ?")

            try:
                rows = conn.execute(query, (limit, offset)).fetchall()
            except Exception as e:
                print(f"[storage.list_scans] Query error: {e}")
                return []

            return [self._parse_scan_row(dict(r)) for r in rows]

    def _parse_scan_row(self, d):
        try:
            t = d.get('targets')
            if isinstance(t, str):
                d['targets'] = self._dedupe_targets(json.loads(t) if t else [])
            elif isinstance(t, list):
                d['targets'] = self._dedupe_targets(t)
            else:
                d['targets'] = []
        except Exception:
            d['targets'] = []

        try:
            c = d.get('config')
            if isinstance(c, str):
                d['config'] = json.loads(c) if c else {}
            elif not isinstance(c, dict):
                d['config'] = {}
        except Exception:
            d['config'] = {}

        return d

    def delete_scan(self, scan_id):
        with self.lock, self._connect() as conn:
            conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))

    # ═══════════════════════════════════════════════════════════════════════
    #  Findings
    # ═══════════════════════════════════════════════════════════════════════

    def add_finding(self, scan_id, finding):
        with self.lock, self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO findings
                   (scan_id, name, severity, url, parameter, detail, evidence,
                    confidence, cve, cwe, cvss, cvss_vector, category,
                    check_name, payload, verification_methods, remediation,
                    verification_steps, all_evidence, extracted_info,
                    request_raw, response_raw, verified)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                           ?, ?, ?, ?, ?, ?)""",
                (scan_id,
                 finding.get('name', ''),
                 finding.get('severity', 'info'),
                 finding.get('url', ''),
                 finding.get('parameter', ''),
                 finding.get('detail', ''),
                 finding.get('evidence', ''),
                 finding.get('confidence', 0.0),
                 finding.get('cve', ''),
                 finding.get('cwe', ''),
                 float(finding.get('cvss', 0) or 0),
                 finding.get('cvss_vector', ''),
                 finding.get('category', ''),
                 finding.get('check_name', ''),
                 finding.get('payload', ''),
                 json.dumps(finding.get('verification_methods', [])),
                 finding.get('remediation', ''),
                 json.dumps(finding.get('verification_steps', []), default=str),
                 json.dumps(finding.get('all_evidence', []), default=str),
                 json.dumps(finding.get('extracted_info', {}), default=str),
                 finding.get('request', '') or '',
                 finding.get('response', '') or '',
                 1 if finding.get('verified') else 0)
            )
            finding_id = cur.lastrowid

            for ev in finding.get('all_evidence', []):
                conn.execute(
                    """INSERT INTO evidence
                       (finding_id, type, data, payload, request, response,
                        confidence, description)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (finding_id,
                     ev.get('type', ''),
                     ev.get('data', '') or ev.get('raw_match', ''),
                     ev.get('payload', ''),
                     json.dumps(ev.get('request', {}), default=str),
                     json.dumps(ev.get('response', {}), default=str),
                     ev.get('confidence', 0.0),
                     ev.get('description', ''))
                )

            sev = finding.get('severity', 'info')
            verified = 1 if finding.get('verified') else 0
            conn.execute(
                """UPDATE scans SET total_findings = total_findings + 1,
                   verified_count = verified_count + ?,
                   critical_count = critical_count + CASE WHEN ?='critical' THEN 1 ELSE 0 END,
                   high_count = high_count + CASE WHEN ?='high' THEN 1 ELSE 0 END,
                   medium_count = medium_count + CASE WHEN ?='medium' THEN 1 ELSE 0 END,
                   low_count = low_count + CASE WHEN ?='low' THEN 1 ELSE 0 END,
                   info_count = info_count + CASE WHEN ?='info' THEN 1 ELSE 0 END
                   WHERE id=?""",
                (verified, sev, sev, sev, sev, sev, scan_id)
            )
            return finding_id

    def get_findings(self, scan_id=None, severity=None,
                    verified_only=False, limit=1000):
        with self._connect() as conn:
            query = "SELECT * FROM findings WHERE 1=1"
            params = []
            if scan_id is not None:
                query += " AND scan_id=?"
                params.append(scan_id)
            if severity:
                query += " AND severity=?"
                params.append(severity)
            if verified_only:
                query += " AND verified=1"
            query += (" ORDER BY CASE severity WHEN 'critical' THEN 1 "
                      "WHEN 'high' THEN 2 WHEN 'medium' THEN 3 "
                      "WHEN 'low' THEN 4 ELSE 5 END, id DESC LIMIT ?")
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
            return [self._parse_finding_row(dict(r)) for r in rows]

    def get_all_findings(self, limit=500):
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT f.*, s.targets as scan_targets
                   FROM findings f
                   LEFT JOIN scans s ON f.scan_id = s.id
                   ORDER BY CASE f.severity WHEN 'critical' THEN 1
                            WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                            WHEN 'low' THEN 4 ELSE 5 END, f.id DESC
                   LIMIT ?""", (limit,)
            ).fetchall()
            return [self._parse_finding_row(dict(r)) for r in rows]

    def _parse_finding_row(self, d):
        for key in ('verification_methods', 'verification_steps',
                   'all_evidence'):
            try:
                v = d.get(key)
                if isinstance(v, str) and v:
                    d[key] = json.loads(v)
                elif not isinstance(v, list):
                    d[key] = []
            except Exception:
                d[key] = []
        try:
            v = d.get('extracted_info')
            if isinstance(v, str) and v:
                d['extracted_info'] = json.loads(v)
            elif not isinstance(v, dict):
                d['extracted_info'] = {}
        except Exception:
            d['extracted_info'] = {}
        return d

    def get_finding_detail(self, finding_id):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id=?",
                             (finding_id,)).fetchone()
            if not row:
                return None
            d = self._parse_finding_row(dict(row))

            ev_rows = conn.execute(
                "SELECT * FROM evidence WHERE finding_id=? ORDER BY id",
                (finding_id,)
            ).fetchall()
            d['evidence_list'] = []
            for ev in ev_rows:
                ed = dict(ev)
                for k in ('request', 'response'):
                    try:
                        v = ed.get(k)
                        if isinstance(v, str) and v:
                            ed[k] = json.loads(v)
                        elif not isinstance(v, dict):
                            ed[k] = {}
                    except Exception:
                        ed[k] = {}
                d['evidence_list'].append(ed)
            return d

    # ═══════════════════════════════════════════════════════════════════════
    #  Stats
    # ═══════════════════════════════════════════════════════════════════════

    def get_stats(self):
        with self._connect() as conn:
            stats = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) as c FROM findings GROUP BY severity"
            ):
                stats[row['severity']] = row['c']
            stats['total_scans'] = conn.execute(
                "SELECT COUNT(*) FROM scans").fetchone()[0]
            stats['total_findings'] = conn.execute(
                "SELECT COUNT(*) FROM findings").fetchone()[0]
            try:
                stats['verified'] = conn.execute(
                    "SELECT COUNT(*) FROM findings WHERE verified=1"
                ).fetchone()[0]
            except Exception:
                stats['verified'] = 0
            return stats

    def get_severity_timeline(self, days=30):
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT DATE(created_at) as day, severity, COUNT(*) as count
                   FROM findings
                   WHERE created_at >= DATE('now', '-' || ? || ' days')
                   GROUP BY day, severity ORDER BY day""", (days,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_top_vulns(self, limit=10):
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT name, severity, COUNT(*) as count
                   FROM findings GROUP BY name, severity
                   ORDER BY count DESC LIMIT ?""", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ═══════════════════════════════════════════════════════════════════════
    #  NEW: Scan metadata (crawl map, server info, login test)
    # ═══════════════════════════════════════════════════════════════════════

    def save_scan_metadata(self, scan_id, crawl_map=None,
                          crawl_stats=None, server_info=None,
                          login_test=None):
        """Save all metadata in one call."""
        with self.lock, self._connect() as conn:
            # Crawl map
            if crawl_map:
                conn.execute(
                    "DELETE FROM scan_crawl_map WHERE scan_id=?", (scan_id,)
                )
                for node in crawl_map:
                    conn.execute(
                        """INSERT INTO scan_crawl_map
                           (scan_id, url, status, content_type, content_length,
                            depth, parent_url, title, parameters, forms,
                            links_found, response_time_ms, is_external, error)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (scan_id,
                         node.get("url", ""),
                         node.get("status", 0),
                         node.get("content_type", ""),
                         node.get("content_length", 0),
                         node.get("depth", 0),
                         node.get("parent_url", ""),
                         node.get("title", ""),
                         json.dumps(node.get("parameters", [])),
                         json.dumps(node.get("forms", [])),
                         node.get("links_found", 0),
                         node.get("response_time_ms", 0.0),
                         1 if node.get("is_external") else 0,
                         node.get("error", ""))
                    )

            # Server info
            if server_info:
                conn.execute(
                    "DELETE FROM scan_server_info WHERE scan_id=?", (scan_id,)
                )
                si = server_info
                conn.execute(
                    """INSERT INTO scan_server_info
                       (scan_id, url, host, ip_addresses, server, powered_by,
                        aspnet_version, operating_system, hosting_provider,
                        cdn, reverse_proxy, port, protocol, response_time_ms,
                        headers, security_headers, ssl_enabled, ssl_issuer,
                        ssl_subject, ssl_expires, ssl_protocol, ssl_cipher,
                        technologies)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                               ?, ?, ?, ?, ?, ?, ?)""",
                    (scan_id,
                     si.get("url", ""),
                     si.get("host", ""),
                     json.dumps(si.get("ip_addresses", [])),
                     si.get("server", ""),
                     si.get("powered_by", ""),
                     si.get("aspnet_version", ""),
                     si.get("operating_system", ""),
                     si.get("hosting_provider", ""),
                     si.get("cdn", ""),
                     si.get("reverse_proxy", ""),
                     si.get("port", 0),
                     si.get("protocol", ""),
                     si.get("response_time_ms", 0.0),
                     json.dumps(si.get("headers", {})),
                     json.dumps(si.get("security_headers", {})),
                     1 if si.get("ssl_enabled") else 0,
                     si.get("ssl_issuer", ""),
                     si.get("ssl_subject", ""),
                     si.get("ssl_expires", ""),
                     si.get("ssl_protocol", ""),
                     si.get("ssl_cipher", ""),
                     json.dumps(si.get("technologies", [])))
                )

            # Login test
            if login_test:
                conn.execute(
                    "DELETE FROM scan_login_test WHERE scan_id=?", (scan_id,)
                )
                lt = login_test
                conn.execute(
                    """INSERT INTO scan_login_test
                       (scan_id, success, confidence, reason, request_url,
                        request_method, request_headers, request_body,
                        response_status, response_headers,
                        response_body_snippet, cookies_before, cookies_after,
                        cookies_added, redirect_chain, errors)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (scan_id,
                     1 if lt.get("success") else 0,
                     lt.get("confidence", 0.0),
                     lt.get("reason", ""),
                     lt.get("request_url", ""),
                     lt.get("request_method", ""),
                     json.dumps(lt.get("request_headers", {})),
                     lt.get("request_body", "")[:2000],
                     lt.get("response_status", 0),
                     json.dumps(lt.get("response_headers", {})),
                     lt.get("response_body_snippet", "")[:3000],
                     json.dumps(lt.get("cookies_before", {})),
                     json.dumps(lt.get("cookies_after", {})),
                     json.dumps(lt.get("cookies_added", [])),
                     json.dumps(lt.get("redirect_chain", [])),
                     json.dumps(lt.get("errors", [])))
                )

    def get_scan_metadata(self, scan_id):
        """Get crawl map, server info, login test."""
        result = {
            "crawl_map": [],
            "crawl_stats": {},
            "server_info": {},
            "login_test": {},
        }

        with self._connect() as conn:
            # Crawl map
            try:
                rows = conn.execute(
                    "SELECT * FROM scan_crawl_map WHERE scan_id=? "
                    "ORDER BY depth, id", (scan_id,)
                ).fetchall()
                for r in rows:
                    d = dict(r)
                    for k in ("parameters", "forms"):
                        try:
                            d[k] = json.loads(d.get(k) or "[]")
                        except Exception:
                            d[k] = []
                    result["crawl_map"].append(d)
            except Exception:
                pass

            result["crawl_stats"] = self._compute_crawl_stats(
                result["crawl_map"]
            )

            # Server info
            try:
                row = conn.execute(
                    "SELECT * FROM scan_server_info WHERE scan_id=?",
                    (scan_id,)
                ).fetchone()
                if row:
                    d = dict(row)
                    for k in ("ip_addresses",):
                        try:
                            d[k] = json.loads(d.get(k) or "[]")
                        except Exception:
                            d[k] = []
                    for k in ("headers", "security_headers"):
                        try:
                            d[k] = json.loads(d.get(k) or "{}")
                        except Exception:
                            d[k] = {}
                    for k in ("technologies",):
                        try:
                            d[k] = json.loads(d.get(k) or "[]")
                        except Exception:
                            d[k] = []
                    result["server_info"] = d
            except Exception:
                pass

            # Login test
            try:
                row = conn.execute(
                    "SELECT * FROM scan_login_test WHERE scan_id=?",
                    (scan_id,)
                ).fetchone()
                if row:
                    d = dict(row)
                    for k in ("cookies_added", "redirect_chain", "errors"):
                        try:
                            d[k] = json.loads(d.get(k) or "[]")
                        except Exception:
                            d[k] = []
                    for k in ("request_headers", "response_headers",
                             "cookies_before", "cookies_after"):
                        try:
                            d[k] = json.loads(d.get(k) or "{}")
                        except Exception:
                            d[k] = {}
                    result["login_test"] = d
            except Exception:
                pass

        return result

    def _compute_crawl_stats(self, nodes):
        internal = [n for n in nodes if not n.get("is_external")]
        external = [n for n in nodes if n.get("is_external")]

        content_types = {}
        for n in internal:
            ct = (n.get("content_type") or "unknown").split(";")[0].strip()
            content_types[ct] = content_types.get(ct, 0) + 1

        statuses = {}
        for n in internal:
            s = str(n.get("status") or 0)
            statuses[s] = statuses.get(s, 0) + 1

        return {
            "total": len(nodes),
            "internal": len(internal),
            "external": len(external),
            "with_forms": sum(1 for n in nodes if n.get("forms")),
            "with_params": sum(1 for n in nodes if n.get("parameters")),
            "content_types": content_types,
            "status_codes": statuses,
        }

    # ═══════════════════════════════════════════════════════════════════════
    #  Schedules
    # ═══════════════════════════════════════════════════════════════════════

    def add_schedule(self, name, cron, targets, config):
        with self.lock, self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO schedules (name, cron_expression, targets, config)
                   VALUES (?, ?, ?, ?)""",
                (name, cron, json.dumps(targets),
                 json.dumps(config, default=str))
            )
            return cur.lastrowid

    def list_schedules(self):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM schedules ORDER BY id DESC").fetchall()
            result = []
            for r in rows:
                d = dict(r)
                try:
                    t = d.get('targets')
                    d['targets'] = json.loads(t) if isinstance(t, str) else (t or [])
                except Exception:
                    d['targets'] = []
                try:
                    c = d.get('config')
                    d['config'] = json.loads(c) if isinstance(c, str) else (c or {})
                except Exception:
                    d['config'] = {}
                result.append(d)
            return result

    def update_schedule_run(self, schedule_id):
        with self.lock, self._connect() as conn:
            conn.execute(
                "UPDATE schedules SET last_run=? WHERE id=?",
                (datetime.now(timezone.utc).isoformat(), schedule_id)
            )

    def toggle_schedule(self, schedule_id, enabled):
        with self.lock, self._connect() as conn:
            conn.execute(
                "UPDATE schedules SET enabled=? WHERE id=?",
                (1 if enabled else 0, schedule_id)
            )

    def delete_schedule(self, schedule_id):
        with self.lock, self._connect() as conn:
            conn.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))

    # ═══════════════════════════════════════════════════════════════════════
    #  Users
    # ═══════════════════════════════════════════════════════════════════════

    def create_user(self, username, password_hash, role="user", email=None):
        with self.lock, self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO users (username, password_hash, role, email)
                   VALUES (?, ?, ?, ?)""",
                (username, password_hash, role, email)
            )
            return cur.lastrowid

    def get_user(self, username):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username=?", (username,)
            ).fetchone()
            return dict(row) if row else None

    def update_last_login(self, user_id):
        with self.lock, self._connect() as conn:
            conn.execute(
                "UPDATE users SET last_login=? WHERE id=?",
                (datetime.now(timezone.utc).isoformat(), user_id)
            )

    def user_count(self):
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    # ═══════════════════════════════════════════════════════════════════════
    #  Active scan target locks
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _normalize_active_target(target):
        """Canonical key used only for active-scan duplicate prevention.

        Keep path/query because two different scoped scans may legitimately
        target different paths. Remove only fragment and cosmetic trailing slash.
        Default ports are canonicalized so :80/:443 do not bypass the lock.
        """
        from urllib.parse import urlsplit, urlunsplit
        raw = str(target or '').strip()
        if not raw:
            return ''
        if '://' not in raw:
            raw = 'https://' + raw
        try:
            p = urlsplit(raw)
            scheme = (p.scheme or 'https').lower()
            host = (p.hostname or '').lower().rstrip('.')
            port = p.port
            if (scheme == 'https' and port == 443) or (scheme == 'http' and port == 80):
                port = None
            netloc = host if port is None else f'{host}:{port}'
            path = p.path or '/'
            path = '/' if path == '' else path.rstrip('/') or '/'
            return urlunsplit((scheme, netloc, path, p.query, '')).lower()
        except Exception:
            return raw.rstrip('/').lower().split('#', 1)[0]

    def lock_target(self, target, scan_uuid):
        """Atomically reserve a normalized target for a running scan."""
        target = self._normalize_active_target(target)
        if not target:
            return False
        with self.lock, self._connect() as conn:
            conn.execute(
                "DELETE FROM active_scan_targets "
                "WHERE created_at < datetime('now', '-2 hours')"
            )
            try:
                conn.execute(
                    "INSERT INTO active_scan_targets (target, scan_uuid) "
                    "VALUES (?, ?)",
                    (target, str(scan_uuid))
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                conn.rollback()
                return False

    def unlock_target(self, target):
        """Release one active target lock."""
        target = self._normalize_active_target(target)
        if not target:
            return
        with self.lock, self._connect() as conn:
            conn.execute(
                "DELETE FROM active_scan_targets WHERE target=?",
                (target,)
            )
            conn.commit()

    def unlock_targets(self, targets):
        """Release multiple active target locks."""
        normalized = []
        for target in targets or []:
            target = self._normalize_active_target(target)
            if target and target not in normalized:
                normalized.append(target)
        if not normalized:
            return
        with self.lock, self._connect() as conn:
            conn.executemany(
                "DELETE FROM active_scan_targets WHERE target=?",
                [(target,) for target in normalized]
            )
            conn.commit()


_storage_instance = None
_storage_lock = threading.Lock()


def get_storage(db_path=None):
    global _storage_instance
    if _storage_instance is None:
        with _storage_lock:
            if _storage_instance is None:
                _storage_instance = Storage(db_path)
    return _storage_instance
