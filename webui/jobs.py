#!/usr/bin/env python3
"""
Scan Jobs v6.9.0
================
- Manages running scans with live event streaming
- list_scans() MERGES memory + SQLite
- Releases target locks on completion (finally block)
- Global scan timeout (safety net)
"""
import json
import time
import uuid
import queue
import threading
import traceback
import collections

from storage import get_storage

try:
    from scanner import Scanner, Finding
    HAS_SCANNER = True
except ImportError:
    HAS_SCANNER = False


# ═══════════════════════════════════════════════════════════════════════════════
#  Global registries
# ═══════════════════════════════════════════════════════════════════════════════

SCANS = {}
SCANS_LOCK = threading.Lock()
WS_CLIENTS = {}
WS_LOCK = threading.Lock()

# Global scan timeout (30 minutes hard limit)
GLOBAL_SCAN_TIMEOUT = 30 * 60


class ScanJob:
    """A running scan with event stream."""

    def __init__(self, scan_id, config, targets):
        self.scan_id = scan_id
        self.config = config
        self.targets = self._dedupe_targets(targets)
        self.status = "pending"
        self.findings = []
        self.events = queue.Queue()
        self.start_time = None
        self.end_time = None
        self.thread = None
        self.stop_event = threading.Event()
        self.scanner = None
        self.storage_scan_id = None
        self._lock = threading.Lock()

    @staticmethod
    def _dedupe_targets(targets):
        result = []
        seen = set()
        for target in targets or []:
            target = str(target).strip()
            key = target.rstrip('/').lower()
            if target and key not in seen:
                seen.add(key)
                result.append(target)
        return result

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    # ═══════════════════════════════════════════════════════════════════════════
    #  Main runner
    # ═══════════════════════════════════════════════════════════════════════════

    def _run(self):
        with self._lock:
            self.status = "running"
            self.start_time = time.time()

        self._emit("status", {
            "status": "running",
            "targets": self.targets,
        })

        try:
            if not HAS_SCANNER:
                raise RuntimeError("Scanner module not available")

            self.scanner = Scanner(self.config)
            self.scanner.load_database()
            self.scanner.stop_event = self.stop_event

            # ═══════════════════════════════════════════════════════════════
            #  Persist to SQLite — normalized targets
            # ═══════════════════════════════════════════════════════════════
            storage = get_storage()
            try:
                from core.utils import normalize_url
                normalized_targets = []
                for t in self.targets:
                    nt = normalize_url(t)
                    if nt not in normalized_targets:
                        normalized_targets.append(nt)

                self.storage_scan_id = storage.create_scan(
                    self.scan_id, normalized_targets, self.config
                )
                # Pass the canonical row id into Scanner. Scanner.scan() must
                # reuse this row instead of creating a second row per target.
                self.scanner.storage_scan_id = self.storage_scan_id
            except Exception as e:
                print(f"[jobs] create_scan failed: {e}")
                self.storage_scan_id = None

            # ═══════════════════════════════════════════════════════════════
            #  Stream findings to WebSocket/SSE
            # ═══════════════════════════════════════════════════════════════
            original_add = self.scanner.add_finding

            def streaming_add(finding):
                original_add(finding)
                self._emit("finding", finding.to_dict())

            self.scanner.add_finding = streaming_add

            # ═══════════════════════════════════════════════════════════════
            #  Run scan for each target
            # ═══════════════════════════════════════════════════════════════
            total_targets = len(self.targets)
            global_start = time.time()

            for idx, target in enumerate(self.targets, 1):
                if self.stop_event.is_set():
                    break

                # ─── Global timeout check ───
                elapsed = time.time() - global_start
                if elapsed > GLOBAL_SCAN_TIMEOUT:
                    self._emit("log", {
                        "msg": f"⚠ Global timeout "
                               f"({GLOBAL_SCAN_TIMEOUT//60} min) reached. "
                               f"Stopping."
                    })
                    self.stop_event.set()
                    break

                self._emit("log", {
                    "msg": f"[{idx}/{total_targets}] Scanning: {target}"
                })

                # ─── Reset per-target state ───
                self.scanner.findings = []
                self.scanner.crawled_urls = set()
                self.scanner.crawled_forms = []
                self.scanner.crawled_params = collections.defaultdict(set)
                self.scanner._404_body_cache = {}
                # Keep the single canonical SQLite scan id for the whole job.
                # Resetting it here created duplicate scan rows for every target.
                self.scanner.storage_scan_id = self.storage_scan_id

                try:
                    findings = self.scanner.scan(target)
                    self.findings.extend(findings)
                except Exception as e:
                    self._emit("log", {
                        "msg": f"Target failed: {target} — {e}"
                    })
                    traceback.print_exc()

            status = ("completed" if not self.stop_event.is_set()
                     else "stopped")
            with self._lock:
                self.status = status
            self._emit("status", {"status": status})

            # ═══════════════════════════════════════════════════════════════
            #  Update storage final status
            # ═══════════════════════════════════════════════════════════════
            if self.storage_scan_id:
                try:
                    totals = {}
                    for f in self.findings:
                        totals[f.severity] = totals.get(f.severity, 0) + 1
                    totals["total"] = len(self.findings)
                    totals["verified"] = sum(
                        1 for f in self.findings
                        if getattr(f, "verified", False)
                    )
                    elapsed = ((self.end_time or time.time()) -
                              (self.start_time or time.time()))
                    storage.update_scan_status(
                        self.storage_scan_id, status,
                        self.scanner.http.request_count,
                        self.scanner.http.error_count,
                        totals, elapsed,
                    )
                except Exception:
                    pass

        except Exception as e:
            with self._lock:
                self.status = "failed"
            self._emit("status", {"status": "failed", "error": str(e)})
            traceback.print_exc()

            # Persist a failed state immediately so a startup/refresh cannot
            # leave this scan looking active in the Web UI.
            try:
                if self.storage_scan_id:
                    storage = get_storage()
                    storage.update_scan_status(
                        self.storage_scan_id, "failed",
                        getattr(getattr(self.scanner, "http", None), "request_count", 0),
                        getattr(getattr(self.scanner, "http", None), "error_count", 0),
                        {},
                        max(0.0, time.time() - (self.start_time or time.time())),
                    )
            except Exception:
                pass

        finally:
            with self._lock:
                self.end_time = time.time()

            # Ensure every terminal state is persisted, including exceptions
            # that occur before the normal completion block.
            try:
                if self.storage_scan_id:
                    storage = get_storage()
                    final_status = self.status if self.status in ("completed", "failed", "stopped") else "failed"
                    storage.update_scan_status(
                        self.storage_scan_id, final_status,
                        getattr(getattr(self.scanner, "http", None), "request_count", 0),
                        getattr(getattr(self.scanner, "http", None), "error_count", 0),
                        {"total": len(self.findings),
                         "critical": sum(1 for f in self.findings if getattr(f, "severity", "") == "critical"),
                         "high": sum(1 for f in self.findings if getattr(f, "severity", "") == "high"),
                         "medium": sum(1 for f in self.findings if getattr(f, "severity", "") == "medium"),
                         "low": sum(1 for f in self.findings if getattr(f, "severity", "") == "low"),
                         "info": sum(1 for f in self.findings if getattr(f, "severity", "") == "info"),
                         "verified": sum(1 for f in self.findings if getattr(f, "verified", False))},
                        max(0.0, self.end_time - (self.start_time or self.end_time)),
                    )
            except Exception:
                pass

            # ═══════════════════════════════════════════════════════════════
            #  Release target locks (CRITICAL — always runs)
            # ═══════════════════════════════════════════════════════════════
            try:
                storage = get_storage()
                if storage:
                    locked = self.config.get("_locked_targets", [])
                    if locked:
                        storage.unlock_targets(locked)
                        print(f"[jobs] Released {len(locked)} target lock(s)")
            except Exception as e:
                print(f"[jobs] Failed to release locks: {e}")

    def _emit(self, event_type, data):
        try:
            self.events.put({
                "type": event_type, "data": data, "ts": time.time()
            })
        except Exception:
            pass

    def stop(self):
        self.stop_event.set()
        with self._lock:
            self.status = "stopped"

    def to_dict(self):
        with self._lock:
            return {
                "scan_id": self.scan_id,
                "scan_uuid": self.scan_id,
                "status": self.status,
                "targets": self.targets,
                "findings_count": len(self.findings),
                "total_findings": len(self.findings),
                "start_time": self.start_time,
                "end_time": self.end_time,
                "duration": ((self.end_time or time.time()) - self.start_time
                            if self.start_time else 0),
                "live": True,
                "source": "memory",
            }


# ═══════════════════════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════════════════════

def start_scan(config, targets, scan_id=None):
    """Start a new scan job.

    When the API has already acquired target locks, pass the same scan_id so
    the lock owner and the job are unambiguous.
    """
    scan_id = str(scan_id or uuid.uuid4())
    job = ScanJob(scan_id, config, targets)
    with SCANS_LOCK:
        SCANS[scan_id] = job
    job.start()
    return scan_id


def get_scan(scan_id):
    """Get in-memory scan job by UUID."""
    return SCANS.get(scan_id)


def list_scans():
    """
    List all scans — MERGES memory (running) + SQLite (historical).
    This is the KEY function for accurate dedup + UI display.
    """
    scans_by_id = {}

    # ═══════════════════════════════════════════════════════════════════════
    #  1. Load from SQLite
    # ═══════════════════════════════════════════════════════════════════════
    try:
        storage = get_storage()
        if storage:
            db_scans = storage.list_scans(limit=100)
            for s in db_scans:
                scan_key = str(s.get("id", ""))
                if not scan_key:
                    continue
                scans_by_id[scan_key] = {
                    "id": s.get("id"),
                    "scan_uuid": s.get("scan_uuid", ""),
                    "scan_id": s.get("scan_uuid", ""),
                    "display_id": f"#{s.get('id')}",
                    "targets": s.get("targets", []),
                    "status": s.get("status", "unknown"),
                    "findings_count": s.get("total_findings", 0),
                    "total_findings": s.get("total_findings", 0),
                    "duration": s.get("duration_seconds"),
                    "duration_seconds": s.get("duration_seconds"),
                    "started_at": s.get("started_at"),
                    "finished_at": s.get("finished_at"),
                    "start_time": None,
                    "end_time": None,
                    "source": "db",
                    "live": False,
                }
    except Exception as e:
        print(f"[jobs.list_scans] SQLite load failed: {e}")

    # ═══════════════════════════════════════════════════════════════════════
    #  2. Merge in-memory (memory WINS for live status)
    # ═══════════════════════════════════════════════════════════════════════
    with SCANS_LOCK:
        mem_scans = list(SCANS.values())

    for j in mem_scans:
        j_dict = j.to_dict()
        uuid_val = j_dict.get("scan_id", "")

        # Find matching DB record by scan_uuid
        matched_key = None
        for key, db_s in scans_by_id.items():
            if db_s.get("scan_uuid") == uuid_val:
                matched_key = key
                break

        if matched_key:
            # Merge — memory wins for live data
            merged = dict(scans_by_id[matched_key])
            merged.update({
                "status": j_dict.get("status"),
                "findings_count": j_dict.get("findings_count"),
                "total_findings": j_dict.get("findings_count"),
                "duration": j_dict.get("duration"),
                "start_time": j_dict.get("start_time"),
                "end_time": j_dict.get("end_time"),
                "scan_uuid": uuid_val,
                "live": True,
                "source": "memory+db",
            })
            scans_by_id[matched_key] = merged
        else:
            # New scan not yet in DB
            new_key = f"live_{uuid_val[:8]}"
            scans_by_id[new_key] = j_dict

    # ═══════════════════════════════════════════════════════════════════════
    #  3. Sort: newest id first
    # ═══════════════════════════════════════════════════════════════════════
    def sort_key(s):
        sid = s.get("id") or 0
        st = s.get("start_time") or 0
        return (-sid, -st)

    return sorted(scans_by_id.values(), key=sort_key)


# ═══════════════════════════════════════════════════════════════════════════════
#  WebSocket
# ═══════════════════════════════════════════════════════════════════════════════

def register_websocket_routes(app):
    """Register WebSocket routes."""
    sock = app.config.get("SOCK")
    if not sock:
        return

    @sock.route("/ws/scan/<scan_id>")
    def ws_scan(ws, scan_id):
        job = SCANS.get(scan_id)
        if not job:
            try:
                ws.send(json.dumps({"error": "scan not found"}))
            except Exception:
                pass
            return

        with WS_LOCK:
            WS_CLIENTS.setdefault(scan_id, set()).add(ws)

        try:
            ws.send(json.dumps({
                "type": "status",
                "data": {"status": job.status, "targets": job.targets},
            }))
            for f in job.findings:
                ws.send(json.dumps({
                    "type": "finding", "data": f.to_dict()
                }))

            last_heartbeat = time.time()
            while True:
                try:
                    event = job.events.get(timeout=5)
                    ws.send(json.dumps(event, default=str))
                    if (event["type"] == "status" and
                        event["data"].get("status") in
                        ("completed", "failed", "stopped")):
                        break
                except queue.Empty:
                    if time.time() - last_heartbeat > 20:
                        try:
                            ws.send(json.dumps({"type": "heartbeat"}))
                        except Exception:
                            break
                        last_heartbeat = time.time()
                    if job.status in ("completed", "failed", "stopped"):
                        break
        except Exception:
            pass
        finally:
            with WS_LOCK:
                if scan_id in WS_CLIENTS:
                    WS_CLIENTS[scan_id].discard(ws)
                    if not WS_CLIENTS[scan_id]:
                        del WS_CLIENTS[scan_id]