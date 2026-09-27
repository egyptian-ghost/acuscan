#!/usr/bin/env python3
"""Scheduled scans (cron-based)."""
import threading
from datetime import datetime, timedelta

try:
    from croniter import croniter
    HAS_CRONITER = True
except ImportError:
    HAS_CRONITER = False

from storage import get_storage


class ScanScheduler:
    """Background scheduler for cron-based scans."""

    def __init__(self, storage, scan_runner):
        self.storage = storage
        self.scan_runner = scan_runner
        self.stop_event = threading.Event()
        self.thread = None
        self.interval = 30

    def start(self):
        if not HAS_CRONITER:
            print("[Scheduler] croniter not installed — disabled")
            return
        if not self.storage:
            print("[Scheduler] no storage — disabled")
            return
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        print("[Scheduler] Started")

    def stop(self):
        self.stop_event.set()

    def _run(self):
        while not self.stop_event.is_set():
            try:
                schedules = self.storage.list_schedules()
                now = datetime.utcnow()
                for sched in schedules:
                    if not sched.get("enabled"):
                        continue
                    cron_expr = sched.get("cron_expression")
                    if not cron_expr:
                        continue
                    try:
                        last_run = sched.get("last_run")
                        last_dt = None
                        if last_run:
                            try:
                                last_dt = datetime.fromisoformat(
                                    str(last_run)
                                )
                            except Exception:
                                pass
                        base = last_dt or (now - timedelta(seconds=60))
                        cron = croniter(cron_expr, base)
                        next_run = cron.get_next(datetime)
                        if next_run <= now:
                            try:
                                self.scan_runner(sched["targets"],
                                                sched["config"])
                                self.storage.update_schedule_run(sched["id"])
                                print(f"[Scheduler] Ran: {sched['name']}")
                            except Exception as e:
                                print(f"[Scheduler] Failed: {e}")
                    except Exception as e:
                        print(f"[Scheduler] Cron error: {e}")
            except Exception as e:
                print(f"[Scheduler] Error: {e}")
            self.stop_event.wait(self.interval)


def _scan_runner(targets, config):
    """Start a scan via the jobs module."""
    from .jobs import start_scan
    full_config = dict(config or {})
    for k, v in {
        "follow_redirects": True,
        "max_redirects": 10,
        "disable_redirects": False,
        "rate_limit": 150,
        "concurrency": 25,
        "no_color": True,
        "silent": True,
        "crawl_depth": 3,
        "crawl_max_pages": 200,
        "timeout": 10,
        "enable_verification": True,
        "enable_oast": False,
        "enable_storage": True,
        "enable_plugins": True,
        "_vars": {},
    }.items():
        full_config.setdefault(k, v)
    return start_scan(full_config, targets)


scheduler = ScanScheduler(get_storage(), _scan_runner) \
    if get_storage else None