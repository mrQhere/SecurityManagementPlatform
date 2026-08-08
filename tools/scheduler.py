import logging
from datetime import datetime
# pyrefly: ignore [missing-import]
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from tools.config_manager import load_settings
from tools.db_manager import (
    get_targets, add_log_entry,
    trigger_scheduled_system_backup_sequence,
    purge_old_backup_snapshots,
)
from scanners.watchdog import run_watchdog

def trigger_soft_delete_gc_job():
    """V9.4.2 - Garbage Collector: Hard deletes soft-deleted targets older than 30 days."""
    logger.info("Scheduler Triggered: Target soft-delete Garbage Collector.")
    from tools.db_manager import get_db_connection
    try:
        conn = get_db_connection()
        # Find targets deleted > 30 days ago
        rows = conn.execute(
            "SELECT id FROM targets WHERE is_deleted = 1 AND deleted_at <= date('now', '-30 days')"
        ).fetchall()
        
        for r in rows:
            target_id = r["id"]
            # Same cleanup logic as the old delete_target
            outputs = conn.execute(
                "SELECT stdout, stderr FROM raw_scan_output WHERE scan_id IN (SELECT id FROM scans WHERE target_id = ?)",
                (target_id,)
            ).fetchall()
            import os
            for out in outputs:
                if out["stdout"] and os.path.exists(out["stdout"]):
                    try: os.remove(out["stdout"])
                    except Exception: pass
                if out["stderr"] and os.path.exists(out["stderr"]):
                    try: os.remove(out["stderr"])
                    except Exception: pass
            
            # Hard delete
            conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        
        conn.commit()
        conn.close()
        if rows:
            logger.info(f"GC: Permanently deleted {len(rows)} expired soft-deleted targets.")
    except Exception as e:
        logger.error(f"GC Error: {e}")

logger = logging.getLogger("smp")

# Global reference to scheduler
_scheduler = None

def trigger_scan_job():
    """Daily scan job. Orchestrates scanning on all monitored URLs."""
    logger.info("Scheduler Triggered: Daily scans job starting.")
    add_log_entry("INFO", "Scheduler Triggered: Daily scans job starting.")
    
    # Import scanning runner dynamically to avoid circular dependencies
    from scanners.scan_runner import start_scan_for_target
    
    targets = get_targets()
    enabled_targets = [t for t in targets if t["status"] == "Enabled"]
    
    if not enabled_targets:
        logger.info("No enabled target URLs found for scanning.")
        add_log_entry("INFO", "Scheduler: No enabled targets found for scanning.")
        return
        
    for target in enabled_targets:
        try:
            logger.info(f"Scheduler: Launching scan for target: {target['url']}")
            # Start scan in a background task/thread (we will implement this in scan_runner.py)
            start_scan_for_target(target)
        except Exception as e:
            logger.error(f"Scheduler failed to launch scan for {target['url']}: {e}")
            add_log_entry("ERROR", f"Scheduler failed to launch scan for {target['url']}: {e}")

def _wait_for_db_ready(max_retries: int = 3, wait_seconds: int = 5) -> bool:
    """
    V9.3.3 P0 Fix — Wait for the DB to be decrypted and accessible.
    Returns True when DB is ready, False if all retries exhausted.
    This ensures CVE sync never starts before the DB is available,
    which was the root cause of all-data-lost-on-reopen bugs.
    """
    import time
    from tools.encryption_manager import is_decryption_ok
    for attempt in range(1, max_retries + 1):
        try:
            if is_decryption_ok():
                # Verify DB is actually accessible
                from tools.db_manager import get_cve_db_connection
                conn = get_cve_db_connection()
                conn.execute("SELECT 1 FROM cves LIMIT 1")
                logger.info(f"[Scheduler] DB ready check passed (attempt {attempt})")
                return True
        except Exception as e:
            logger.warning(f"[Scheduler] DB not ready yet (attempt {attempt}/{max_retries}): {e}")
        if attempt < max_retries:
            logger.info(f"[Scheduler] Retrying DB check in {wait_seconds}s...")
            time.sleep(wait_seconds)
            wait_seconds *= 2  # Exponential backoff
    logger.error("[Scheduler] DB never became ready. Intel sync skipped this cycle.")
    return False


def trigger_intel_job():
    """Hourly threat intelligence feed update job — V9.4.2: waits for DB to be ready."""
    logger.info("Scheduler Triggered: Threat intelligence update starting.")
    add_log_entry("INFO", "Scheduler Triggered: Threat intelligence update starting.")

    # ── V9.3.3 P0 FIX: Ensure DB is decrypted before syncing ──────────────────
    if not _wait_for_db_ready(max_retries=3, wait_seconds=5):
        add_log_entry("WARNING", "Intel sync skipped: DB not ready (still encrypting/decrypting).")
        return

    # Import update functions dynamically
    from intelligence.nvd import sync_nvd
    from intelligence.cisa import sync_cisa
    from intelligence.github_adv import sync_github_adv
    from intelligence.epss import sync_epss

    success = True

    try:
        sync_nvd()
    except Exception as e:
        logger.error(f"NVD sync failed: {e}")
        success = False

    try:
        sync_cisa()
    except Exception as e:
        logger.error(f"CISA sync failed: {e}")
        success = False

    try:
        sync_github_adv()
    except Exception as e:
        logger.error(f"GitHub Advisories sync failed: {e}")
        success = False

    try:
        sync_epss()
    except Exception as e:
        logger.error(f"EPSS sync failed: {e}")
        success = False

    if success:
        logger.info("CVE Feed Synced successfully.")
        add_log_entry("INFO", "CVE Feed Synced")
    else:
        logger.warning("Threat Intel sync completed with errors.")
        add_log_entry("WARNING", "Update Failed: Threat Intel sync completed with errors")


def trigger_db_purge_job():
    """Weekly job: purge ZIP backup snapshots older than 30 days."""
    try:
        deleted = purge_old_backup_snapshots(days=30)
        logger.info(f"[DB Purge] Weekly snapshot cleanup: {deleted} archive(s) removed.")
        add_log_entry("INFO", f"DB Purge: {deleted} old backup snapshot(s) removed.")
    except Exception as e:
        logger.error(f"DB Purge job failed: {e}")


def trigger_watchdog_job():
    """Every-15-minute job: lightweight continuous monitoring checks."""
    try:
        run_watchdog()
    except Exception as e:
        logger.error(f"Watchdog job failed: {e}")

def trigger_nuclei_update_job():
    """Weekly job: auto-update nuclei templates."""
    try:
        import subprocess
        logger.info("[Nuclei Update] Starting nuclei template auto-update...")
        subprocess.run(["nuclei", "-update-templates"], capture_output=True, text=True, timeout=120)
        logger.info("[Nuclei Update] Templates updated successfully.")
        add_log_entry("INFO", "Nuclei Update: Templates updated successfully.")
    except Exception as e:
        logger.error(f"[Nuclei Update] Job failed: {e}")
        add_log_entry("ERROR", f"Nuclei Update failed: {e}")

def start_scheduler():
    """Initialize and start the background scheduler."""
    global _scheduler
    if _scheduler is not None:
        return
        
    settings = load_settings()
    _scheduler = BackgroundScheduler()
    
    # Schedule Daily Scan Job
    cron_trigger = CronTrigger(
        hour=settings.get("scan_schedule_hour", 2),
        minute=settings.get("scan_schedule_minute", 0)
    )
    _scheduler.add_job(
        trigger_scan_job,
        trigger=cron_trigger,
        id="daily_scan_job",
        replace_existing=True
    )
    
    # Schedule Daily Threat Intel Sync Job
    interval_trigger = IntervalTrigger(
        hours=settings.get("intel_sync_interval_hours", 24)
    )
    _scheduler.add_job(
        trigger_intel_job,
        trigger=interval_trigger,
        id="hourly_intel_sync_job",
        replace_existing=True
    )

    # Schedule Daily Backup Job
    backup_trigger = IntervalTrigger(
        hours=24
    )
    _scheduler.add_job(
        trigger_scheduled_system_backup_sequence,
        trigger=backup_trigger,
        id="daily_backup_job",
        replace_existing=True
    )

    # Schedule Weekly DB Snapshot Purge Job
    purge_trigger = IntervalTrigger(hours=168)  # 7 days
    _scheduler.add_job(
        trigger_db_purge_job,
        trigger=purge_trigger,
        id="weekly_db_purge_job",
        replace_existing=True
    )

    # ── V9.3.3 — Schedule Weekly Nuclei Templates Update Job ──────────────
    nuclei_update_trigger = IntervalTrigger(hours=168)
    _scheduler.add_job(
        trigger_nuclei_update_job,
        trigger=nuclei_update_trigger,
        id="weekly_nuclei_update_job",
        replace_existing=True
    )

    # ── V9.3.3 — Schedule Daily GC for Soft-Deleted Targets ──────────────
    gc_trigger = IntervalTrigger(hours=24)
    _scheduler.add_job(
        trigger_soft_delete_gc_job,
        trigger=gc_trigger,
        id="daily_soft_delete_gc_job",
        replace_existing=True
    )

    # Schedule Watchdog Continuous Monitoring (every 2 hours)
    watchdog_trigger = IntervalTrigger(hours=2)
    _scheduler.add_job(
        trigger_watchdog_job,
        trigger=watchdog_trigger,
        id="watchdog_monitor_job",
        replace_existing=True
    )

    _scheduler.start()
    logger.info("Scheduler started successfully.")
    add_log_entry("INFO", "Scheduler Triggered: Scheduler system started.")

def shutdown_scheduler():
    """Stop the scheduler."""
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Scheduler shutdown.")
        add_log_entry("INFO", "Scheduler system stopped.")

def reschedule_jobs():
    """Apply updated settings to the scheduler jobs."""
    global _scheduler
    if not _scheduler:
        return
        
    settings = load_settings()
    
    try:
        # Reschedule Daily Scan
        cron_trigger = CronTrigger(
            hour=settings.get("scan_schedule_hour", 2),
            minute=settings.get("scan_schedule_minute", 0)
        )
        _scheduler.reschedule_job("daily_scan_job", trigger=cron_trigger)
        
        # Reschedule Intel Sync
        interval_trigger = IntervalTrigger(
            hours=settings.get("intel_sync_interval_hours", 24)
        )
        _scheduler.reschedule_job("hourly_intel_sync_job", trigger=interval_trigger)

        # Reschedule Daily Backup
        backup_trigger = IntervalTrigger(hours=24)
        _scheduler.reschedule_job("daily_backup_job", trigger=backup_trigger)

        # Reschedule Weekly DB Purge
        purge_trigger = IntervalTrigger(hours=168)
        _scheduler.reschedule_job("weekly_db_purge_job", trigger=purge_trigger)

        # Reschedule Weekly Nuclei Update
        nuclei_trigger = IntervalTrigger(hours=168)
        _scheduler.reschedule_job("weekly_nuclei_update_job", trigger=nuclei_trigger)

        # Reschedule Watchdog
        watchdog_trigger = IntervalTrigger(hours=2)
        _scheduler.reschedule_job("watchdog_monitor_job", trigger=watchdog_trigger)

        logger.info("Scheduler jobs rescheduled successfully.")
        add_log_entry("INFO", "Scheduler Triggered: Jobs rescheduled.")
    except Exception as e:
        logger.error(f"Failed to reschedule jobs: {e}")
        add_log_entry("ERROR", f"Scheduler reconfiguration failed: {e}")
