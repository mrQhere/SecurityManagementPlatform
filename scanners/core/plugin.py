"""
Scanner Plugin Base Class
=========================
Defines the interface for all scanners in the new DAG-based execution engine.
"""

class ScannerPlugin:
    """Base class for all SMP scanners."""

    # Name of the scanner (e.g., 'WhatWeb')
    name = "BaseScanner"

    # The step name used in the database and UI (e.g., 'Running WhatWeb')
    step_name = "Running BaseScanner"

    # List of scanner names that must complete before this one starts
    depends_on = []

    def __init__(self, target_url, scan_id):
        self.target_url = target_url
        self.scan_id = scan_id

    def execute(self):
        """
        Executes the scanner.
        Must be overridden by subclasses.
        Returns: The raw results of the scan (or None if failed).
        """
        raise NotImplementedError("Scanners must implement the execute method.")

    def process_results(self, raw_results):
        """
        Processes raw results and saves them to the database.
        Must be overridden by subclasses.
        """
        raise NotImplementedError("Scanners must implement the process_results method.")


class GenericPlugin(ScannerPlugin):
    """A generic wrapper to adapt existing scanner functions into the DAG framework."""
    def __init__(self, target_url, scan_id, name, step_name, depends_on, scan_func, binary_name, process_func, needs_binary=True, precondition=None, resume_status=None, brain_insights=None, engagement_id=None, auth_id=None, scan_policy=None, cancel_event=None):
        super().__init__(target_url, scan_id)
        self.name = name
        self.step_name = step_name
        self.depends_on = depends_on
        self.scan_func = scan_func
        self.binary_name = binary_name
        self.process_func = process_func
        self.needs_binary = needs_binary
        self.precondition = precondition
        self.resume_status = resume_status
        self.brain_insights = brain_insights
        self.engagement_id = engagement_id
        self.auth_id = auth_id
        self.scan_policy = scan_policy
        self.cancel_event = cancel_event

    def execute(self, cancel_event=None):
        from scanners.scan_runner import run_with_resilience, _log_raw, _should_run_step
        import scanners.scan_runner as sr
        from tools.db_manager import update_scan_status, add_log_entry
        import logging
        logger = logging.getLogger("smp.scan")
        
        effective_cancel = cancel_event if cancel_event is not None else self.cancel_event

        # ── V9.5.10 Server-side execution gate check ──────────────────────────
        from core.execution_gate import verify_scan_execution
        allowed, reason = verify_scan_execution(
            target=self.target_url,
            scanner_name=self.name,
            engagement_id=self.engagement_id,
            auth_id=self.auth_id,
            scan_policy=self.scan_policy,
            cancel_event=effective_cancel,
        )
        if not allowed:
            logger.warning(f"{self.name} BLOCKED by execution gate: {reason}")
            try:
                add_log_entry("WARNING", f"{self.name} blocked for {self.target_url}: {reason}")
            except Exception:
                pass
            return []

        # Check if this scanner is allowed under the current scan profile and resume status
        if not _should_run_step(self.step_name, self.resume_status):
            logger.info(f"{self.name} SKIPPED by scan profile or resume status.")
            return []

        if self.precondition and not self.precondition():
            logger.warning(f"{self.name} SKIPPED — Precondition failed.")
            add_log_entry("WARNING", f"{self.name} skipped for {self.target_url}: Precondition failed.")
            return []

        # Route through scan_runner module namespace to respect unit test patches
        func_to_run = getattr(sr, self.scan_func.__name__, self.scan_func)

        res, success = run_with_resilience(
            self.scan_id,
            self.step_name,
            func_to_run,
            self.target_url,
            self.binary_name,
            self.needs_binary,
            attempt=1,
            brain_insights=self.brain_insights,
            cancel_event=effective_cancel,
            engagement_id=self.engagement_id,
            auth_id=self.auth_id,
            scan_policy=self.scan_policy,
        )
        if success:
            _log_raw(self.scan_id, self.name, res)
            return res
        return None

    def process_results(self, raw_results):
        if self.process_func:
            self.process_func(raw_results)
