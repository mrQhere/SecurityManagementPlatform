"""
Session Manager V9.3.1
====================
Tracks user activity and fires an auto-lock signal after a configurable
idle timeout. Designed to work with the PySide6 dashboard without requiring
a full restart — the password dialog is re-shown and the user can resume.

Usage:
    from tools.session_manager import SessionManager
    sm = SessionManager(timeout_minutes=15, on_lock=dashboard.trigger_lock)
    sm.start()
    sm.reset()   # call on any user interaction
    sm.stop()    # call on app quit
"""
import threading
import logging
from datetime import datetime, timedelta

logger = logging.getLogger("smp")


class SessionManager:
    """
    Idle session timeout with re-lock callback.
    
    The timer resets on every call to `reset()`. If no reset occurs
    within `timeout_minutes`, the `on_lock` callback is invoked from
    a background thread (caller must ensure Qt thread-safety).
    """

    def __init__(self, timeout_minutes: int = 15, on_lock=None):
        self.timeout_minutes = timeout_minutes
        self.on_lock = on_lock
        self._lock = threading.Lock()
        self._last_activity = datetime.now()
        self._timer: threading.Timer = None
        self._stopped = False
        self._locked = False

    def start(self):
        """Start the idle timer."""
        self._stopped = False
        self._locked = False
        self._schedule()
        logger.info(f"[SessionManager] Started — idle timeout: {self.timeout_minutes} min")

    def stop(self):
        """Stop the session manager (call on app quit)."""
        self._stopped = True
        if self._timer:
            self._timer.cancel()
        logger.info("[SessionManager] Stopped.")

    def reset(self):
        """Reset the idle timer — call this on any user interaction."""
        if self._stopped:
            return
        with self._lock:
            self._last_activity = datetime.now()
            self._locked = False
        self._reschedule()

    def unlock(self):
        """Called after successful password re-entry to resume session."""
        with self._lock:
            self._locked = False
            self._last_activity = datetime.now()
        self._reschedule()
        logger.info("[SessionManager] Session unlocked by user.")

    def is_locked(self) -> bool:
        return self._locked

    def _check_idle(self):
        """Check if the session has been idle for too long."""
        if self._stopped:
            return
        with self._lock:
            elapsed = (datetime.now() - self._last_activity).total_seconds() / 60
            if elapsed >= self.timeout_minutes and not self._locked:
                self._locked = True
                logger.info(f"[SessionManager] Idle timeout reached ({elapsed:.1f} min). Locking session.")
                if self.on_lock:
                    try:
                        self.on_lock()
                    except Exception as e:
                        logger.error(f"[SessionManager] Lock callback error: {e}")
                return
        # Not yet idle — reschedule
        self._schedule()

    def _schedule(self):
        """Schedule the next idle check."""
        if self._stopped:
            return
        # Check every 60 seconds
        self._timer = threading.Timer(60.0, self._check_idle)
        self._timer.daemon = True
        self._timer.start()

    def _reschedule(self):
        """Cancel current timer and schedule fresh."""
        if self._timer:
            self._timer.cancel()
        self._schedule()


# Global singleton — set up by dashboard on startup
_SESSION: SessionManager = None


def get_session() -> SessionManager:
    return _SESSION


def init_session(timeout_minutes: int = 15, on_lock=None) -> SessionManager:
    """Initialize the global session manager."""
    global _SESSION
    if _SESSION:
        _SESSION.stop()
    _SESSION = SessionManager(timeout_minutes=timeout_minutes, on_lock=on_lock)
    _SESSION.start()
    return _SESSION


def reset_session():
    """Reset idle timer — call on any user interaction."""
    if _SESSION:
        _SESSION.reset()
