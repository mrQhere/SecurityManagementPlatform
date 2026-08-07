import os
import logging
import threading
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QListWidget, QListWidgetItem, QTextEdit, QMessageBox, QGroupBox,
    QSplitter, QFrame, QStackedWidget, QFormLayout, QCheckBox, QComboBox,
    QScrollArea, QSizePolicy, QSpacerItem
)
from PySide6.QtCore import Qt, QTimer, QSize, QPropertyAnimation, QEasingCurve, QThread, Signal
from PySide6.QtGui import QFont, QColor, QBrush, QPalette, QFontDatabase, QTextCursor
import hashlib

class WorkerThread(QThread):
    finished_signal = Signal(object)

    def __init__(self, target_func, *args, **kwargs):
        super().__init__()
        self.target_func = target_func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            res = self.target_func(*self.args, **self.kwargs)
            self.finished_signal.emit((True, res))
        except Exception as e:
            self.finished_signal.emit((False, e))

from tools.db_manager import (
    get_targets, add_target, delete_target, set_target_status,
    get_active_scans, get_cves, get_cve_stats, get_log_entries
)
from tools.config_manager import load_settings, save_settings

logger = logging.getLogger("smp")


# ─── Helper DB Helpers ────────────────────────────────────────────────────────

def get_latest_risk_score_for_target(target_id):
    from tools.db_manager import get_db_connection
    conn = get_db_connection()
    try:
        row = conn.execute("""
            SELECT rs.score, rs.rating FROM risk_scores rs
            JOIN scans s ON rs.scan_id = s.id
            WHERE s.target_id = ?
            ORDER BY s.id DESC LIMIT 1
        """, (target_id,)).fetchone()
        return dict(row) if row else None
    except Exception:
        return None
    finally:
        conn.close()


def get_latest_scan_operator_for_target(target_id):
    from tools.db_manager import get_db_connection
    conn = get_db_connection()
    try:
        row = conn.execute("""
            SELECT s.scanned_by FROM scans s
            WHERE s.target_id = ?
            ORDER BY s.id DESC LIMIT 1
        """, (target_id,)).fetchone()
        return row["scanned_by"] if (row and row["scanned_by"]) else "N/A"
    except Exception:
        return "N/A"
    finally:
        conn.close()


# ─── Apple-Style Stylesheet ───────────────────────────────────────────────────




from ui.views.dashboard_layout import DashboardLayoutMixin
from ui.controllers.dashboard_logic import DashboardLogicMixin
from ui.theme import apply_theme

class DashboardWindow(QMainWindow, DashboardLayoutMixin, DashboardLogicMixin):
    # ─── Init ──────────────────────────────────────────────────────────────────

    def __init__(self):
        super().__init__()
        import json
        version = "V9.3.3"
        try:
            metadata_path = os.path.join(os.path.dirname(__file__), "..", "config", "metadata.json")
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                version = metadata.get("version", "V9.3.3")
        except Exception:
            pass
        self.setWindowTitle(f"Security Management Platform • {version}")
        self.version = version
        # The stylesheet is now applied globally via main.py applying style.qss
        # Set window dimensions
        self.setMinimumSize(900, 600)
        self.resize(1400, 860)

        self._cache_kpis = None
        self._cache_targets_hash = None
        self._cache_scans_hash = None
        self._cache_intel_hash = None
        self._cache_updates_hash = None
        self._cache_log_mtime = None
        self._cache_cve_log_mtime = None
        self._cache_scan_log_mtime = None
        self._cache_error_log_mtime = None

        apply_theme(self)
        self._setup_ui()
        
        # ── V9.3.3 — Restore Splitter States ──
        try:
            from tools.config_manager import load_settings
            import base64
            from PySide6.QtCore import QByteArray
            s = load_settings()
            if hasattr(self, 'dashboard_splitter') and 'dashboard_splitter' in s:
                self.dashboard_splitter.restoreState(QByteArray(base64.b64decode(s['dashboard_splitter'])))
            if hasattr(self, 'targets_splitter') and 'targets_splitter' in s:
                self.targets_splitter.restoreState(QByteArray(base64.b64decode(s['targets_splitter'])))
        except Exception:
            pass

        self.load_smtp_fields()

        # Phase 6 IPC Integration: Replace SQLite polling timer with real-time UDP pipe
        from ui.controllers.dashboard_logic import UDPListenerThread
        self.ipc_listener = UDPListenerThread(self)
        self.ipc_listener.event_received.connect(self._on_ipc_event)
        self.ipc_listener.start()

        # Safety fallback polling timer (coexists with UDP IPC to ensure UI updates never fail if UDP gets dropped)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll_updates)
        self.timer.start(3000)

        self.poll_updates()
        logger.info("Program Started")

    # ─── Graceful Close ────────────────────────────────────────────────────────

    def closeEvent(self, event):
        """
        Override Qt close event (X button, Alt+F4, window manager close).
        Shows a confirmation dialog, handles running scans gracefully, then
        performs a safe shutdown with visual feedback before the window hides.
        """
        from PySide6.QtWidgets import QDialog
        from PySide6.QtCore import QTimer
        from tools.db_manager import update_scan_status

        active = get_active_scans()
        n_active = len(active)

        # ── Confirmation dialog ────────────────────────────────────────────────
        dlg = QMessageBox(self)
        dlg.setWindowTitle("Close Security Management Platform")

        if n_active > 0:
            dlg.setIcon(QMessageBox.Warning)
            scan_word = "scans are" if n_active > 1 else "scan is"
            dlg.setText(
                f"<b>\u26a0\ufe0f  {n_active} {scan_word} currently running.</b>"
            )
            dlg.setInformativeText(
                "Closing now will pause the active scan(s).\n"
                "All data collected so far is safely stored in the database\n"
                "and the redundancy backup will be preserved.\n\n"
                "The scan(s) can be resumed next time you open SMP.\n\n"
                "Do you want to close?"
            )
        else:
            dlg.setIcon(QMessageBox.Question)
            dlg.setText("<b>Close Security Management Platform?</b>")
            dlg.setInformativeText(
                "All databases will be safely saved and encrypted before closing."
            )

        dlg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        dlg.setDefaultButton(QMessageBox.No)
        dlg.button(QMessageBox.Yes).setText("  Close SMP  ")
        dlg.button(QMessageBox.No).setText("  Keep Open  ")

        if dlg.exec() == QMessageBox.No:
            event.ignore()
            return

        # ── Accepted — begin graceful shutdown ─────────────────────────────────
        event.accept()

        # 1. Signal scan_runner to NOT wipe the redundancy DB when scan threads die
        try:
            import scanners.scan_runner as _sr
            _sr.signal_app_shutdown()
        except Exception:
            pass

        # ── V9.3.3 — Save Splitter States ──
        try:
            from tools.config_manager import load_settings, save_settings
            import base64
            s = load_settings()
            if hasattr(self, 'dashboard_splitter'):
                s['dashboard_splitter'] = base64.b64encode(self.dashboard_splitter.saveState().data()).decode('utf-8')
            if hasattr(self, 'targets_splitter'):
                s['targets_splitter'] = base64.b64encode(self.targets_splitter.saveState().data()).decode('utf-8')
            save_settings(s)
        except Exception:
            pass

        # 2. Stop UI timers so no further DB reads race with shutdown
        try:
            self.timer.stop()
        except Exception:
            pass
        # Cleanly stop the IPC UDP listener thread
        try:
            self.ipc_listener.stop()
            self.ipc_listener.wait(1000)  # wait up to 1 second
        except Exception:
            pass

        # 3. Mark in-flight scans as "Paused" (recoverable) instead of "Failed"
        if n_active > 0:
            for scan in active:
                try:
                    update_scan_status(scan.get("scan_id", scan.get("id")), "Paused")
                except Exception:
                    pass

        # 4. Brief "Closing safely…" overlay so the user sees feedback
        from PySide6.QtWidgets import QApplication as _App
        closing = QDialog(None, Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        closing.setAttribute(Qt.WA_TranslucentBackground)
        closing.setFixedSize(360, 120)

        card = QLabel(closing)
        card.setFixedSize(360, 120)
        card.setAlignment(Qt.AlignCenter)
        card.setStyleSheet(
            "background: #111111; border: 1px solid #2A2A2A; border-radius: 14px;"
        )
        inner = QVBoxLayout(card)
        inner.setSpacing(8)
        inner.setContentsMargins(28, 20, 28, 20)

        lbl_title = QLabel("🔐  Closing SMP Safely…")
        lbl_title.setAlignment(Qt.AlignCenter)
        lbl_title.setStyleSheet(
            "color: #DDDDDD; font-size: 14px; font-weight: 700; background: transparent;"
        )
        lbl_sub = QLabel("Saving databases and encrypting…")
        lbl_sub.setAlignment(Qt.AlignCenter)
        lbl_sub.setStyleSheet(
            "color: #555555; font-size: 11px; background: transparent;"
        )
        inner.addWidget(lbl_title)
        inner.addWidget(lbl_sub)

        screen = _App.primaryScreen().availableGeometry()
        closing.move(
            screen.center().x() - closing.width() // 2,
            screen.center().y() - closing.height() // 2,
        )
        closing.show()
        _App.processEvents()

        # Let the overlay render before Qt proceeds with on_quit / aboutToQuit
        QTimer.singleShot(600, closing.close)
        _App.processEvents()

