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

APPLE_STYLESHEET = """
/* ── Root ── */
QMainWindow, QWidget {
    background-color: #0D0D0D;
    color: #E8E8E8;
    font-family: -apple-system, "SF Pro Text", "Helvetica Neue", Arial, sans-serif;
    font-size: 14px;
    border: none;
    outline: none;
}

/* ── Sidebar ── */
QFrame#sidebar {
    background-color: #111111;
    border-right: 1px solid #222222;
}

QLabel#brand_label {
    color: #FFFFFF;
    font-size: 16px;
    font-weight: 700;
    letter-spacing: 0.5px;
    padding: 0px 20px;
}

QLabel#brand_sub {
    color: #555555;
    font-size: 10px;
    letter-spacing: 1.5px;
    padding: 0px 20px 16px 20px;
}

QPushButton#nav_btn {
    background-color: transparent;
    color: #888888;
    border: none;
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 13px;
    font-weight: 500;
    text-align: left;
}
QPushButton#nav_btn:hover {
    background-color: #1A1A1A;
    color: #CCCCCC;
}
QPushButton#nav_btn[active="true"] {
    background-color: #1E1E1E;
    color: #FFFFFF;
    font-weight: 600;
    border-left: 2px solid #FFFFFF;
}

/* ── Content Area ── */
QFrame#content_area {
    background-color: #0D0D0D;
}

/* ── Page Title ── */
QLabel#page_title {
    color: #FFFFFF;
    font-size: 24px;
    font-weight: 700;
    letter-spacing: -0.3px;
    padding: 4px 0px;
}
QLabel#page_subtitle {
    color: #555555;
    font-size: 12px;
    padding: 0px 0px 8px 0px;
    letter-spacing: 0.2px;
}

/* ── Cards ── */
QFrame#card {
    background-color: #141414;
    border: 1px solid #222222;
    border-radius: 10px;
}
QFrame#card_highlight {
    background-color: #141414;
    border: 1px solid #444444;
    border-radius: 10px;
}
QFrame#kpi_card {
    background-color: #141414;
    border: 1px solid #222222;
    border-radius: 10px;
}

/* ── Group Boxes ── */
QGroupBox {
    background-color: #141414;
    border: 1px solid #222222;
    border-radius: 10px;
    margin-top: 20px;
    padding: 20px 16px 16px 16px;
    font-size: 13px;
    font-weight: 600;
    color: #AAAAAA;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 16px;
    top: 8px;
    padding: 0 8px;
    color: #888888;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
}

/* ── Buttons ── */
QPushButton {
    background-color: #1E1E1E;
    color: #DDDDDD;
    border: 1px solid #333333;
    border-radius: 6px;
    padding: 8px 16px;
    font-size: 13px;
    font-weight: 500;
    min-height: 20px;
}
QPushButton:hover {
    background-color: #282828;
    border-color: #444444;
    color: #FFFFFF;
}
QPushButton:pressed {
    background-color: #111111;
}
QPushButton:disabled {
    background-color: #161616;
    color: #333333;
    border-color: #222222;
}
QPushButton#btn_secondary {
    background-color: transparent;
    color: #888888;
    border: 1px solid #2A2A2A;
}
QPushButton#btn_secondary:hover {
    background-color: #1A1A1A;
    color: #CCCCCC;
    border-color: #333333;
}
QPushButton#btn_danger {
    background-color: #2A0D0D;
    color: #FF6B6B;
    border: 1px solid #3D1515;
}
QPushButton#btn_danger:hover {
    background-color: #3D1515;
    color: #FF4444;
}
QPushButton#btn_success {
    background-color: #0D2A15;
    color: #5ADB7E;
    border: 1px solid #153D22;
}
QPushButton#btn_success:hover {
    background-color: #153D22;
    color: #44FF77;
}
QPushButton#btn_warning {
    background-color: #2A1D00;
    color: #FFAA44;
    border: 1px solid #3D2B00;
}
QPushButton#btn_small {
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 11px;
    min-height: 14px;
}

/* ── Inputs ── */
QLineEdit {
    background-color: #111111;
    border: 1px solid #2A2A2A;
    border-radius: 6px;
    padding: 8px 12px;
    color: #E0E0E0;
    font-size: 13px;
    selection-background-color: #444444;
}
QLineEdit:focus {
    border: 1px solid #555555;
    background-color: #161616;
}
QLineEdit::placeholder {
    color: #333333;
}

QComboBox {
    background-color: #111111;
    border: 1px solid #2A2A2A;
    border-radius: 6px;
    padding: 8px 12px;
    color: #E0E0E0;
    font-size: 13px;
    min-width: 120px;
}
QComboBox:focus {
    border: 1px solid #555555;
}
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QComboBox QAbstractItemView {
    background-color: #141414;
    border: 1px solid #2A2A2A;
    border-radius: 6px;
    selection-background-color: #2A2A2A;
    selection-color: #FFFFFF;
    padding: 4px;
    color: #E0E0E0;
}

QCheckBox {
    color: #AAAAAA;
    font-size: 13px;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid #333333;
    background-color: #111111;
}
QCheckBox::indicator:checked {
    background-color: #444444;
    border-color: #666666;
}

/* ── Tables ── */
QTableWidget {
    background-color: #111111;
    border: 1px solid #222222;
    border-radius: 8px;
    gridline-color: #1A1A1A;
    selection-background-color: #222222;
    selection-color: #FFFFFF;
    alternate-background-color: #131313;
    font-size: 13px;
    color: #CCCCCC;
}
QTableWidget::item {
    padding: 6px 10px;
    border: none;
}
QTableWidget::item:selected {
    background-color: #222222;
    color: #FFFFFF;
}
QHeaderView {
    background-color: transparent;
}
QHeaderView::section {
    background-color: #0D0D0D;
    color: #555555;
    padding: 10px 10px;
    border: none;
    border-bottom: 1px solid #1E1E1E;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
}
QHeaderView::section:first {
    border-top-left-radius: 7px;
}
QHeaderView::section:last {
    border-top-right-radius: 7px;
}

/* ── Lists ── */
QListWidget {
    background-color: #111111;
    border: 1px solid #222222;
    border-radius: 8px;
    padding: 4px;
    font-size: 13px;
    color: #CCCCCC;
}
QListWidget::item {
    padding: 9px 12px;
    border-radius: 4px;
    border-bottom: 1px solid #1A1A1A;
    color: #CCCCCC;
}
QListWidget::item:last {
    border-bottom: none;
}
QListWidget::item:hover {
    background-color: #1A1A1A;
}
QListWidget::item:selected {
    background-color: #222222;
    color: #FFFFFF;
}

/* ── Text Areas ── */
QTextEdit {
    background-color: #0A0A0A;
    border: 1px solid #1E1E1E;
    border-radius: 8px;
    font-family: "Menlo", "Monaco", "Courier New", monospace;
    font-size: 12px;
    color: #CCCCCC;
    padding: 14px;
    line-height: 1.6;
    selection-background-color: #333333;
}

/* ── Scroll Bars ── */
QScrollBar:vertical {
    border: none;
    background: transparent;
    width: 6px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #2A2A2A;
    min-height: 32px;
    border-radius: 3px;
}
QScrollBar::handle:vertical:hover {
    background: #383838;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    border: none;
    background: transparent;
    height: 6px;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background: #2A2A2A;
    min-width: 32px;
    border-radius: 3px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ── Splitter ── */
QSplitter::handle {
    background: #1E1E1E;
    width: 1px;
    height: 1px;
}

/* ── Form Layout Labels ── */
QLabel#form_label {
    color: #888888;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.8px;
    text-transform: uppercase;
}

/* ── All labels default ── */
QLabel {
    color: #CCCCCC;
    background: transparent;
}

/* ── Small buttons ── */
QPushButton#btn_small {
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 11px;
    min-height: 14px;
    background-color: #1A1A1A;
    color: #AAAAAA;
    border: 1px solid #2A2A2A;
}
QPushButton#btn_small:hover {
    background-color: #222222;
    color: #DDDDDD;
}

/* ── Status Badges ── */
QLabel#badge_green {
    color: #5ADB7E;
    background-color: #0D2018;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}
QLabel#badge_red {
    color: #FF6B6B;
    background-color: #2A0D0D;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}
QLabel#badge_orange {
    color: #FFAA44;
    background-color: #2A1800;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}
QLabel#badge_blue {
    color: #88BBFF;
    background-color: #0D1A2A;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}
QLabel#badge_gray {
    color: #888888;
    background-color: #1A1A1A;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}

/* ── Divider ── */
QFrame#divider {
    background-color: #1E1E1E;
    max-height: 1px;
    min-height: 1px;
}

/* ── Message Box ── */
QMessageBox {
    background-color: #141414;
    color: #CCCCCC;
}
QMessageBox QLabel {
    color: #CCCCCC;
}
"""


from ui.views.dashboard_layout import DashboardLayoutMixin
from ui.controllers.dashboard_logic import DashboardLogicMixin

class DashboardWindow(QMainWindow, DashboardLayoutMixin, DashboardLogicMixin):
    # ─── Init ──────────────────────────────────────────────────────────────────

    def __init__(self):
        super().__init__()
        import json
        import os
        version = "V7.0"
        try:
            metadata_path = os.path.join(os.path.dirname(__file__), "..", "config", "metadata.json")
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                version = metadata.get("version", "V7.0")
        except Exception:
            pass
        self.setWindowTitle(f"Security Management Platform • {version}")
        self.version = version
        self.setStyleSheet(APPLE_STYLESHEET)
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

        self._setup_ui()
        
        # ── V7.0 — Restore Splitter States ──
        try:
            from tools.config_manager import load_settings
            import base64
            from PySide6.QtCore import QByteArray
            s = load_settings()
            if hasattr(self, 'dashboard_splitter') and 'dashboard_splitter' in s:
                self.dashboard_splitter.restoreState(QByteArray(base64.b64decode(s['dashboard_splitter'])))
            if hasattr(self, 'targets_splitter') and 'targets_splitter' in s:
                self.targets_splitter.restoreState(QByteArray(base64.b64decode(s['targets_splitter'])))
        except Exception as e:
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
        from PySide6.QtWidgets import QMessageBox, QDialog, QVBoxLayout, QLabel
        from PySide6.QtCore import Qt, QTimer
        from tools.db_manager import get_active_scans, update_scan_status

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

        # ── V7.0 — Save Splitter States ──
        try:
            from tools.config_manager import load_settings, save_settings
            import base64
            s = load_settings()
            if hasattr(self, 'dashboard_splitter'):
                s['dashboard_splitter'] = base64.b64encode(self.dashboard_splitter.saveState().data()).decode('utf-8')
            if hasattr(self, 'targets_splitter'):
                s['targets_splitter'] = base64.b64encode(self.targets_splitter.saveState().data()).decode('utf-8')
            save_settings(s)
        except Exception as e:
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

