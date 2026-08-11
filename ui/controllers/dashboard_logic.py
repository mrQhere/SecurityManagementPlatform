import os
import socket
import json
import logging
import threading
from datetime import datetime

from PySide6.QtCharts import QPieSeries
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QListWidget, QListWidgetItem, QTextEdit, QMessageBox, QGroupBox,
    QSplitter, QFrame, QStackedWidget, QFormLayout, QCheckBox, QComboBox,
    QScrollArea, QSizePolicy, QSpacerItem
)
from PySide6.QtCore import Qt, QTimer, QSize, QThread, Signal
from PySide6.QtGui import QFont, QColor, QBrush, QTextCursor
from PySide6.QtWidgets import QProgressBar
import hashlib

from ui.utils import WorkerThread

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
    except Exception as e:
        from tools.errors import SMPUnclassifiedError
        import traceback
        import logging
        logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
        raise SMPUnclassifiedError(str(e))
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
    except Exception as e:
        from tools.errors import SMPUnclassifiedError
        import traceback
        import logging
        logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
        raise SMPUnclassifiedError(str(e))
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






class UDPListenerThread(QThread):
    """Listens for real-time IPC events from the scan pipeline via UDP.
    Uses SO_REUSEADDR so restarts don't fail with 'address already in use'.
    """
    event_received = Signal(str, dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True
        self._sock = None

    def stop(self):
        """Signal the thread to stop and unblock the socket."""
        self._running = False
        try:
            # Send a dummy packet to wake up recvfrom so the loop exits
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b'{}', ("127.0.0.1", 5005))
            s.close()
        except Exception as e:
            from tools.errors import SMPUnclassifiedError
            import traceback
            import logging
            logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
            raise SMPUnclassifiedError(str(e))
            pass
        if self._sock:
            try:
                self._sock.close()
            except Exception as e:
                from tools.errors import SMPUnclassifiedError
                import traceback
                import logging
                logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
                raise SMPUnclassifiedError(str(e))
                pass

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)  # 1-second timeout so stop() wakes the loop
            sock.bind(("127.0.0.1", 5005))
            self._sock = sock
        except OSError as e:
            import logging
            logging.getLogger("smp").warning(f"IPC listener could not bind to port 5005: {e}")
            return

        while self._running:
            try:
                data, _ = sock.recvfrom(4096)
                if not data or not self._running:
                    continue
                msg = json.loads(data.decode("utf-8", errors="replace"))
                event_type = msg.get("type") or ""
                event_data = msg.get("data") or {}
                if event_type:  # ignore empty/dummy stop packets
                    self.event_received.emit(event_type, event_data)
            except socket.timeout:
                continue  # expected — just loops and checks _running
            except OSError:
                break  # socket was closed
            except Exception as e:
                from tools.errors import SMPUnclassifiedError
                import traceback
                import logging
                logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
                raise SMPUnclassifiedError(str(e))
                pass

        try:
            sock.close()
        except Exception as e:
            from tools.errors import SMPUnclassifiedError
            import traceback
            import logging
            logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
            raise SMPUnclassifiedError(str(e))
            pass

class DashboardLogicMixin:
    # ─── Logic Helpers ─────────────────────────────────────────────────────────

    def _save_auth_headers(self):
        """Save custom auth headers from the settings table to settings.json."""
        headers = {}
        for row in range(self.tbl_auth_headers.rowCount()):
            key_item = self.tbl_auth_headers.item(row, 0)
            val_item = self.tbl_auth_headers.item(row, 1)
            if key_item and val_item:
                key = key_item.text().strip()
                val = val_item.text().strip()
                if key:
                    headers[key] = val
        s = load_settings()
        s["auth_headers"] = headers
        save_settings(s)
        QMessageBox.information(self, "Saved", f"{len(headers)} authentication header(s) saved.")

    def toggle_password_visibility(self):

        if self.btn_show_pass.isChecked():
            self.txt_smtp_pass.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_show_pass.setText("Hide")
        else:
            self.txt_smtp_pass.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_show_pass.setText("Show")

    def show_cve_detail(self, item):
        description = item.toolTip()
        if description:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Vulnerability Advisory Detail")
            msg_box.setText(item.text())
            msg_box.setInformativeText(description)
            msg_box.setIcon(QMessageBox.Information)
            msg_box.exec()

    def load_smtp_fields(self):
        settings = load_settings()
        self.txt_smtp_host.setText(settings.get("smtp_host", "smtp.gmail.com"))
        self.txt_smtp_port.setText(str(settings.get("smtp_port", 587)))
        self.txt_smtp_user.setText(settings.get("smtp_user", ""))
        self.txt_smtp_pass.setText(settings.get("smtp_pass", ""))
        self.txt_smtp_sender.setText(settings.get("smtp_sender", ""))
        self.txt_smtp_receiver.setText(settings.get("smtp_receiver", ""))
        self.chk_smtp_ssl.setChecked(settings.get("smtp_ssl", False))
        self.txt_tester_name.setText(settings.get("tester_name", "Security Auditor"))
        if hasattr(self, "txt_qa_reviewer"):
            self.txt_qa_reviewer.setText(settings.get("qa_reviewer", "QA Manager"))
        self.txt_report_email.setText(settings.get("report_email", ""))
        self.chk_zap_enabled.setChecked(settings.get("zap_enabled", False))
        # ── V9.4.2 — Load API Keys & Proxies ──
        if hasattr(self, "txt_github_token"):
            self.txt_github_token.setText(settings.get("github_token", ""))
        if hasattr(self, "txt_http_proxy"):
            self.txt_http_proxy.setText(settings.get("http_proxy", ""))
        if hasattr(self, "txt_https_proxy"):
            self.txt_https_proxy.setText(settings.get("https_proxy", ""))

    def save_smtp_settings(self):
        host = self.txt_smtp_host.text().strip()
        port_text = self.txt_smtp_port.text().strip()
        user = self.txt_smtp_user.text().strip()
        pw = self.txt_smtp_pass.text().strip()
        sender = self.txt_smtp_sender.text().strip() or user
        receiver = self.txt_smtp_receiver.text().strip()
        ssl_val = self.chk_smtp_ssl.isChecked()
        tester = self.txt_tester_name.text().strip() or "Security Auditor"
        qa_reviewer = self.txt_qa_reviewer.text().strip() or "QA Manager" if hasattr(self, "txt_qa_reviewer") else "QA Manager"
        report_email = self.txt_report_email.text().strip()

        current_settings = load_settings()
        current_settings["tester_name"] = tester
        current_settings["qa_reviewer"] = qa_reviewer
        current_settings["report_email"] = report_email
        current_settings["zap_enabled"] = self.chk_zap_enabled.isChecked()

        # ── V9.4.2 — Save API Keys & Proxies ──
        if hasattr(self, "txt_github_token"):
            current_settings["github_token"] = self.txt_github_token.text().strip()
        if hasattr(self, "txt_http_proxy"):
            current_settings["http_proxy"] = self.txt_http_proxy.text().strip()
        if hasattr(self, "txt_https_proxy"):
            current_settings["https_proxy"] = self.txt_https_proxy.text().strip()

        smtp_configured = True
        if not host and not port_text and not user and not pw and not receiver:
            smtp_configured = False
        else:
            if not host or not port_text or not user or not pw or not receiver:
                QMessageBox.warning(self, "Missing Settings", "To configure email notifications, all SMTP fields are required.")
                return
            try:
                port = int(port_text)
            except ValueError:
                QMessageBox.warning(self, "Invalid Port", "SMTP Port must be a number.")
                return

            current_settings.update({
                "smtp_host": host,
                "smtp_port": port,
                "smtp_ssl": ssl_val,
                "smtp_user": user,
                "smtp_pass": pw,
                "smtp_sender": sender,
                "smtp_receiver": receiver
            })

        if save_settings(current_settings):
            if smtp_configured:
                self.lbl_smtp_status.setText("✓  Settings saved successfully.")
                self.lbl_smtp_status.setStyleSheet("color: #34C759; font-weight: 600; font-size: 13px;")
            else:
                self.lbl_smtp_status.setText("General settings saved (SMTP disabled).")
                self.lbl_smtp_status.setStyleSheet("color: #8E8E93; font-style: italic; font-size: 13px;")
            QMessageBox.information(self, "Settings Saved", "SMTP, Report, and Scan settings updated.")

    def verify_shasum(self, file_path):
        try:
            # Compute raw file SHA256 (for display purposes)
            raw_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    raw_sha256.update(byte_block)
            raw_file_hash = raw_sha256.hexdigest()

            # Extract the SMP content hash that was embedded in the report at generation time
            from tools.verify_report import extract_embedded_hash
            embedded_hash = extract_embedded_hash(file_path)

            if not embedded_hash:
                QMessageBox.warning(
                    self, "No Embedded Hash",
                    f"No SMP verification hash was found in this file.\n\n"
                    f"This may be an older report (pre-V9.4.2) or not an SMP report.\n\n"
                    f"Raw file SHA256:\n{raw_file_hash}"
                )
                return

            # Check embedded content hash against the database
            from tools.db_manager import get_db_connection
            conn = get_db_connection()
            row = conn.execute("SELECT id FROM scans WHERE report_hash = ?", (embedded_hash,)).fetchone()
            conn.close()

            if row:
                QMessageBox.information(
                    self, "✅ SHASUM Valid",
                    f"Report is VALID and authentic.\n\n"
                    f"Content Hash (embedded): {embedded_hash[:32]}…\n"
                    f"Matched Scan ID: {row['id']}\n\n"
                    f"Raw file SHA256:\n{raw_file_hash}"
                )
            else:
                QMessageBox.warning(
                    self, "⚠️ Hash Not in Database",
                    f"The report's embedded content hash was NOT found in the scan database.\n\n"
                    f"This can happen if:\n"
                    f"  • The database was reset after the report was generated\n"
                    f"  • The report was generated on a different machine\n\n"
                    f"Content Hash (embedded): {embedded_hash[:32]}…\n"
                    f"Raw file SHA256:\n{raw_file_hash}\n\n"
                    f"To verify authenticity without the DB, use:\n"
                    f"  python3 tools/verify_report.py <report_file>"
                )
        except Exception as e:
            QMessageBox.critical(self, "SHASUM Error", f"Failed to verify file: {e}")

    def reset_to_default(self):
        reply = QMessageBox.warning(self, "Reset to Default", 
                                    "This will reset the website scan settings, turn off OWASP ZAP, and delete the cache.\n\nAre you sure you want to continue?",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            try:
                from tools.db_manager import get_db_connection
                conn = get_db_connection()
                conn.execute("DELETE FROM targets")
                conn.execute("DELETE FROM scans")
                conn.execute("DELETE FROM scan_results")
                conn.commit()
                conn.close()
                self._cache_targets_hash = None
                self.poll_updates()

                self.chk_zap_enabled.setChecked(False)
                current_settings = load_settings()
                current_settings["zap_enabled"] = False
                save_settings(current_settings)

                import shutil
                import os
                from tools.config_manager import BASE_DIR
                cache_dir = os.path.join(BASE_DIR, "cache")
                if os.path.exists(cache_dir):
                    shutil.rmtree(cache_dir)
                    os.makedirs(cache_dir)
                
                QMessageBox.information(self, "Reset Successful", "Settings have been reset to default.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to reset: {e}")

    def full_reset(self):
        reply = QMessageBox.critical(self, "FULL RESET", 
                                    "WARNING: This will delete ALL data including databases, PDF reports, logs, and reset everything to a first-install state.\n\nThis action CANNOT be undone!\nAre you absolutely sure?",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            try:
                import shutil
                import os
                import sys
                from tools.config_manager import BASE_DIR
                
                # Wipe config files
                auth_path = os.path.join(BASE_DIR, "config", "auth.json")
                resp_path = os.path.join(BASE_DIR, "config", "responsibility.json")
                if os.path.exists(auth_path):
                    os.remove(auth_path)
                if os.path.exists(resp_path):
                    os.remove(resp_path)
                
                # Wipe databases EXCEPT cve.db
                db_dir = os.path.join(BASE_DIR, "database")
                if os.path.exists(db_dir):
                    for filename in os.listdir(db_dir):
                        if filename == "cve.db" or filename == "cve.db-journal" or filename == "cve.db-wal" or filename == "cve.db-shm":
                            continue
                        file_path = os.path.join(db_dir, filename)
                        if os.path.isfile(file_path):
                            os.remove(file_path)

                # Wipe auto-restoring backups
                backup_dir = os.path.join(BASE_DIR, "database", "backup")
                if os.path.exists(backup_dir):
                    shutil.rmtree(backup_dir)
                os.makedirs(backup_dir, exist_ok=True)

                reports_dir = os.path.join(BASE_DIR, "reports")
                if os.path.exists(reports_dir):
                    shutil.rmtree(reports_dir)
                os.makedirs(os.path.join(reports_dir, "pdf"), exist_ok=True)
                os.makedirs(os.path.join(reports_dir, "html"), exist_ok=True)

                logs_dir = os.path.join(BASE_DIR, "logs")
                if os.path.exists(logs_dir):
                    shutil.rmtree(logs_dir)
                os.makedirs(logs_dir, exist_ok=True)
                
                cache_dir = os.path.join(BASE_DIR, "cache")
                if os.path.exists(cache_dir):
                    shutil.rmtree(cache_dir)
                os.makedirs(cache_dir, exist_ok=True)

                self._cache_targets_hash = None
                self._cache_scans_hash = None
                self.poll_updates()

                
                QMessageBox.information(self, "Full Reset Complete", "The platform has been reset to its factory state.\nPlease restart the application.")
                sys.exit(0)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to perform full reset: {e}")

    def load_statistics(self):
        pass

    def check_tools_dependencies(self):
        from tools.tool_installer import check_and_install_all
        self.btn_check_tools.setEnabled(False)
        self.btn_check_tools.setText("Checking…")
        self.tools_worker = WorkerThread(check_and_install_all, auto_install=True)

        def _done(result_tuple):
            success, err = result_tuple
            self.btn_check_tools.setEnabled(True)
            self.btn_check_tools.setText("Check Dependencies & Tools")
            if success:
                QMessageBox.information(self, "Tools Check Complete", "Dependencies and tools have been verified. Check the Audit Logs for detailed output.")
            else:
                QMessageBox.critical(self, "Error", f"An error occurred while checking tools: {err}")

        self.tools_worker.finished_signal.connect(_done)
        self.tools_worker.start()

    def test_smtp_connection(self):
        host = self.txt_smtp_host.text().strip()
        port_text = self.txt_smtp_port.text().strip()
        user = self.txt_smtp_user.text().strip()
        pw = self.txt_smtp_pass.text().strip()
        sender = self.txt_smtp_sender.text().strip() or user
        receiver = self.txt_smtp_receiver.text().strip()
        ssl_val = self.chk_smtp_ssl.isChecked()
        tester = self.txt_tester_name.text().strip() or "Security Auditor"

        if not host or not port_text or not user or not pw or not receiver:
            QMessageBox.warning(self, "Missing Settings", "Please fill in all SMTP settings to run a test.")
            return

        try:
            port = int(port_text)
        except ValueError:
            QMessageBox.warning(self, "Invalid Port", "SMTP Port must be a number.")
            return

        current_settings = load_settings()
        current_settings.update({
            "smtp_host": host, "smtp_port": port, "smtp_ssl": ssl_val,
            "smtp_user": user, "smtp_pass": pw, "smtp_sender": sender,
            "smtp_receiver": receiver, "tester_name": tester
        })
        save_settings(current_settings)

        self.btn_test_smtp.setEnabled(False)
        self.btn_test_smtp.setText("Testing…")
        self.lbl_smtp_status.setText("Connecting to SMTP server…")
        self.lbl_smtp_status.setStyleSheet("color: #FF9500; font-weight: 600; font-size: 13px;")

        from tools.alert_engine import test_smtp_connection as _test_conn
        self.smtp_worker = WorkerThread(_test_conn)

        def test_done(result_tuple):
            success, val = result_tuple
            self.btn_test_smtp.setEnabled(True)
            self.btn_test_smtp.setText("Test Connection")
            if success and isinstance(val, tuple) and val[0]:
                self.lbl_smtp_status.setText("✓  Test email sent successfully!")
                self.lbl_smtp_status.setStyleSheet("color: #34C759; font-weight: 600; font-size: 13px;")
                QMessageBox.information(self, "Test Success", f"Connected successfully!\n\n{val[1]}")
            else:
                msg = val[1] if (success and isinstance(val, tuple)) else str(val)
                self.lbl_smtp_status.setText("✗  Test failed — check Audit Logs for details.")
                self.lbl_smtp_status.setStyleSheet("color: #FF3B30; font-weight: 600; font-size: 13px;")
                QMessageBox.critical(self, "Test Failed", f"SMTP connection failed:\n\n{msg}")

        self.smtp_worker.finished_signal.connect(test_done)
        self.smtp_worker.start()


    def _invalidate_log_cache(self):
        self._cache_log_mtime = None
        self.refresh_master_log()

    def _invalidate_cve_log_cache(self):
        self._cache_cve_log_mtime = None
        self.refresh_cve_log()

    def _invalidate_scan_log_cache(self):
        self._cache_scan_log_mtime = None
        self.refresh_scan_log()

    def _invalidate_error_log_cache(self):
        self._cache_error_log_mtime = None
        self.refresh_error_log()

    def _invalidate_all_log_caches(self):
        self._cache_log_mtime = None
        self._cache_error_log_mtime = None
        self.refresh_master_log()
        self.refresh_error_log()

    def _force_full_refresh(self):
        """Manually clear all caches and force a full redraw of every widget."""
        self._cache_kpis = None
        self._cache_targets_hash = None
        self._cache_scans_hash = None
        self._cache_intel_hash = None
        self._cache_updates_hash = None
        self._invalidate_all_log_caches()
        self.poll_updates()

    def _restart_application(self):
        """Fully restart the entire process — use when the app is stuck."""
        import sys
        reply = QMessageBox.question(
            self,
            "Restart Application",
            "This will close and restart the Security Management Platform.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        try:
            # Stop the polling timer cleanly before exit
            self.timer.stop()
        except Exception as e:
            from tools.errors import SMPUnclassifiedError
            import traceback
            import logging
            logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
            raise SMPUnclassifiedError(str(e))
            pass
        try:
            import os
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception as e:
            # Fallback: just quit and let the user relaunch
            logger.error(f"Restart failed: {e}")
            QApplication.quit()

    # ─── Polling ───────────────────────────────────────────────────────────────

    def poll_updates(self):
        """Timer callback: refresh only the data relevant to the active page.
        Expensive refreshes (intel, logs) are rate-limited to avoid UI stutter.
        """
        # Always refresh critical real-time data
        self.update_kpis()
        self.refresh_ongoing_scans()
        self.refresh_updates_errors()

        # Refresh targets only when on Dashboard (0) or Targets (1) page
        current_page = self.content_stack.currentIndex() if hasattr(self, 'content_stack') else 0
        if current_page in (0, 1):
            self.refresh_targets()

        # Refresh intel only when on Threat Intel page (2) — it's expensive
        if current_page == 2:
            self.refresh_intel_feed()

        # Refresh logs only when on Audit Logs page (5)
        if current_page == 5:
            self.refresh_master_log()
            self.refresh_error_log()

    def update_kpis(self):
        targets = get_targets()
        stats   = get_cve_stats()
        active  = get_active_scans()
        settings = load_settings()

        kpi_hash = hashlib.md5(str((len(targets), stats.get("total", 0), len(active), bool(settings.get("smtp_user")))).encode('utf-8')).hexdigest()
        if self._cache_kpis == kpi_hash:
            return
        self._cache_kpis = kpi_hash

        self.lbl_kpi_targets.setText(str(len(targets)))
        self.lbl_kpi_intel.setText(str(stats.get("total", 0)))

        if active:
            self.lbl_kpi_scans.setText(f"{len(active)} Running")
            self.lbl_kpi_scans.setStyleSheet("color: #FF9500; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;")
        else:
            self.lbl_kpi_scans.setText("None")
            self.lbl_kpi_scans.setStyleSheet("color: #34C759; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;")

        if settings.get("smtp_user") and settings.get("smtp_pass") and settings.get("smtp_receiver"):
            self.lbl_kpi_status.setText("Enabled")
            self.lbl_kpi_status.setStyleSheet("color: #34C759; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;")
        else:
            self.lbl_kpi_status.setText("Not Set")
            self.lbl_kpi_status.setStyleSheet("color: #FF3B30; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;")

    def refresh_targets(self):
        targets = get_targets()
        # Use a lightweight hash (just IDs + statuses + last_scan) — NOT the full target dict
        t_hash = hashlib.md5(str([(t["id"], t["status"], t["last_scan"]) for t in targets]).encode()).hexdigest()
        if self._cache_targets_hash == t_hash:
            return
        self._cache_targets_hash = t_hash

        # Batch-fetch all risk scores and operators in ONE query each (avoids N+1 DB calls)
        risk_map = self._batch_get_risk_scores([t["id"] for t in targets])
        operator_map = self._batch_get_operators([t["id"] for t in targets])

        # Cache scanning state once, not per-row
        from scanners.scan_runner import is_target_scanning

        # ── Targets table ──
        self.tbl_targets.setRowCount(len(targets))
        for idx, target in enumerate(targets):
            self.tbl_targets.setRowHeight(idx, 38)
            self.tbl_targets.setItem(idx, 0, self._item(target["url"]))

            status = target["status"]
            status_item = self._item(status)
            status_item.setForeground(QBrush(QColor("#34C759" if status == "Enabled" else "#8E8E93")))
            self.tbl_targets.setItem(idx, 1, status_item)

            score_data = risk_map.get(target["id"])
            if score_data:
                sv = f"{score_data['score']} ({score_data['rating']})"
                score_item = self._item(sv)
                rating = score_data["rating"]
                color = "#FF3B30" if rating in ("Critical", "High") else "#FF9500" if rating == "Medium" else "#34C759"
                score_item.setForeground(QBrush(QColor(color)))
            else:
                score_item = self._item("N/A")
                score_item.setForeground(QBrush(QColor("#8E8E93")))
            self.tbl_targets.setItem(idx, 2, score_item)

            self.tbl_targets.setItem(idx, 3, self._item(target["last_scan"] or "Never"))
            self.tbl_targets.setItem(idx, 4, self._item(operator_map.get(target["id"], "N/A")))

            # Action buttons
            actions_w = QWidget()
            actions_w.setObjectName("actions_w")
            actions_w.setStyleSheet("QWidget#actions_w { background: transparent; }")
            actions_layout = QHBoxLayout(actions_w)
            actions_layout.setContentsMargins(4, 2, 4, 2)
            actions_layout.setSpacing(4)

            toggle_text = "Disable" if status == "Enabled" else "Enable"
            btn_toggle = QPushButton(toggle_text)
            btn_toggle.setObjectName("btn_small")
            btn_toggle.setFixedHeight(26)
            btn_toggle.clicked.connect(lambda _, t=target: self.toggle_target(t))
            actions_layout.addWidget(btn_toggle)

            btn_scan = QPushButton("Scan")
            btn_scan.setObjectName("btn_small")
            btn_scan.setFixedHeight(26)
            # Check if there's an interrupted scan to resume
            has_interrupted = False
            try:
                from tools.db_manager import get_scans_for_target
                recent = get_scans_for_target(target["id"], limit=1)
                if recent and recent[0]["status"] not in ("Completed", "Failed", "Cancelled"):
                    has_interrupted = True
            except Exception as e:
                from tools.errors import SMPUnclassifiedError
                import traceback
                import logging
                logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
                raise SMPUnclassifiedError(str(e))
                pass

            if is_target_scanning(target["id"]):
                btn_scan.setText("Cancel")
                btn_scan.setStyleSheet(
                    "background-color: #DC2626; color: white; border: none;"
                    " border-radius: 4px; font-size: 11px; padding: 0 6px;"
                )
                btn_scan.clicked.connect(lambda _, t=target: self.cancel_scan(t["id"]))
            elif has_interrupted:
                btn_scan.setText("▶ Resume")
                btn_scan.setStyleSheet(
                    "background-color: #1A3A1A; color: #22C55E; border: 1px solid #166534;"
                    " border-radius: 4px; font-size: 11px; padding: 0 6px; font-weight: 600;"
                )
                btn_scan.setToolTip("Resume interrupted scan from last checkpoint")
                btn_scan.clicked.connect(lambda _, t=target: self.trigger_manual_scan(t))
            else:
                btn_scan.clicked.connect(lambda _, t=target: self.trigger_manual_scan(t))
            actions_layout.addWidget(btn_scan)

            btn_report = QPushButton("Report")
            btn_report.setObjectName("btn_small")
            btn_report.setFixedHeight(26)
            if not target["last_scan"]:
                btn_report.setEnabled(False)
            else:
                btn_report.clicked.connect(lambda _, t=target: self.open_latest_report(t))
            actions_layout.addWidget(btn_report)

            btn_del = QPushButton("✕")
            btn_del.setObjectName("btn_small")
            btn_del.setFixedSize(26, 26)
            btn_del.clicked.connect(lambda _, t=target: self.delete_target_click(t))
            actions_layout.addWidget(btn_del)

            self.tbl_targets.setCellWidget(idx, 5, actions_w)

        # ── Dashboard summary table ──
        self.tbl_dashboard_targets.setRowCount(len(targets))
        for idx, target in enumerate(targets):
            self.tbl_dashboard_targets.setItem(idx, 0, self._item(target["url"]))
            si = self._item(target["status"])
            si.setForeground(QBrush(QColor("#34C759" if target["status"] == "Enabled" else "#8E8E93")))
            self.tbl_dashboard_targets.setItem(idx, 1, si)
            score_data = risk_map.get(target["id"])
            if score_data:
                sc_item = self._item(f"{score_data['score']} ({score_data['rating']})")
                rating = score_data["rating"]
                sc_item.setForeground(QBrush(QColor("#FF3B30" if rating in ("Critical","High") else "#FF9500" if rating=="Medium" else "#34C759")))
            else:
                sc_item = self._item("N/A")
                sc_item.setForeground(QBrush(QColor("#8E8E93")))
            self.tbl_dashboard_targets.setItem(idx, 2, sc_item)

    def _batch_get_risk_scores(self, target_ids: list) -> dict:
        """Fetch risk scores for multiple targets in a single DB query. Returns {target_id: {...}}."""
        if not target_ids:
            return {}
        from tools.db_manager import get_db_connection
        conn = get_db_connection()
        try:
            placeholders = ",".join("?" * len(target_ids))
            rows = conn.execute(f"""
                SELECT s.target_id, rs.score, rs.rating
                FROM risk_scores rs
                JOIN scans s ON rs.scan_id = s.id
                WHERE s.target_id IN ({placeholders})
                AND rs.id = (
                    SELECT rs2.id FROM risk_scores rs2
                    JOIN scans s2 ON rs2.scan_id = s2.id
                    WHERE s2.target_id = s.target_id
                    ORDER BY s2.id DESC LIMIT 1
                )
            """, target_ids).fetchall()
            return {row["target_id"]: {"score": row["score"], "rating": row["rating"]} for row in rows}
        except Exception as e:
            from tools.errors import SMPUnclassifiedError
            import traceback
            import logging
            logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
            raise SMPUnclassifiedError(str(e))
            return {}
        finally:
            conn.close()

    def _batch_get_operators(self, target_ids: list) -> dict:
        """Fetch latest operator name for multiple targets in a single DB query. Returns {target_id: name}."""
        if not target_ids:
            return {}
        from tools.db_manager import get_db_connection
        conn = get_db_connection()
        try:
            placeholders = ",".join("?" * len(target_ids))
            rows = conn.execute(f"""
                SELECT target_id, scanned_by
                FROM scans
                WHERE target_id IN ({placeholders})
                GROUP BY target_id
                HAVING id = MAX(id)
            """, target_ids).fetchall()
            return {row["target_id"]: (row["scanned_by"] or "N/A") for row in rows}
        except Exception as e:
            from tools.errors import SMPUnclassifiedError
            import traceback
            import logging
            logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
            raise SMPUnclassifiedError(str(e))
            return {}
        finally:
            conn.close()

    def refresh_ongoing_scans(self):
        active = get_active_scans()
        
        # Update the scan count badge
        count = len(active)
        self.lbl_scan_count.setText(f"{count} running")
        if count > 0:
            self.lbl_scan_count.setStyleSheet(
                "color: #FF9500; font-size: 11px; padding: 2px 8px; "
                "background: #2A1800; border-radius: 8px; font-weight: 700;"
            )
            self.lbl_scan_pulse.setStyleSheet("color: #FF9500; font-size: 10px; padding-right: 6px;")
        else:
            self.lbl_scan_count.setStyleSheet(
                "color: #555555; font-size: 11px; padding: 2px 8px; "
                "background: #1A1A1A; border-radius: 8px;"
            )
            self.lbl_scan_pulse.setStyleSheet("color: #34C759; font-size: 10px; padding-right: 6px;")

        active_target_ids = [scan["target_id"] for scan in active]
        
        # Remove old items
        for idx in range(self.lst_scans.count() - 1, -1, -1):
            item = self.lst_scans.item(idx)
            tid = item.data(Qt.UserRole)
            if tid is None and not active:
                pass # keep "No scans" message
            elif tid not in active_target_ids:
                self.lst_scans.takeItem(idx)
                
        if not active:
            if self.lst_scans.count() == 0:
                item = QListWidgetItem("  No scans currently running.")
                item.setForeground(QBrush(QColor("#8E8E93")))
                self.lst_scans.addItem(item)
            return

        status_map = {
            "Running HTTPx":            "⬤  [1/50] HTTPx — HTTP probe",
            "Running WhatWeb":          "⬤  [2/50] WhatWeb — fingerprinting",
            "Running Subfinder":        "⬤  [3/50] Subfinder — subdomain discovery",
            "Running Amass":            "⬤  [4/50] Amass — OSINT subdomain enum",
            "Running theHarvester":     "⬤  [5/50] theHarvester — OSINT profiling",
            "Running SpiderFoot OSINT": "⬤  [6/50] SpiderFoot — passive OSINT",
            "Running CRT.sh":           "⬤  [7/50] CRT.sh — certificate transparency",
            "Running HackerTarget":     "⬤  [8/50] HackerTarget — reverse DNS",
            "Running Whois":            "⬤  [9/50] Whois — registry info",
            "Running Wayback Machine":  "⬤  [10/50] Wayback Machine — historical URLs",
            "Running Traceroute":       "⬤  [11/50] Traceroute — network path",
            "Running Nmap":             "⬤  [12/50] Nmap — port & service scan",
            "Running Masscan":          "⬤  [13/50] Masscan — fast port scan",
            "Running DNSx":             "⬤  [14/50] DNSx — DNS enumeration",
            "Running SSL Scan":         "⬤  [15/50] SSL Scanner — TLS/certificate",
            "Running HTTP Smuggling Scanner": "⬤  [16/50] HTTP Smuggling — req smuggling",
            "Running Security Headers": "⬤  [17/50] Security Headers — HTTP headers",
            "Running Robots.txt":       "⬤  [18/50] Robots.txt — sitemap analysis",
            "Running CORS":             "⬤  [19/50] CORS — misconfiguration check",
            "Running CMS Scanner":      "⬤  [20/50] CMS Scanner — platform detection",
            "Running Katana":           "⬤  [21/50] Katana — web crawler",
            "Running Nikto":            "⬤  [22/50] Nikto — web vulnerability scan",
            "Running Nuclei":           "⬤  [23/50] Nuclei — template-based scan",
            "Running ffuf":             "⬤  [24/50] ffuf — directory fuzzing",
            "Running Feroxbuster":      "⬤  [25/50] Feroxbuster — deep fuzzing",
            "Running API Fuzzer":       "⬤  [26/50] API Fuzzer — OpenAPI endpoints",
            "Running GraphQL Scanner":  "⬤  [27/50] GraphQL Scanner — introspection",
            "Running ParamSpider":      "⬤  [28/50] ParamSpider — parameter mining",
            "Running Arjun":            "⬤  [29/50] Arjun — HTTP parameter discovery",
            "Running Retire.js Scanner":"⬤  [30/50] Retire.js — outdated JS check",
            "Running Tech Fingerprint": "⬤  [31/50] Tech Fingerprint — deep analysis",
            "Running Open Redirect":    "⬤  [32/50] Open Redirect — parameter check",
            "Running CRLF Scanner":     "⬤  [33/50] CRLF Scanner — header injection",
            "Running Wapiti":           "⬤  [34/50] Wapiti — OWASP web scan",
            "Running SQLMap":           "⬤  [35/50] SQLMap — SQL injection",
            "Running Dalfox":           "⬤  [36/50] Dalfox — XSS parameter scan",
            "Running Commix":           "⬤  [37/50] Commix — command injection",
            "Running SSRF Scanner":     "⬤  [38/50] SSRF Scanner — server-side forgery",
            "Running XXE Scanner":      "⬤  [39/50] XXE Scanner — XML entity injection",
            "Running Path Traversal Scanner": "⬤  [40/50] Path Traversal — LFI testing",
            "Running JWT Scanner":      "⬤  [41/50] JWT Scanner — token analysis",
            "Running WPScan":           "⬤  [42/50] WPScan — WordPress scanner",
            "Running Auth Brute-Force Test": "⬤  [43/50] Auth Brute-Force — hydra",
            "Running Cloud Enum":       "⬤  [44/50] Cloud Enum — cloud assets",
            "Running Gitleaks":         "⬤  [45/50] Gitleaks — secret scanning",
            "Running TruffleHog":       "⬤  [46/50] TruffleHog — secret scanning",
            "Running Semgrep":          "⬤  [47/50] Semgrep — static analysis",
            "Running Trivy":            "⬤  [48/50] Trivy — container scan",
            "Running Shodan":           "⬤  [49/50] Shodan — passive profiling",
            "Running ZAP":              "⬤  [50/50] OWASP ZAP — active scan",
            "Correlating CVEs":         "◌  CVE Correlation — intel matching",
            "Report Pending":           "◌  Report Generation",
            "Completed":                "✓  Completed",
            "Failed":                   "✗  Failed",
        }

        if self.lst_scans.count() == 1 and self.lst_scans.item(0).data(Qt.UserRole) is None:
            self.lst_scans.takeItem(0)

        for scan in active:
            target_id = scan["target_id"]
            dur_str = "00:00:00"
            try:
                start_dt = datetime.strptime(scan["start_time"], "%Y-%m-%d %H:%M:%S")
                diff = datetime.now() - start_dt
                h, rem = divmod(diff.total_seconds(), 3600)
                m, s = divmod(rem, 60)
                dur_str = f"{int(h):02}:{int(m):02}:{int(s):02}"
            except Exception as e:
                from tools.errors import SMPUnclassifiedError
                import traceback
                import logging
                logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
                raise SMPUnclassifiedError(str(e))
                pass
            
            current_status = scan.get("scanner_status") or scan["status"]
            prog = status_map.get(current_status, f"⬤  {current_status}")
            
            text = f"{scan['url']}   {prog}   [{dur_str}]"
            color = "#3B82F6" if "Running" in prog else "#F59E0B" if "◌" in prog else "#22C55E"

            _STEP_MAP = {
                "Running HTTPx": 1, "Running WhatWeb": 2, "Running Subfinder": 3,
                "Running Amass": 4, "Running theHarvester": 5, "Running SpiderFoot OSINT": 6,
                "Running CRT.sh": 7, "Running HackerTarget": 8, "Running Whois": 9,
                "Running Wayback Machine": 10, "Running Traceroute": 11, "Running Nmap": 12,
                "Running Masscan": 13, "Running DNSx": 14, "Running SSL Scan": 15,
                "Running HTTP Smuggling Scanner": 16, "Running Security Headers": 17,
                "Running Robots.txt": 18, "Running CORS": 19, "Running CMS Scanner": 20,
                "Running Katana": 21, "Running Nikto": 22, "Running Nuclei": 23,
                "Running ffuf": 24, "Running Feroxbuster": 25, "Running API Fuzzer": 26,
                "Running GraphQL Scanner": 27, "Running ParamSpider": 28, "Running Arjun": 29,
                "Running Retire.js Scanner": 30, "Running Tech Fingerprint": 31,
                "Running Open Redirect": 32, "Running CRLF Scanner": 33,
                "Running Wapiti": 34, "Running SQLMap": 35, "Running Dalfox": 36,
                "Running Commix": 37, "Running SSRF Scanner": 38, "Running XXE Scanner": 39,
                "Running Path Traversal Scanner": 40, "Running JWT Scanner": 41,
                "Running WPScan": 42, "Running Auth Brute-Force Test": 43,
                "Running Cloud Enum": 44, "Running Gitleaks": 45, "Running TruffleHog": 46,
                "Running Semgrep": 47, "Running Trivy": 48, "Running Shodan": 49,
                "Running ZAP": 50, "Correlating CVEs": 50, "Report Pending": 50,
            }
            step_num = _STEP_MAP.get(current_status, 0)
            existing_item = None
            for idx in range(self.lst_scans.count()):
                it = self.lst_scans.item(idx)
                if it.data(Qt.UserRole) == target_id:
                    existing_item = it
                    break
                    
            if existing_item:
                widget = self.lst_scans.itemWidget(existing_item)
                if widget:
                    lbl = widget.findChild(QLabel)
                    if lbl:
                        lbl.setText(text)
                        lbl.setStyleSheet(f"color: {color}; font-family: Menlo; font-size: 11px; background: transparent;")
                    pbar = widget.findChild(QProgressBar)
                    if pbar:
                        pbar.setValue(step_num)
            else:
                item = QListWidgetItem()
                item.setData(Qt.UserRole, target_id)
                self.lst_scans.addItem(item)
                
                widget = QWidget()
                widget.setStyleSheet("background: transparent;")
                layout = QVBoxLayout(widget)
                layout.setContentsMargins(8, 4, 8, 4)
                layout.setSpacing(4)

                # Top row: text + cancel button
                top_row = QHBoxLayout()
                top_row.setSpacing(6)

                lbl_text = QLabel(text)
                lbl_text.setWordWrap(False)
                lbl_text.setStyleSheet(f"color: {color}; font-family: Menlo; font-size: 11px; background: transparent;")
                top_row.addWidget(lbl_text, 1)

                btn_cancel = QPushButton("Cancel")
                btn_cancel.setFixedSize(58, 22)
                btn_cancel.setStyleSheet(
                    "background-color: #3A0A0A; color: #EF4444; border: 1px solid #7F1D1D;"
                    " border-radius: 3px; font-size: 10px; font-weight: 600;"
                )
                btn_cancel.setCursor(Qt.PointingHandCursor)
                btn_cancel.clicked.connect(lambda checked=False, tid=target_id: self.cancel_scan(tid))
                top_row.addWidget(btn_cancel)
                layout.addLayout(top_row)

                # Progress bar (step_num computed above)
                pbar = QProgressBar()
                pbar.setRange(0, 50)
                pbar.setValue(step_num)
                pbar.setTextVisible(False)
                pbar.setFixedHeight(4)
                pbar.setObjectName("scan_progress")
                pbar.setStyleSheet(
                    "QProgressBar { background: #1A1A1A; border: none; border-radius: 2px; }"
                    "QProgressBar::chunk { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
                    "stop:0 #3B82F6, stop:1 #22C55E); border-radius: 2px; }"
                )
                layout.addWidget(pbar)

                item.setSizeHint(QSize(0, 62))
                self.lst_scans.setItemWidget(item, widget)

    def refresh_intel_feed(self):
        stats = get_cve_stats()
        
        self.lbl_stats.setText(
            f"Total CVEs: {stats['total']:,}   ·   New Today: {stats.get('new_today', 0)}   ·   Critical Today: {stats.get('critical_today', 0)}"
        )
        
        # Update Pie Chart
        counts = stats.get('counts', {})
        if hasattr(self, 'cve_chart'):
            self.cve_chart.removeAllSeries()
            series = QPieSeries()
            
            critical_slice = series.append("Critical", counts.get("Critical", 0))
            from PySide6.QtGui import QColor
            critical_slice.setColor(QColor("#FF3333"))
            
            high_slice = series.append("High", counts.get("High", 0))
            high_slice.setColor(QColor("#FF9933"))
            
            medium_slice = series.append("Medium", counts.get("Medium", 0))
            medium_slice.setColor(QColor("#FFCC00"))
            
            low_slice = series.append("Low", counts.get("Low", 0))
            low_slice.setColor(QColor("#33CC33"))
            
            info_slice = series.append("Info", counts.get("Info", 0))
            info_slice.setColor(QColor("#3399FF"))
            
            for s in series.slices():
                if s.value() > 0:
                    s.setLabelVisible(True)
                    s.setLabel(f"{s.label()} ({int(s.value())})")
            
            self.cve_chart.addSeries(series)


        search = self.txt_intel_search.text().lower().strip()
        sel_sev = self.cmb_intel_severity.currentText()

        cves = get_cves(search_query=search, limit=500, severity_filter=sel_sev)
        i_hash = hashlib.md5(str(cves).encode('utf-8')).hexdigest()
        if self._cache_intel_hash == i_hash:
            return
        self._cache_intel_hash = i_hash

        self.lst_intel.clear()
        if not cves:
            item = QListWidgetItem("No CVEs found matching your search criteria.")
            item.setForeground(QBrush(QColor("#8E8E93")))
            self.lst_intel.addItem(item)
            return

        sev_colors = {
            "Critical": "#FF3B30", "High": "#FF9500",
            "Medium": "#FFCC00",  "Low": "#007AFF", "Info": "#8E8E93"
        }
        count = 0
        for cve in cves:
            sev, cve_id = cve["severity"], cve["cve"]
            title = cve.get("title") or cve.get("description", "Advisory")
            title = title.split("\n")[0][:100] if title else "Advisory"
            cvss = cve.get("cvss_score")
            cvss_str = f"  CVSS:{cvss:.1f}" if cvss else ""
            if sel_sev != "All Severities" and sev.lower() != sel_sev.lower():
                continue
            item_text = f"[{sev}]{cvss_str}  {cve_id}  —  {title}"
            item = QListWidgetItem(item_text)
            # Tooltip shows full description
            desc = cve.get("description", "") or ""
            affected = cve.get("affected_products", "") or ""
            tooltip = f"{cve_id}\n\nDescription:\n{desc[:800]}"
            if affected:
                tooltip += f"\n\nAffected Products:\n{affected[:400]}"
            item.setToolTip(tooltip)
            item.setForeground(QBrush(QColor(sev_colors.get(sev, "#8E8E93"))))
            self.lst_intel.addItem(item)
            count += 1
            if count >= 200:
                break

    def refresh_master_log(self):
        from tools.config_manager import BASE_DIR
        log_path = os.path.join(BASE_DIR, "logs", "master.log")
        if not os.path.exists(log_path):
            self.txt_logs.setPlainText("No log file found yet.")
            return

        try:
            mtime = os.path.getmtime(log_path)
            if self._cache_log_mtime == mtime:
                return
            self._cache_log_mtime = mtime

            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-600:]

            lines.reverse()  # newest at top

            # Dynamically extract unique levels to populate the dropdown
            import re
            level_set = set()
            for line in lines:
                m = re.search(r'\[([A-Z]{3,8})\]', line)
                if m:
                    level_set.add(m.group(1))
            new_levels = ["All Levels"] + sorted(list(level_set))
            current_levels = [self.cmb_log_level.itemText(i) for i in range(self.cmb_log_level.count())]
            if new_levels != current_levels:
                current_text = self.cmb_log_level.currentText()
                self.cmb_log_level.blockSignals(True)
                self.cmb_log_level.clear()
                self.cmb_log_level.addItems(new_levels)
                if current_text in new_levels:
                    self.cmb_log_level.setCurrentText(current_text)
                self.cmb_log_level.blockSignals(False)

            level_filter = self.cmb_log_level.currentText()
            search = self.txt_log_search.text().lower().strip()

            filtered = []
            for line in lines:
                if level_filter != "All Levels" and f"[{level_filter}]" not in line:
                    continue
                if search and search not in line.lower():
                    continue
                filtered.append(line)

            log_text = "".join(filtered)
            current_text = self.txt_logs.toPlainText()
            if not current_text or len(filtered) < 10:
                self.txt_logs.setPlainText(log_text)
            else:
                current_lines = set(current_text.splitlines()[:1000])
                new_lines = []
                for line in filtered:
                    line_stripped = line.rstrip('\r\n')
                    if line_stripped and line_stripped not in current_lines:
                        new_lines.append(line)
                if new_lines:
                    cursor = self.txt_logs.textCursor()
                    cursor.movePosition(QTextCursor.Start)
                    self.txt_logs.setTextCursor(cursor)
                    self.txt_logs.insertPlainText("".join(new_lines))

        except Exception as e:
            self.txt_logs.setPlainText(f"Error reading log: {e}")

    def refresh_cve_log(self):
        """Read logs/cve.log and display in the CVE Log tab (newest first)."""
        self._display_log_file("cve.log", "txt_cve_logs", "txt_cve_log_search", "cmb_cve_log_level", "_cache_cve_log_mtime",
                               "No CVE log yet. CVE events appear after the first intelligence sync.")

    def refresh_scan_log(self):
        """Read logs/scan.log and display in the Scan Log tab (newest first)."""
        self._display_log_file("scan.log", "txt_scan_log", "txt_scan_log_search", "cmb_scan_log_level", "_cache_scan_log_mtime",
                               "No scan log yet. Scan events appear after the first scan runs.")

    def refresh_error_log(self):
        """Read logs/error.log and display in the Error Log tab (newest first)."""
        self._display_log_file("error.log", "txt_error_logs", "txt_error_log_search", "cmb_error_log_level", "_cache_error_log_mtime",
                               "No errors logged yet.")

    def _display_log_file(self, filename, widget_attr, search_attr, level_widget_attr, cache_attr, empty_msg):
        """Generic helper: read a log file and show it newest-first in a QTextEdit."""
        widget = getattr(self, widget_attr, None)
        if widget is None:
            return
        from tools.config_manager import BASE_DIR
        log_path = os.path.join(BASE_DIR, "logs", filename)
        if not os.path.exists(log_path):
            widget.setPlainText(empty_msg)
            return
        try:
            mtime = os.path.getmtime(log_path)
            if getattr(self, cache_attr, None) == mtime:
                return
            setattr(self, cache_attr, mtime)

            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-800:]
            lines.reverse()  # newest at top

            # Level filter
            level_widget = getattr(self, level_widget_attr, None)
            level_filter = level_widget.currentText() if level_widget else "All Levels"
            if level_filter != "All Levels":
                lines = [l for l in lines if f"[{level_filter}]" in l]

            # Search text filter
            search_widget = getattr(self, search_attr, None)
            search_text = search_widget.text().lower().strip() if search_widget else ""
            if search_text:
                lines = [l for l in lines if search_text in l.lower()]

            log_text = "".join(lines)
            current_text = widget.toPlainText()
            if not current_text or len(lines) < 10:
                widget.setPlainText(log_text)
            else:
                current_lines = set(current_text.splitlines()[:1000])
                new_lines = []
                for line in lines:
                    line_stripped = line.rstrip('\r\n')
                    if line_stripped and line_stripped not in current_lines:
                        new_lines.append(line)
                if new_lines:
                    cursor = widget.textCursor()
                    cursor.movePosition(QTextCursor.Start)
                    widget.setTextCursor(cursor)
                    widget.insertPlainText("".join(new_lines))
        except Exception as e:
            widget.setPlainText(f"Error reading {filename}: {e}")

    def refresh_updates_errors(self):
        logs = get_log_entries(limit=100)
        u_hash = hashlib.md5(str(logs).encode('utf-8')).hexdigest()
        if self._cache_updates_hash == u_hash:
            return
        self._cache_updates_hash = u_hash

        self.lst_dashboard_updates.clear()
        keywords = ["updated", "synced", "failed", "failure", "success", "locked", "smtp", "feed", "scan"]

        has_items = False
        for entry in logs:
            msg = entry["message"].lower()
            if entry["level"] in ("ERROR", "WARNING") or any(k in msg for k in keywords):
                item = QListWidgetItem(f"[{entry['timestamp']}]  {entry['message']}")
                if entry["level"] == "ERROR":
                    item.setForeground(QBrush(QColor("#FF3B30")))
                elif entry["level"] == "WARNING":
                    item.setForeground(QBrush(QColor("#FF9500")))
                else:
                    item.setForeground(QBrush(QColor("#34C759")))
                self.lst_dashboard_updates.addItem(item)
                has_items = True

        if not has_items:
            item = QListWidgetItem("No warnings or errors recorded.")
            item.setForeground(QBrush(QColor("#8E8E93")))
            self.lst_dashboard_updates.addItem(item)

    # ─── Table helper ──────────────────────────────────────────────────────────

    @staticmethod
    def _item(text):
        item = QTableWidgetItem(str(text))
        item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        return item

    # ─── Controller Actions ────────────────────────────────────────────────────

    def add_new_target(self):
        url = self.txt_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Invalid URL", "Please enter a target URL.")
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        # Read company metadata fields from the UI
        company_name = self.txt_company_name.text().strip() or None
        submitted_to = self.txt_submitted_to.text().strip() or None
        success = add_target(url, company_name=company_name, submitted_to=submitted_to)
        if success:
            logger.info(f"Target Added: {url}")
            self.txt_url.clear()
            self.txt_company_name.clear()
            self.txt_submitted_to.clear()
            self._cache_targets_hash = None
            self.poll_updates()
        else:
            QMessageBox.warning(self, "Duplicate Target", "This URL is already monitored.")

    def delete_target_click(self, target):
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Delete target: {target['url']}?\nThis removes all scans, reports, and logs for this URL.",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            if delete_target(target["id"]):
                logger.info(f"Target Deleted: {target['url']}")
                self._cache_targets_hash = None
                self.poll_updates()
            else:
                QMessageBox.critical(self, "Error", "Failed to delete target.")

    def toggle_target(self, target):
        new_status = "Disabled" if target["status"] == "Enabled" else "Enabled"
        if set_target_status(target["id"], new_status):
            logger.info(f"Target {target['url']} set to {new_status}")
            self._cache_targets_hash = None
            self.poll_updates()

    def cancel_scan(self, target_id):
        reply = QMessageBox.question(
            self,
            "Cancel Scan",
            "Are you sure you want to cancel the ongoing scan for this target?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            from scanners.scan_runner import cancel_scan
            cancel_scan(target_id)
            logger.info(f"Cancellation requested for target {target_id}")
            self._cache_scans_hash = None
            self.poll_updates()

    def trigger_manual_scan(self, target):
        from PySide6.QtWidgets import QInputDialog, QLineEdit, QDialog
        from tools.responsibility_manager import check_target_attestation
        from ui.components.responsibility_dialog import ResponsibilityDialog
        
        target_id = target.get("id")
        if target_id and not check_target_attestation(target_id):
            dlg = ResponsibilityDialog(self, target)
            if dlg.exec() != QDialog.Accepted:
                logger.info("Scan cancelled due to missing responsibility attestation.")
                return

        sudo_password, ok = QInputDialog.getText(
            self, 
            "Scan Elevation Mode", 
            "Enter system sudo password to run in Full Mode (elevated rights)\nor leave blank / click Cancel for Standard Mode (no root):",
            QLineEdit.EchoMode.Password
        )
        
        verified_sudo_password = None
        if ok and sudo_password.strip():
            import subprocess
            try:
                proc = subprocess.Popen(
                    ["sudo", "-S", "id"], 
                    stdin=subprocess.PIPE, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True
                )
                stdout, stderr = proc.communicate(input=f"{sudo_password}\n", timeout=5)
                if proc.returncode == 0:
                    verified_sudo_password = sudo_password
                    logger.info("Scan Elevation: Sudo password verified. Scan running in Full Mode.")
                else:
                    reply = QMessageBox.question(
                        self, 
                        "Invalid Password", 
                        "Sudo password verification failed.\nWould you like to run the scan in Standard Mode instead?",
                        QMessageBox.Yes | QMessageBox.No, 
                        QMessageBox.Yes
                    )
                    if reply == QMessageBox.No:
                        logger.info("Scan cancelled due to invalid sudo password.")
                        return
                    else:
                        logger.info("Scan Elevation: Sudo verification failed. Falling back to Standard Mode.")
            except Exception as e:
                logger.error(f"Sudo verification error: {e}")
        
        from scanners.scan_runner import start_scan_for_target
        success = start_scan_for_target(target, sudo_password=verified_sudo_password)
        if success:
            logger.info(f"Scan Triggered: {target['url']}")
            self._cache_targets_hash = None
            self.poll_updates()
        else:
            QMessageBox.warning(self, "Scan In Progress", "A scan is already running for this target or the maximum concurrent scans limit has been reached.")

    def force_intel_sync(self):
        self.btn_sync.setEnabled(False)
        self.btn_sync.setText("Syncing…")
        if hasattr(self, "btn_cve_sync"):
            self.btn_cve_sync.setEnabled(False)
            self.btn_cve_sync.setText("Syncing…")

        self.intel_worker = WorkerThread(self._run_async_intel_sync)

        def sync_done(result_tuple):
            self._enable_sync_button()
            success, val = result_tuple
            if not success or not val:
                logger.warning("Threat Intel sync completed with errors.")
            else:
                logger.info("CVE Feed Synced successfully.")

        self.intel_worker.finished_signal.connect(sync_done)
        self.intel_worker.start()

    def _run_async_intel_sync(self):
        logger.info("Scheduler Triggered: Intelligence feed sync requested manually.")
        from intelligence.cisa import sync_cisa
        from intelligence.github_adv import sync_github_adv
        from intelligence.nvd import sync_nvd
        from intelligence.epss import sync_epss

        success = True
        for fn, name in [(sync_cisa, "CISA"), (sync_github_adv, "GitHub"), (sync_nvd, "NVD"), (sync_epss, "EPSS")]:
            try:
                fn()
            except Exception as e:
                logger.error(f"{name} sync failed: {e}")
                success = False
        return success

    def _enable_sync_button(self):
        self.btn_sync.setEnabled(True)
        self.btn_sync.setText("↻  Sync Threat Intel")
        if hasattr(self, "btn_cve_sync"):
            self.btn_cve_sync.setEnabled(True)
            self.btn_cve_sync.setText("↻  Fetch CVEs")
        self._cache_intel_hash = None
        self.poll_updates()

    def reset_and_refresh_intel(self):
        self._enable_sync_button()
        if hasattr(self, "_on_intel_filter_changed"):
            self._on_intel_filter_changed()

    def open_latest_report(self, target):
        import glob
        import webbrowser
        from tools.config_manager import BASE_DIR

        url = target["url"]
        safe_name = url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_").strip("_")
        html_dir = os.path.join(BASE_DIR, "reports", "html")
        pattern = os.path.join(html_dir, f"report_{safe_name}_*.html")

        try:
            files = glob.glob(pattern)
            if not files:
                QMessageBox.information(self, "No Reports", f"No reports found for {url}.\nRun a scan first.")
                return
            latest = max(files, key=os.path.getmtime)
            webbrowser.open(f"file:///{os.path.abspath(latest).replace(chr(92), '/')}")
            logger.info(f"Opened report: {latest}")
        except Exception as e:
            logger.error(f"Failed to open report: {e}")
            QMessageBox.critical(self, "Error", f"Failed to open report: {e}")

    def _backup_cve_db(self):
        """Sync CVE data to cve_secondary.db backup."""
        self.btn_backup_cve.setEnabled(False)
        self.btn_backup_cve.setText("Backing up…")

        from tools.db_manager import backup_cve_database
        self.backup_worker = WorkerThread(backup_cve_database)

        def _done(result_tuple):
            success, ok = result_tuple
            self.btn_backup_cve.setEnabled(True)
            self.btn_backup_cve.setText("⮦  Backup CVE Database")
            if success and ok:
                QMessageBox.information(self, "Backup Complete",
                    "CVE database backed up to backup/cve_secondary.db")
            else:
                QMessageBox.warning(self, "Backup Failed",
                    "CVE backup encountered an error. Check Audit Logs.")

        self.backup_worker.finished_signal.connect(_done)
        self.backup_worker.start()

    def _download_backup_zip(self):
        """Export all backup databases as a ZIP file."""
        from PySide6.QtWidgets import QFileDialog
        from tools.config_manager import BASE_DIR
        from tools.db_manager import export_raw_scans_as_zip

        default_path = os.path.join(os.path.expanduser("~"), "smp_backup.zip")
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Backup ZIP", default_path, "ZIP Archive (*.zip)"
        )
        if not path:
            return

        self.btn_download_backup.setEnabled(False)
        self.btn_download_backup.setText("Exporting…")

        self.export_worker = WorkerThread(export_raw_scans_as_zip, path)

        def _done(result_tuple):
            success, ok = result_tuple
            self.btn_download_backup.setEnabled(True)
            self.btn_download_backup.setText("⭳  Download Raw Data ZIP")
            if success and ok:
                QMessageBox.information(self, "Export Complete",
                    f"Raw data exported to:\n{path}")
            else:
                QMessageBox.warning(self, "Export Failed",
                    "ZIP export encountered an error. Check Audit Logs.")

        self.export_worker.finished_signal.connect(_done)
        self.export_worker.start()


    def _on_ipc_event(self, event_type, data):
        if event_type == "scan_status":
            self.refresh_ongoing_scans()
            self.refresh_targets()
        elif event_type == "target_update":
            self.refresh_targets()
        elif event_type == "new_log":
            # Just trigger the logs refresh (but don't force full disk read if we can append, 
            # for now we just call the existing refresh_master_log which handles caching smartly)
            self.refresh_master_log()
            self.refresh_scan_log()
            self.refresh_cve_log()
            self.refresh_error_log()
