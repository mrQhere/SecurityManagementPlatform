import sys
import time
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QProgressBar
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QPainter, QLinearGradient

class StartupWorker(QThread):
    progress = Signal(int, str)

    def run(self):
        # 1. Verify decryption status — ACTIVE_KEY was set in the password dialog
        # and decrypt_databases() was already called. We just need to ensure the
        # plain DB files exist before running init_db().
        self.progress.emit(10, "Verifying database integrity...")
        time.sleep(0.3)
        try:
            from tools.encryption_manager import is_decryption_ok, ACTIVE_KEY, decrypt_databases
            # Re-run decryption if the DB files are missing (safety net)
            import os
            from tools.config_manager import BASE_DIR
            db_path = os.path.join(BASE_DIR, "database", "security.db")
            enc_path = os.path.join(BASE_DIR, "database", "security.db.enc")
            if not os.path.exists(db_path) and os.path.exists(enc_path):
                # Plain DB missing but .enc exists — attempt decryption again
                decrypt_databases()
        except Exception as e:
            print(f"[Startup] Decryption verification error: {e}")

        self.progress.emit(20, "Initializing database schema...")
        time.sleep(0.3)
        from tools.db_manager import init_db
        init_db()

        # 2. Check Directories & Logs
        self.progress.emit(30, "Verifying workspace and logs...")
        from tools.config_manager import init_directories
        from tools.logger_setup import setup_logging
        init_directories()
        setup_logging()
        time.sleep(0.5)

        # 3. Component Verifier (Tools Check)
        try:
            from tools.tool_installer import TOOLS
            tool_count = len(TOOLS)
        except Exception:
            tool_count = 34
        self.progress.emit(50, f"Running Verifier Checker on all {tool_count} tools...")
        try:
            from tools.tool_installer import check_and_install_all
            def _progress_cb(current, total, name):
                percent = 50 + int((current / total) * 30) # scale 50-80
                self.progress.emit(percent, f"Verifying {name} ({current}/{total})...")
            check_and_install_all(auto_install=True, progress_callback=_progress_cb)
        except Exception as e:
            print(f"Tool check error: {e}")
        
        self.progress.emit(80, "Resuming interrupted scans & syncing CVEs...")
        try:
            from scanners.scan_runner import resume_interrupted_scans
            resume_interrupted_scans()
        except Exception:
            pass

        # 4. Starting background schedulers
        self.progress.emit(95, "Booting up background schedulers...")
        try:
            from tools.scheduler import start_scheduler
            start_scheduler()
        except Exception:
            pass
        time.sleep(0.5)

        self.progress.emit(100, "Ready.")


class SplashScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(400, 250)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Brand / Title
        self.lbl_title = QLabel("SMP")
        self.lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_title.setStyleSheet("color: #FFFFFF; font-size: 36px; font-weight: 800; letter-spacing: 2px;")
        layout.addWidget(self.lbl_title)

        import json
        import os
        version = "V9.2.1"
        try:
            metadata_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", "metadata.json")
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                version = metadata.get("version", "V9.2.1")
        except Exception:
            pass

        self.lbl_subtitle = QLabel(f"SECURITY PLATFORM • {version}")
        self.lbl_subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_subtitle.setStyleSheet("color: #007AFF; font-size: 12px; font-weight: 600; letter-spacing: 1px;")
        layout.addWidget(self.lbl_subtitle)

        layout.addSpacing(30)

        # Progress Label
        self.lbl_status = QLabel("Initializing engine...")
        self.lbl_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_status.setStyleSheet("color: #AAAAAA; font-size: 11px;")
        layout.addWidget(self.lbl_status)

        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(4)
        self.progress.setStyleSheet("""
            QProgressBar {
                background-color: #222222;
                border-radius: 2px;
                border: none;
            }
            QProgressBar::chunk {
                background-color: #007AFF;
                border-radius: 2px;
            }
        """)
        layout.addWidget(self.progress)

    def paintEvent(self, event):
        # Draw a sleek dark rounded rectangle for the splash screen
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Gradient background
        gradient = QLinearGradient(0, 0, 0, self.height())
        gradient.setColorAt(0, QColor("#1A1A1D"))
        gradient.setColorAt(1, QColor("#0D0D0F"))
        
        painter.setBrush(gradient)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(self.rect(), 12, 12)
        
        # Border
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QColor("#333333"))
        painter.drawRoundedRect(self.rect(), 12, 12)

    def update_progress(self, value, text):
        self.progress.setValue(value)
        self.lbl_status.setText(text)
