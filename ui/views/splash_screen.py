import sys
import time
import random
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QProgressBar, QGraphicsDropShadowEffect
from PySide6.QtCore import Qt, QThread, Signal, QPropertyAnimation, QTimer
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
        except Exception as e:
            from tools.errors import SMPUnclassifiedError
            import traceback, logging
            logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
            raise SMPUnclassifiedError(str(e))
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
        except Exception as e:
            from tools.errors import SMPUnclassifiedError
            import traceback, logging
            logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
            raise SMPUnclassifiedError(str(e))
            pass

        # 4. Starting background schedulers
        self.progress.emit(95, "Booting up background schedulers...")
        try:
            from tools.scheduler import start_scheduler
            start_scheduler()
        except Exception as e:
            from tools.errors import SMPUnclassifiedError
            import traceback, logging
            logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
            raise SMPUnclassifiedError(str(e))
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
        self.final_title = "SMP"
        self.lbl_title = QLabel(self.final_title)
        self.lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_title.setStyleSheet("background-color: transparent; color: #FFFFFF; font-size: 36px; font-weight: 800; letter-spacing: 2px; font-family: monospace;")
        layout.addWidget(self.lbl_title)

        import json
        import os
        version = "V9.4.2"
        try:
            metadata_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", "metadata.json")
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                version = metadata.get("version", "V9.4.2")
        except Exception as e:
            from tools.errors import SMPUnclassifiedError
            import traceback, logging
            logging.getLogger('smp').error(f'Unexpected error: {e}\n{traceback.format_exc()}')
            raise SMPUnclassifiedError(str(e))
            pass

        self.final_subtitle = f"SECURITY PLATFORM • {version}"
        self.lbl_subtitle = QLabel(self.final_subtitle)
        self.lbl_subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_subtitle.setStyleSheet("background-color: transparent; color: #007AFF; font-size: 12px; font-weight: 600; letter-spacing: 1px; font-family: monospace;")
        layout.addWidget(self.lbl_subtitle)
        
        # Matrix Decoding Timer
        self.decode_ticks = 0
        self.decode_timer = QTimer(self)
        self.decode_timer.timeout.connect(self._animate_matrix_decode)
        self.decode_timer.start(50)

        layout.addSpacing(30)

        # Progress Label
        self.lbl_status = QLabel("> [SYS] Initializing engine...")
        self.lbl_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_status.setStyleSheet("background-color: transparent; color: #34C759; font-size: 11px; font-family: monospace;")
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

    def update_progress(self, val, text):
        self.progress.setValue(val)
        self.lbl_status.setText(f"> [SYS] {text}")
        if val >= 100:
            self.close()

    def _animate_matrix_decode(self):
        self.decode_ticks += 1
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;':,./<>?"
        
        revealed_count_sub = self.decode_ticks // 2
        revealed_count_title = self.decode_ticks // 4
        
        if revealed_count_sub >= len(self.final_subtitle):
            self.lbl_subtitle.setText(self.final_subtitle)
            self.lbl_title.setText(self.final_title)
            self.decode_timer.stop()
            return
            
        display_sub = ""
        for i in range(len(self.final_subtitle)):
            if i < revealed_count_sub:
                display_sub += self.final_subtitle[i]
            elif self.final_subtitle[i] == " ":
                display_sub += " "
            else:
                display_sub += random.choice(chars)
                
        self.lbl_subtitle.setText(display_sub)

        display_title = ""
        for i in range(len(self.final_title)):
            if i < revealed_count_title:
                display_title += self.final_title[i]
            else:
                display_title += random.choice(chars)
                
        self.lbl_title.setText(display_title)
