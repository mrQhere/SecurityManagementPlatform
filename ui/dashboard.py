"""
SMP V9.5 — Main Dashboard Window
Combines DashboardLayoutMixin and DashboardLogicMixin via multiple inheritance.
"""
import os, sys
from PySide6.QtWidgets import QMainWindow, QApplication
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIcon, QFont

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ui.views.dashboard_layout import DashboardLayoutMixin
from ui.controllers.dashboard_logic import DashboardLogicMixin
from ui.theme import apply_theme

class DashboardWindow(QMainWindow, DashboardLayoutMixin, DashboardLogicMixin):
    def __init__(self, parent=None, operator_name='Unknown'):
        super().__init__(parent)
        self._operator_name = operator_name
        self._active_workers = {}
        self._findings_cache = []
        self.setWindowTitle('Security Management Platform V9.5')
        self.setMinimumSize(1280, 800)
        self.resize(1440, 900)
        self._setup_ui()
        apply_theme(self)
        self._connect_signals()
        QTimer.singleShot(200, self._init_logic)
    
    def closeEvent(self, event):
        for worker in self._active_workers.values():
            if worker.isRunning():
                worker.quit()
                worker.wait(2000)
        if hasattr(self, 'udp_thread') and self.udp_thread.isRunning():
            self.udp_thread.stop()
            self.udp_thread.wait(2000)
        if hasattr(self, '_poll_timer'):
            self._poll_timer.stop()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = DashboardWindow(operator_name='Dev')
    window.show()
    sys.exit(app.exec())
