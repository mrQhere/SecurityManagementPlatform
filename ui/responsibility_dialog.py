import os
from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QCheckBox, QPushButton, QMessageBox
from PySide6.QtCore import Qt
from .theme import apply_theme
from tools.responsibility_manager import load_responsibility_flag, set_responsibility_flag

class ResponsibilityDialog(QDialog):
    """Show a disclaimer and require the user to accept responsibility before using the tool."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Responsibility Disclaimer")
        self.setFixedSize(500, 250)
        self.setWindowFlags(Qt.Window | Qt.CustomizeWindowHint | Qt.WindowTitleHint)

        # Simple stylesheet for consistency (will be overridden by theme)
        self.setStyleSheet("""
            QDialog { background-color: #FFFFFF; }
            QLabel { color: #1C1C1E; font-size: 13px; }
            QPushButton { background-color: #007AFF; color: #FFF; border: none; border-radius: 8px; padding: 8px 16px; }
            QPushButton:hover { background-color: #0071EB; }
        """)
        try:
            apply_theme(self, dark_mode=False)
        except Exception as e:
            # Non‑critical – UI will still work
            pass

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        disclaimer = (
            "By using Security Management Platform you acknowledge that you are fully responsible "
            "for any consequences, data loss, security incidents, or legal ramifications that may "
            "arise from its use. The developers provide no warranty or liability."
        )
        lbl = QLabel(disclaimer)
        lbl.setWordWrap(True)
        layout.addWidget(lbl)

        self.chk_accept = QCheckBox("I have read and accept the responsibility disclaimer.")
        layout.addWidget(self.chk_accept)

        btn_layout = QVBoxLayout()
        self.btn_ok = QPushButton("Continue")
        self.btn_ok.clicked.connect(self._on_accept)
        btn_layout.addWidget(self.btn_ok)
        layout.addLayout(btn_layout)

    def _on_accept(self):
        if not self.chk_accept.isChecked():
            QMessageBox.warning(self, "Acceptance Required", "You must check the box to proceed.")
            return
        set_responsibility_flag(True)
        self.accept()
