from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QCheckBox, QPushButton, QMessageBox
from PySide6.QtCore import Qt
from tools.responsibility_manager import load_responsibility_flag, set_responsibility_flag

class ResponsibilityDialog(QDialog):
    """Show a disclaimer and require the user to accept responsibility before using the tool."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Responsibility Disclaimer")
        self.setFixedSize(500, 250)
        self.setWindowFlags(Qt.Window | Qt.CustomizeWindowHint | Qt.WindowTitleHint)

        # Dark minimalist style
        self.setStyleSheet("""
            QDialog {
                background-color: #0D0D0D;
                color: #CCCCCC;
                font-family: -apple-system, 'SF Pro Text', 'Helvetica Neue', Arial, sans-serif;
            }
            QLabel { color: #AAAAAA; font-size: 13px; background: transparent; }
            QCheckBox { color: #CCCCCC; font-size: 13px; spacing: 10px; }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 1.5px solid #555555;
                background-color: #111111;
            }
            QCheckBox::indicator:hover {
                border-color: #888888;
                background-color: #1A1A1A;
            }
            QCheckBox::indicator:checked {
                background-color: #D8D8D8;
                border: 2px solid #BBBBBB;
            }
            QPushButton {
                background-color: #1E1E1E;
                color: #DDDDDD;
                border: 1px solid #333333;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 13px;
            }
            QPushButton:hover { background-color: #282828; color: #FFFFFF; border-color: #555555; }
        """)

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

        from datetime import datetime
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.lbl_timestamp = QLabel(f"Confirmation timestamp: {now}")
        self.lbl_timestamp.setStyleSheet("color: #777777; font-size: 11px;")
        layout.addWidget(self.lbl_timestamp)

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
