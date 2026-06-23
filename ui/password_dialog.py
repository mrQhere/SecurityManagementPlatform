# =============================================================================
# PROPRIETARY SOFTWARE — ALL RIGHTS RESERVED
# Security Management Platform (SMP)
# Owner: Authorised Personnel Only
#
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  ⚠  CRITICAL NOTICE — Read way.md before ANY changes.                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# =============================================================================
"""
Password Dialog — GUI popup prompting for Master Password initialization or validation.
"""

from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
import logging
logger = logging.getLogger('smp')
from tools.encryption_manager import has_password_set, setup_password, verify_password, decrypt_databases

class PasswordDialog(QDialog):
    def __init__(self, parent=None, is_setup=False):
        super().__init__(parent)
        self.is_setup = is_setup
        self.success = False
        
        self.setWindowTitle("SMP Security Lock" if not is_setup else "SMP Master Password Setup")
        self.setFixedSize(400, 200 if not is_setup else 250)
        self.setWindowFlags(Qt.Window | Qt.CustomizeWindowHint | Qt.WindowTitleHint)
        
        # Apply glassmorphism theme (light mode for dialog)
        try:
            from .theme import apply_theme
            apply_theme(self, dark_mode=False)
        except Exception as e:
            logger.warning(f"Theme application failed: {e}")
        # Ensure user has accepted responsibility disclaimer before proceeding
        from .responsibility_dialog import ResponsibilityDialog
        if not load_responsibility_flag():
            dlg = ResponsibilityDialog(self)
            if dlg.exec() != QDialog.Accepted:
                self.reject()
                return
        
        self._setup_ui()
        
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)
        
        # Header Info
        header_text = (
            "Create a Master Password to encrypt and secure target databases and findings:"
            if self.is_setup else
            "Enter Master Password to decrypt targets and database findings:"
        )
        self.lbl_info = QLabel(header_text)
        self.lbl_info.setWordWrap(True)
        layout.addWidget(self.lbl_info)
        
        # Input Field
        self.txt_pass = QLineEdit()
        self.txt_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_pass.setPlaceholderText("Password")
        self.txt_pass.returnPressed.connect(self.handle_submit)
        layout.addWidget(self.txt_pass)
        
        if self.is_setup:
            self.txt_confirm = QLineEdit()
            self.txt_confirm.setEchoMode(QLineEdit.EchoMode.Password)
            self.txt_confirm.setPlaceholderText("Confirm Password")
            self.txt_confirm.returnPressed.connect(self.handle_submit)
            layout.addWidget(self.txt_confirm)
            
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        self.btn_cancel = QPushButton("Exit")
        self.btn_cancel.setObjectName("btn_cancel")
        self.btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(self.btn_cancel)
        
        self.btn_ok = QPushButton("Unlock" if not self.is_setup else "Create Password")
        self.btn_ok.clicked.connect(self.handle_submit)
        btn_layout.addWidget(self.btn_ok)
        
        layout.addLayout(btn_layout)
        
    def handle_submit(self):
        password = self.txt_pass.text().strip()
        if not password:
            QMessageBox.warning(self, "Invalid Entry", "Password cannot be empty.")
            return
            
        if self.is_setup:
            confirm = self.txt_confirm.text().strip()
            if password != confirm:
                QMessageBox.warning(self, "Mismatch", "Passwords do not match.")
                return
            setup_password(password)
            QMessageBox.information(self, "Success", "Master Password successfully configured and databases secured.")
            self.success = True
            self.accept()
        else:
            if verify_password(password):
                decrypt_databases()
                self.success = True
                self.accept()
            else:
                QMessageBox.critical(self, "Authentication Failed", "Incorrect Master Password.")
                self.txt_pass.clear()
                self.txt_pass.setFocus()

def run_password_protection() -> bool:
    """Run verification dialog; returns True if unlocked/set successfully."""
    if not has_password_set():
        dialog = PasswordDialog(is_setup=True)
    else:
        dialog = PasswordDialog(is_setup=False)
        
    dialog.exec()
    return dialog.success
