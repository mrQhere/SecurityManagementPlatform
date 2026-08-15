import sys
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                               QLineEdit, QPushButton, QTextEdit, QApplication, QFrame)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

class ResponsibilityDialog(QDialog):
    def __init__(self, parent=None, target_url='', operator=''):
        super().__init__(parent)
        self.target_url = target_url
        self.operator = operator
        self.is_accepted = False
        self.attestation_text = ""
        self.setWindowTitle("Authorization Required")
        self.setFixedSize(600, 700)
        self.scrolled_to_bottom = False
        
        self._init_ui()
        self._apply_styles()
        
    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("⚠️ AUTHORISATION REQUIRED")
        header.setFont(QFont("Arial", 18, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("color: #FF8C42;")
        layout.addWidget(header)
        
        # Target Box
        target_box = QFrame()
        target_box.setStyleSheet("background-color: #1A1F2E; border: 1px solid #2A2F3D; border-radius: 8px;")
        target_layout = QVBoxLayout(target_box)
        target_label = QLabel("Target for Security Assessment:")
        target_label.setStyleSheet("color: #A0A0A0;")
        target_value = QLabel(self.target_url if self.target_url else "N/A")
        target_value.setFont(QFont("Arial", 14, QFont.Bold))
        target_value.setStyleSheet("color: #FFFFFF;")
        target_layout.addWidget(target_label)
        target_layout.addWidget(target_value)
        layout.addWidget(target_box)
        
        # Legal Text
        self.legal_text = QTextEdit()
        self.legal_text.setReadOnly(True)
        self.legal_text.setText(self._get_legal_text())
        self.legal_text.verticalScrollBar().valueChanged.connect(self._on_scroll)
        layout.addWidget(self.legal_text)
        
        # Confirmation
        self.confirm_label1 = QLabel("To confirm, type:")
        self.confirm_label1.setStyleSheet("color: #A0A0A0;")
        self.confirm_label2 = QLabel("I accept full legal responsibility for scanning this target.")
        self.confirm_label2.setStyleSheet("color: #F87171; font-weight: bold;")
        
        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Type the exact phrase above...")
        self.confirm_input.setEnabled(False)
        self.confirm_input.textChanged.connect(self._on_text_changed)
        
        layout.addWidget(self.confirm_label1)
        layout.addWidget(self.confirm_label2)
        layout.addWidget(self.confirm_input)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        
        self.accept_btn = QPushButton("I Accept")
        self.accept_btn.setEnabled(False)
        self.accept_btn.clicked.connect(self._on_accept)
        
        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addWidget(self.accept_btn)
        layout.addLayout(btn_layout)

    def _apply_styles(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #0D0F14;
            }
            QTextEdit {
                background-color: #151820;
                color: #D1D5DB;
                border: 1px solid #2A2F3D;
                border-radius: 6px;
                padding: 10px;
            }
            QLineEdit {
                background-color: #151820;
                border: 1px solid #2A2F3D;
                border-radius: 6px;
                color: #FFFFFF;
                padding: 8px;
            }
            QLineEdit:disabled {
                background-color: #2A2F3D;
                color: #9CA3AF;
            }
            QPushButton {
                background-color: #1A1F2E;
                color: white;
                border: 1px solid #2A2F3D;
                border-radius: 6px;
                padding: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2A2F3D;
            }
            QPushButton#accept_btn {
                background-color: #FF8C42;
                color: #0D0F14;
            }
            QPushButton#accept_btn:disabled {
                background-color: #4B5563;
                color: #9CA3AF;
            }
        """)
        self.accept_btn.setObjectName("accept_btn")

    def _get_legal_text(self):
        return (
            "LEGAL ATTESTATION AND LIABILITY WAIVER\n\n"
            "This software is provided for authorized security testing and administrative purposes only. "
            "By proceeding with this scan, you explicitly acknowledge and attest that you possess the "
            "necessary written authorization from the owner(s) of the target infrastructure and data "
            "to perform these activities.\n\n"
            "1. WRITTEN AUTHORIZATION REQUIREMENT\n"
            "You affirm that you have documented, legally binding consent to interact with the target "
            "systems. Unstructured or verbal consent is insufficient. You agree to produce this documentation "
            "upon request by legal authorities or the software vendors.\n\n"
            "2. SCOPE LIMITATION\n"
            "Your actions are restricted exclusively to the explicitly authorized scope. Any deviation, "
            "intentional or unintentional, that impacts external systems, neighboring networks, or third-party "
            "services is your sole responsibility.\n\n"
            "3. LEGAL LIABILITY\n"
            "Under no circumstances shall the creators, maintainers, or distributors of this Security Management "
            "Platform be held liable for any direct, indirect, incidental, or consequential damages resulting from "
            "the use of this software. You bear complete personal and professional liability for any disruptions, "
            "data loss, or regulatory violations.\n\n"
            "4. DATA HANDLING AND NON-DISCLOSURE\n"
            "Any vulnerabilities discovered or sensitive data accessed during this assessment must be handled "
            "in strict adherence with prevailing data protection laws (e.g., GDPR, CCPA, HIPAA). Unauthorized "
            "disclosure, sale, or exploitation of findings is strictly prohibited and constitutes a material breach "
            "of this agreement.\n\n"
            "5. COMPLIANCE OBLIGATIONS\n"
            "You agree to comply with all applicable local, national, and international laws regarding cyber "
            "activities, including but not limited to the Computer Fraud and Abuse Act (CFAA) in the United States, "
            "and equivalent legislation in your jurisdiction.\n\n"
            "Failure to abide by these terms may result in civil or criminal prosecution. Scroll to the bottom "
            "to acknowledge and accept these terms in their entirety."
        )

    def _on_scroll(self, value):
        if not self.scrolled_to_bottom:
            scrollbar = self.legal_text.verticalScrollBar()
            if value >= scrollbar.maximum() - 10:
                self.scrolled_to_bottom = True
                self.confirm_input.setEnabled(True)

    def _on_text_changed(self, text):
        expected = "I accept full legal responsibility for scanning this target."
        if text.strip() == expected:
            self.accept_btn.setEnabled(True)
        else:
            self.accept_btn.setEnabled(False)

    def _on_accept(self):
        self.is_accepted = True
        self.attestation_text = self.confirm_input.text()
        try:
            from tools import responsibility_manager
            responsibility_manager.set_target_attestation(self.target_url, self.operator)
        except Exception:
            pass
        self.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    d = ResponsibilityDialog(target_url="https://example.com")
    d.show()
    sys.exit(app.exec())
