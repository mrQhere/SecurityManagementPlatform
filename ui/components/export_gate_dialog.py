import datetime
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QLineEdit, QPushButton, QFrame, QSizePolicy
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QFont, QIcon

class ExportGateDialog(QDialog):
    def __init__(self, parent=None, engagement_id='', target='', export_format='', estimated_files=0, operator=''):
        super().__init__(parent)
        self._confirmed = False
        self._confirmed_at = ""
        
        self.setWindowTitle("Export Confirmation")
        self.setWindowFlags(self.windowFlags() | Qt.WindowMaximizeButtonHint)
        self.showFullScreen()
        self.setStyleSheet("background-color: #0D0F14; color: #E8EAED;")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)
        
        # Header
        header_layout = QHBoxLayout()
        warning_icon = QLabel()
        # Fallback text if icon is not available, but styled appropriately
        warning_icon.setText("⚠️") 
        warning_icon.setStyleSheet("color: #FF3D5A; font-size: 32px;")
        
        header_label = QLabel("PLAINTEXT DATA EXPORT — LEGAL ACKNOWLEDGMENT REQUIRED")
        header_label.setStyleSheet("color: #FF3D5A; font-size: 24px; font-weight: bold;")
        
        header_layout.addWidget(warning_icon)
        header_layout.addWidget(header_label)
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Details Card
        details_card = QFrame()
        details_card.setStyleSheet("background-color: #151820; border: 1px solid #1E2330; border-radius: 8px;")
        details_layout = QVBoxLayout(details_card)
        
        details_text = (f"<b>Engagement ID:</b> {engagement_id}<br>"
                        f"<b>Target:</b> {target}<br>"
                        f"<b>Export Format:</b> {export_format}<br>"
                        f"<b>Estimated Files:</b> {estimated_files}<br>"
                        f"<b>Operator:</b> {operator}")
        details_label = QLabel(details_text)
        details_label.setStyleSheet("font-size: 14px; border: none;")
        details_layout.addWidget(details_label)
        
        layout.addWidget(details_card)
        
        # Legal Text
        legal_text = (
            "This export operation will produce UNENCRYPTED plaintext data containing sensitive vulnerability findings, asset information, service enumeration data, and security intelligence gathered during authorised penetration testing.\n\n"
            "Once exported, this data is NO LONGER protected by the Security Management Platform's AES-256 encryption layer. You become solely and fully responsible for:\n\n"
            "• Securing this data at rest (encryption, access controls)\n"
            "• Securing this data in transit (TLS, secure channels only)\n"
            "• Restricting access to authorised personnel only\n"
            "• Complying with all applicable data protection regulations (GDPR, HIPAA, PCI-DSS, etc.)\n"
            "• Not sharing this data with unauthorised third parties\n"
            "• Properly disposing of this data when no longer required\n\n"
            "This export will be permanently recorded in the encrypted audit log including: your identity, timestamp, engagement details, and a cryptographic hash of the exported payload. This record cannot be deleted.\n\n"
            "By typing \"I AGREE\" below you confirm that:\n"
            "• You are an authorised operator of this platform\n"
            "• You have a valid legal basis for conducting this export\n"
            "• You accept full legal and operational responsibility for securing this data\n"
            "• You understand this action is logged and non-repudiable"
        )
        self.legal_edit = QTextEdit()
        self.legal_edit.setReadOnly(True)
        self.legal_edit.setText(legal_text)
        self.legal_edit.setStyleSheet("background-color: #0D0F14; border: 1px solid #1E2330; padding: 10px; font-size: 14px;")
        layout.addWidget(self.legal_edit, 1)
        
        # Input
        self.gate_input = QLineEdit()
        self.gate_input.setObjectName("gate_input")
        self.gate_input.setPlaceholderText("Type I AGREE to confirm...")
        self.gate_input.setStyleSheet("QLineEdit { background-color: #151820; border: 1px solid #1E2330; padding: 10px; font-size: 16px; border-radius: 4px; } QLineEdit:focus { border: 1px solid #FF3D5A; }")
        self.gate_input.textChanged.connect(self._on_text_changed)
        layout.addWidget(self.gate_input)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setObjectName("btn_cancel")
        self.btn_cancel.setStyleSheet("QPushButton { background-color: #2A2A2A; border: none; padding: 10px 20px; font-size: 16px; border-radius: 4px; } QPushButton:hover { background-color: #3A3A3A; }")
        self.btn_cancel.clicked.connect(self.reject)
        
        self.btn_export = QPushButton("Export Data")
        self.btn_export.setObjectName("btn_export")
        self.btn_export.setEnabled(False)
        self.btn_export.setStyleSheet("QPushButton { background-color: #FF3D5A; color: white; border: none; padding: 10px 20px; font-size: 16px; border-radius: 4px; font-weight: bold; } QPushButton:disabled { background-color: #2A2A2A; color: #8A94A6; } QPushButton:hover:!disabled { background-color: #ff5e77; }")
        self.btn_export.clicked.connect(self._on_confirmed)
        
        button_layout.addWidget(self.btn_cancel)
        button_layout.addWidget(self.btn_export)
        layout.addLayout(button_layout)
        
    def _on_text_changed(self, text):
        self.btn_export.setEnabled(text.strip() == "I AGREE")
        
    def _on_confirmed(self):
        self._confirmed = True
        self._confirmed_at = datetime.datetime.now().isoformat()
        self.accept()
        
    @property
    def is_confirmed(self) -> bool:
        return self._confirmed
        
    @property
    def confirmed_at(self) -> str:
        return self._confirmed_at
