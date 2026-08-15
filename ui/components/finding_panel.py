import json
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, 
    QPushButton, QScrollArea, QFrame, QApplication
)
from PySide6.QtCore import Qt, QPropertyAnimation, QRect, QEasingCurve
from PySide6.QtGui import QClipboard

class FindingDetailPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(480)
        self.setStyleSheet("background-color: #151820; color: #E8EAED; border-left: 1px solid #1E2330;")
        
        # Will hold the finding data for copying
        self.current_finding = {}
        
        # Setup Animation
        self.animation = QPropertyAnimation(self, b"maximumWidth")
        self.animation.setDuration(250)
        self.animation.setEasingCurve(QEasingCurve.OutCubic)
        self.setMaximumWidth(0)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Scroll Area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("""
            QScrollArea { border: none; }
            QScrollBar:vertical {
                border: none;
                background: #0D0F14;
                width: 8px;
                margin: 0px 0px 0px 0px;
            }
            QScrollBar::handle:vertical {
                background: #2A2A2A;
                min-height: 20px;
                border-radius: 4px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        
        content_widget = QWidget()
        self.content_layout = QVBoxLayout(content_widget)
        self.content_layout.setContentsMargins(20, 20, 20, 20)
        self.content_layout.setSpacing(15)
        
        # 1. Header
        header_layout = QHBoxLayout()
        self.severity_badge = QLabel("SEVERITY")
        self.severity_badge.setStyleSheet("background-color: #FF3D5A; color: #000000; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 10px;")
        
        self.title_label = QLabel("Finding Title")
        self.title_label.setWordWrap(True)
        self.title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        
        self.close_btn = QPushButton("X")
        self.close_btn.setFixedSize(24, 24)
        self.close_btn.setStyleSheet("QPushButton { background-color: transparent; color: #8A94A6; border: none; font-weight: bold; } QPushButton:hover { color: #E8EAED; background-color: #2A2A2A; border-radius: 12px; }")
        self.close_btn.clicked.connect(self.hide_panel)
        
        header_layout.addWidget(self.severity_badge)
        header_layout.addWidget(self.title_label, 1)
        header_layout.addWidget(self.close_btn)
        
        self.content_layout.addLayout(header_layout)
        
        # 2. Meta row
        self.meta_label = QLabel()
        self.meta_label.setStyleSheet("color: #8A94A6; font-size: 12px;")
        self.content_layout.addWidget(self.meta_label)
        
        # 3. Description
        desc_label = QLabel("DESCRIPTION")
        desc_label.setStyleSheet("color: #8A94A6; font-size: 10px; font-weight: bold;")
        self.content_layout.addWidget(desc_label)
        
        self.desc_edit = QTextEdit()
        self.desc_edit.setReadOnly(True)
        self.desc_edit.setStyleSheet("background-color: #0D0F14; border: 1px solid #1E2330; border-radius: 4px; padding: 8px;")
        self.desc_edit.setMinimumHeight(100)
        self.content_layout.addWidget(self.desc_edit)
        
        # 4. Remediation
        rem_label = QLabel("REMEDIATION")
        rem_label.setStyleSheet("color: #8A94A6; font-size: 10px; font-weight: bold;")
        self.content_layout.addWidget(rem_label)
        
        self.rem_edit = QTextEdit()
        self.rem_edit.setReadOnly(True)
        self.rem_edit.setStyleSheet("background-color: rgba(0, 201, 167, 0.1); border: 1px solid rgba(0, 201, 167, 0.3); border-radius: 4px; padding: 8px; color: #E8EAED;")
        self.rem_edit.setMinimumHeight(80)
        self.content_layout.addWidget(self.rem_edit)
        
        # 5. Evidence
        ev_label = QLabel("EVIDENCE")
        ev_label.setStyleSheet("color: #8A94A6; font-size: 10px; font-weight: bold;")
        self.content_layout.addWidget(ev_label)
        
        self.evidence_label = QLabel()
        self.evidence_label.setWordWrap(True)
        self.evidence_label.setStyleSheet("font-family: monospace; background-color: #0D0F14; border: 1px solid #1E2330; border-radius: 4px; padding: 8px; font-size: 11px;")
        self.content_layout.addWidget(self.evidence_label)
        
        # 6. Provenance
        prov_label = QLabel("PROVENANCE")
        prov_label.setStyleSheet("color: #8A94A6; font-size: 10px; font-weight: bold;")
        self.content_layout.addWidget(prov_label)
        
        self.provenance_label = QLabel()
        self.provenance_label.setStyleSheet("color: #A0AABF; font-size: 12px;")
        self.content_layout.addWidget(self.provenance_label)
        
        self.content_layout.addStretch()
        
        # 7. Copy Button
        self.copy_btn = QPushButton("Copy Finding JSON")
        self.copy_btn.setStyleSheet("QPushButton { background-color: #2A2A2A; color: #E8EAED; border: none; padding: 10px; border-radius: 4px; } QPushButton:hover { background-color: #3A3A3A; }")
        self.copy_btn.clicked.connect(self._copy_json)
        self.content_layout.addWidget(self.copy_btn)
        
        scroll_area.setWidget(content_widget)
        main_layout.addWidget(scroll_area)
        
    def _copy_json(self):
        cb = QApplication.clipboard()
        cb.setText(json.dumps(self.current_finding, indent=2))
        
    def show_finding(self, finding: dict):
        self.current_finding = finding
        
        severity_colors = {
            "Critical": "#FF3D5A",
            "High": "#FF8C42",
            "Medium": "#FFD700",
            "Low": "#00C9A7",
            "Info": "#00D4FF"
        }
        
        severity = finding.get("severity", "Info")
        color = severity_colors.get(severity, "#00D4FF")
        text_color = "#000000" if severity in ["Medium", "Low", "High"] else "#FFFFFF" # Contrast adjustment
        
        self.severity_badge.setText(severity.upper())
        self.severity_badge.setStyleSheet(f"background-color: {color}; color: {text_color}; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 10px;")
        
        self.title_label.setText(finding.get("title", "Untitled Finding"))
        
        # Meta row
        cve = finding.get("cve", "No CVE")
        cvss = finding.get("cvss", "N/A")
        epss = finding.get("epss", "N/A")
        kev = " | KEV" if finding.get("kev") else ""
        self.meta_label.setText(f"{cve} | CVSS: {cvss} | EPSS: {epss}{kev}")
        
        self.desc_edit.setText(finding.get("description", ""))
        self.rem_edit.setText(finding.get("remediation", ""))
        
        evidence = finding.get("evidence", [])
        if isinstance(evidence, list):
            self.evidence_label.setText("\\n".join(evidence) if evidence else "No evidence provided.")
        else:
            self.evidence_label.setText(str(evidence))
            
        scanner = finding.get("scanner", "Unknown")
        date = finding.get("scan_date", "Unknown")
        conf = finding.get("confidence", "Unknown")
        self.provenance_label.setText(f"Scanner: {scanner}\\nDate: {date}\\nConfidence: {conf}")
        
        self.animation.setStartValue(self.maximumWidth())
        self.animation.setEndValue(480)
        self.animation.start()
        
    def hide_panel(self):
        self.animation.setStartValue(self.maximumWidth())
        self.animation.setEndValue(0)
        self.animation.start()
