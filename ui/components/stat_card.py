from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel
from PySide6.QtCore import Qt

class StatCard(QFrame):
    def __init__(self, title: str, value: str='0', subtitle: str='', severity_color: str='#00D4FF', parent=None):
        super().__init__(parent)
        self.setObjectName("stat_card")
        self.severity_color = severity_color
        
        self._apply_style()
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(5)
        
        self.title_label = QLabel(title.upper())
        self.title_label.setStyleSheet("color: #8A94A6; font-size: 10px; font-weight: bold; letter-spacing: 1px;")
        
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet("color: #E8EAED; font-size: 28px; font-weight: bold;")
        
        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setStyleSheet("color: #4A5568; font-size: 11px;")
        
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.subtitle_label)
        
    def _apply_style(self):
        self.setStyleSheet(f"""
            QFrame#stat_card {{
                background-color: #151820;
                border: 1px solid #1E2330;
                border-radius: 8px;
                border-left: 3px solid {self.severity_color};
            }}
        """)
        
    def set_value(self, value: str):
        self.value_label.setText(value)
        
    def set_severity(self, color: str):
        self.severity_color = color
        self._apply_style()
        
    def set_trend(self, delta: float):
        if delta > 0:
            trend_text = f"<span style='color: #00C9A7;'>▲ +{delta}</span>"
        elif delta < 0:
            trend_text = f"<span style='color: #FF3D5A;'>▼ {delta}</span>"
        else:
            trend_text = f"<span style='color: #8A94A6;'>— {delta}</span>"
            
        current_subtitle = self.subtitle_label.text().split("<span")[0].strip()
        self.subtitle_label.setText(f"{current_subtitle} {trend_text}")
