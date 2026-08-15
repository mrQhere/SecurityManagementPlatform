import os
from PySide6.QtGui import QFontDatabase, QFont
from PySide6.QtWidgets import QApplication

COLORS = {
    "bg_base": "#0D0F14",
    "bg_card": "#151820",
    "bg_sidebar": "#0A0C10",
    "border_subtle": "#1E2330",
    "border_accent": "#2A3045",
    "text_primary": "#E8EAED",
    "text_secondary": "#8A94A6",
    "text_muted": "#4A5568",
    "accent_cyan": "#00D4FF",
    "accent_green": "#00E676",
    "accent_blue": "#3B82F6",
    "sev_critical": "#FF3D5A",
    "sev_high": "#FF8C42",
    "sev_medium": "#FFD700",
    "sev_low": "#00C9A7",
    "sev_info": "#00D4FF",
}

FONTS = {
    "Inter_Regular": 10,
    "Inter_Bold": 12,
    "Inter_Header": 16,
}

SPACING = {
    "padding_small": 8,
    "padding_medium": 16,
    "padding_large": 24,
    "margin_small": 8,
    "margin_medium": 16,
    "margin_large": 24,
    "border_radius": 8,
}

SEVERITY_COLORS = {
    "Critical": COLORS["sev_critical"],
    "High": COLORS["sev_high"],
    "Medium": COLORS["sev_medium"],
    "Low": COLORS["sev_low"],
    "Info": COLORS["sev_info"],
}

SEVERITY_BG = {
    "Critical": "rgba(255, 61, 90, 0.2)",
    "High": "rgba(255, 140, 66, 0.2)",
    "Medium": "rgba(255, 215, 0, 0.2)",
    "Low": "rgba(0, 201, 167, 0.2)",
    "Info": "rgba(0, 212, 255, 0.2)",
}

def apply_theme(widget):
    """Loads the Inter font if available and applies style.qss to the widget."""
    font_path = "/home/dxt/SecurityManagementPlatform/ui/static/Inter-Regular.ttf"
    if os.path.exists(font_path):
        QFontDatabase.addApplicationFont(font_path)
        app = QApplication.instance()
        if app:
            app.setFont(QFont("Inter", FONTS["Inter_Regular"]))
    
    qss_path = "/home/dxt/SecurityManagementPlatform/ui/style.qss"
    if os.path.exists(qss_path):
        with open(qss_path, "r", encoding="utf-8") as f:
            widget.setStyleSheet(f.read())
