import os
from PySide6.QtGui import QFontDatabase

# Theme definitions
class Theme:
    # Colors (Ollama-style minimalist)
    LIGHT_BG = "#FFFFFF"
    DARK_BG = "#000000"
    PRIMARY = "#FFFFFF"
    SECONDARY = "#1A1A1A"
    TEXT_LIGHT = "#000000"
    TEXT_DARK = "#FFFFFF"
    ACCENT = "#FFFFFF"
    ACCENT_HOVER = "#DDDDDD"

    @staticmethod
    def load_fonts():
        # Load Google Font Inter from local assets if available, else fallback
        font_path = os.path.join(os.path.dirname(__file__), "..", "assets", "Inter-Regular.ttf")
        if os.path.exists(font_path):
            QFontDatabase.addApplicationFont(font_path)

def apply_theme(widget, dark_mode: bool = True):
    """Apply glassmorphism style to a QWidget or QDialog.
    dark_mode: toggle dark/light palette.
    """
    Theme.load_fonts()
    qss_path = os.path.join(os.path.dirname(__file__), "style.qss")
    if os.path.exists(qss_path):
        with open(qss_path, "r") as f:
            stylesheet = f.read()
        widget.setStyleSheet(stylesheet)
    else:
        # Fallback if style.qss is missing
        pass
