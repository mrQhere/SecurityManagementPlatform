import os
from PySide6.QtGui import QFontDatabase

# Theme definitions
class Theme:
    # Colors (glassmorphism style) - using semi-transparent whites for light mode and dark for dark mode
    LIGHT_BG = "rgba(255, 255, 255, 0.6)"
    DARK_BG = "rgba(30, 30, 30, 0.6)"
    PRIMARY = "#0066FF"
    SECONDARY = "#F2F2F7"
    TEXT_LIGHT = "#1C1C1E"
    TEXT_DARK = "#E5E5EA"
    ACCENT = "#007AFF"
    ACCENT_HOVER = "#0071EB"

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
