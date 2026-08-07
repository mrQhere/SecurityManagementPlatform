import os
from PySide6.QtGui import QFontDatabase

# ─── Canonical Design Tokens ─────────────────────────────────────────────────
# Single source of truth for all colors used across the UI.
# Python code should import from here instead of hardcoding hex strings.
COLORS = {
    # Backgrounds
    "bg_base":       "#0A0A0B",   # True black base
    "bg_card":       "#121215",   # Card surface
    "bg_raised":     "#1A1A1F",   # Hover/input backgrounds
    "bg_table":      "#0D0D0D",   # Table background

    # Borders
    "border":        "#1E1E1E",   # Default border
    "border_muted":  "#252525",   # Subtle separator

    # Text
    "text_primary":  "#E8E8F0",   # Main readable text
    "text_secondary":"#CCCCCC",   # Secondary text
    "text_muted":    "#555555",   # Muted / labels
    "text_disabled": "#333333",   # Disabled state

    # Semantic accents — never mix contexts
    "accent_blue":   "#3B82F6",   # Primary action (CTA, running)
    "accent_green":  "#22C55E",   # Success, completed, enabled
    "accent_red":    "#EF4444",   # Error, critical, danger
    "accent_amber":  "#F59E0B",   # Warning, in-progress, paused
    "accent_purple": "#A855F7",   # Intelligence / Brain page
    "accent_white":  "#FFFFFF",   # High-contrast accent

    # Severity semantic colors
    "sev_critical":  "#EF4444",
    "sev_high":      "#F97316",
    "sev_medium":    "#F59E0B",
    "sev_low":       "#3B82F6",
    "sev_info":      "#6B7280",
}

# Theme definitions
class Theme:
    # Legacy constants — prefer COLORS dict above for new code
    LIGHT_BG = "#FFFFFF"
    DARK_BG = "#0A0A0B"
    PRIMARY = "#FFFFFF"
    SECONDARY = "#1A1A1A"
    TEXT_LIGHT = "#000000"
    TEXT_DARK = "#E8E8F0"
    ACCENT = COLORS["accent_blue"]
    ACCENT_HOVER = "#2563EB"

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
