"""
System Check Dialog V7.0.5
=========================
Shows a pre-scan warning dialog when system resources are low.
Gives the analyst a "Continue Anyway" or "Cancel" choice.
"""
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QWidget
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor


class SystemCheckDialog(QDialog):
    """
    Pre-scan resource warning dialog.
    
    Shows detected issues and lets the analyst decide whether to continue.
    """

    def __init__(self, check_result: dict, parent=None):
        super().__init__(parent)
        self.check_result = check_result
        self.setWindowTitle("⚠️  System Resource Warning")
        self.setMinimumWidth(520)
        self.setModal(True)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        header = QLabel("⚠️  System Resources Warning")
        header_font = QFont()
        header_font.setPointSize(14)
        header_font.setBold(True)
        header.setFont(header_font)
        header.setStyleSheet("color: #E65100;")
        layout.addWidget(header)

        # Metrics bar
        metrics = self.check_result.get("metrics", {})
        metrics_frame = QFrame()
        metrics_frame.setStyleSheet("background: #FFF3E0; border-radius: 6px; padding: 10px;")
        metrics_layout = QHBoxLayout(metrics_frame)
        for label, value in [
            ("CPU", f"{metrics.get('cpu_pct', 0):.1f}%"),
            ("Free RAM", f"{metrics.get('free_ram_mb', 0):.0f} MB"),
            ("Free Disk", f"{metrics.get('free_disk_gb', 0):.2f} GB"),
            ("Network", "✅ OK" if metrics.get("network_ok", True) else "❌ Down"),
        ]:
            col = QVBoxLayout()
            lbl_label = QLabel(label)
            lbl_label.setAlignment(Qt.AlignCenter)
            lbl_label.setStyleSheet("color: #666; font-size: 11px;")
            lbl_value = QLabel(value)
            lbl_value.setAlignment(Qt.AlignCenter)
            lbl_value.setStyleSheet("color: #333; font-weight: bold; font-size: 13px;")
            col.addWidget(lbl_label)
            col.addWidget(lbl_value)
            metrics_layout.addLayout(col)
        layout.addWidget(metrics_frame)

        # Warning list
        warnings = self.check_result.get("warnings", [])
        if warnings:
            warn_label = QLabel("Issues Detected:")
            warn_label.setStyleSheet("font-weight: bold; color: #B71C1C;")
            layout.addWidget(warn_label)

            for w in warnings:
                warn_item = QLabel(w)
                warn_item.setWordWrap(True)
                warn_item.setStyleSheet(
                    "background: #FFEBEE; border-left: 3px solid #E53935; "
                    "padding: 8px 10px; border-radius: 3px; color: #333;"
                )
                layout.addWidget(warn_item)

        # Advice
        advice = QLabel(
            "Running a scan under these conditions may cause:\n"
            "• Scanner timeouts or crashes\n"
            "• System slowdowns for other users\n"
            "• Incomplete or missing scan results\n\n"
            "You may continue at your own discretion."
        )
        advice.setStyleSheet("color: #555; font-size: 12px; padding-top: 6px;")
        advice.setWordWrap(True)
        layout.addWidget(advice)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        btn_cancel = QPushButton("✕  Cancel Scan")
        btn_cancel.setStyleSheet(
            "background: #ECEFF1; color: #333; border: 1px solid #B0BEC5; "
            "padding: 8px 20px; border-radius: 5px; font-weight: bold;"
        )
        btn_cancel.clicked.connect(self.reject)

        btn_continue = QPushButton("▶  Continue Anyway")
        btn_continue.setStyleSheet(
            "background: #E65100; color: white; border: none; "
            "padding: 8px 20px; border-radius: 5px; font-weight: bold;"
        )
        btn_continue.clicked.connect(self.accept)

        btn_layout.addWidget(btn_cancel)
        btn_layout.addStretch()
        btn_layout.addWidget(btn_continue)
        layout.addLayout(btn_layout)


def run_system_check_if_needed(settings: dict = None, parent=None) -> bool:
    """
    Run system check and show dialog if issues found.
    
    Returns True if scan should proceed, False if cancelled.
    Fallback: always returns True if dialog cannot be shown.
    """
    try:
        from tools.system_checker import check_system_resources
        result = check_system_resources(settings)
        if result["ok"]:
            return True  # All good — no dialog needed

        # Show warning dialog
        try:
            dialog = SystemCheckDialog(result, parent=parent)
            return dialog.exec() == QDialog.Accepted
        except Exception:
            # If dialog fails, default to allowing the scan
            return True

    except Exception as e:
        import logging
        logging.getLogger("smp").warning(f"[SystemCheck] Check failed: {e}. Allowing scan.")
        return True
