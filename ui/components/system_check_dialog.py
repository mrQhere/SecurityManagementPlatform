import sys
import os
import shutil
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                               QPushButton, QTableWidget, QTableWidgetItem, 
                               QHeaderView, QApplication, QFrame)
from PySide6.QtCore import Qt, QTimer, QProcess
from PySide6.QtGui import QFont, QColor

class SystemCheckDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("System Readiness Check")
        self.setFixedSize(600, 700)
        self.scanners_available = 0
        self.scanners_total = 0
        
        self._init_ui()
        self._apply_styles()
        
        QTimer.singleShot(100, self._run_checks)

    def _init_ui(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)
        
        # Header
        header = QLabel("System Readiness Check")
        header.setFont(QFont("Arial", 16, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("color: #FFFFFF;")
        self.layout.addWidget(header)
        
        # Resource Check Section
        self.resource_box = QFrame()
        self.resource_box.setObjectName("section_box")
        res_layout = QVBoxLayout(self.resource_box)
        res_label = QLabel("1. Resource Check")
        res_label.setFont(QFont("Arial", 12, QFont.Bold))
        res_layout.addWidget(res_label)
        self.res_content = QLabel("Checking resources...")
        res_layout.addWidget(self.res_content)
        self.layout.addWidget(self.resource_box)
        
        # Architecture Check Section
        self.arch_box = QFrame()
        self.arch_box.setObjectName("section_box")
        arch_layout = QVBoxLayout(self.arch_box)
        arch_label = QLabel("2. V9.5 Architecture Check")
        arch_label.setFont(QFont("Arial", 12, QFont.Bold))
        arch_layout.addWidget(arch_label)
        self.arch_content = QLabel("Checking core modules...")
        arch_layout.addWidget(self.arch_content)
        self.layout.addWidget(self.arch_box)
        
        # Scanner Registry Check Section
        self.scan_box = QFrame()
        self.scan_box.setObjectName("section_box")
        scan_layout = QVBoxLayout(self.scan_box)
        scan_label = QLabel("3. Scanner Registry Check")
        scan_label.setFont(QFont("Arial", 12, QFont.Bold))
        scan_layout.addWidget(scan_label)
        
        self.scan_table = QTableWidget(0, 3)
        self.scan_table.setHorizontalHeaderLabels(["Scanner Name", "Binary", "Status"])
        self.scan_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.scan_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.scan_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Fixed)
        self.scan_table.horizontalHeader().resizeSection(2, 80)
        self.scan_table.verticalHeader().setVisible(False)
        self.scan_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.scan_table.setFocusPolicy(Qt.NoFocus)
        scan_layout.addWidget(self.scan_table)
        self.layout.addWidget(self.scan_box)
        
        # Warning Banner
        self.warning_banner = QLabel("")
        self.warning_banner.setStyleSheet("color: #F87171; background-color: #3F1D1D; padding: 10px; border-radius: 6px; font-weight: bold;")
        self.warning_banner.setAlignment(Qt.AlignCenter)
        self.warning_banner.hide()
        self.layout.addWidget(self.warning_banner)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.troubleshoot_btn = QPushButton("Open Troubleshooter")
        self.troubleshoot_btn.clicked.connect(self._open_troubleshooter)
        
        self.continue_btn = QPushButton("Continue Anyway")
        self.continue_btn.clicked.connect(self.accept)
        self.continue_btn.setEnabled(False)
        
        btn_layout.addWidget(self.troubleshoot_btn)
        btn_layout.addWidget(self.continue_btn)
        self.layout.addLayout(btn_layout)

    def _apply_styles(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #0D0F14;
                color: #FFFFFF;
            }
            QFrame#section_box {
                background-color: #151820;
                border: 1px solid #2A2F3D;
                border-radius: 8px;
            }
            QLabel {
                color: #D1D5DB;
            }
            QTableWidget {
                background-color: #0D0F14;
                color: #FFFFFF;
                border: 1px solid #2A2F3D;
                border-radius: 4px;
                gridline-color: #2A2F3D;
            }
            QHeaderView::section {
                background-color: #1A1F2E;
                color: #FFFFFF;
                border: none;
                border-bottom: 1px solid #2A2F3D;
                padding: 4px;
            }
            QTableWidget::item {
                border-bottom: 1px solid #1A1F2E;
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
            QPushButton:disabled {
                background-color: #2A2F3D;
                color: #6B7280;
            }
        """)

    def _run_checks(self):
        self._check_resources()
        self._check_architecture()
        self._check_scanners()
        
        if self.scanners_total > 0 and (self.scanners_available / self.scanners_total) < 0.5:
            self.warning_banner.setText(f"Warning: {self.scanners_total - self.scanners_available}/{self.scanners_total} scanners unavailable. Some scan results may be incomplete.")
            self.warning_banner.show()
            
        self.continue_btn.setEnabled(True)

    def _check_resources(self):
        try:
            import psutil
            cpu_pct = psutil.cpu_percent(interval=0.1)
            ram = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            ram_gb_avail = ram.available / (1024**3)
            disk_gb_free = disk.free / (1024**3)
            
            res_text = f"CPU Usage: {cpu_pct}%\nRAM Available: {ram_gb_avail:.1f} GB\nDisk Free: {disk_gb_free:.1f} GB"
            self.res_content.setText(res_text)
            
            if cpu_pct > 90 or ram_gb_avail < 1.0 or disk_gb_free < 5.0:
                self.res_content.setStyleSheet("color: #F87171;")
            elif cpu_pct > 70 or ram_gb_avail < 2.0 or disk_gb_free < 10.0:
                self.res_content.setStyleSheet("color: #FBBF24;")
            else:
                self.res_content.setStyleSheet("color: #34D399;")
        except ImportError:
            self.res_content.setText("psutil not installed. Cannot verify resources.")
            self.res_content.setStyleSheet("color: #FBBF24;")

    def _check_architecture(self):
        base_dir = "/home/dxt/SecurityManagementPlatform"
        req_files = [
            "core/scope_engine.py",
            "core/observation.py",
            "core/state_machine.py",
            "scanners/adapters/nmap_adapter.py"
        ]
        
        missing = []
        for rf in req_files:
            if not os.path.exists(os.path.join(base_dir, rf)):
                missing.append(rf)
                
        if missing:
            self.arch_content.setText("Missing core modules:\n" + "\n".join(missing))
            self.arch_content.setStyleSheet("color: #F87171;")
        else:
            self.arch_content.setText("All core modules present.")
            self.arch_content.setStyleSheet("color: #34D399;")

    def _check_scanners(self):
        # Mocking registry get_registered_scanners
        scanners = []
        try:
            from scanners.core.registry import get_registered_scanners
            scanners = get_registered_scanners()
        except Exception:
            # Fallback list if registry unimportable
            scanners = [
                {"name": "Nmap", "binary": "nmap"},
                {"name": "Masscan", "binary": "masscan"},
                {"name": "Nuclei", "binary": "nuclei"},
                {"name": "Amass", "binary": "amass"}
            ]
            
        self.scanners_total = len(scanners)
        self.scanners_available = 0
        
        self.scan_table.setRowCount(self.scanners_total)
        
        for row, scanner in enumerate(scanners):
            name = scanner.get("name", "Unknown")
            binary = scanner.get("binary", "unknown")
            
            has_bin = shutil.which(binary) is not None
            
            name_item = QTableWidgetItem(name)
            bin_item = QTableWidgetItem(binary)
            status_item = QTableWidgetItem("✅" if has_bin else "❌")
            status_item.setTextAlignment(Qt.AlignCenter)
            
            if has_bin:
                self.scanners_available += 1
            
            # Alternating row colors
            bg_color = QColor("#1A1F2E") if row % 2 == 0 else QColor("#151820")
            for item in (name_item, bin_item, status_item):
                item.setBackground(bg_color)
                
            self.scan_table.setItem(row, 0, name_item)
            self.scan_table.setItem(row, 1, bin_item)
            self.scan_table.setItem(row, 2, status_item)

    def _open_troubleshooter(self):
        process = QProcess(self)
        process.startDetached("python3", ["tools/troubleshoot.py", "--check"])

if __name__ == "__main__":
    app = QApplication(sys.argv)
    d = SystemCheckDialog()
    d.show()
    sys.exit(app.exec())
