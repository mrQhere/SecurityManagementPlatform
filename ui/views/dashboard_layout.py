import os
import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QGridLayout, QLabel, QPushButton, QStackedWidget, QTableWidget, 
    QTableWidgetItem, QSplitter, QListWidget, QLineEdit, QComboBox, 
    QFrame, QProgressBar, QTextEdit, QGroupBox, QTabWidget, QCheckBox,
    QSizePolicy, QFormLayout, QHeaderView, QAbstractItemView, QToolBar,
    QStatusBar, QSpacerItem, QScrollArea, QDialog
)
from PySide6.QtCore import Qt, QSize, Signal, Slot, QTimer
from PySide6.QtGui import QIcon, QFont, QColor, QPalette, QCursor

# Try to import custom components, fallback to stub if not available
try:
    from ui.components.stat_card import StatCard
except ImportError:
    class StatCard(QFrame):
        """Fallback StatCard if component is not found."""
        def __init__(self, title, value="0", parent=None):
            super().__init__(parent)
            self.setObjectName(f"statCard_{title.replace(' ', '')}")
            self.setFrameShape(QFrame.StyledPanel)
            self.setFrameShadow(QFrame.Raised)
            self.setStyleSheet("""
                QFrame {
                    background-color: #2b2b2b;
                    border-radius: 8px;
                    border: 1px solid #3d3d3d;
                    padding: 15px;
                }
            """)
            layout = QVBoxLayout(self)
            self.lbl_title = QLabel(title)
            self.lbl_title.setStyleSheet("color: #aaaaaa; font-size: 14px; font-weight: bold;")
            self.lbl_value = QLabel(value)
            self.lbl_value.setStyleSheet("color: #ffffff; font-size: 28px; font-weight: bold;")
            self.lbl_value.setAlignment(Qt.AlignCenter)
            layout.addWidget(self.lbl_title)
            layout.addWidget(self.lbl_value)
            layout.addStretch()

        def set_value(self, val):
            self.lbl_value.setText(str(val))


try:
    from ui.components.finding_panel import FindingDetailPanel
except ImportError:
    class FindingDetailPanel(QFrame):
        """Fallback FindingDetailPanel if component is not found."""
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setObjectName("findingDetailPanel")
            self.setFrameShape(QFrame.StyledPanel)
            self.hide()
            layout = QVBoxLayout(self)
            layout.addWidget(QLabel("Finding Details Overlay Placeholder"))
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(self.hide)
            layout.addWidget(close_btn)

        def show_finding(self, finding_data=None):
            self.show()


class DashboardLayoutMixin:
    """
    Mixin class that provides the UI layout for the SMP V9.5 Dashboard.
    The main DashboardWindow should inherit from this.
    """

    PAGE_NAMES = [
        ('📊', 'Dashboard'),       # index 0
        ('🎯', 'Targets'),         # index 1  
        ('🚨', 'Active Scans'),    # index 2
        ('🔍', 'Findings'),        # index 3
        ('🧠', 'Intelligence'),    # index 4
        ('🌐', 'Assets'),          # index 5
        ('📄', 'Reports'),         # index 6
        ('📤', 'Exporter'),        # index 7
        ('🔧', 'Scanners'),        # index 8
        ('⚙️', 'Settings'),        # index 9
    ]

    def _setup_ui(self):
        """Main entry point to setup the UI."""
        self.setObjectName("DashboardWindow")
        if hasattr(self, 'setWindowTitle'):
            self.setWindowTitle("SMP V9.5 - Security Management Platform")
            self.resize(1400, 900)

        # Main central widget
        self.central_widget = QWidget()
        self.central_widget.setObjectName("centralWidget")
        if hasattr(self, 'setCentralWidget'):
            self.setCentralWidget(self.central_widget)

        # Main horizontal layout: Sidebar + Content
        self.main_layout = QHBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # 1. Sidebar
        self._create_sidebar()

        # 2. Content Stack
        self._create_content_stack()

        # 3. Status Bar
        self._setup_status_bar()

    def _create_sidebar(self):
        """Creates the left navigation sidebar."""
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebarFrame")
        self.sidebar.setFixedWidth(220)
        self.sidebar.setStyleSheet("""
            QFrame#sidebarFrame {
                background-color: #1e1e1e;
                border-right: 1px solid #333333;
            }
        """)

        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(10, 20, 10, 15)
        sidebar_layout.setSpacing(5)

        # Top: Logo area
        logo_layout = QVBoxLayout()
        logo_layout.setSpacing(2)
        
        self.lbl_logo = QLabel("SMP")
        self.lbl_logo.setObjectName("lblLogo")
        logo_font = QFont("Arial", 28, QFont.Bold)
        self.lbl_logo.setFont(logo_font)
        self.lbl_logo.setStyleSheet("color: #4a90e2; letter-spacing: 2px;")
        self.lbl_logo.setAlignment(Qt.AlignCenter)
        
        self.lbl_subtitle = QLabel("V9.5")
        self.lbl_subtitle.setObjectName("lblSubtitle")
        self.lbl_subtitle.setStyleSheet("color: #888888; font-size: 12px; font-weight: bold; letter-spacing: 4px;")
        self.lbl_subtitle.setAlignment(Qt.AlignCenter)
        
        logo_layout.addWidget(self.lbl_logo)
        logo_layout.addWidget(self.lbl_subtitle)
        
        sidebar_layout.addLayout(logo_layout)
        sidebar_layout.addSpacing(30)

        # Nav buttons
        self._nav_buttons = []
        for index, (icon, text) in enumerate(self.PAGE_NAMES):
            btn = QPushButton(f"{icon}  {text}")
            btn.setObjectName(f"navBtn_{index}")
            btn.setCheckable(True)
            btn.setAutoExclusive(True)
            btn.setCursor(QCursor(Qt.PointingHandCursor))
            btn.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    padding: 10px 15px;
                    border: none;
                    border-radius: 6px;
                    color: #d4d4d4;
                    font-size: 14px;
                    font-weight: 500;
                    background-color: transparent;
                }
                QPushButton:hover {
                    background-color: #2d2d2d;
                    color: #ffffff;
                }
                QPushButton:checked {
                    background-color: #0d47a1;
                    color: #ffffff;
                    font-weight: bold;
                }
            """)
            btn.clicked.connect(lambda checked, idx=index: self._nav_clicked(idx))
            self._nav_buttons.append(btn)
            sidebar_layout.addWidget(btn)

        if self._nav_buttons:
            self._nav_buttons[0].setChecked(True)

        sidebar_layout.addStretch()

        # Bottom: Version Label
        self.lbl_version_info = QLabel("V9.5 Build 2026\nby mrQhere")
        self.lbl_version_info.setObjectName("lblVersionInfo")
        self.lbl_version_info.setStyleSheet("color: #555555; font-size: 10px;")
        self.lbl_version_info.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(self.lbl_version_info)

        self.main_layout.addWidget(self.sidebar)

    def _create_content_stack(self):
        """Creates the main content area with a stacked widget for pages."""
        self.content_stack = QStackedWidget()
        self.content_stack.setObjectName("contentStack")
        self.content_stack.setStyleSheet("""
            QStackedWidget#contentStack {
                background-color: #121212;
            }
            QLabel { color: #e0e0e0; }
        """)

        # Initialize pages
        self._setup_page_0_dashboard()
        self._setup_page_1_targets()
        self._setup_page_2_active_scans()
        self._setup_page_3_findings()
        self._setup_page_4_intelligence()
        self._setup_page_5_assets()
        self._setup_page_6_reports()
        self._setup_page_7_exporter()
        self._setup_page_8_scanners()
        self._setup_page_9_settings()

        self.main_layout.addWidget(self.content_stack, 1)

    def _setup_page_0_dashboard(self):
        page = QWidget()
        page.setObjectName("pageDashboard")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Title
        title = QLabel("Dashboard Overview")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)

        # Top row: StatCards
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(15)
        
        self.card_total_targets = StatCard("Total Targets", "0")
        self.card_critical_findings = StatCard("Critical Findings", "0")
        self.card_active_scans = StatCard("Active Scans", "0")
        self.card_intel_count = StatCard("Intel Updates", "0")
        
        cards_layout.addWidget(self.card_total_targets)
        cards_layout.addWidget(self.card_critical_findings)
        cards_layout.addWidget(self.card_active_scans)
        cards_layout.addWidget(self.card_intel_count)
        
        layout.addLayout(cards_layout)

        # Second row: Splitter
        splitter = QSplitter(Qt.Horizontal)
        splitter.setObjectName("dashboardSplitter")
        
        # Left (60%)
        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)
        lbl_overview = QLabel("Targets Overview")
        lbl_overview.setStyleSheet("font-size: 16px; font-weight: bold;")
        left_layout.addWidget(lbl_overview)
        
        self.tbl_targets_overview = QTableWidget(0, 5)
        self.tbl_targets_overview.setObjectName("tbl_targets_overview")
        self.tbl_targets_overview.setHorizontalHeaderLabels(["Target", "Risk Rating", "Last Scan", "Status", "Findings"])
        self.tbl_targets_overview.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_targets_overview.setSelectionBehavior(QAbstractItemView.SelectRows)
        left_layout.addWidget(self.tbl_targets_overview)
        
        # Right (40%)
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        lbl_events = QLabel("Recent Security Events")
        lbl_events.setStyleSheet("font-size: 16px; font-weight: bold;")
        right_layout.addWidget(lbl_events)
        
        self.lst_recent_events = QListWidget()
        self.lst_recent_events.setObjectName("lst_recent_events")
        right_layout.addWidget(self.lst_recent_events)
        
        splitter.addWidget(left_container)
        splitter.addWidget(right_container)
        splitter.setSizes([600, 400])
        
        layout.addWidget(splitter, 1)

        # Bottom
        self.lbl_last_updated = QLabel("Last Updated: Never")
        self.lbl_last_updated.setObjectName("lbl_last_updated")
        self.lbl_last_updated.setStyleSheet("color: #777777;")
        layout.addWidget(self.lbl_last_updated)

        self.content_stack.addWidget(page)

    def _setup_page_1_targets(self):
        page = QWidget()
        page.setObjectName("pageTargets")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Target Management")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)

        # Toolbar
        toolbar_layout = QHBoxLayout()
        
        self.inp_target_url = QLineEdit()
        self.inp_target_url.setObjectName("inp_target_url")
        self.inp_target_url.setPlaceholderText("https://target.com or 192.168.1.0/24")
        self.inp_target_url.setMinimumWidth(300)
        
        self.btn_add_target = QPushButton("+ Add Target")
        self.btn_add_target.setObjectName("btn_add_target")
        self.btn_add_target.setStyleSheet("background-color: #2e7d32; color: white; padding: 5px 15px; border-radius: 4px;")
        
        self.btn_delete_target = QPushButton("🗑 Remove")
        self.btn_delete_target.setObjectName("btn_delete_target")
        self.btn_delete_target.setStyleSheet("background-color: #c62828; color: white; padding: 5px 15px; border-radius: 4px;")
        
        self.btn_scan_target = QPushButton("▶ Scan Target")
        self.btn_scan_target.setObjectName("btn_scan_target")
        self.btn_scan_target.setStyleSheet("background-color: #1565c0; color: white; padding: 5px 15px; border-radius: 4px;")
        
        toolbar_layout.addWidget(self.inp_target_url)
        toolbar_layout.addWidget(self.btn_add_target)
        toolbar_layout.addWidget(self.btn_scan_target)
        toolbar_layout.addStretch()
        toolbar_layout.addWidget(self.btn_delete_target)
        
        layout.addLayout(toolbar_layout)
        layout.addSpacing(10)

        # Table
        self.tbl_targets = QTableWidget(0, 7)
        self.tbl_targets.setObjectName("tbl_targets")
        self.tbl_targets.setHorizontalHeaderLabels(["ID", "URL/IP", "Status", "Last Scan", "Findings Count", "Risk Score", "Actions"])
        self.tbl_targets.horizontalHeader().setStretchLastSection(True)
        self.tbl_targets.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_targets.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        layout.addWidget(self.tbl_targets, 1)
        self.content_stack.addWidget(page)

    def _setup_page_2_active_scans(self):
        page = QWidget()
        page.setObjectName("pageActiveScans")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Active Scans")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)

        self.lbl_scan_status = QLabel("No active scans")
        self.lbl_scan_status.setObjectName("lbl_scan_status")
        self.lbl_scan_status.setStyleSheet("color: #aaaaaa; font-style: italic;")
        layout.addWidget(self.lbl_scan_status)

        # Table
        self.tbl_active_scans = QTableWidget(0, 6)
        self.tbl_active_scans.setObjectName("tbl_active_scans")
        self.tbl_active_scans.setHorizontalHeaderLabels(["Target", "Scanner", "Status", "Progress", "Started", "ETA"])
        self.tbl_active_scans.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_active_scans.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.tbl_active_scans, 1)

        # Toolbar for scans
        scan_toolbar = QHBoxLayout()
        self.btn_pause_scan = QPushButton("⏸ Pause")
        self.btn_pause_scan.setObjectName("btn_pause_scan")
        
        self.btn_stop_scan = QPushButton("🛑 Stop")
        self.btn_stop_scan.setObjectName("btn_stop_scan")
        self.btn_stop_scan.setStyleSheet("background-color: #c62828; color: white;")
        
        self.btn_view_log = QPushButton("📄 View Log")
        self.btn_view_log.setObjectName("btn_view_log")
        
        scan_toolbar.addWidget(self.btn_pause_scan)
        scan_toolbar.addWidget(self.btn_stop_scan)
        scan_toolbar.addWidget(self.btn_view_log)
        scan_toolbar.addStretch()
        layout.addLayout(scan_toolbar)

        # Log view
        log_label = QLabel("Scanner Output Log")
        log_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(log_label)
        
        self.txt_scan_log = QTextEdit()
        self.txt_scan_log.setObjectName("txt_scan_log")
        self.txt_scan_log.setReadOnly(True)
        self.txt_scan_log.setStyleSheet("background-color: #000000; color: #00ff00; font-family: monospace;")
        self.txt_scan_log.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.txt_scan_log, 1)

        self.content_stack.addWidget(page)

    def _setup_page_3_findings(self):
        page = QWidget()
        page.setObjectName("pageFindings")
        
        # Use a container widget so we can place an overlay
        container_layout = QVBoxLayout(page)
        container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.findings_inner = QWidget()
        layout = QVBoxLayout(self.findings_inner)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Findings & Vulnerabilities")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)

        # Filter toolbar
        filter_layout = QHBoxLayout()
        
        self.cmb_severity = QComboBox()
        self.cmb_severity.setObjectName("cmb_severity")
        self.cmb_severity.addItems(['All Severities', 'Critical', 'High', 'Medium', 'Low', 'Info'])
        
        self.cmb_status = QComboBox()
        self.cmb_status.setObjectName("cmb_status")
        self.cmb_status.addItems(['All', 'Open', 'Confirmed', 'False Positive', 'Mitigated'])
        
        self.inp_search_findings = QLineEdit()
        self.inp_search_findings.setObjectName("inp_search_findings")
        self.inp_search_findings.setPlaceholderText("Search CVE, Title, Target...")
        
        self.btn_search_findings = QPushButton("🔍 Search")
        self.btn_search_findings.setObjectName("btn_search_findings")
        
        filter_layout.addWidget(self.cmb_severity)
        filter_layout.addWidget(self.cmb_status)
        filter_layout.addWidget(self.inp_search_findings)
        filter_layout.addWidget(self.btn_search_findings)
        filter_layout.addStretch()
        
        layout.addLayout(filter_layout)
        layout.addSpacing(10)

        # Table
        self.tbl_findings = QTableWidget(0, 9)
        self.tbl_findings.setObjectName("tbl_findings")
        self.tbl_findings.setHorizontalHeaderLabels(["Severity", "Title", "Target", "CVE", "CVSS", "EPSS", "KEV", "Scanner", "Status"])
        self.tbl_findings.horizontalHeader().setStretchLastSection(True)
        self.tbl_findings.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_findings.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.tbl_findings, 1)

        container_layout.addWidget(self.findings_inner)

        # Setup Overlay Panel
        self.finding_panel = FindingDetailPanel(parent=page)
        # Assuming FindingDetailPanel handles its own sizing/positioning in its logic,
        # but we add it to the page as a child so it can overlay.
        
        self.content_stack.addWidget(page)

    def _setup_page_4_intelligence(self):
        page = QWidget()
        page.setObjectName("pageIntelligence")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Threat Intelligence")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setObjectName("intelSplitter")

        # Left Panel: CVE Search
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        search_layout = QHBoxLayout()
        self.inp_cve_search = QLineEdit()
        self.inp_cve_search.setObjectName("inp_cve_search")
        self.inp_cve_search.setPlaceholderText("Search CVE (e.g. CVE-2023-12345)")
        self.btn_cve_search = QPushButton("Search")
        self.btn_cve_search.setObjectName("btn_cve_search")
        search_layout.addWidget(self.inp_cve_search)
        search_layout.addWidget(self.btn_cve_search)
        left_layout.addLayout(search_layout)

        self.tbl_cve_results = QTableWidget(0, 6)
        self.tbl_cve_results.setObjectName("tbl_cve_results")
        self.tbl_cve_results.setHorizontalHeaderLabels(["CVE ID", "Severity", "CVSS", "EPSS", "KEV", "Description"])
        self.tbl_cve_results.horizontalHeader().setStretchLastSection(True)
        self.tbl_cve_results.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        left_layout.addWidget(self.tbl_cve_results)
        
        # Right Panel: Stats & KEV
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

        intel_cards_layout = QVBoxLayout()
        self.card_total_cve = StatCard("Tracked CVEs", "0")
        self.card_kev_count = StatCard("CISA KEV Items", "0")
        self.card_critical_cve = StatCard("Critical CVEs", "0")
        intel_cards_layout.addWidget(self.card_total_cve)
        intel_cards_layout.addWidget(self.card_kev_count)
        intel_cards_layout.addWidget(self.card_critical_cve)
        right_layout.addLayout(intel_cards_layout)
        
        lbl_kev = QLabel("Recent KEV Additions")
        lbl_kev.setStyleSheet("font-weight: bold; margin-top: 10px;")
        right_layout.addWidget(lbl_kev)
        
        self.lst_kev_recent = QListWidget()
        self.lst_kev_recent.setObjectName("lst_kev_recent")
        right_layout.addWidget(self.lst_kev_recent)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([700, 300])

        layout.addWidget(splitter, 1)
        self.content_stack.addWidget(page)

    def _setup_page_5_assets(self):
        page = QWidget()
        page.setObjectName("pageAssets")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Assets & Services Inventory")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)

        tabs = QTabWidget()
        tabs.setObjectName("assetsTabs")

        # Tab 1: Assets
        tab_assets = QWidget()
        layout_assets = QVBoxLayout(tab_assets)
        self.tbl_assets = QTableWidget(0, 5)
        self.tbl_assets.setObjectName("tbl_assets")
        self.tbl_assets.setHorizontalHeaderLabels(["IP/Host", "Hostname", "OS", "Open Ports", "Last Seen"])
        self.tbl_assets.horizontalHeader().setStretchLastSection(True)
        self.tbl_assets.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout_assets.addWidget(self.tbl_assets)
        tabs.addTab(tab_assets, "Assets")

        # Tab 2: Services
        tab_services = QWidget()
        layout_services = QVBoxLayout(tab_services)
        self.tbl_services = QTableWidget(0, 7)
        self.tbl_services.setObjectName("tbl_services")
        self.tbl_services.setHorizontalHeaderLabels(["IP", "Port", "Protocol", "Service", "Product", "Version", "CPE"])
        self.tbl_services.horizontalHeader().setStretchLastSection(True)
        self.tbl_services.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout_services.addWidget(self.tbl_services)
        tabs.addTab(tab_services, "Services")

        layout.addWidget(tabs, 1)
        self.content_stack.addWidget(page)

    def _setup_page_6_reports(self):
        page = QWidget()
        page.setObjectName("pageReports")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Report Generation")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)

        # Toolbar
        toolbar = QHBoxLayout()
        self.cmb_report_target = QComboBox()
        self.cmb_report_target.setObjectName("cmb_report_target")
        self.cmb_report_target.addItem("Select Target...")
        self.cmb_report_target.setMinimumWidth(200)

        self.btn_gen_report = QPushButton("Generate Report")
        self.btn_gen_report.setObjectName("btn_gen_report")
        self.btn_gen_report.setStyleSheet("background-color: #4a148c; color: white;")

        self.btn_verify_report = QPushButton("✓ Verify")
        self.btn_verify_report.setObjectName("btn_verify_report")
        self.btn_verify_report.setStyleSheet("background-color: #004d40; color: white;")

        toolbar.addWidget(self.cmb_report_target)
        toolbar.addWidget(self.btn_gen_report)
        toolbar.addWidget(self.btn_verify_report)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Table
        self.tbl_reports = QTableWidget(0, 7)
        self.tbl_reports.setObjectName("tbl_reports")
        self.tbl_reports.setHorizontalHeaderLabels(["Report ID", "Target", "Generated", "Format", "Risk Rating", "Size", "Actions"])
        self.tbl_reports.horizontalHeader().setStretchLastSection(True)
        self.tbl_reports.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.tbl_reports, 1)

        # Preview
        grp_preview = QGroupBox("Report Preview")
        preview_layout = QVBoxLayout(grp_preview)
        self.txt_report_preview = QTextEdit()
        self.txt_report_preview.setObjectName("txt_report_preview")
        self.txt_report_preview.setReadOnly(True)
        self.txt_report_preview.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        preview_layout.addWidget(self.txt_report_preview)
        
        layout.addWidget(grp_preview, 1)
        self.content_stack.addWidget(page)

    def _setup_page_7_exporter(self):
        page = QWidget()
        page.setObjectName("pageExporter")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Data Exporter")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)

        # Warning banner
        warn_frame = QFrame()
        warn_frame.setObjectName("warn_frame")
        warn_frame.setStyleSheet("background-color: #3b0000; border: 1px solid #ff0000; border-radius: 4px;")
        warn_layout = QVBoxLayout(warn_frame)
        lbl_warn = QLabel("⚠  DATA EXPORT — All exports produce UNENCRYPTED plaintext data. Explicit legal acknowledgment required.")
        lbl_warn.setStyleSheet("color: #ff5555; font-weight: bold; font-size: 14px;")
        warn_layout.addWidget(lbl_warn)
        layout.addWidget(warn_frame)
        layout.addSpacing(10)

        # Config GroupBox
        grp_config = QGroupBox("Export Configuration")
        grp_config.setStyleSheet("QGroupBox { font-weight: bold; }")
        config_layout = QGridLayout(grp_config)

        self.cmb_export_target = QComboBox()
        self.cmb_export_target.setObjectName("cmb_export_target")
        self.cmb_export_target.addItem("Select Engagement/Target...")
        
        self.cmb_export_format = QComboBox()
        self.cmb_export_format.setObjectName("cmb_export_format")
        self.cmb_export_format.addItems(['Jira JSON', 'ServiceNow CSV', 'DefectDojo JSON', 'Generic JSON', 'Markdown ZIP', 'SARIF 2.1.0'])
        
        config_layout.addWidget(QLabel("Target:"), 0, 0)
        config_layout.addWidget(self.cmb_export_target, 0, 1)
        config_layout.addWidget(QLabel("Format:"), 1, 0)
        config_layout.addWidget(self.cmb_export_format, 1, 1)

        # Checkboxes
        chk_layout = QVBoxLayout()
        self.chk_include_findings = QCheckBox("Include Findings")
        self.chk_include_findings.setObjectName("chk_include_findings")
        self.chk_include_findings.setChecked(True)
        
        self.chk_include_assets = QCheckBox("Include Assets")
        self.chk_include_assets.setObjectName("chk_include_assets")
        
        self.chk_include_services = QCheckBox("Include Services")
        self.chk_include_services.setObjectName("chk_include_services")
        
        self.chk_include_evidence_hashes = QCheckBox("Include Evidence Hashes")
        self.chk_include_evidence_hashes.setObjectName("chk_include_evidence_hashes")
        
        self.chk_include_scan_timeline = QCheckBox("Include Scan Timeline")
        self.chk_include_scan_timeline.setObjectName("chk_include_scan_timeline")
        
        chk_layout.addWidget(self.chk_include_findings)
        chk_layout.addWidget(self.chk_include_assets)
        chk_layout.addWidget(self.chk_include_services)
        chk_layout.addWidget(self.chk_include_evidence_hashes)
        chk_layout.addWidget(self.chk_include_scan_timeline)
        
        config_layout.addWidget(QLabel("Includes:"), 2, 0, Qt.AlignTop)
        config_layout.addLayout(chk_layout, 2, 1)

        # Output Dir
        dir_layout = QHBoxLayout()
        self.inp_export_dir = QLineEdit()
        self.inp_export_dir.setObjectName("inp_export_dir")
        self.btn_browse_export = QPushButton("📁 Browse")
        self.btn_browse_export.setObjectName("btn_browse_export")
        dir_layout.addWidget(self.inp_export_dir)
        dir_layout.addWidget(self.btn_browse_export)
        
        config_layout.addWidget(QLabel("Output Dir:"), 3, 0)
        config_layout.addLayout(dir_layout, 3, 1)

        layout.addWidget(grp_config)

        # Legal Notice GroupBox
        grp_legal = QGroupBox("Legal Notice & Authorization")
        grp_legal.setStyleSheet("QGroupBox { border: 2px solid #b71c1c; border-radius: 5px; margin-top: 1ex; font-weight: bold; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; color: #ff5252; }")
        legal_layout = QVBoxLayout(grp_legal)
        
        lbl_legal_text = QLabel("By proceeding, you acknowledge that you are authorized to export this sensitive vulnerability data.\n"
                                "You are responsible for the secure transmission and storage of the exported files.")
        lbl_legal_text.setStyleSheet("color: #ff8a80;")
        legal_layout.addWidget(lbl_legal_text)
        
        lbl_gate = QLabel('Type "I AGREE" below to unlock export:')
        legal_layout.addWidget(lbl_gate)
        
        gate_layout = QHBoxLayout()
        self.inp_legal_gate = QLineEdit()
        self.inp_legal_gate.setObjectName("inp_legal_gate")
        self.inp_legal_gate.setPlaceholderText("I AGREE")
        self.inp_legal_gate.setMaximumWidth(200)
        
        self.btn_export = QPushButton("Export Data")
        self.btn_export.setObjectName("btn_export")
        self.btn_export.setEnabled(False)
        self.btn_export.setStyleSheet("""
            QPushButton:disabled { background-color: #424242; color: #757575; }
            QPushButton:enabled { background-color: #d32f2f; color: white; font-weight: bold; }
        """)
        
        gate_layout.addWidget(self.inp_legal_gate)
        gate_layout.addWidget(self.btn_export)
        gate_layout.addStretch()
        
        legal_layout.addLayout(gate_layout)
        
        self.inp_legal_gate.textChanged.connect(lambda t: self.btn_export.setEnabled(t.strip() == 'I AGREE'))
        
        layout.addWidget(grp_legal)

        # Export History
        grp_history = QGroupBox("Export History")
        history_layout = QVBoxLayout(grp_history)
        self.tbl_export_history = QTableWidget(0, 7)
        self.tbl_export_history.setObjectName("tbl_export_history")
        self.tbl_export_history.setHorizontalHeaderLabels(["Export ID", "Target", "Format", "Exported By", "Timestamp", "SHA-256", "Files"])
        self.tbl_export_history.horizontalHeader().setStretchLastSection(True)
        self.tbl_export_history.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        history_layout.addWidget(self.tbl_export_history)
        
        layout.addWidget(grp_history, 1)

        self.content_stack.addWidget(page)

    def _setup_page_8_scanners(self):
        page = QWidget()
        page.setObjectName("pageScanners")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("Scanner Registry")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)

        toolbar = QHBoxLayout()
        self.cmb_scanner_filter = QComboBox()
        self.cmb_scanner_filter.setObjectName("cmb_scanner_filter")
        self.cmb_scanner_filter.addItems(['All Categories', 'recon', 'network', 'web', 'exploit', 'intel'])
        
        self.inp_scanner_search = QLineEdit()
        self.inp_scanner_search.setObjectName("inp_scanner_search")
        self.inp_scanner_search.setPlaceholderText("Search scanners...")
        
        self.btn_refresh_scanners = QPushButton("Refresh")
        self.btn_refresh_scanners.setObjectName("btn_refresh_scanners")
        
        self.btn_check_tools = QPushButton("Check Tools")
        self.btn_check_tools.setObjectName("btn_check_tools")
        self.btn_check_tools.setStyleSheet("background-color: #0277bd; color: white;")
        
        toolbar.addWidget(self.cmb_scanner_filter)
        toolbar.addWidget(self.inp_scanner_search)
        toolbar.addWidget(self.btn_refresh_scanners)
        toolbar.addWidget(self.btn_check_tools)
        toolbar.addStretch()
        
        layout.addLayout(toolbar)

        self.tbl_scanners = QTableWidget(0, 7)
        self.tbl_scanners.setObjectName("tbl_scanners")
        self.tbl_scanners.setHorizontalHeaderLabels(["Scanner Name", "Category", "Binary", "Version", "Status", "Timeout", "DAG Dependencies"])
        self.tbl_scanners.horizontalHeader().setStretchLastSection(True)
        self.tbl_scanners.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        layout.addWidget(self.tbl_scanners, 1)
        self.content_stack.addWidget(page)

    def _setup_page_9_settings(self):
        page = QWidget()
        page.setObjectName("pageSettings")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("System Settings")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title)

        tabs = QTabWidget()
        tabs.setObjectName("settingsTabs")

        # Tab: General
        tab_general = QWidget()
        layout_gen = QFormLayout(tab_general)
        self.nmap_path = QLineEdit("/usr/bin/nmap")
        self.nmap_path.setObjectName("nmap_path")
        self.scan_timeout = QLineEdit("3600")
        self.scan_timeout.setObjectName("scan_timeout")
        self.max_concurrent_scanners = QLineEdit("5")
        self.max_concurrent_scanners.setObjectName("max_concurrent_scanners")
        self.output_dir = QLineEdit("/var/opt/smp/output")
        self.output_dir.setObjectName("output_dir")
        self.operator_name = QLineEdit("admin")
        self.operator_name.setObjectName("operator_name")
        
        layout_gen.addRow("Nmap Path:", self.nmap_path)
        layout_gen.addRow("Scan Timeout (s):", self.scan_timeout)
        layout_gen.addRow("Max Concurrent Scanners:", self.max_concurrent_scanners)
        layout_gen.addRow("Default Output Dir:", self.output_dir)
        layout_gen.addRow("Operator Name:", self.operator_name)
        tabs.addTab(tab_general, "General")

        # Tab: Security
        tab_security = QWidget()
        layout_sec = QVBoxLayout(tab_security)
        self.btn_change_pw = QPushButton("Change Master Password")
        self.btn_change_pw.setObjectName("btn_change_pw")
        self.btn_export_audit = QPushButton("Export Audit Log")
        self.btn_export_audit.setObjectName("btn_export_audit")
        self.btn_wipe_db = QPushButton("Wipe Database")
        self.btn_wipe_db.setObjectName("btn_wipe_db")
        self.btn_wipe_db.setStyleSheet("background-color: #b71c1c; color: white; font-weight: bold;")
        
        layout_sec.addWidget(self.btn_change_pw)
        layout_sec.addWidget(self.btn_export_audit)
        layout_sec.addWidget(self.btn_wipe_db)
        layout_sec.addStretch()
        tabs.addTab(tab_security, "Security")

        # Tab: API
        tab_api = QWidget()
        layout_api = QFormLayout(tab_api)
        self.enable_api = QCheckBox("Enable REST API")
        self.enable_api.setObjectName("enable_api")
        self.api_host = QLineEdit("127.0.0.1")
        self.api_host.setObjectName("api_host")
        self.api_port = QLineEdit("8443")
        self.api_port.setObjectName("api_port")
        self.api_key = QLineEdit("********************")
        self.api_key.setObjectName("api_key")
        self.api_key.setReadOnly(True)
        
        layout_api.addRow("", self.enable_api)
        layout_api.addRow("API Host:", self.api_host)
        layout_api.addRow("API Port:", self.api_port)
        layout_api.addRow("Current API Key:", self.api_key)
        tabs.addTab(tab_api, "API")

        # Tab: Notifications
        tab_notif = QWidget()
        layout_notif = QFormLayout(tab_notif)
        self.enable_smtp = QCheckBox("Enable SMTP Notifications")
        self.enable_smtp.setObjectName("enable_smtp")
        self.smtp_host = QLineEdit("smtp.example.com")
        self.smtp_host.setObjectName("smtp_host")
        self.smtp_port = QLineEdit("587")
        self.smtp_port.setObjectName("smtp_port")
        self.smtp_user = QLineEdit("admin@example.com")
        self.smtp_user.setObjectName("smtp_user")
        self.smtp_password = QLineEdit()
        self.smtp_password.setObjectName("smtp_password")
        self.smtp_password.setEchoMode(QLineEdit.Password)
        self.btn_test_email = QPushButton("Test Email Configuration")
        self.btn_test_email.setObjectName("btn_test_email")
        
        layout_notif.addRow("", self.enable_smtp)
        layout_notif.addRow("SMTP Host:", self.smtp_host)
        layout_notif.addRow("SMTP Port:", self.smtp_port)
        layout_notif.addRow("SMTP User:", self.smtp_user)
        layout_notif.addRow("SMTP Password:", self.smtp_password)
        layout_notif.addRow("", self.btn_test_email)
        tabs.addTab(tab_notif, "Notifications")

        # Tab: Audit Log
        tab_audit = QWidget()
        layout_audit = QVBoxLayout(tab_audit)
        self.tbl_audit_log = QTableWidget(0, 4)
        self.tbl_audit_log.setObjectName("tbl_audit_log")
        self.tbl_audit_log.setHorizontalHeaderLabels(["Timestamp", "Level", "Message", "Scan ID"])
        self.tbl_audit_log.horizontalHeader().setStretchLastSection(True)
        self.tbl_audit_log.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout_audit.addWidget(self.tbl_audit_log)
        tabs.addTab(tab_audit, "Audit Log")

        layout.addWidget(tabs, 1)
        self.content_stack.addWidget(page)

    def _setup_status_bar(self):
        """Setup the application status bar."""
        if not hasattr(self, 'statusBar'):
            return
            
        self.status_bar = self.statusBar()
        self.status_bar.setObjectName("statusBar")
        self.status_bar.setStyleSheet("background-color: #1a1a1a; color: #888888; border-top: 1px solid #333333;")
        
        self.status_version = QLabel(" SMP V9.5 ")
        self.status_version.setStyleSheet("font-weight: bold; color: #4a90e2;")
        self.status_bar.addWidget(self.status_version)
        
        self.status_operator = QLabel(" Operator: admin ")
        self.status_bar.addPermanentWidget(self.status_operator)
        
        self.status_db = QLabel(" 🔒 DB Encrypted ")
        self.status_db.setStyleSheet("color: #4caf50;")
        self.status_bar.addPermanentWidget(self.status_db)

    def _nav_clicked(self, index: int):
        """
        Handle navigation button clicks.
        This method is meant to be overridden or extended by the main logic class,
        but we provide base functionality to switch the stacked widget.
        """
        if hasattr(self, 'content_stack'):
            self.content_stack.setCurrentIndex(index)
            
        # Update button states
        for i, btn in enumerate(self._nav_buttons):
            if i != index:
                btn.setChecked(False)

