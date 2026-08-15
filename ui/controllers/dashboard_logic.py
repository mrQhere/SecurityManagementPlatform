import os
import sys
import json
import shutil
import hashlib
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtWidgets import (
    QMessageBox, QFileDialog, QProgressDialog, QTableWidgetItem, QHeaderView
)
from PySide6.QtCore import QThread, Signal, Qt, QTimer
from PySide6.QtGui import QColor, QBrush, QIcon

# Project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


class ScanWorker(QThread):
    scan_progress = Signal(str, str, int)  # target, scanner_name, percent
    scan_complete = Signal(str, bool)      # target, success
    scan_log = Signal(str)                 # log line
    scan_error = Signal(str, str)          # target, error_message

    def __init__(self, target: dict, settings: dict):
        super().__init__()
        self.target = target
        self.settings = settings
        self.target_url = target.get('url', 'unknown')

    def run(self):
        try:
            self.scan_log.emit(f"Starting scan for {self.target_url}...")
            # Deferred import
            from scanners import scan_runner
            
            # Since scan_runner._run_scan_sequence might not be fully async with signals natively, 
            # we simulate wrapping it here or calling it. We will emit signals based on its execution if possible.
            # In a real scenario we'd pass callbacks or use a custom runner that emits.
            scan_runner._run_scan_sequence(self.target_url, self.settings, 
                                          progress_callback=lambda s, p: self.scan_progress.emit(self.target_url, s, p),
                                          log_callback=lambda l: self.scan_log.emit(l))
            
            self.scan_log.emit(f"Scan complete for {self.target_url}.")
            self.scan_complete.emit(self.target_url, True)
        except Exception as e:
            self.scan_log.emit(f"Scan error for {self.target_url}: {str(e)}")
            self.scan_error.emit(self.target_url, str(e))
            self.scan_complete.emit(self.target_url, False)


class UDPListenerThread(QThread):
    event_received = Signal(dict)

    def __init__(self, port=5005):
        super().__init__()
        self.port = port
        self._running = True
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow reuse address
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Set a timeout so we can periodically check self._running
        self.socket.settimeout(1.0)

    def run(self):
        try:
            self.socket.bind(('127.0.0.1', self.port))
            while self._running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    if data:
                        event = json.loads(data.decode('utf-8'))
                        self.event_received.emit(event)
                except socket.timeout:
                    continue
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            print(f"UDPListenerThread error: {e}")
        finally:
            self.socket.close()

    def stop(self):
        self._running = False


class DashboardLogicMixin:
    """
    Mixin class that wires up ALL the business logic.
    The main DashboardWindow inherits from both DashboardLayoutMixin and DashboardLogicMixin.
    """
    
    def _init_logic(self):
        self._active_workers = {}
        self._findings_cache = []
        
        self._connect_signals()
        
        self.udp_thread = UDPListenerThread()
        self.udp_thread.event_received.connect(self._on_ipc_event)
        self.udp_thread.start()
        
        self._poll_timer = QTimer()
        self._poll_timer.timeout.connect(self._load_active_scans)
        self._poll_timer.start(30000)
        
        self._load_all_pages()

    def _connect_signals(self):
        # Navigation
        for i, btn in enumerate(self._nav_buttons):
            btn.clicked.connect(lambda checked, idx=i: self._nav_clicked(idx))

        # Page 1 - Targets
        if hasattr(self, 'btn_add_target'):
            self.btn_add_target.clicked.connect(self._add_target)
        if hasattr(self, 'btn_delete_target'):
            self.btn_delete_target.clicked.connect(self._delete_target)
        if hasattr(self, 'btn_scan_target'):
            self.btn_scan_target.clicked.connect(self._scan_target)
        if hasattr(self, 'tbl_targets'):
            self.tbl_targets.cellDoubleClicked.connect(self._target_double_clicked)

        # Page 2 - Active Scans
        if hasattr(self, 'btn_pause_scan'):
            self.btn_pause_scan.clicked.connect(self._pause_scan)
        if hasattr(self, 'btn_stop_scan'):
            self.btn_stop_scan.clicked.connect(self._stop_scan)
        if hasattr(self, 'btn_view_log'):
            self.btn_view_log.clicked.connect(self._toggle_log)

        # Page 3 - Findings
        if hasattr(self, 'btn_search_findings'):
            self.btn_search_findings.clicked.connect(self._search_findings)
        if hasattr(self, 'cmb_severity'):
            self.cmb_severity.currentTextChanged.connect(self._filter_findings)
        if hasattr(self, 'cmb_status'):
            self.cmb_status.currentTextChanged.connect(self._filter_findings)
        if hasattr(self, 'tbl_findings'):
            self.tbl_findings.cellClicked.connect(self._show_finding_detail)

        # Page 4 - Intel
        if hasattr(self, 'btn_cve_search'):
            self.btn_cve_search.clicked.connect(self._search_cve)

        # Page 6 - Reports
        if hasattr(self, 'btn_gen_report'):
            self.btn_gen_report.clicked.connect(self._generate_report)
        if hasattr(self, 'btn_verify_report'):
            self.btn_verify_report.clicked.connect(self._verify_report)

        # Page 7 - Exporter
        if hasattr(self, 'btn_browse_export'):
            self.btn_browse_export.clicked.connect(self._browse_export_dir)
        if hasattr(self, 'btn_export'):
            self.btn_export.clicked.connect(self._execute_export)

        # Page 8 - Scanners
        if hasattr(self, 'btn_refresh_scanners'):
            self.btn_refresh_scanners.clicked.connect(self._load_scanner_registry)
        if hasattr(self, 'btn_check_tools'):
            self.btn_check_tools.clicked.connect(self._check_scanner_tools)

        # Page 9 - Settings
        if hasattr(self, 'btn_save_settings'):
            self.btn_save_settings.clicked.connect(self._save_settings)
        if hasattr(self, 'btn_change_password'):
            self.btn_change_password.clicked.connect(self._change_password)
        if hasattr(self, 'btn_wipe_db'):
            self.btn_wipe_db.clicked.connect(self._wipe_database)

    def _nav_clicked(self, index: int):
        if hasattr(self, 'content_stack'):
            self.content_stack.setCurrentIndex(index)
        for i, btn in enumerate(self._nav_buttons):
            if i == index:
                btn.setChecked(True)
            else:
                btn.setChecked(False)
        
        # Call page-specific load method if needed
        # Assuming index maps roughly to pages
        if index == 0:
            self._load_dashboard_overview()
        elif index == 1:
            self._load_targets_page()
        elif index == 2:
            self._load_active_scans()
        elif index == 3:
            self._load_findings_page()
        elif index == 4:
            self._load_intelligence_page()
        elif index == 5:
            self._load_assets_page()
        elif index == 6:
            self._load_reports_page()
        elif index == 7:
            self._load_exporter_page()
        elif index == 8:
            self._load_scanner_registry()
        elif index == 9:
            self._load_settings_page()
        elif index == 10:
            self._load_audit_log()

    def _get_operator_name(self) -> str:
        try:
            from core import config_manager
            settings = config_manager.load_settings()
            return settings.get('operator_name', 'Unknown')
        except Exception:
            return 'Unknown'

    def _get_db(self):
        try:
            from database import db_manager
            return db_manager
        except ImportError as e:
            self._show_status(f"Database module unavailable: {e}")
            return None

    def _show_status(self, message: str, timeout: int = 3000):
        if hasattr(self, 'statusBar'):
            self.statusBar().showMessage(message, timeout)
        else:
            print(f"STATUS: {message}")

    def _severity_color(self, severity: str) -> str:
        s = severity.lower()
        if s == 'critical': return '#dc3545'
        if s == 'high': return '#fd7e14'
        if s == 'medium': return '#ffc107'
        if s == 'low': return '#17a2b8'
        return '#6c757d'

    def _set_table_item_severity(self, table, row, col, severity):
        item = table.item(row, col)
        if not item:
            item = QTableWidgetItem(severity)
            table.setItem(row, col, item)
        else:
            item.setText(severity)
        
        color = self._severity_color(severity)
        item.setBackground(QBrush(QColor(color)))
        item.setForeground(QBrush(QColor('#ffffff')))

    def _load_all_pages(self):
        self._load_dashboard_overview()
        self._load_targets_page()
        self._load_active_scans()
        self._load_findings_page()
        self._load_intelligence_page()
        self._load_assets_page()
        self._load_reports_page()
        self._load_exporter_page()
        self._load_scanner_registry()
        self._load_settings_page()
        self._load_audit_log()

    def _load_dashboard_overview(self):
        # Update stat cards, recent events
        db = self._get_db()
        if not db: return
        try:
            # Example logic
            targets = db.get_targets()
            findings = db.get_all_findings()
            # Update UI elements here if they exist
        except Exception as e:
            print(f"Error loading overview: {e}")

    def _load_targets_page(self):
        if not hasattr(self, 'tbl_targets'): return
        db = self._get_db()
        if not db: return
        try:
            targets = db.get_targets()
            self.tbl_targets.setRowCount(0)
            for i, t in enumerate(targets):
                self.tbl_targets.insertRow(i)
                self.tbl_targets.setItem(i, 0, QTableWidgetItem(str(t.get('id', ''))))
                self.tbl_targets.setItem(i, 1, QTableWidgetItem(t.get('url', '')))
                self.tbl_targets.setItem(i, 2, QTableWidgetItem(t.get('status', '')))
                self.tbl_targets.setItem(i, 3, QTableWidgetItem(t.get('added_at', '')))
        except Exception as e:
            self._show_status(f"Error loading targets: {e}")

    def _load_active_scans(self):
        if not hasattr(self, 'tbl_active_scans'): return
        db = self._get_db()
        if not db: return
        try:
            scans = db.get_active_scans()
            self.tbl_active_scans.setRowCount(0)
            for i, s in enumerate(scans):
                self.tbl_active_scans.insertRow(i)
                self.tbl_active_scans.setItem(i, 0, QTableWidgetItem(str(s.get('id', ''))))
                self.tbl_active_scans.setItem(i, 1, QTableWidgetItem(s.get('target', '')))
                self.tbl_active_scans.setItem(i, 2, QTableWidgetItem(s.get('progress', '0%')))
                self.tbl_active_scans.setItem(i, 3, QTableWidgetItem(s.get('status', '')))
        except Exception as e:
            pass

    def _load_findings_page(self, severity_filter=None, status_filter=None, search=None):
        if not hasattr(self, 'tbl_findings'): return
        db = self._get_db()
        if not db: return
        try:
            findings = db.get_all_findings()
            
            # Apply filters
            if severity_filter and severity_filter != 'All':
                findings = [f for f in findings if f.get('severity', '').lower() == severity_filter.lower()]
            if status_filter and status_filter != 'All':
                findings = [f for f in findings if f.get('status', '').lower() == status_filter.lower()]
            if search:
                s = search.lower()
                findings = [f for f in findings if s in f.get('title', '').lower() or s in f.get('description', '').lower()]
            
            self._findings_cache = findings
            self.tbl_findings.setRowCount(0)
            for i, f in enumerate(findings):
                self.tbl_findings.insertRow(i)
                self.tbl_findings.setItem(i, 0, QTableWidgetItem(str(f.get('id', ''))))
                self.tbl_findings.setItem(i, 1, QTableWidgetItem(f.get('title', '')))
                self._set_table_item_severity(self.tbl_findings, i, 2, f.get('severity', 'Info'))
                self.tbl_findings.setItem(i, 3, QTableWidgetItem(f.get('status', '')))
        except Exception as e:
            pass

    def _load_intelligence_page(self):
        pass

    def _load_assets_page(self):
        pass

    def _load_reports_page(self):
        if not hasattr(self, 'tbl_reports'): return
        try:
            reports_dir = Path(BASE_DIR) / 'reports'
            if not reports_dir.exists():
                return
                
            self.tbl_reports.setRowCount(0)
            files = list(reports_dir.glob('*.pdf')) + list(reports_dir.glob('*.html'))
            for i, f in enumerate(files):
                self.tbl_reports.insertRow(i)
                self.tbl_reports.setItem(i, 0, QTableWidgetItem(f.name))
                self.tbl_reports.setItem(i, 1, QTableWidgetItem(str(f.stat().st_size)))
                self.tbl_reports.setItem(i, 2, QTableWidgetItem(datetime.fromtimestamp(f.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')))
        except Exception as e:
            pass

    def _load_exporter_page(self):
        if not hasattr(self, 'cmb_export_target'): return
        db = self._get_db()
        if not db: return
        try:
            targets = db.get_targets()
            self.cmb_export_target.clear()
            for t in targets:
                self.cmb_export_target.addItem(t.get('url', ''), t.get('id'))
        except Exception:
            pass

    def _load_scanner_registry(self):
        if not hasattr(self, 'tbl_scanners'): return
        try:
            from core import registry
            scanners = registry.get_registered_scanners()
            self.tbl_scanners.setRowCount(0)
            for i, s in enumerate(scanners):
                self.tbl_scanners.insertRow(i)
                self.tbl_scanners.setItem(i, 0, QTableWidgetItem(s.get('name', '')))
                bin_path = s.get('binary', '')
                self.tbl_scanners.setItem(i, 1, QTableWidgetItem(bin_path))
                
                # Check binary
                is_installed = shutil.which(bin_path) is not None
                status = "Installed" if is_installed else "Missing"
                status_item = QTableWidgetItem(status)
                if is_installed:
                    status_item.setBackground(QBrush(QColor('#28a745')))
                else:
                    status_item.setBackground(QBrush(QColor('#dc3545')))
                status_item.setForeground(QBrush(QColor('#ffffff')))
                self.tbl_scanners.setItem(i, 2, status_item)
        except Exception as e:
            self._show_status(f"Error loading registry: {e}")

    def _load_settings_page(self):
        pass

    def _load_audit_log(self):
        if not hasattr(self, 'tbl_audit_log'): return
        db = self._get_db()
        if not db: return
        try:
            logs = db.get_log_entries(limit=500)
            self.tbl_audit_log.setRowCount(0)
            for i, log in enumerate(logs):
                self.tbl_audit_log.insertRow(i)
                self.tbl_audit_log.setItem(i, 0, QTableWidgetItem(log.get('timestamp', '')))
                self.tbl_audit_log.setItem(i, 1, QTableWidgetItem(log.get('action', '')))
                self.tbl_audit_log.setItem(i, 2, QTableWidgetItem(log.get('user', '')))
        except Exception:
            pass

    # Target operations
    def _add_target(self):
        url = self.inp_target_url.text().strip()
        if not url:
            QMessageBox.warning(self, "Invalid Input", "Target URL cannot be empty.")
            return
        if not (url.startswith('http://') or url.startswith('https://') or self._is_ip(url)):
            QMessageBox.warning(self, "Invalid Input", "Must be HTTP/HTTPS or valid IP.")
            return
            
        try:
            from ui.components.responsibility_dialog import ResponsibilityDialog
            op_name = self._get_operator_name()
            dlg = ResponsibilityDialog(target_url=url, operator=op_name, parent=self)
            if dlg.exec() == QDialog.Accepted:
                db = self._get_db()
                if db:
                    db.add_target(url)
                    self._load_targets_page()
                    self._show_status(f"Added target: {url}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add target: {e}")

    def _is_ip(self, text):
        import re
        return re.match(r'^\d{1,3}(\.\d{1,3}){3}$', text) is not None

    def _delete_target(self):
        if not hasattr(self, 'tbl_targets'): return
        row = self.tbl_targets.currentRow()
        if row < 0: return
        
        target_id = self.tbl_targets.item(row, 0).text()
        url = self.tbl_targets.item(row, 1).text()
        
        reply = QMessageBox.question(self, 'Confirm Delete', f"Delete target {url}?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            db = self._get_db()
            if db:
                try:
                    db.delete_target(int(target_id))
                    self._load_targets_page()
                    self._show_status(f"Deleted target: {url}")
                except Exception as e:
                    self._show_status(f"Failed to delete: {e}")

    def _scan_target(self):
        if not hasattr(self, 'tbl_targets'): return
        row = self.tbl_targets.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Select Target", "Please select a target to scan.")
            return
            
        target_id = self.tbl_targets.item(row, 0).text()
        url = self.tbl_targets.item(row, 1).text()
        
        try:
            from ui.components.system_check_dialog import SystemCheckDialog
            dlg = SystemCheckDialog(parent=self)
            if dlg.exec() == QDialog.Accepted:
                target = {'id': target_id, 'url': url}
                from core import config_manager
                settings = config_manager.load_settings()
                
                worker = ScanWorker(target, settings)
                worker.scan_progress.connect(self._on_scan_progress)
                worker.scan_complete.connect(self._on_scan_complete)
                worker.scan_log.connect(self._on_scan_log)
                worker.scan_error.connect(self._on_scan_error)
                
                self._active_workers[target_id] = worker
                worker.start()
                
                self._nav_clicked(2) # Switch to Active Scans
                self._show_status(f"Started scan on {url}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not start scan: {e}")

    def _target_double_clicked(self, row, col):
        pass

    # Active scans ops
    def _pause_scan(self):
        pass

    def _stop_scan(self):
        pass

    def _toggle_log(self):
        pass

    # Worker callbacks
    def _on_scan_progress(self, target, scanner, percent):
        pass

    def _on_scan_complete(self, target, success):
        self._show_status(f"Scan complete for {target}. Success: {success}")
        self._load_active_scans()
        self._load_findings_page()

    def _on_scan_log(self, line):
        if hasattr(self, 'txt_scan_log'):
            ts = datetime.now().strftime('%H:%M:%S')
            self.txt_scan_log.append(f"[{ts}] {line}")

    def _on_scan_error(self, target, error):
        QMessageBox.warning(self, "Scan Error", f"Error scanning {target}:\n{error}")

    # Findings
    def _search_findings(self):
        search_text = self.inp_search_findings.text().strip() if hasattr(self, 'inp_search_findings') else None
        sev = self.cmb_severity.currentText() if hasattr(self, 'cmb_severity') else None
        stat = self.cmb_status.currentText() if hasattr(self, 'cmb_status') else None
        self._load_findings_page(severity_filter=sev, status_filter=stat, search=search_text)

    def _filter_findings(self):
        self._search_findings()

    def _show_finding_detail(self, row, col):
        if row < len(self._findings_cache):
            finding = self._findings_cache[row]
            if hasattr(self, 'finding_panel'):
                self.finding_panel.show_finding(finding)

    # Intel
    def _search_cve(self):
        pass

    # Reports
    def _generate_report(self):
        try:
            target_id = self.cmb_report_target.currentData() if hasattr(self, 'cmb_report_target') else None
            from tools.report_generator import ReportGenerator
            rg = ReportGenerator()
            output_path = rg.generate(target_id)
            QMessageBox.information(self, "Report Generated", f"Success!\nSaved to: {output_path}")
            self._load_reports_page()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Generation failed: {e}")

    def _verify_report(self):
        if not hasattr(self, 'tbl_reports'): return
        row = self.tbl_reports.currentRow()
        if row < 0: return
        
        filename = self.tbl_reports.item(row, 0).text()
        filepath = Path(BASE_DIR) / 'reports' / filename
        
        try:
            from tools import verify_report
            result = verify_report.verify_report(str(filepath))
            if result:
                QMessageBox.information(self, "Verification", "Report is authentic and untampered.")
            else:
                QMessageBox.warning(self, "Verification Failed", "Report verification failed!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Verification error: {e}")

    # Exporter
    def _browse_export_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select Export Directory")
        if d and hasattr(self, 'inp_export_dir'):
            self.inp_export_dir.setText(d)

    def _execute_export(self):
        if not hasattr(self, 'inp_legal_gate') or self.inp_legal_gate.text().strip() != 'I AGREE':
            QMessageBox.warning(self, "Legal Gate", "You must type 'I AGREE' to confirm authorization.")
            return
            
        target_id = self.cmb_export_target.currentData() if hasattr(self, 'cmb_export_target') else None
        fmt = self.cmb_export_format.currentText() if hasattr(self, 'cmb_export_format') else 'JSON'
        out_dir = self.inp_export_dir.text() if hasattr(self, 'inp_export_dir') else str(Path.home())
        
        try:
            from ui.components.export_gate_dialog import ExportGateDialog
            dlg = ExportGateDialog(engagement_details={"target": target_id}, parent=self)
            if not dlg.exec():
                return
            if not dlg.is_confirmed:
                return
                
            progress = QProgressDialog("Preparing export...", "Cancel", 0, 100, self)
            progress.setWindowModality(Qt.WindowModal)
            progress.show()
            
            from tools.data_exporter import DataExporter
            exporter = DataExporter()
            op = self._get_operator_name()
            
            result = exporter.export(
                engagement_id=target_id,
                format=fmt,
                output_dir=out_dir,
                operator=op,
                gate_confirmed=True,
                gate_confirmed_at=dlg.confirmed_at
            )
            
            progress.close()
            
            QMessageBox.information(self, "Export Complete", f"<span style='color:green;'>Export Complete — sha256: {result.get('sha256', 'UNKNOWN')}</span>")
            QMessageBox.warning(self, "Security Warning", "<b>This export is NOT encrypted. Secure it immediately.</b>")
            
            self._load_exporter_page()
            
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    # Scanner registry
    def _check_scanner_tools(self):
        try:
            script_path = Path(BASE_DIR) / 'tools' / 'troubleshoot.py'
            process = subprocess.Popen([sys.executable, str(script_path), '--check'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = process.communicate()
            
            msg = out.decode() if out else err.decode()
            QMessageBox.information(self, "Troubleshoot Output", msg)
            self._load_scanner_registry()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to run checks: {e}")

    # Settings
    def _save_settings(self):
        try:
            from core import config_manager
            # Collect data from form
            settings = {}
            config_manager.save_settings(settings)
            self._show_status("Settings saved.")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _change_password(self):
        pass

    def _wipe_database(self):
        text, ok = QInputDialog.getText(self, "Wipe Database", "Type WIPE to confirm full database destruction:")
        if ok and text == 'WIPE':
            db = self._get_db()
            if db:
                try:
                    db.wipe_database()
                    QMessageBox.information(self, "Wiped", "Database has been wiped.")
                    self._load_all_pages()
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))

    def _on_ipc_event(self, event: dict):
        event_type = event.get('type')
        if event_type == 'scan_progress':
            pass
        elif event_type == 'scan_complete':
            self._load_active_scans()
            self._load_findings_page()

    def closeEvent(self, event):
        if hasattr(self, 'udp_thread'):
            self.udp_thread.stop()
            self.udp_thread.wait()
        for worker in self._active_workers.values():
            if worker.isRunning():
                worker.quit()
                worker.wait()
        event.accept()

