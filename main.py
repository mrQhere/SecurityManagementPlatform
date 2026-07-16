# =============================================================================
# Security Management Platform (SMP) V6.0
# Mega Cooperative — Authorised Personnel Only
# =============================================================================
import sys
import os
import signal
import fcntl

if os.environ.get("XDG_SESSION_TYPE") == "wayland":
    os.environ["QT_QPA_PLATFORM"] = "xcb"

# Add the project directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtWidgets import QApplication
from tools.config_manager import load_settings, init_directories
from tools.db_manager import init_db
from tools.logger_setup import setup_logging
from tools.scheduler import start_scheduler, shutdown_scheduler
from ui.dashboard import DashboardWindow

lock_file_fd = None

def enforce_single_instance():
    """Improvement 1: Establish a strict system-level application lock."""
    global lock_file_fd
    lock_file_path = os.path.join(os.path.expanduser("~"), ".smp_runtime.lock")
    try:
        lock_file_fd = open(lock_file_path, "w")
        fcntl.flock(lock_file_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        print("[❌ FATAL] SMP is already running. Core initialization aborted.")
        sys.exit(1)

def release_lock():
    global lock_file_fd
    if lock_file_fd:
        try:
            fcntl.flock(lock_file_fd, fcntl.LOCK_UN)
            lock_file_fd.close()
        except Exception:
            pass

def handle_system_signals(signum, frame):
    """Handle OS termination requests (SIGINT/SIGTERM) without corrupting SQLite buffers."""
    sig_name = "SIGINT (Ctrl+C)" if signum == 2 else f"signal {signum}"
    print(f"\n  ⚠️   {sig_name} received.")
    print("  Please use the ✕ button inside SMP to close safely next time.")
    print("  Attempting graceful shutdown…")

    # Signal scan_runner to preserve redundancy DB
    try:
        import scanners.scan_runner as _sr
        _sr.signal_app_shutdown()
    except Exception:
        pass

    release_lock()
    try:
        from tools.encryption_manager import encrypt_databases
        encrypt_databases()
        print("  ✅  Databases saved.")
    except Exception as e:
        print(f"  ⚠️   Database save error: {e}")
    try:
        shutdown_scheduler()
    except Exception:
        pass
    # Quit Qt cleanly (triggers on_quit via aboutToQuit)
    try:
        QApplication.quit()
    except Exception:
        pass
    sys.exit(0)



def main():
    import argparse
    parser = argparse.ArgumentParser(description="Security Management Platform")
    parser.add_argument("--api", action="store_true", help="Run the FastAPI backend server instead of the GUI")
    args, unknown = parser.parse_known_args()
    
    if args.api:
        print("[*] Starting SMP V6.0 in Headless API Mode...")
        enforce_single_instance()
        init_directories()
        # ── V6.0 P0 FIX: Decrypt before DB access ─────────────────────────
        from tools.encryption_manager import decrypt_databases
        decrypt_databases()
        init_db()
        setup_logging()

        try:
            import uvicorn
        except ImportError:
            print("[❌ FATAL] FastAPI/uvicorn not installed. Run: pip install fastapi uvicorn")
            sys.exit(1)

        import api.server
        api.server.start_server()
        return

    enforce_single_instance()
    
    # Register OS Signal Interception
    signal.signal(signal.SIGINT, handle_system_signals)
    signal.signal(signal.SIGTERM, handle_system_signals)

    # 1. Initialize PySide6 GUI QApplication early so we can run dialogs
    app = QApplication(sys.argv)

    # ── Force light theme regardless of OS dark-mode setting ──────────────────
    # This ensures the app always renders as light, readable, and consistent.
    app.setStyle("Fusion")
    from PySide6.QtGui import QPalette, QColor
    palette = QPalette()
    palette.setColor(QPalette.Window,          QColor("#F2F2F7"))
    palette.setColor(QPalette.WindowText,      QColor("#1C1C1E"))
    palette.setColor(QPalette.Base,            QColor("#FFFFFF"))
    palette.setColor(QPalette.AlternateBase,   QColor("#F9F9FB"))
    palette.setColor(QPalette.ToolTipBase,     QColor("#FFFFFF"))
    palette.setColor(QPalette.ToolTipText,     QColor("#1C1C1E"))
    palette.setColor(QPalette.Text,            QColor("#1C1C1E"))
    palette.setColor(QPalette.Button,          QColor("#F2F2F7"))
    palette.setColor(QPalette.ButtonText,      QColor("#1C1C1E"))
    palette.setColor(QPalette.BrightText,      QColor("#FF3B30"))
    palette.setColor(QPalette.Link,            QColor("#007AFF"))
    palette.setColor(QPalette.Highlight,       QColor("#007AFF"))
    palette.setColor(QPalette.HighlightedText, QColor("#FFFFFF"))
    palette.setColor(QPalette.Mid,             QColor("#C7C7CC"))
    palette.setColor(QPalette.Shadow,          QColor("#E5E5EA"))
    app.setPalette(palette)
    # ─────────────────────────────────────────────────────────────────────────

    # Register clean shutdown callback
    app.aboutToQuit.connect(on_quit)

    # 2. Run Password Protection dialog
    from ui.components.password_dialog import run_password_protection
    if not run_password_protection():
        print("[!] Security Lock: Authentication failed or cancelled. Exiting.")
        sys.exit(0)

    # Prepend project-local bin/ directory to system PATH
    base_dir = os.path.dirname(os.path.abspath(__file__))
    bin_dir = os.path.join(base_dir, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    if bin_dir not in os.environ["PATH"].split(os.path.pathsep):
        os.environ["PATH"] = bin_dir + os.path.pathsep + os.environ["PATH"]

    # Show Verifier Checker Splash Screen
    from ui.views.splash_screen import SplashScreen, StartupWorker
    splash = SplashScreen()
    splash.show()

    # Keep a global reference so it isn't garbage collected
    global window

    def on_startup_finished():
        global window
        splash.hide()
        splash.close()
        window = DashboardWindow()
        window.show()

    worker = StartupWorker()
    worker.progress.connect(splash.update_progress)
    worker.finished.connect(on_startup_finished)
    # Prevent garbage collection of the worker
    splash.worker = worker 
    worker.start()

    # ── V6.0 P0 FIX: Strict startup order ────────────────────────────────────
    # 1. Decrypt DBs FIRST — before any scheduler, CVE sync, or UI load
    # 2. Initialize DB schema
    # 3. Setup logging (needs DB)
    # 4. THEN start background workers (scheduler, intel sync)
    # This ensures all data (CVEs, scans, findings, risk scores) is available
    # immediately when the UI opens, fixing the "data lost on reopen" P0 bug.
    # ─────────────────────────────────────────────────────────────────────────
    init_directories()

    from tools.encryption_manager import decrypt_databases, is_decryption_ok
    decrypt_databases()

    if not is_decryption_ok():
        print("[⚠️] Warning: DB decryption status uncertain. Data may be incomplete.")

    init_db()
    setup_logging()

    # ── Now safe to start background workers ──────────────────────────────────
    start_scheduler()

    # Run loop
    exit_code = app.exec()
    sys.exit(exit_code)

def on_quit():
    """Cleanup routine when GUI application closes — connected to aboutToQuit signal."""
    import logging
    logger = logging.getLogger("smp")
    logger.info("SMP shutdown initiated.")

    # Stop background tasks
    try:
        shutdown_scheduler()
    except Exception as e:
        logger.warning(f"Scheduler shutdown error: {e}")

    # Encrypt databases
    try:
        from tools.encryption_manager import encrypt_databases
        encrypt_databases()
        logger.info("Databases successfully encrypted.")
    except Exception as e:
        logger.error(f"Failed to encrypt databases: {e}")

    release_lock()
    logger.info("SMP closed successfully.")
    print("\n  ✅  SMP closed successfully. All data saved.\n")

if __name__ == "__main__":
    main()
