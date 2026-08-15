"""
Security Management Platform V9.5 — Application Entry Point
"""
import os
import sys
import signal
import argparse
if os.name != "nt":
    import fcntl
import atexit
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

LOCK_FILE = '/tmp/.smp_runtime.lock'
lock_fd = None

def single_instance_lock():
    if os.name == "nt":
        return
    global lock_fd
    try:
        lock_fd = open(LOCK_FILE, 'w')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        print("Another instance of SMP is already running. Exiting.")
        sys.exit(1)

def release_lock():
    if os.name == "nt":
        return
    global lock_fd
    if lock_fd:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()
            os.remove(LOCK_FILE)
        except Exception:
            pass

def graceful_shutdown(signum, frame):
    print("Received signal, shutting down gracefully...")
    release_lock()
    sys.exit(0)

def start_api_mode():
    try:
        from api.server import start_server
        start_server()
    except ImportError:
        print("Error: Required API packages (FastAPI/uvicorn) not installed.")
        sys.exit(1)

def start_gui_mode(operator_name):
    from PySide6.QtWidgets import QApplication, QMessageBox
    from PySide6.QtCore import QTimer

    from ui.views.splash_screen import SplashScreen
    from ui.components.password_dialog import PasswordDialog
    from ui.dashboard import DashboardWindow
    from tools.encryption_manager import KeyStore as EncryptionManager

    app = QApplication(sys.argv)

    splash = SplashScreen()
    splash.show()

    # Process events to show splash screen properly
    app.processEvents()

    def on_splash_timeout():
        splash.close()

        enc_manager = EncryptionManager()
        is_first_run = not enc_manager.has_password_set()
        
        auth_success = False
        attempts = 0
        max_attempts = 3
        
        while attempts < max_attempts and not auth_success:
            dialog = PasswordDialog(first_run=is_first_run)
            if dialog.exec():
                pwd = dialog.get_password()
                if is_first_run:
                    if enc_manager.setup_password(pwd):
                        auth_success = True
                    else:
                        QMessageBox.critical(None, "Error", "Failed to setup password.")
                        sys.exit(1)
                else:
                    if enc_manager.verify_password(pwd):
                        auth_success = True
                    else:
                        attempts += 1
                        QMessageBox.warning(None, "Authentication Failed", f"Incorrect password. Attempts remaining: {max_attempts - attempts}")
            else:
                sys.exit(0)
                
        if not auth_success:
            QMessageBox.critical(None, "Authentication Failed", "Maximum password attempts exceeded. Exiting.")
            sys.exit(1)
            
        window = DashboardWindow(operator_name=operator_name)
        window.show()
        
        # Keep reference to avoid garbage collection
        app._main_window = window
        
    QTimer.singleShot(2000, on_splash_timeout)
    
    sys.exit(app.exec())

def main():
    parser = argparse.ArgumentParser(description="Security Management Platform V9.5")
    parser.add_argument("--api", action="store_true", help="Start in API mode")
    parser.add_argument("--operator", type=str, default="Unknown", help="Operator name")
    parser.add_argument("--no-lock", action="store_true", help="Disable single instance lock")
    args = parser.parse_args()

    if not args.no_lock:
        single_instance_lock()
        atexit.register(release_lock)

    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    if args.api:
        start_api_mode()
    else:
        start_gui_mode(args.operator)

if __name__ == '__main__':
    main()
