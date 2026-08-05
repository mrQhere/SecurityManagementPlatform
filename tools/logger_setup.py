import os
import logging
from tools.config_manager import BASE_DIR, init_directories
from tools.db_manager import add_log_entry

import logging.handlers

class RecreatingFileHandler(logging.handlers.RotatingFileHandler):
    """FileHandler that automatically recreates the log file and directories on disk if deleted."""
    def __init__(self, filename, mode='a', maxBytes=10*1024*1024, backupCount=5, encoding=None, delay=False):
        super().__init__(filename, mode, maxBytes, backupCount, encoding, delay)

    def emit(self, record):
        try:
            if not os.path.exists(self.baseFilename):
                os.makedirs(os.path.dirname(self.baseFilename), exist_ok=True)
                self.stream = self._open()
        except Exception:
            pass
        super().emit(record)

class SQLiteLogHandler(logging.Handler):
    """Custom logging handler to write logs to the SQLite database logs table."""
    def emit(self, record):
        try:
            log_msg = self.format(record)
            add_log_entry(record.levelname, log_msg)
        except Exception as e:
            # Prevent recursive loop if DB logging fails, print to stderr
            import sys
            sys.stderr.write(f"Failed to log to SQLite: {e}\n")

def setup_logging():
    init_directories()
    
    # Base path for logs
    log_dir = os.path.join(BASE_DIR, "logs")
    
    # Unified single log file for all subsystems
    unified_log_path = os.path.join(log_dir, "smp.log")
    
    # Create formatters
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    
    # 1. Master Unified Handler (everything INFO and above)
    master_handler = RecreatingFileHandler(unified_log_path, encoding="utf-8")
    master_handler.setLevel(logging.INFO)
    master_handler.setFormatter(formatter)
    
    # 2. Error Handler (also writes to the same unified log for console/tail tracking if needed, 
    # but since master captures INFO, it's redundant. We'll just keep the master handler.)
    
    # 3. SQLite DB Log Handler (INFO and above)
    db_handler = SQLiteLogHandler()
    db_handler.setLevel(logging.INFO)
    db_handler.setFormatter(logging.Formatter("%(message)s")) # Simple message for database log table
    
    # Setup logger names for scans and updates
    logger_root = logging.getLogger("smp")
    logger_root.setLevel(logging.INFO)
    
    # Add shared handlers to root logger
    logger_root.addHandler(master_handler)
    logger_root.addHandler(db_handler)
    
    # 4. Scan Log Handler (Only for smp.scan logger)
    logger_scan = logging.getLogger("smp.scan")
    logger_scan.addHandler(master_handler)
    
    # 5. Update Log Handler (Only for smp.update logger)
    logger_update = logging.getLogger("smp.update")
    logger_update.addHandler(master_handler)
    
    # 6. CVE Log Handler (Only for smp.cve logger)
    logger_cve = logging.getLogger("smp.cve")
    logger_cve.addHandler(master_handler)
    
    # Ensure standard library warnings are captured
    logging.captureWarnings(True)
    
    return logger_root
