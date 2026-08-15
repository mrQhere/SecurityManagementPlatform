import time
from typing import Tuple

class TimeoutHandler:
    def __init__(self, hard_timeout: int, soft_timeout: int = None):
        self.hard_timeout = hard_timeout
        self.soft_timeout = soft_timeout or int(hard_timeout * 0.9)
        self.start_time = None
    
    def start_timer(self):
        """Start timeout timer."""
        self.start_time = time.time()
    
    def check_timeout(self) -> Tuple[bool, str]:
        """Check if timeout exceeded."""
        if not self.start_time:
            return False, ""
            
        elapsed = time.time() - self.start_time
        if elapsed >= self.hard_timeout:
            return True, "hard_timeout"
        elif elapsed >= self.soft_timeout:
            return True, "soft_timeout"
            
        return False, ""
    
    def handle_timeout(self, process_tracker, pid: str) -> str:
        """Handle timeout with graceful shutdown."""
        is_timeout, reason = self.check_timeout()
        if not is_timeout:
            return ""
            
        if reason == "soft_timeout":
            # Graceful terminate
            process_tracker.terminate_process(pid, force=False)
        elif reason == "hard_timeout":
            # Force kill
            process_tracker.terminate_process(pid, force=True)
            
        return reason
