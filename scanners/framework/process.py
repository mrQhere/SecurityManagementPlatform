import subprocess
import time
import psutil
from typing import Dict, List

class ProcessTracker:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.processes: Dict[str, Dict] = {}
    
    def start_process(self, scanner_name: str, command: List[str], workspace: str) -> str:
        """Start and track a subprocess."""
        start_time = time.time()
        
        proc = subprocess.Popen(
            command,
            cwd=workspace,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        pid = str(proc.pid)
        self.processes[pid] = {
            "scanner_name": scanner_name,
            "command": command,
            "workspace": workspace,
            "start_time": start_time,
            "process_obj": proc,
            "status": "RUNNING"
        }
        return pid
    
    def monitor_process(self, pid: str) -> Dict:
        """Monitor process status."""
        p_info = self.processes.get(pid)
        if not p_info:
            return {}
            
        proc = p_info["process_obj"]
        retcode = proc.poll()
        
        if retcode is not None:
            p_info["status"] = "COMPLETED"
            p_info["exit_code"] = retcode
            p_info["end_time"] = time.time()
            # Read streams
            stdout_data, stderr_data = proc.communicate()
            p_info["stdout"] = stdout_data
            p_info["stderr"] = stderr_data
            
        return p_info
    
    def terminate_process(self, pid: str, force: bool = False) -> bool:
        """Terminate process and process tree."""
        p_info = self.processes.get(pid)
        if not p_info:
            return False
            
        proc = p_info["process_obj"]
        if proc.poll() is None:
            try:
                parent = psutil.Process(proc.pid)
                children = parent.children(recursive=True)
                
                # Kill children first
                for child in children:
                    if force:
                        child.kill()
                    else:
                        child.terminate()
                        
                # Kill parent
                if force:
                    parent.kill()
                else:
                    parent.terminate()
                    
                parent.wait(timeout=5)
                p_info["status"] = "TERMINATED"
                return True
            except psutil.NoSuchProcess:
                pass
            except Exception:
                pass
        return False
    
    def get_process_info(self, pid: str) -> Dict:
        """Get detailed process information."""
        return self.processes.get(pid, {})
