import psutil
from typing import Dict

class ResourceMonitor:
    def __init__(self):
        self.limits: Dict[str, float] = {}

    def set_limits(self, limits: Dict[str, float]):
        self.limits = limits

    def monitor_resources(self, pid: int) -> Dict[str, float]:
        """Monitor resource usage for process."""
        try:
            proc = psutil.Process(pid)
            cpu_percent = proc.cpu_percent(interval=0.1)
            mem_info = proc.memory_info()
            return {
                "cpu_percent": cpu_percent,
                "memory_mb": mem_info.rss / (1024 * 1024)
            }
        except psutil.NoSuchProcess:
            return {}

    def check_limits(self, usage: Dict[str, float], limits: Dict[str, float]) -> bool:
        """Check if resource limits exceeded."""
        if "cpu_percent" in limits and usage.get("cpu_percent", 0) > limits["cpu_percent"]:
            return False
        if "memory_mb" in limits and usage.get("memory_mb", 0) > limits["memory_mb"]:
            return False
        return True

    def enforce_limits(self, pid: int, limits: Dict[str, float]):
        """Enforce resource limits (stub implementation, typically requires cgroups)."""
        # Monitoring and potentially sending SIGSTOP/SIGCONT or altering nice level
        usage = self.monitor_resources(pid)
        if not self.check_limits(usage, limits):
            # Try to renice process if it's using too much CPU
            try:
                proc = psutil.Process(pid)
                proc.nice(10)
            except psutil.NoSuchProcess:
                pass
