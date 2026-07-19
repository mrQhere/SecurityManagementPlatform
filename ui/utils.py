"""
ui/utils.py — Shared UI utilities for Security Management Platform.
Single source of truth. Import WorkerThread from here everywhere.
"""
from PySide6.QtCore import QThread, Signal


class WorkerThread(QThread):
    """Run any callable in a background thread and emit (success, result) when done."""
    finished_signal = Signal(object)

    def __init__(self, target_func, *args, **kwargs):
        super().__init__()
        self.target_func = target_func
        self.args = args
        self.kwargs = kwargs
        self._result = None

    def run(self):
        try:
            res = self.target_func(*self.args, **self.kwargs)
            self.finished_signal.emit((True, res))
        except Exception as e:
            self.finished_signal.emit((False, e))
