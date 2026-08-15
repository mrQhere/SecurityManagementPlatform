import os
import shutil
import logging

logger = logging.getLogger("smp")

class WorkspaceManager:
    def __init__(self, base_work_dir: str):
        self.base_work_dir = base_work_dir
        
    def create_workspace(self, scan_id: str) -> str:
        """Create a temporary workspace for a scanner."""
        workspace_path = os.path.join(self.base_work_dir, scan_id)
        
        directories = [
            workspace_path,
            os.path.join(workspace_path, "scanner_outputs"),
            os.path.join(workspace_path, "parsed_data"),
            os.path.join(workspace_path, "evidence"),
            os.path.join(workspace_path, "logs")
        ]
        
        try:
            for directory in directories:
                os.makedirs(directory, exist_ok=True)
            return workspace_path
        except Exception as e:
            logger.error(f"Failed to create workspace {workspace_path}: {e}")
            raise

    def get_workspace_path(self, scan_id: str) -> str:
        """Get the base workspace path."""
        return os.path.join(self.base_work_dir, scan_id)

    def cleanup_workspace(self, scan_id: str):
        """Clean up the workspace and its contents."""
        workspace_path = self.get_workspace_path(scan_id)
        if os.path.exists(workspace_path):
            try:
                shutil.rmtree(workspace_path)
            except Exception as e:
                logger.error(f"Failed to cleanup workspace {workspace_path}: {e}")
