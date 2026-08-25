import os
import sys
import ctypes

from core.runtime_paths import RuntimePaths

class WatchtowerContext:
    """
    Centralized singleton for environment configuration and absolute path resolution.
    Ensures all components reference the same directories regardless of working directory.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(WatchtowerContext, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        # 1. Resolve Project Root (Assume this file is in core/context.py)
        self.root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        
        # 2. Standardize Key Directories
        self.runtime_paths = RuntimePaths.from_environment(repository_root=self.root_dir)
        self.runtime_paths.ensure()
        self.data_dir = str(self.runtime_paths.data)
        self.config_dir = str(self.runtime_paths.config)
        self.cache_dir = str(self.runtime_paths.cache)
        self.logs_dir = str(self.runtime_paths.logs)
        self.temp_dir = str(self.runtime_paths.temp)
        self.legacy_data_source = self.runtime_paths.legacy_data_source
        
        # 4. Critical Files
        self.daemon_key_file = os.path.join(self.data_dir, "daemon.key")
        self.daemon_port = 9999
        self.ui_port = 8000

    @property
    def is_admin(self) -> bool:
        """Check if the current process has administrative privileges."""
        if sys.platform == 'win32':
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        return os.geteuid() == 0

    def elevate(self):
        """Attempt to re-launch the current process with elevated privileges and exit current."""
        if sys.platform == 'win32':
            params = " ".join([f'"{arg}"' for arg in sys.argv])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            sys.exit(0)
        else:
            print("Root privileges required. Please re-run with sudo.")
            sys.exit(1)

    def run_elevated(self, executable, params, cwd=None):
        """Launches a separate process with elevated privileges without exiting current."""
        if sys.platform == 'win32':
            # 1 = SW_SHOWNORMAL
            return ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, cwd, 1)
        return False

# Global Accessor
context = WatchtowerContext()
