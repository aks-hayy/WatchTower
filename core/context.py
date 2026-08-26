import os
import sys
import ctypes
import base64

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
        try:
            configured_daemon_port = int(os.environ.get("WATCHTOWER_DAEMON_PORT", "9999"))
        except (TypeError, ValueError):
            configured_daemon_port = 9999
        self.daemon_port = configured_daemon_port if 1 <= configured_daemon_port <= 65535 else 9999
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
            # ShellExecute does not inherit ad-hoc environment variables across
            # the UAC boundary.  The hybrid sensor uses WATCHTOWER_HOME to keep
            # its daemon, database, and key isolated from the controller, so
            # launch the elevated command through PowerShell with that variable
            # explicitly restored.
            runtime_home = os.environ.get("WATCHTOWER_HOME")
            if runtime_home:
                def ps_quote(value):
                    return "'" + str(value).replace("'", "''") + "'"

                command = (
                    f"Set-Location -LiteralPath {ps_quote(cwd or os.getcwd())}; "
                    f"$env:WATCHTOWER_HOME = {ps_quote(runtime_home)}; "
                )
                runtime_port = os.environ.get("WATCHTOWER_DAEMON_PORT")
                if runtime_port:
                    command += f"$env:WATCHTOWER_DAEMON_PORT = {ps_quote(runtime_port)}; "
                if os.environ.get("WATCHTOWER_SENSOR_SERVICE") == "1":
                    command += "$env:WATCHTOWER_SENSOR_SERVICE = '1'; "
                command += (
                    f"& {ps_quote(executable)} {params}; "
                    "exit $LASTEXITCODE"
                )
                encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
                powershell = os.environ.get("WINDIR", r"C:\Windows") + r"\System32\WindowsPowerShell\v1.0\powershell.exe"
                elevated_params = f"-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {encoded}"
                return ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", powershell, elevated_params, cwd, 0
                )
            # 1 = SW_SHOWNORMAL
            return ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, cwd, 1)
        return False

# Global Accessor
context = WatchtowerContext()
