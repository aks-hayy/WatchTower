# Windows 11

Open PowerShell in the repository root and run:

```powershell
.\install.ps1
.\watchtower.ps1 start
```

The installer creates `.venv`, installs the pinned Python runtime, builds the
Rust sensor, builds the UI container, and checks Docker Desktop. Npcap is a
separate operator-managed install because its license and driver setup may
require visible confirmation. Run `tower sources` after installation to see
the exact capture names.

Optional integrations:

```powershell
.\install.ps1 -WithSysmon -SysmonExecutable C:\Tools\Sysmon64.exe
.\install.ps1 -WithNeo4j
```

The installer creates the local Neo4j credential in the ignored runtime
secrets directory. Set `WATCHTOWER_NEO4J_PASSWORD_FILE` only when supplying
an operator-managed secret file.

The recommended runtime is the hybrid controller plus native Rust sensor.
Use `watchtower.ps1 status`, `logs`, and `repair` for lifecycle recovery.
