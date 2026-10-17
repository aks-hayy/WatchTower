# Windows 11

Open PowerShell in the repository root and run the automatic installer:

```powershell
.\install.ps1
```

It selects hybrid only when the local Docker Desktop, Compose, and Linux
engine are ready; otherwise it installs the native single-host edition. It
does not install Docker automatically or select remote Docker contexts. To
require a specific deployment shape, choose one explicitly:

```powershell
.\install.ps1 -Mode hybrid
.\install.ps1 -Mode native
```

Hybrid mode creates `.venv`, installs the pinned Python runtime, builds the
Rust sensor and UI container, and checks Docker Desktop. Start its UI and
companion CLI with `.\watchtower.ps1 start`.

To install without Docker Desktop, use native mode and launch the UI/API:

```powershell
.\install.ps1 -Mode native
.\.venv\Scripts\tower.exe ui
```

Keep that terminal open while using the UI; press Ctrl+C to stop the local
UI/API. Open a second PowerShell for the interactive CLI:

```powershell
.\.venv\Scripts\tower.exe
```

Both installation paths install the Rust sensor. Windows live capture also
requires Npcap and its SDK, plus Visual C++ Build Tools; setup can install the
pinned SDK and Npcap driver when prerequisites are enabled. Npcap's license
requires visible confirmation. Run `tower sources` to see available capture
names and backends.

Optional integrations:

```powershell
.\install.ps1 -WithSysmon -SysmonExecutable C:\Tools\Sysmon64.exe
.\install.ps1 -WithNeo4j
```

The installer creates the local Neo4j credential in the ignored runtime
secrets directory. Set `WATCHTOWER_NEO4J_PASSWORD_FILE` only when supplying
an operator-managed secret file.

For hybrid mode, use the small public lifecycle surface:

```powershell
.\watchtower.ps1 start       # start the runtime and both operator surfaces
.\watchtower.ps1 ui          # start/reuse the runtime and open only the UI
.\watchtower.ps1 cli         # start/reuse the runtime and open only the CLI
.\watchtower.ps1 stop        # drain capture and stop WatchTower services
.\watchtower.ps1 uninstall   # remove generated runtime state after confirmation
```

Hybrid is the recommended multi-node path; native mode avoids the controller
container on a single Windows host. Advanced diagnostics and bridge repair
remain available through the scripts under `scripts/`.
