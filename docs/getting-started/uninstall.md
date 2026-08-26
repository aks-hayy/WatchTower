# Uninstall

The supported one-command uninstall is:

```powershell
.\watchtower.ps1 uninstall
```

Type `UNINSTALL` when prompted. This stops WatchTower-owned services and
removes generated dependencies, containers, volumes, and local sensor state;
source files and the Git repository remain intact.

To only stop the runtime without removing anything:

```powershell
.\watchtower.ps1 stop
```

On Linux, stop the runtime with:

```bash
./watchtower.sh stop
```

Remove the repository and the runtime state under the platform WatchTower
application-data directory when you no longer need local evidence. Remove
Npcap, Sysmon, Docker Desktop, or the optional Neo4j volume separately using
their platform tools. Preserve a verified case bundle before deleting data.
