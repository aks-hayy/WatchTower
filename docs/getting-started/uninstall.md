# Uninstall

The supported one-command uninstall is:

```powershell
.\watchtower.ps1 uninstall
```

Type `UNINSTALL` when prompted. This stops WatchTower-owned services, removes
their containers and generated dependencies, and keeps named Docker volumes,
deployment configuration and encryption keys, and local sensor state. Stored
captures, cases, identity data, and source files remain intact. Optional
Ollama, Linux sensor, mesh, and configured Neo4j containers are included in
cleanup; normal uninstall does not remove their volumes.

Only use `-Purge` after verifying a backup when you intend to remove the stored
data as well. This removes WatchTower's Docker volumes, local runtime data,
deployment configuration, and encryption keys. If the active processes or
container deployment cannot be stopped safely, uninstall reports failure and
leaves the data files in place:

```powershell
.\watchtower.ps1 uninstall -Purge
```

To only stop the runtime without removing anything:

```powershell
.\watchtower.ps1 stop
```

On Linux, stop the runtime with:

```bash
./watchtower.sh stop
```

Remove Npcap, Sysmon, or Docker Desktop separately using their platform tools.
Preserve a verified case bundle and deployment encryption key before deleting
container data.
