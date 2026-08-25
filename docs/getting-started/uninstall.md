# Uninstall

Stop WatchTower-owned services first:

```powershell
.\watchtower.ps1 stop
```

or:

```bash
./watchtower.sh stop
```

Remove the repository and the runtime state under the platform WatchTower
application-data directory when you no longer need local evidence. Remove
Npcap, Sysmon, Docker Desktop, or the optional Neo4j volume separately using
their platform tools. Preserve a verified case bundle before deleting data.
