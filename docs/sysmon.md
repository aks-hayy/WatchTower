# Sysmon Process and Service Attribution

WatchTower can correlate Windows Sysmon Event ID 3 network connections with Event ID 1 process creation records. The supplied policy is [config/sysmon/watchtower-sysmon.xml](../config/sysmon/watchtower-sysmon.xml).

## Install

Install Sysmon from Microsoft, then run an elevated setup:

```powershell
.\scripts\setup.ps1 -WithSysmon -SysmonExecutable C:\Tools\Sysmon64.exe
```

If Sysmon is already installed, setup updates its configuration instead of attempting a second installation. WatchTower validates that the expected event channel exists.

## Correlation

Flow attribution uses protocol, local/remote tuple, direction, event time, process lifetime, and Windows service PID mappings. Results are classified as:

- `sysmon_exact`: an exact event-backed tuple and time match.
- `socket_fallback`: a bounded local socket observation supports the mapping.
- `ambiguous`: multiple processes or services remain plausible.
- `unattributed`: no reliable process evidence exists.

An unattributed metadata record does not count as successful coverage. Shared `svchost.exe` mappings remain service candidates unless PID-to-service evidence identifies one service.

## Stored fields

Image path, PID, parent process, user, hashes, service names/candidates, timestamps, and provenance may be stored. Command lines are redacted, and credentials or packet payloads are never persisted as attribution evidence.

## Health

```text
tower endpoint sysmon status
tower endpoint processes --ip 192.168.1.20
```

Health reports channel availability, bookmark state, backlog, observation count, parsing errors, and exact/fallback/ambiguous/unattributed coverage.
