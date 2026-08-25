# Operations

## Runtime layout

WatchTower does not use the Git checkout as its normal data directory.

Windows stores state under `%LOCALAPPDATA%\WatchTower`. Linux uses XDG state, configuration, and cache directories. `WATCHTOWER_HOME` creates a portable isolated tree and is recommended for development, demonstrations, and tests.

Runtime data includes the SQLite database, logs, spools, case metadata, temporary analysis files, exports, configuration overrides, and synchronization state. It must not be committed.

## Service lifecycle

```text
tower daemon start
tower daemon status
tower daemon restart
tower daemon stop
tower daemon repair
```

The daemon owns capture workers and exposes local control state. Capture sessions have independent lifecycle state. `tower daemon repair` reconciles stale local PID or daemon state without killing unrelated processes.

## Capture lifecycle

```text
tower start -i INTERFACE
tower status
tower stop -i INTERFACE
```

Shutdown order is capture stop, queue drain, final detector pass, persistence acknowledgement, and terminal session state. Do not terminate the process to stop a normal capture. Forced termination is recoverable but correctly marks unprocessed work as partial.

## Health interpretation

The UI and `tower status` expose:

- Received, emitted, processed, dropped, and pending packet counts.
- Queue depth and queue lag.
- Detector and evidence failures.
- Capture backend and process state.
- Database connection-pool pressure.
- Session completeness and completion reason.
- Sensor, Sysmon, and graph freshness where configured.

An unsupported metric is different from zero. A stale heartbeat is different from a stopped session. WatchTower keeps these states distinct.

## Operational reset

`tower clean` removes operational observations while preserving authentication configuration, provider credentials, mesh trust, enrollments, and operator configuration. Factory reset removes those retained settings as well and requires explicit confirmation.

Always stop capture and analysis services before restoring databases or scoring backups.

## Backups

Database migrations and scoring promotion use SQLite's backup API, verify `quick_check`, and record hashes. Case exports are separate hashed bundles. Copying a live `.db` file directly is not a supported backup procedure.

## Upgrades

1. Stop capture and the mesh controller cleanly.
2. Back up the runtime directory.
3. Pull the new source revision.
4. Rerun the setup script without deleting `.venv` unless Python changed.
5. Run `tower doctor` and `tower plugins calibration verify`.
6. Start a short capture and confirm flow/session provenance before returning to normal operation.

Database schema changes are additive unless a release note explicitly documents a migration.
