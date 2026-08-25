# Upgrade and Rollback

Stop the current runtime, make a verified backup of the WatchTower data
directory, and then update the checkout. Run the installer again; it is
designed to be repeatable and preserves existing operator trust, mesh
enrollment, credentials, and configuration.

If a release is not acceptable, stop services and restore the verified SQLite
backup using the documented restore operation. Do not copy a live database
while WatchTower is writing to it. Keep V1 and V2 data directories separate
when testing both product lines.
