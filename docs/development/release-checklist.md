# V2 Release Checklist

1. Verify the external pre-cleanup manifest and stop WatchTower-owned
   processes, containers, and sensors.
2. Run the Python, Rust, UI, container, calibration, and product smoke gates.
3. Run the release-tree, secret, PII, large-file, and Markdown-link checks on
   the exact candidate tree.
4. Build and test from a fresh Windows and Ubuntu checkout, recording any
   unsupported hardware capability explicitly.
5. Run SQLite `quick_check`, hash the acceptance artifacts, and verify the
   calibration attestation digests.
6. Create or update the V1 maintenance refs, then create the parentless V2
   commit and RC tag only after every release blocker is resolved or documented.

The release commit is not a substitute for independent operational acceptance.
