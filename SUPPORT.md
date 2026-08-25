# WatchTower Support Policy

WatchTower V2 is an independent rewrite. The supported release line is the
branch and tag documented by the current release notes; V1 maintenance remains
on `v1-maintenance`.

## Before reporting a problem

1. Reproduce it on a clean checkout with the documented Python version.
2. Run `tower doctor` and record the sanitized output.
3. Include the operating system, WatchTower version, backend, command or UI
   route, and a short reproduction.
4. Attach request IDs, stack traces, and hashes, but never attach credentials,
   raw packet payloads, private keys, runtime databases, or personal data.

Security issues belong in the private process described in `SECURITY.md`.
Feature requests should explain the analyst workflow, evidence needed, and
how the behavior can remain bounded and auditable.
