# Storage and Data Boundaries

SQLite is the local source of truth for capture sessions, conversations,
findings, identities, evidence references, analyst audit records, and the
graph outbox. Runtime state belongs in the platform application-data
directory, never in the repository.

Repository methods own database access. New schema changes are additive and
must preserve source, interface, session, node, and analysis scope. Evidence
records are immutable; projected cards and compatibility API responses may be
rebuilt. Run SQLite `quick_check` on generated smoke-test databases before
publishing a release.
