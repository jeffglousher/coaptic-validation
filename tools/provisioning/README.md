# Receipt recovery fixture

Run `python -m unittest discover -s tools/provisioning -p 'test_*.py'` from the
suite root. Python's standard SQLite module provides this bounded host fixture.
It stores telemetry and its receipt in one transaction, retains complete content
for duplicate comparison, and holds the caller's policy fence until commit.

Tests terminate child processes before and after commit, reopen the database,
retry lost acknowledgements, and refuse changed content, revoked policy,
capacity exhaustion and stale backup checkpoints. Desired and applied versions
are separate, monotonic and scoped to the complete principal and resource.

The authority in these tests is in memory. A supplied checkpoint must come from
an independently current source; hashing a backup does not establish freshness.
These checks do not qualify physical power loss, a production authority, protected
backup storage, device flash or an application service. Process-crash recovery
under SQLite FULL synchronization is the demonstrated boundary.

[provenance.json](provenance.json) records the original source revision and file
hashes before migration. No firmware or compiled archive is included.
