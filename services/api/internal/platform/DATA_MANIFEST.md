# Data Manifest — Platform (shared infrastructure)

Per Art. 8 (privacy is the default; minimum data, documented purpose).

`internal/platform` is not a capability and holds no capability-specific
user data of its own — it is shared, capability-agnostic infrastructure
(a Postgres connection pool, a Redis client, an S3-compatible object-storage
client, and a migration runner) that other capabilities' own stores are
built on top of. See `docs/DECISION_LOG.md`, "Database setup: shared
platform foundation + Audit on real Postgres," and this package's own
`platform.go` doc comment for why it exists and why it is exempt from Art.
10's normal cross-capability-import restriction (`scripts/constitution/
check-modularity.sh`'s `shared_exempt` list).

## Scope (no fields of its own)

This package defines no persisted data fields of its own — no struct here
carries an `// ascend:persisted` marker, so there is deliberately no
`## Fields` heading in this manifest (`scripts/constitution/
check-data-manifests.sh`'s "every bullet needs a Purpose:" rule only
applies under a literal `## Fields`-prefixed heading, and a heading here
would be actively misleading — it would imply fields this package doesn't
actually own). Every real field this package's clients read or write
belongs to whichever capability owns the schema/data in question:

- Audit's `audit_events` table (and its documented field purposes) is
  specified in `services/api/internal/audit/DATA_MANIFEST.md` — this
  package's `internal/platform/migrations/0001_audit_events.up.sql` is the
  schema for it, drafted alongside Audit's own capability-engineer and
  reviewed/merged here per this pass's ownership split, but the *data* and
  its *purpose* belong to Audit's manifest, not this one.
- The one operational secret this package's Go code ever handles directly —
  the `ascend_app` database role's login password (`migrate.go`'s
  `ProvisionAppRolePassword`) — is not a data field in the Art. 8 sense at
  all: it is infrastructure credential material, sourced only from the
  `ASCEND_APP_DB_PASSWORD` environment variable, never persisted by this
  package, never logged, never returned from any function here.

## Retention

Not applicable — this package retains nothing itself; it only hands back
live client handles (`*pgxpool.Pool`, `*redis.Client`, `*s3.Client`) to
whichever capability's own store uses them.
