package permissions

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is a Postgres-backed implementation of Store, persisting
// grants/owners/policies/history into the permissions_grants,
// permissions_owners, permissions_policies, and permissions_history tables
// (see internal/platform/migrations/0003_permissions.up.sql). It replicates
// InMemoryStore's observable behavior exactly (owner bootstrap-once
// semantics, active-grant overwrite-on-regrant semantics, subject-or-grantor
// filter predicates) — Service (service.go) is written against the Store
// interface and does not know or care which implementation actually backs
// it.
//
// NewPostgresStore constructs a PostgresStore against an already-connected
// pool. Callers are responsible for having already run this package's
// migration (0003_permissions.up.sql) against the same database — this
// constructor does not run migrations itself (that is platform.New's job,
// at server startup).
//
// # Error-handling design decision (read this before touching any method below)
//
// Store's 11 methods (store.go) were introduced in this same change,
// alongside this implementation — but their signatures are fixed by that
// introduction to match InMemoryStore's own pre-existing, error-return-free
// method set exactly, so that Service's call sites (service.go) stay
// textually and behaviorally identical (Service must not need to change at
// all beyond the *Store -> Store field/parameter type). That constraint is
// treated here as load-bearing, not merely a suggestion: adding error
// returns to Store would be an interface change reaching back into Part 1
// of this same task, and is exactly the kind of quiet interface drift a
// capability engineer must not do without a charter amendment. So the real
// design question this file answers is narrower: given NO error-return
// channel exists on any of these 11 methods, how does a genuine Postgres
// failure (a dropped connection, a context timeout, etc. — as opposed to a
// legitimate "not found") get handled without either (a) silently pretending
// a mutation succeeded when it didn't, or (b) silently pretending a security
// check passed when it didn't?
//
// The seven methods that already return a meaningful zero-ish value follow
// Audit's own precedent (internal/audit/postgres_store.go's Get/All
// "defensive-error-handling" notes) of folding a genuine query failure into
// the same shape as a legitimate "nothing found" result — fail closed, in
// the sense that uncertainty must never look like "yes, allow this" or "yes,
// this resource type is registered":
//
//   - activeGrant: DB error -> (Grant{}, false), same as a genuine miss.
//     Every caller (CheckPermission, authorizeGrant's delegated-scope check,
//     RevokePermission's existence check) already treats ok=false as "deny"
//     or "nothing to revoke" — never as an implicit allow.
//   - hasPolicy: DB error -> false. CheckPermission already fails closed on
//     an unregistered resource_type ("Fail closed: an unregistered resource
//     type is always denied" — service.go); folding a DB error into the same
//     false routes straight into that already-safe deny path.
//   - grantsForResource / grantsForSubject / historyForIdentity /
//     activeGrantsForIdentity: DB error -> nil/empty slice. These four are
//     read-only list/export paths (ListGrantsForResource,
//     ListGrantsForSubject, ExportPermissions) with no allow/deny decision
//     riding on them; an empty result during an outage is indistinguishable
//     from a genuinely empty result, an accepted limitation shared with
//     Audit's All()/Query() for the identical reason.
//   - ownerOf is the one method in this group that needs a DIFFERENT
//     treatment from "fold into the miss shape", specifically because
//     folding a genuine error into (owner="", ok=false) would look
//     IDENTICAL to "this resource has never been granted before" —
//     Service.authorizeGrant reads exactly that shape as license to let the
//     requesting grantor bootstrap themselves in as the resource's owner
//     ("bootstrap_owner", service.go). Silently manufacturing a bootstrap-
//     owner opportunity out of a database hiccup would be a genuine
//     privilege-escalation hole, not just a stale read — categorically worse
//     than Audit's Get/All visibility gap. So on a genuine (non-ErrNoRows)
//     query failure, ownerOf returns ("", true) instead: ok=true asserts
//     "yes, this resource is owned", while owner="" is a value no real
//     owner can ever hold (every Grantor that can become an owner is
//     required non-empty by GrantPermission's own validation before
//     putGrant is ever called) — so every owner-equality check downstream
//     (CheckPermission's `owner == req.Subject`, authorizeGrant/
//     authorizeRevoke's `owner == req.Grantor`) fails to match, which is the
//     safe, deny-shaped direction, without ever hitting the bootstrap
//     branch.
//
// The four remaining methods (putGrant, removeGrant, appendHistory,
// setPolicy) return NOTHING AT ALL, not even a bool — there is no return
// value to fold a failure into, defensively or otherwise. Silently no-oping
// on a genuine write failure here is not a visibility gap like the read
// methods above; it is Service proceeding to append a "grant"/"revoke"
// history record and emit a "permissions.grant"/"permissions.revoke"/
// "permissions.define_policy" audit event reporting SUCCESS for a mutation
// that never actually reached the database — exactly the "silent success
// hazard Art. 5 forbids" service.go's own comments already call out
// repeatedly for the audit-emit step, now one layer lower. So these four
// panic on a genuine query/exec failure rather than silently returning.
// A panic inside an HTTP handler goroutine is recovered per-request by Go's
// own net/http server (it logs the stack trace and closes that single
// connection without ever writing a 200-with-lies response) — the caller
// sees a hard failure, not a soft one, and no other in-flight request is
// affected. This is the disciplined extension of this package's existing
// "fail loudly, never silently report success" philosophy to the one layer
// where the interface (as constrained by Part 1) leaves no other channel to
// do so.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore constructs a PostgresStore against an already-connected
// pool. See the package-level PostgresStore doc comment for the migration
// this implementation depends on.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// storeFailure panics with a message identifying which void-return
// mutation method failed and why. See PostgresStore's doc comment above for
// the full reasoning.
func storeFailure(op string, err error) {
	panic(fmt.Sprintf("permissions: postgres %s: %v", op, err))
}

// activeGrant looks up the single currently-effective grant for
// (subject, action, resource). See PostgresStore's doc comment for how a
// genuine query failure is folded into ok=false, matching a legitimate miss.
func (s *PostgresStore) activeGrant(subject, action string, resource ResourceRef) (Grant, bool) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, `
		SELECT grantor, subject, action, resource_type, resource_id, scope, granted_at_unix
		FROM permissions_grants
		WHERE subject = $1 AND action = $2 AND resource_type = $3 AND resource_id = $4
	`, subject, action, resource.ResourceType, resource.ResourceID)

	g, err := scanGrant(row)
	if err != nil {
		return Grant{}, false
	}
	return g, true
}

// ownerOf looks up the resource's recorded implicit owner. See
// PostgresStore's doc comment for why a genuine query failure returns
// ("", true) rather than ("", false) — the two are NOT equivalent for this
// method specifically.
func (s *PostgresStore) ownerOf(resource ResourceRef) (string, bool) {
	ctx := context.Background()
	var owner string
	err := s.pool.QueryRow(ctx, `
		SELECT owner_subject FROM permissions_owners
		WHERE resource_type = $1 AND resource_id = $2
	`, resource.ResourceType, resource.ResourceID).Scan(&owner)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Genuinely no owner recorded yet — matches
			// InMemoryStore.ownerOf's ok=false for a missing map entry.
			return "", false
		}
		// Genuine DB failure: must NOT look like "no owner yet" (see doc
		// comment) — owner="" can never match a real Grantor, ok=true
		// prevents the bootstrap-owner branch from ever being reached.
		return "", true
	}
	return owner, true
}

// putGrant upserts g as the active grant for its (subject, action,
// resource) tuple and, if this resource has no owner recorded yet, records
// g's grantor as the resource's implicit owner — once, and only once. This
// bootstrap-once behavior is the direct Postgres equivalent of
// InMemoryStore.putGrant's `if _, hasOwner := s.owners[...]; !hasOwner`
// check: the INSERT ... ON CONFLICT (resource_type, resource_id) DO NOTHING
// below is a no-op if a row already exists (whether or not the grant that
// originally created it has since been revoked — removeGrant below never
// touches permissions_owners, exactly like InMemoryStore.removeGrant never
// touches the owners map), so the ORIGINAL owner is never overwritten by a
// later grantor. Both writes happen in a single transaction so a concurrent
// reader can never observe the new active grant without its owner-bootstrap
// side effect (or vice versa) — matching InMemoryStore's single
// mutex-protected critical section covering both maps.
func (s *PostgresStore) putGrant(g Grant) {
	ctx := context.Background()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		storeFailure("put_grant: beginning transaction", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op if Commit already succeeded

	_, err = tx.Exec(ctx, `
		INSERT INTO permissions_grants
			(grantor, subject, action, resource_type, resource_id, scope, granted_at_unix)
		VALUES
			($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (subject, action, resource_type, resource_id)
		DO UPDATE SET grantor = EXCLUDED.grantor,
		              scope = EXCLUDED.scope,
		              granted_at_unix = EXCLUDED.granted_at_unix
	`,
		g.Grantor, g.Subject, g.Action, g.Resource.ResourceType, g.Resource.ResourceID, g.Scope, g.GrantedAtUnix,
	)
	if err != nil {
		storeFailure("put_grant: upserting grant", err)
	}

	// Bootstrap-owner-once: ON CONFLICT DO NOTHING means an existing owner
	// row is never touched by this or any later grant on the same resource.
	_, err = tx.Exec(ctx, `
		INSERT INTO permissions_owners (resource_type, resource_id, owner_subject)
		VALUES ($1, $2, $3)
		ON CONFLICT (resource_type, resource_id) DO NOTHING
	`, g.Resource.ResourceType, g.Resource.ResourceID, g.Grantor)
	if err != nil {
		storeFailure("put_grant: bootstrapping owner", err)
	}

	if err := tx.Commit(ctx); err != nil {
		storeFailure("put_grant: committing transaction", err)
	}
}

// removeGrant deletes the active grant for (subject, action, resource), if
// any. Mirrors InMemoryStore.removeGrant exactly: it never touches
// permissions_owners — a resource's recorded owner outlives the grant that
// established it, even after that original grant is revoked.
func (s *PostgresStore) removeGrant(subject, action string, resource ResourceRef) {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `
		DELETE FROM permissions_grants
		WHERE subject = $1 AND action = $2 AND resource_type = $3 AND resource_id = $4
	`, subject, action, resource.ResourceType, resource.ResourceID)
	if err != nil {
		storeFailure("remove_grant", err)
	}
}

// appendHistory inserts h as a new row in the append-only permissions_history
// table.
func (s *PostgresStore) appendHistory(h HistoryEntry) {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO permissions_history
			(event_type, grantor, subject, action, resource_type, resource_id, scope, at_unix, outcome, denial_reason)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`,
		h.EventType, h.Grantor, h.Subject, h.Action, h.Resource.ResourceType, h.Resource.ResourceID,
		h.Scope, h.AtUnix, h.Outcome, h.DenialReason,
	)
	if err != nil {
		storeFailure("append_history", err)
	}
}

// setPolicy upserts resourceType's registered default policy, matching
// InMemoryStore.setPolicy's unconditional overwrite-on-redefine semantics
// (`s.policies[p.ResourceType] = p`, no bootstrap-once behavior here — that
// rule only applies to ownership).
func (s *PostgresStore) setPolicy(p Policy) {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO permissions_policies (resource_type, default_rules, defined_at_unix)
		VALUES ($1, $2, $3)
		ON CONFLICT (resource_type)
		DO UPDATE SET default_rules = EXCLUDED.default_rules,
		              defined_at_unix = EXCLUDED.defined_at_unix
	`, p.ResourceType, p.DefaultRules, p.DefinedAtUnix)
	if err != nil {
		storeFailure("set_policy", err)
	}
}

// hasPolicy reports whether resourceType has a registered policy. See
// PostgresStore's doc comment for why a genuine query failure folds into
// false — the same fail-closed shape CheckPermission already applies to a
// legitimately-unregistered resource_type.
func (s *PostgresStore) hasPolicy(resourceType string) bool {
	ctx := context.Background()
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM permissions_policies WHERE resource_type = $1)
	`, resourceType).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

// grantsForResource returns every active grant on resource. See
// PostgresStore's doc comment for why a genuine query failure folds into a
// nil slice.
func (s *PostgresStore) grantsForResource(resource ResourceRef) []Grant {
	return s.queryGrants(`
		SELECT grantor, subject, action, resource_type, resource_id, scope, granted_at_unix
		FROM permissions_grants
		WHERE resource_type = $1 AND resource_id = $2
	`, resource.ResourceType, resource.ResourceID)
}

// grantsForSubject returns every active grant held by subject. See
// PostgresStore's doc comment for why a genuine query failure folds into a
// nil slice.
func (s *PostgresStore) grantsForSubject(subject string) []Grant {
	return s.queryGrants(`
		SELECT grantor, subject, action, resource_type, resource_id, scope, granted_at_unix
		FROM permissions_grants
		WHERE subject = $1
	`, subject)
}

// activeGrantsForIdentity returns every active grant where identityRef
// appears as EITHER subject or grantor, matching
// InMemoryStore.activeGrantsForIdentity's exact filter predicate. See
// PostgresStore's doc comment for why a genuine query failure folds into a
// nil slice.
func (s *PostgresStore) activeGrantsForIdentity(identityRef string) []Grant {
	return s.queryGrants(`
		SELECT grantor, subject, action, resource_type, resource_id, scope, granted_at_unix
		FROM permissions_grants
		WHERE subject = $1 OR grantor = $1
	`, identityRef)
}

func (s *PostgresStore) queryGrants(query string, args ...any) []Grant {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil
		}
		out = append(out, g)
	}
	if rows.Err() != nil {
		return nil
	}
	return out
}

// historyForIdentity returns every history entry where identityRef appears
// as EITHER subject or grantor, matching
// InMemoryStore.historyForIdentity's exact filter predicate, in insertion
// (append) order — ORDER BY id ASC mirrors InMemoryStore's own append-order
// slice iteration. See PostgresStore's doc comment for why a genuine query
// failure folds into a nil slice.
func (s *PostgresStore) historyForIdentity(identityRef string) []HistoryEntry {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, `
		SELECT event_type, grantor, subject, action, resource_type, resource_id, scope, at_unix, outcome, denial_reason
		FROM permissions_history
		WHERE subject = $1 OR grantor = $1
		ORDER BY id ASC
	`, identityRef)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []HistoryEntry
	for rows.Next() {
		h, err := scanHistoryEntry(rows)
		if err != nil {
			return nil
		}
		out = append(out, h)
	}
	if rows.Err() != nil {
		return nil
	}
	return out
}

// rowScanner is the common subset of pgx.Row and pgx.Rows this package
// needs (just Scan), matching Audit's/Identity's own equivalent seam
// (internal/audit/postgres_store.go, internal/identity/postgres_store.go).
type rowScanner interface {
	Scan(dest ...any) error
}

func scanGrant(row rowScanner) (Grant, error) {
	var g Grant
	err := row.Scan(
		&g.Grantor,
		&g.Subject,
		&g.Action,
		&g.Resource.ResourceType,
		&g.Resource.ResourceID,
		&g.Scope,
		&g.GrantedAtUnix,
	)
	if err != nil {
		return Grant{}, err
	}
	return g, nil
}

func scanHistoryEntry(row rowScanner) (HistoryEntry, error) {
	var h HistoryEntry
	err := row.Scan(
		&h.EventType,
		&h.Grantor,
		&h.Subject,
		&h.Action,
		&h.Resource.ResourceType,
		&h.Resource.ResourceID,
		&h.Scope,
		&h.AtUnix,
		&h.Outcome,
		&h.DenialReason,
	)
	if err != nil {
		return HistoryEntry{}, err
	}
	return h, nil
}
