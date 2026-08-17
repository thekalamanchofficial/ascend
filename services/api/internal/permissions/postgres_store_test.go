package permissions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/ascend/services/api/internal/platform"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This file exercises PostgresStore against a real Postgres database. It
// assumes internal/platform/migrations/0003_permissions.up.sql has already
// been applied to that database — by `go run .` (main.go runs migrations
// automatically at startup, see internal/platform/platform.go's New) or by
// whatever else set up the test database. This file deliberately does NOT
// call platform.RunMigrations itself: running migrations is the composition
// root's job, not a test's.
//
// Gate: every test here is skipped (visibly, via t.Skip) unless DATABASE_URL
// is set. Run `docker compose up -d` from the repo root first, with a
// populated .env (see .env.example), then set DATABASE_URL before `go test`.

// requirePostgres skips the calling test if DATABASE_URL is not set, and
// otherwise returns it.
func requirePostgres(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres-backed permissions store tests — run `docker compose up -d` from the repo root first")
	}
	return url
}

// newTestPostgresStore constructs a real PostgresStore against
// DATABASE_URL, closing the pool when the test completes.
func newTestPostgresStore(t *testing.T) *PostgresStore {
	t.Helper()
	url := requirePostgres(t)
	pool, err := platform.NewPostgresPool(context.Background(), url)
	if err != nil {
		t.Fatalf("connecting to postgres (is `docker compose up -d` running, and have migrations been applied?): %v", err)
	}
	t.Cleanup(pool.Close)
	return NewPostgresStore(pool)
}

// uniqueRunID returns a value distinct to this single test invocation, used
// to tag every row a test writes (resource_type/subject/grantor/action) so
// its assertions are isolated from any other test's data — including any
// left behind by a prior run whose cleanup could not run — without requiring
// the tables to be empty.
func uniqueRunID(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generating unique run id: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// cleanupGrantsAndOwners deletes every permissions_grants/permissions_owners
// row tagged with resourceType, via the store's own app-role connection —
// both tables have DELETE granted to ascend_app (0003_permissions.up.sql),
// unlike permissions_history below.
func cleanupGrantsAndOwners(t *testing.T, store *PostgresStore, resourceType string) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.pool.Exec(ctx, "DELETE FROM permissions_grants WHERE resource_type = $1", resourceType); err != nil {
		t.Logf("cleanup: deleting test grants: %v", err)
	}
	if _, err := store.pool.Exec(ctx, "DELETE FROM permissions_owners WHERE resource_type = $1", resourceType); err != nil {
		t.Logf("cleanup: deleting test owners: %v", err)
	}
}

// adminCleanup runs a best-effort admin-connection statement (used for
// permissions_history and permissions_policies, neither of which grants
// DELETE to ascend_app), mirroring internal/audit/postgres_store_test.go's
// cleanupEvents pattern exactly, including its disclosure: if
// MIGRATIONS_DATABASE_URL isn't set, cleanup is skipped with a logged note,
// and every test's own assertions remain correct regardless because they
// scope reads through a uniqueRunID tag rather than requiring the tables to
// be empty.
func adminCleanup(t *testing.T, query string, args ...any) {
	t.Helper()
	adminURL := os.Getenv("MIGRATIONS_DATABASE_URL")
	if adminURL == "" {
		t.Logf("MIGRATIONS_DATABASE_URL not set; skipping cleanup (%s) — this table is append-only/no-DELETE for the DATABASE_URL role by design, so only the admin connection can remove rows. Leftover rows are harmless (each test scopes its own reads to a unique run id) but will persist in the database.", query)
		return
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Logf("cleanup: connecting via MIGRATIONS_DATABASE_URL: %v", err)
		return
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, query, args...); err != nil {
		t.Logf("cleanup: %s: %v", query, err)
	}
}

func mustPutGrant(t *testing.T, store *PostgresStore, g Grant) {
	t.Helper()
	store.putGrant(g)
}

// TestPostgresStore_OwnerBootstrapOnce is the direct proof of the
// bootstrap-owner-once rule: putGrant's owner-bootstrap side effect fires
// only on a resource's first-ever grant, survives that grant's later
// revocation, and is never overwritten by a subsequent grantor — matching
// InMemoryStore.putGrant/removeGrant exactly (see postgres_store.go's doc
// comment on putGrant).
func TestPostgresStore_OwnerBootstrapOnce(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	t.Cleanup(func() { cleanupGrantsAndOwners(t, store, "res-"+run) })

	resource := ResourceRef{ResourceType: "res-" + run, ResourceID: "id-" + run}
	action := "read-" + run
	originalOwner := "identity:owner-" + run
	subject := "identity:subject-" + run
	laterGrantor := "identity:later-grantor-" + run

	// No grant yet: ownerOf reports genuinely no owner.
	if owner, ok := store.ownerOf(resource); ok {
		t.Fatalf("expected no owner before any grant, got owner=%q ok=%v", owner, ok)
	}

	// First-ever grant on this resource: originalOwner becomes the implicit
	// owner.
	mustPutGrant(t, store, Grant{
		Grantor: originalOwner, Subject: subject, Action: action,
		Resource: resource, Scope: "full", GrantedAtUnix: 100,
	})
	owner, ok := store.ownerOf(resource)
	if !ok || owner != originalOwner {
		t.Fatalf("expected owner=%q ok=true after first grant, got owner=%q ok=%v", originalOwner, owner, ok)
	}

	// Revoke the grant that established ownership.
	store.removeGrant(subject, action, resource)
	if _, found := store.activeGrant(subject, action, resource); found {
		t.Fatal("expected the grant to no longer be active after removeGrant")
	}
	// Ownership must survive the revoke of the grant that established it.
	owner, ok = store.ownerOf(resource)
	if !ok || owner != originalOwner {
		t.Fatalf("expected owner to survive revocation: owner=%q ok=%v, want %q true", owner, ok, originalOwner)
	}

	// A different grantor grants a (new) action on the SAME resource.
	// Ownership must NOT change to this later grantor.
	mustPutGrant(t, store, Grant{
		Grantor: laterGrantor, Subject: subject, Action: "write-" + run,
		Resource: resource, Scope: "full", GrantedAtUnix: 200,
	})
	owner, ok = store.ownerOf(resource)
	if !ok || owner != originalOwner {
		t.Fatalf("expected owner to remain %q after a later grantor's grant, got owner=%q ok=%v", originalOwner, owner, ok)
	}
}

// TestPostgresStore_ActiveGrantHitMissAndOverwrite covers activeGrant's
// hit/miss semantics and putGrant's re-grant-overwrites-in-place behavior
// (InMemoryStore.putGrant: "Re-granting the same tuple overwrites the
// previous entry").
func TestPostgresStore_ActiveGrantHitMissAndOverwrite(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	resource := ResourceRef{ResourceType: "res-" + run, ResourceID: "id-" + run}
	t.Cleanup(func() { cleanupGrantsAndOwners(t, store, resource.ResourceType) })

	subject := "identity:subject-" + run
	grantor := "identity:grantor-" + run
	action := "read-" + run

	// Miss before any grant.
	if _, ok := store.activeGrant(subject, action, resource); ok {
		t.Fatal("expected no active grant before any putGrant call")
	}

	mustPutGrant(t, store, Grant{
		Grantor: grantor, Subject: subject, Action: action,
		Resource: resource, Scope: "read_only", GrantedAtUnix: 100,
	})
	got, ok := store.activeGrant(subject, action, resource)
	if !ok {
		t.Fatal("expected a hit after putGrant")
	}
	if got.Scope != "read_only" || got.Grantor != grantor || got.GrantedAtUnix != 100 {
		t.Fatalf("unexpected grant fields: %+v", got)
	}

	// Re-grant the same (subject, action, resource) tuple: overwrite, not a
	// second row.
	mustPutGrant(t, store, Grant{
		Grantor: grantor, Subject: subject, Action: action,
		Resource: resource, Scope: "full", GrantedAtUnix: 200,
	})
	got, ok = store.activeGrant(subject, action, resource)
	if !ok || got.Scope != "full" || got.GrantedAtUnix != 200 {
		t.Fatalf("expected re-grant to overwrite in place, got %+v ok=%v", got, ok)
	}

	// A different action on the same resource/subject is a genuine miss.
	if _, ok := store.activeGrant(subject, "delete-"+run, resource); ok {
		t.Fatal("expected a miss for a different action")
	}

	// removeGrant clears it.
	store.removeGrant(subject, action, resource)
	if _, ok := store.activeGrant(subject, action, resource); ok {
		t.Fatal("expected a miss after removeGrant")
	}
}

// TestPostgresStore_HasPolicyAndSetPolicy covers hasPolicy's before/after
// registration transition and setPolicy's redefine-overwrites behavior
// (InMemoryStore.setPolicy: unconditional `s.policies[p.ResourceType] = p`).
func TestPostgresStore_HasPolicyAndSetPolicy(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	resourceType := "policy-res-" + run
	t.Cleanup(func() { adminCleanup(t, "DELETE FROM permissions_policies WHERE resource_type = $1", resourceType) })

	if store.hasPolicy(resourceType) {
		t.Fatal("expected hasPolicy=false before any setPolicy call")
	}

	store.setPolicy(Policy{ResourceType: resourceType, DefaultRules: "deny_all", DefinedAtUnix: 100})
	if !store.hasPolicy(resourceType) {
		t.Fatal("expected hasPolicy=true after setPolicy")
	}

	// Redefine: must not error (upsert, not a duplicate-key failure) and
	// must remain registered.
	store.setPolicy(Policy{ResourceType: resourceType, DefaultRules: "allow_owner_only", DefinedAtUnix: 200})
	if !store.hasPolicy(resourceType) {
		t.Fatal("expected hasPolicy=true after redefining the policy")
	}

	// Exactly one row for this resource_type — redefine upserted in place,
	// it did not insert a second row.
	var count int
	if err := store.pool.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM permissions_policies WHERE resource_type = $1", resourceType,
	).Scan(&count); err != nil {
		t.Fatalf("counting policy rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 policy row after redefine, got %d", count)
	}
}

// TestPostgresStore_GrantsForResourceAndSubjectFiltering covers
// grantsForResource's and grantsForSubject's exact filter predicates.
func TestPostgresStore_GrantsForResourceAndSubjectFiltering(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	resourceType := "res-" + run
	resourceA := ResourceRef{ResourceType: resourceType, ResourceID: "a-" + run}
	resourceB := ResourceRef{ResourceType: resourceType, ResourceID: "b-" + run}
	t.Cleanup(func() { cleanupGrantsAndOwners(t, store, resourceType) })

	subjectX := "identity:x-" + run
	subjectY := "identity:y-" + run
	grantor := "identity:grantor-" + run

	// subjectX/resourceA, subjectX/resourceB, subjectY/resourceA
	mustPutGrant(t, store, Grant{Grantor: grantor, Subject: subjectX, Action: "read-" + run, Resource: resourceA, Scope: "s", GrantedAtUnix: 1})
	mustPutGrant(t, store, Grant{Grantor: grantor, Subject: subjectX, Action: "write-" + run, Resource: resourceB, Scope: "s", GrantedAtUnix: 2})
	mustPutGrant(t, store, Grant{Grantor: grantor, Subject: subjectY, Action: "read-" + run, Resource: resourceA, Scope: "s", GrantedAtUnix: 3})

	byResourceA := store.grantsForResource(resourceA)
	if len(byResourceA) != 2 {
		t.Fatalf("grantsForResource(resourceA): expected 2, got %d (%+v)", len(byResourceA), byResourceA)
	}
	for _, g := range byResourceA {
		if g.Resource != resourceA {
			t.Fatalf("grantsForResource returned a grant for the wrong resource: %+v", g)
		}
	}

	byResourceB := store.grantsForResource(resourceB)
	if len(byResourceB) != 1 || byResourceB[0].Subject != subjectX {
		t.Fatalf("grantsForResource(resourceB): expected exactly subjectX's grant, got %+v", byResourceB)
	}

	bySubjectX := store.grantsForSubject(subjectX)
	if len(bySubjectX) != 2 {
		t.Fatalf("grantsForSubject(subjectX): expected 2, got %d (%+v)", len(bySubjectX), bySubjectX)
	}
	for _, g := range bySubjectX {
		if g.Subject != subjectX {
			t.Fatalf("grantsForSubject returned a grant for the wrong subject: %+v", g)
		}
	}

	bySubjectY := store.grantsForSubject(subjectY)
	if len(bySubjectY) != 1 || bySubjectY[0].Resource != resourceA {
		t.Fatalf("grantsForSubject(subjectY): expected exactly one grant on resourceA, got %+v", bySubjectY)
	}
}

// TestPostgresStore_HistoryAndActiveGrantsForIdentity_MatchSubjectOrGrantor
// is the direct proof that historyForIdentity and activeGrantsForIdentity
// both match an identity appearing as EITHER subject or grantor — not just
// subject — mirroring InMemoryStore's exact predicates
// (`h.Subject == identityRef || h.Grantor == identityRef`, same shape for
// grants).
func TestPostgresStore_HistoryAndActiveGrantsForIdentity_MatchSubjectOrGrantor(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	resourceType := "res-" + run
	resource := ResourceRef{ResourceType: resourceType, ResourceID: "id-" + run}
	t.Cleanup(func() { cleanupGrantsAndOwners(t, store, resourceType) })
	t.Cleanup(func() {
		adminCleanup(t, "DELETE FROM permissions_history WHERE resource_type = $1", resourceType)
	})

	identity := "identity:target-" + run
	otherA := "identity:other-a-" + run
	otherB := "identity:other-b-" + run
	unrelated := "identity:unrelated-" + run

	// Grants: one where `identity` is the subject, one where `identity` is
	// the grantor, one involving neither.
	mustPutGrant(t, store, Grant{Grantor: otherA, Subject: identity, Action: "read-" + run, Resource: resource, Scope: "s", GrantedAtUnix: 1})
	mustPutGrant(t, store, Grant{Grantor: identity, Subject: otherB, Action: "write-" + run, Resource: resource, Scope: "s", GrantedAtUnix: 2})
	mustPutGrant(t, store, Grant{Grantor: otherA, Subject: unrelated, Action: "delete-" + run, Resource: resource, Scope: "s", GrantedAtUnix: 3})

	grants := store.activeGrantsForIdentity(identity)
	if len(grants) != 2 {
		t.Fatalf("activeGrantsForIdentity: expected 2 grants (as subject and as grantor), got %d (%+v)", len(grants), grants)
	}
	sawAsSubject, sawAsGrantor := false, false
	for _, g := range grants {
		if g.Subject == identity {
			sawAsSubject = true
		}
		if g.Grantor == identity {
			sawAsGrantor = true
		}
	}
	if !sawAsSubject || !sawAsGrantor {
		t.Fatalf("expected identity to be matched both as subject and as grantor, got %+v", grants)
	}

	// History: same subject-or-grantor shape.
	store.appendHistory(HistoryEntry{EventType: "grant", Grantor: otherA, Subject: identity, Action: "read-" + run, Resource: resource, AtUnix: 10, Outcome: outcomeAllowed})
	store.appendHistory(HistoryEntry{EventType: "grant", Grantor: identity, Subject: otherB, Action: "write-" + run, Resource: resource, AtUnix: 20, Outcome: outcomeAllowed})
	store.appendHistory(HistoryEntry{EventType: "revoke", Grantor: otherA, Subject: unrelated, Action: "delete-" + run, Resource: resource, AtUnix: 30, Outcome: outcomeDenied, DenialReason: "not_found"})

	history := store.historyForIdentity(identity)
	if len(history) != 2 {
		t.Fatalf("historyForIdentity: expected 2 entries (as subject and as grantor), got %d (%+v)", len(history), history)
	}
	sawAsSubject, sawAsGrantor = false, false
	for _, h := range history {
		if h.Subject == identity {
			sawAsSubject = true
		}
		if h.Grantor == identity {
			sawAsGrantor = true
		}
		if h.Subject == unrelated || h.Grantor == unrelated {
			t.Fatalf("historyForIdentity returned an entry involving neither subject nor grantor match: %+v", h)
		}
	}
	if !sawAsSubject || !sawAsGrantor {
		t.Fatalf("expected identity to be matched both as subject and as grantor in history, got %+v", history)
	}
}

// TestPostgresStore_AppendHistory_QueryableAndNotDeletableByAppRole is the
// direct, live proof that (a) appendHistory writes a genuinely queryable
// row and (b) migration 0003's `REVOKE UPDATE, DELETE ON permissions_history
// FROM ascend_app` actually holds against the app-role connection this
// store uses — mirroring the discipline
// internal/audit/postgres_store_test.go's cleanupEvents comment documents
// for audit_events (same REVOKE pattern, same scope caveat: this proves the
// grant restricts ascend_app specifically, not that the row is unconditionally
// immutable — see this test's own log message and
// docs/DECISION_LOG.md's "Database setup: Security Steward block and fix"
// entry for why table ownership by the migration-admin role is a separate,
// undefeated privilege this REVOKE cannot reach).
func TestPostgresStore_AppendHistory_QueryableAndNotDeletableByAppRole(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	resourceType := "res-" + run
	resource := ResourceRef{ResourceType: resourceType, ResourceID: "id-" + run}
	identity := "identity:subject-" + run
	t.Cleanup(func() {
		adminCleanup(t, "DELETE FROM permissions_history WHERE resource_type = $1", resourceType)
	})

	store.appendHistory(HistoryEntry{
		EventType: "grant", Grantor: "identity:grantor-" + run, Subject: identity,
		Action: "read-" + run, Resource: resource, Scope: "full", AtUnix: 111, Outcome: outcomeAllowed,
	})

	got := store.historyForIdentity(identity)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 history entry queryable after appendHistory, got %d (%+v)", len(got), got)
	}
	if got[0].EventType != "grant" || got[0].Outcome != outcomeAllowed || got[0].AtUnix != 111 {
		t.Fatalf("unexpected history entry: %+v", got[0])
	}

	// Attempt a DELETE via the store's own app-role (DATABASE_URL)
	// connection — the same connection every production request uses. This
	// must fail with a Postgres insufficient-privilege error, proving the
	// REVOKE in 0003_permissions.up.sql actually holds for that role.
	_, err := store.pool.Exec(context.Background(), "DELETE FROM permissions_history WHERE resource_type = $1", resourceType)
	if err == nil {
		t.Fatal("expected DELETE on permissions_history to fail for the ascend_app role (REVOKE UPDATE, DELETE), but it succeeded")
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code != "42501" {
		t.Fatalf("expected a Postgres insufficient_privilege (42501) error, got code=%s: %v", pgErr.Code, err)
	}
	t.Logf("confirmed DELETE on permissions_history was rejected for the app role: %v", err)

	// The row must still be there — the rejected DELETE had no effect.
	still := store.historyForIdentity(identity)
	if len(still) != 1 {
		t.Fatalf("expected the history row to survive the rejected DELETE, got %d rows", len(still))
	}
}

// TestPostgresStore_OwnerOfMiss covers ownerOf's genuine-miss path directly
// (no grant ever made for the resource), distinct from the
// error-folds-to-("",true) path documented in postgres_store.go, which is
// not exercisable from a black-box test without actually breaking the
// connection.
func TestPostgresStore_OwnerOfMiss(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	resource := ResourceRef{ResourceType: "res-" + run, ResourceID: "id-" + run}

	if owner, ok := store.ownerOf(resource); ok {
		t.Fatalf("expected no owner for a resource that was never granted, got owner=%q ok=%v", owner, ok)
	}
}
