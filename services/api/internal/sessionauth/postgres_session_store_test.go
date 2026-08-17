package sessionauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/ascend/services/api/internal/platform"
)

// This file exercises PostgresSessionStore against a real Postgres
// database. It assumes
// internal/platform/migrations/0006_sessionauth_sessions.up.sql has already
// been applied to that database — by `go run .` (main.go runs migrations
// automatically at startup) or by whatever else set up the test database.
// This file deliberately does NOT call platform.RunMigrations itself:
// running migrations is the composition root's job, not a test's.
//
// Gate: every test here is skipped (visibly, via t.Skip) unless
// DATABASE_URL is set. Run `docker compose up -d` from the repo root
// first, with a populated .env (see .env.example), then set DATABASE_URL
// before `go test`.

// requireSessionPostgres skips the calling test if DATABASE_URL is not
// set, and otherwise returns it.
func requireSessionPostgres(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres-backed session store tests — run `docker compose up -d` from the repo root first")
	}
	return url
}

// newTestPostgresSessionStore constructs a real PostgresSessionStore
// against DATABASE_URL, closing the pool when the test completes.
func newTestPostgresSessionStore(t *testing.T) *PostgresSessionStore {
	t.Helper()
	url := requireSessionPostgres(t)
	pool, err := platform.NewPostgresPool(context.Background(), url)
	if err != nil {
		t.Fatalf("connecting to postgres (is `docker compose up -d` running, and have migrations been applied?): %v", err)
	}
	t.Cleanup(pool.Close)
	return NewPostgresSessionStore(pool)
}

// uniqueSessionRunID returns a value distinct to this single test
// invocation, used to tag every row a test writes (session_token,
// identity_ref) so its assertions are isolated from any other test's data
// — including any left behind by a prior run whose cleanup could not run —
// without requiring the table to be empty.
func uniqueSessionRunID(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generating unique run id: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// cleanupSessionsForIdentity deletes every sessionauth_sessions row for
// identityRef, via the store's own app-role connection —
// sessionauth_sessions has DELETE granted to ascend_app
// (0006_sessionauth_sessions.up.sql), unlike audit_events/
// permissions_history's append-only tables.
func cleanupSessionsForIdentity(t *testing.T, store *PostgresSessionStore, identityRef string) {
	t.Helper()
	if _, err := store.pool.Exec(context.Background(),
		"DELETE FROM sessionauth_sessions WHERE identity_ref = $1", identityRef); err != nil {
		t.Logf("cleanup: deleting test sessions: %v", err)
	}
}

func TestPostgresSessionStore_PutThenGet(t *testing.T) {
	store := newTestPostgresSessionStore(t)
	run := uniqueSessionRunID(t)
	identityRef := "identity:" + run
	t.Cleanup(func() { cleanupSessionsForIdentity(t, store, identityRef) })

	sess := Session{
		SessionToken:   "token-" + run,
		IdentityRef:    identityRef,
		DeviceID:       "device-" + run,
		IssuedAtUnix:   1000,
		ExpiresAtUnix:  2000,
		LastUsedAtUnix: 1000,
	}
	store.put(sess)

	got, ok := store.get(sess.SessionToken)
	if !ok {
		t.Fatal("expected get to find the freshly put session")
	}
	if got != sess {
		t.Fatalf("expected %+v, got %+v", sess, got)
	}
}

func TestPostgresSessionStore_Get_ReturnsExpiredSessionUnchanged(t *testing.T) {
	store := newTestPostgresSessionStore(t)
	run := uniqueSessionRunID(t)
	identityRef := "identity:" + run
	t.Cleanup(func() { cleanupSessionsForIdentity(t, store, identityRef) })

	// ExpiresAtUnix is deliberately in the past — proves get performs no
	// store-level expiry filtering.
	sess := Session{
		SessionToken:   "token-" + run,
		IdentityRef:    identityRef,
		DeviceID:       "device-" + run,
		IssuedAtUnix:   100,
		ExpiresAtUnix:  200,
		LastUsedAtUnix: 150,
	}
	store.put(sess)

	got, ok := store.get(sess.SessionToken)
	if !ok {
		t.Fatal("expected get to return the expired session, not filter it out")
	}
	if got != sess {
		t.Fatalf("expected expired session returned unchanged: expected %+v, got %+v", sess, got)
	}
}

func TestPostgresSessionStore_Get_UnknownToken_ReturnsFalse(t *testing.T) {
	store := newTestPostgresSessionStore(t)
	run := uniqueSessionRunID(t)

	_, ok := store.get("nonexistent-token-" + run)
	if ok {
		t.Fatal("expected get for an unknown token to return ok=false")
	}
}

func TestPostgresSessionStore_TouchLastUsed(t *testing.T) {
	store := newTestPostgresSessionStore(t)
	run := uniqueSessionRunID(t)
	identityRef := "identity:" + run
	t.Cleanup(func() { cleanupSessionsForIdentity(t, store, identityRef) })

	sess := Session{
		SessionToken:   "token-" + run,
		IdentityRef:    identityRef,
		DeviceID:       "device-" + run,
		IssuedAtUnix:   1000,
		ExpiresAtUnix:  2000,
		LastUsedAtUnix: 1000,
	}
	store.put(sess)

	store.touchLastUsed(sess.SessionToken, 1500)

	got, ok := store.get(sess.SessionToken)
	if !ok {
		t.Fatal("expected session to still exist after touchLastUsed")
	}
	if got.LastUsedAtUnix != 1500 {
		t.Fatalf("expected LastUsedAtUnix updated to 1500, got %d", got.LastUsedAtUnix)
	}
}

func TestPostgresSessionStore_TouchLastUsed_UnknownToken_SafeNoOp(t *testing.T) {
	store := newTestPostgresSessionStore(t)
	run := uniqueSessionRunID(t)

	// Must not panic or error for an unknown token — matches
	// InMemorySessionStore.touchLastUsed's documented no-op behavior.
	store.touchLastUsed("nonexistent-token-"+run, 1500)
}

func TestPostgresSessionStore_Delete(t *testing.T) {
	store := newTestPostgresSessionStore(t)
	run := uniqueSessionRunID(t)
	identityRef := "identity:" + run
	t.Cleanup(func() { cleanupSessionsForIdentity(t, store, identityRef) })

	sess := Session{
		SessionToken:   "token-" + run,
		IdentityRef:    identityRef,
		DeviceID:       "device-" + run,
		IssuedAtUnix:   1000,
		ExpiresAtUnix:  2000,
		LastUsedAtUnix: 1000,
	}
	store.put(sess)

	store.delete(sess.SessionToken)

	if _, ok := store.get(sess.SessionToken); ok {
		t.Fatal("expected session to be gone after delete")
	}
}

func TestPostgresSessionStore_Delete_UnknownToken_SafeNoOp(t *testing.T) {
	store := newTestPostgresSessionStore(t)
	run := uniqueSessionRunID(t)

	// Must not panic or error for an unknown token.
	store.delete("nonexistent-token-" + run)
}

func TestPostgresSessionStore_DeleteAllForIdentity_CountCorrect(t *testing.T) {
	store := newTestPostgresSessionStore(t)
	run := uniqueSessionRunID(t)
	identityRef := "identity:" + run
	otherIdentityRef := "identity:other-" + run
	t.Cleanup(func() {
		cleanupSessionsForIdentity(t, store, identityRef)
		cleanupSessionsForIdentity(t, store, otherIdentityRef)
	})

	for i := 0; i < 3; i++ {
		store.put(Session{
			SessionToken:   "token-" + run + "-" + string(rune('a'+i)),
			IdentityRef:    identityRef,
			DeviceID:       "device-" + run,
			IssuedAtUnix:   1000,
			ExpiresAtUnix:  2000,
			LastUsedAtUnix: 1000,
		})
	}
	// A session for a different identity must not be counted or deleted.
	store.put(Session{
		SessionToken:   "token-" + run + "-other",
		IdentityRef:    otherIdentityRef,
		DeviceID:       "device-" + run,
		IssuedAtUnix:   1000,
		ExpiresAtUnix:  2000,
		LastUsedAtUnix: 1000,
	})

	count := store.deleteAllForIdentity(identityRef)
	if count != 3 {
		t.Fatalf("expected deleteAllForIdentity to report 3, got %d", count)
	}

	if all := store.listAllForIdentity(identityRef); len(all) != 0 {
		t.Fatalf("expected 0 sessions remaining for %s, got %d", identityRef, len(all))
	}
	if all := store.listAllForIdentity(otherIdentityRef); len(all) != 1 {
		t.Fatalf("expected the other identity's session to be untouched, got %d", len(all))
	}
}

func TestPostgresSessionStore_ListActiveVsListAll_GenuinelyDiffer(t *testing.T) {
	store := newTestPostgresSessionStore(t)
	run := uniqueSessionRunID(t)
	identityRef := "identity:" + run
	otherIdentityRef := "identity:other-" + run
	t.Cleanup(func() {
		cleanupSessionsForIdentity(t, store, identityRef)
		cleanupSessionsForIdentity(t, store, otherIdentityRef)
	})

	const now = int64(5000)

	active := Session{
		SessionToken:   "token-active-" + run,
		IdentityRef:    identityRef,
		DeviceID:       "device-" + run,
		IssuedAtUnix:   1000,
		ExpiresAtUnix:  now + 1000, // unexpired
		LastUsedAtUnix: 1000,
	}
	expired := Session{
		SessionToken:   "token-expired-" + run,
		IdentityRef:    identityRef,
		DeviceID:       "device-" + run,
		IssuedAtUnix:   1000,
		ExpiresAtUnix:  now - 1000, // expired
		LastUsedAtUnix: 1000,
	}
	otherIdentitySession := Session{
		SessionToken:   "token-other-" + run,
		IdentityRef:    otherIdentityRef,
		DeviceID:       "device-" + run,
		IssuedAtUnix:   1000,
		ExpiresAtUnix:  now + 1000,
		LastUsedAtUnix: 1000,
	}

	store.put(active)
	store.put(expired)
	store.put(otherIdentitySession)

	activeList := store.listActiveForIdentity(identityRef, now)
	if len(activeList) != 1 || activeList[0].SessionToken != active.SessionToken {
		t.Fatalf("expected listActiveForIdentity to return exactly the active session, got %+v", activeList)
	}

	allList := store.listAllForIdentity(identityRef)
	if len(allList) != 2 {
		t.Fatalf("expected listAllForIdentity to return both active and expired sessions, got %d", len(allList))
	}
	tokens := map[string]bool{}
	for _, s := range allList {
		tokens[s.SessionToken] = true
	}
	if !tokens[active.SessionToken] || !tokens[expired.SessionToken] {
		t.Fatalf("expected listAllForIdentity to include both sessions, got %+v", allList)
	}

	// The other identity's session must never appear in either list.
	otherActive := store.listActiveForIdentity(otherIdentityRef, now)
	if len(otherActive) != 1 || otherActive[0].SessionToken != otherIdentitySession.SessionToken {
		t.Fatalf("expected the other identity's own active list to contain only its own session, got %+v", otherActive)
	}
	for _, s := range activeList {
		if s.IdentityRef != identityRef {
			t.Fatalf("cross-identity leak in listActiveForIdentity: %+v", s)
		}
	}
	for _, s := range allList {
		if s.IdentityRef != identityRef {
			t.Fatalf("cross-identity leak in listAllForIdentity: %+v", s)
		}
	}
}
