package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/ascend/services/api/internal/platform"
	"github.com/jackc/pgx/v5"
)

// This file exercises PostgresStore against a real Postgres database. It
// assumes internal/platform/migrations/0001_audit_events.up.sql has
// already been applied to that database — by `go run .` (main.go runs
// migrations automatically at startup, see internal/platform/platform.go's
// New) or by whatever else set up the test database. This file
// deliberately does NOT call platform.RunMigrations itself: running
// migrations is the composition root's job, not a test's.
//
// Gate: every test here is skipped (visibly, via t.Skip — not a build tag,
// since this repo doesn't use any) unless DATABASE_URL is set. Run
// `docker compose up -d` from the repo root first, with a populated .env
// (see .env.example), then set DATABASE_URL before `go test`.

// requirePostgres skips the calling test if DATABASE_URL is not set, and
// otherwise returns it.
func requirePostgres(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres-backed audit store tests — run `docker compose up -d` from the repo root first")
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
// to tag every row a test writes (actor/action) so its Query assertions
// are isolated from any other test's data — including any left behind by a
// prior run whose cleanup could not run (see cleanupEvents below) — without
// requiring the table to be empty.
func uniqueRunID(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generating unique run id: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// cleanupEvents best-effort deletes the given event_ids after a test
// finishes, via MIGRATIONS_DATABASE_URL (the elevated admin connection),
// never via DATABASE_URL — migration 0001 REVOKEs UPDATE/DELETE on
// audit_events from ascend_app (the role DATABASE_URL authenticates as)
// and from PUBLIC, so this cleanup could not use the app's own runtime
// credentials even if it wanted to.
//
// IMPORTANT, disclosed honestly (charter §6 amendment, 2026-08-17, Security
// Steward merge-gate finding — docs/DECISION_LOG.md, "Database setup:
// Security Steward block and fix"): this function is a live, standing
// demonstration that the REVOKE above does NOT enforce the charter's
// "including platform operators" tamper-evidence promise — it only ever
// restricts ascend_app/PUBLIC. MIGRATIONS_DATABASE_URL's role (ascend_admin)
// OWNS this table (it ran the CREATE TABLE), and table ownership in
// Postgres cannot be REVOKEd away from its own owner. This function's own
// DELETE calls are genuine proof of that: they succeed silently, with no
// chain-repair, exactly like an actual operator-tamper event would. Tests
// using this helper must run alone against a table no other process is
// concurrently relying on (deleting from the middle of the chain orphans
// every later row's prev_hash) — see the false-alarm entry in
// docs/DECISION_LOG.md for a real instance of this biting concurrent local
// verification runs. If MIGRATIONS_DATABASE_URL isn't set (only
// DATABASE_URL is required to run these tests at all — see
// requirePostgres), cleanup is skipped with a logged note; every test's own
// assertions are still correct regardless, because they scope every read
// through a uniqueRunID-tagged actor/action rather than depending on the
// table being empty.
func cleanupEvents(t *testing.T, ids []string) {
	t.Helper()
	if len(ids) == 0 {
		return
	}
	adminURL := os.Getenv("MIGRATIONS_DATABASE_URL")
	if adminURL == "" {
		t.Logf("MIGRATIONS_DATABASE_URL not set; skipping cleanup of %d test row(s) — audit_events is append-only for the DATABASE_URL role by design, so only the admin connection can remove them. Leftover rows are harmless to other tests (each test scopes its own reads to a unique run id) but will persist in the database.", len(ids))
		return
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Logf("cleanup: connecting via MIGRATIONS_DATABASE_URL: %v", err)
		return
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "DELETE FROM audit_events WHERE event_id = ANY($1)", ids); err != nil {
		t.Logf("cleanup: deleting test rows: %v", err)
	}
}

func TestPostgresStore_AppendGetRoundTrip(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)

	e := AuditEvent{
		Actor:          "identity:alice-" + run,
		Action:         "file.viewed-" + run,
		Resource:       ResourceRef{ResourceType: "file-" + run, ResourceID: "f1-" + run},
		RuleReference:  "rule.example",
		Metadata:       map[string]string{"note": "test"},
		OccurredAtUnix: 111,
	}
	appended, err := store.Append(e)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	t.Cleanup(func() { cleanupEvents(t, []string{appended.EventID}) })

	if appended.EventID == "" {
		t.Fatal("expected a non-empty EventID")
	}

	got, ok := store.Get(appended.EventID)
	if !ok {
		t.Fatalf("expected Get to find the just-appended event %q", appended.EventID)
	}
	if got.EventID != appended.EventID {
		t.Errorf("EventID: got %q, want %q", got.EventID, appended.EventID)
	}
	if got.PrevHash != appended.PrevHash {
		t.Errorf("PrevHash: got %q, want %q", got.PrevHash, appended.PrevHash)
	}
	if got.Actor != e.Actor {
		t.Errorf("Actor: got %q, want %q", got.Actor, e.Actor)
	}
	if got.Action != e.Action {
		t.Errorf("Action: got %q, want %q", got.Action, e.Action)
	}
	if got.Resource != e.Resource {
		t.Errorf("Resource: got %+v, want %+v", got.Resource, e.Resource)
	}
	if got.RuleReference != e.RuleReference {
		t.Errorf("RuleReference: got %q, want %q", got.RuleReference, e.RuleReference)
	}
	if len(got.Metadata) != 1 || got.Metadata["note"] != "test" {
		t.Errorf("Metadata: got %+v, want %+v", got.Metadata, e.Metadata)
	}
	if got.OccurredAtUnix != e.OccurredAtUnix {
		t.Errorf("OccurredAtUnix: got %d, want %d", got.OccurredAtUnix, e.OccurredAtUnix)
	}

	if _, ok := store.Get("does-not-exist-" + run); ok {
		t.Error("expected Get to report ok=false for an unknown event_id")
	}
}

func TestPostgresStore_AppendChainsHashes(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)

	e1, err := store.Append(AuditEvent{Actor: "identity:alice-" + run, Action: "file.viewed-" + run, OccurredAtUnix: 100})
	if err != nil {
		t.Fatalf("append 1: %v", err)
	}
	e2, err := store.Append(AuditEvent{Actor: "identity:alice-" + run, Action: "file.shared-" + run, OccurredAtUnix: 200})
	if err != nil {
		t.Fatalf("append 2: %v", err)
	}
	t.Cleanup(func() { cleanupEvents(t, []string{e1.EventID, e2.EventID}) })

	if e2.PrevHash != e1.EventID {
		t.Fatalf("expected e2.PrevHash == e1.EventID (%q), got %q", e1.EventID, e2.PrevHash)
	}
	if e2.EventID == e1.EventID {
		t.Fatal("expected distinct event IDs for distinct events")
	}

	// VerifyIntegrity is checked over the WHOLE table (All()), not just
	// this test's two rows: because every row in audit_events was written
	// via PostgresStore.Append itself (the only path that can write to
	// this append-only table), the full chain is always internally
	// consistent regardless of how many other tests' rows currently exist
	// alongside these two — this is a meaningful, not vacuous, assertion.
	if err := VerifyIntegrity(store.All()); err != nil {
		t.Fatalf("expected the real Postgres-backed chain to verify clean, got %v", err)
	}
}

func TestPostgresStore_QueryFilters(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)

	rtype := "file-" + run
	actorA := "identity:alice-" + run
	actorB := "identity:bob-" + run
	actionViewed := "file.viewed-" + run
	actionShared := "file.shared-" + run

	var ids []string
	mustAppend := func(actor, action, resourceID string, occurred int64) AuditEvent {
		e, err := store.Append(AuditEvent{
			Actor:          actor,
			Action:         action,
			Resource:       ResourceRef{ResourceType: rtype, ResourceID: resourceID},
			OccurredAtUnix: occurred,
		})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		ids = append(ids, e.EventID)
		return e
	}

	e1 := mustAppend(actorA, actionViewed, "f1-"+run, 1000)
	e2 := mustAppend(actorA, actionShared, "f2-"+run, 2000)
	e3 := mustAppend(actorB, actionViewed, "f1-"+run, 3000)
	t.Cleanup(func() { cleanupEvents(t, ids) })

	// actor
	got, err := store.Query(QueryFilter{Subject: actorA})
	if err != nil {
		t.Fatalf("query by actor: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("actor filter: expected 2 events, got %d", len(got))
	}
	if got[0].EventID != e2.EventID { // most-recent-first
		t.Errorf("actor filter: expected most-recent-first ordering, got first=%s want=%s", got[0].EventID, e2.EventID)
	}

	// resource_type
	got, err = store.Query(QueryFilter{ResourceTypeFilter: rtype})
	if err != nil {
		t.Fatalf("query by resource_type: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("resource_type filter: expected 3 events, got %d", len(got))
	}

	// resource_id
	got, err = store.Query(QueryFilter{ResourceIDFilter: "f1-" + run})
	if err != nil {
		t.Fatalf("query by resource_id: %v", err)
	}
	if len(got) != 2 || !containsEventID(got, e1.EventID) || !containsEventID(got, e3.EventID) {
		t.Fatalf("resource_id filter: expected exactly {e1, e3}, got %+v", got)
	}

	// action
	got, err = store.Query(QueryFilter{ActionFilter: actionViewed})
	if err != nil {
		t.Fatalf("query by action: %v", err)
	}
	if len(got) != 2 || !containsEventID(got, e1.EventID) || !containsEventID(got, e3.EventID) {
		t.Fatalf("action filter: expected exactly {e1, e3}, got %+v", got)
	}

	// since (scoped with actor so leftover data from other runs can't
	// interfere with the count)
	got, err = store.Query(QueryFilter{Subject: actorA, SinceUnix: 1500})
	if err != nil {
		t.Fatalf("query by since: %v", err)
	}
	if len(got) != 1 || got[0].EventID != e2.EventID {
		t.Fatalf("since filter: expected only e2, got %+v", got)
	}

	// until (scoped with actor, same reason)
	got, err = store.Query(QueryFilter{Subject: actorA, UntilUnix: 1500})
	if err != nil {
		t.Fatalf("query by until: %v", err)
	}
	if len(got) != 1 || got[0].EventID != e1.EventID {
		t.Fatalf("until filter: expected only e1, got %+v", got)
	}
}

func containsEventID(events []AuditEvent, eventID string) bool {
	for _, e := range events {
		if e.EventID == eventID {
			return true
		}
	}
	return false
}

// TestPostgresStore_ConcurrentAppends_ChainStaysConsistent is the direct
// proof the advisory-lock serialization in Append actually works under
// real concurrent load, not just a happy-path CRUD test — see
// appendAdvisoryLockKey's doc comment in postgres_store.go for why an
// unconditional advisory lock, not a row-level lock, is required for this
// to hold.
func TestPostgresStore_ConcurrentAppends_ChainStaysConsistent(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	const n = 20

	action := "concurrent.append-" + run

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results = make([]AuditEvent, 0, n)
		errs    = make([]error, 0)
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e, err := store.Append(AuditEvent{
				Actor:          fmt.Sprintf("identity:worker-%d-%s", i, run),
				Action:         action,
				OccurredAtUnix: int64(1000 + i),
			})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			results = append(results, e)
		}(i)
	}
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("%d/%d concurrent Append calls failed, first error: %v", len(errs), n, errs[0])
	}
	if len(results) != n {
		t.Fatalf("expected %d successful appends, got %d", n, len(results))
	}

	ids := make([]string, 0, n)
	for _, e := range results {
		ids = append(ids, e.EventID)
	}
	t.Cleanup(func() { cleanupEvents(t, ids) })

	seen := make(map[string]bool, n)
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate EventID returned by concurrent Append calls: %s", id)
		}
		seen[id] = true
	}

	// Full-chain integrity over the WHOLE table — proves the advisory lock
	// prevented any interleaving that could have corrupted PrevHash
	// linkage anywhere, not just among this test's own rows.
	if err := VerifyIntegrity(store.All()); err != nil {
		t.Fatalf("VerifyIntegrity after %d concurrent appends: %v", n, err)
	}

	// Exactly N events carry this run's distinguishing action, and no
	// duplicates among them — the direct proof all N concurrent Append
	// calls landed exactly once. Scoped via ActionFilter (unique to this
	// run) rather than asserting a literal All() row count: audit_events
	// is append-only (ascend_app has no DELETE grant — see cleanupEvents),
	// so a bare global row-count assertion would be fragile against any
	// earlier suite run whose own cleanup could not run because
	// MIGRATIONS_DATABASE_URL wasn't set in that environment.
	got, err := store.Query(QueryFilter{ActionFilter: action})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != n {
		t.Fatalf("expected exactly %d events for this run's distinguishing action, got %d", n, len(got))
	}
	gotIDs := make(map[string]bool, n)
	for _, e := range got {
		if gotIDs[e.EventID] {
			t.Fatalf("duplicate EventID in Query results: %s", e.EventID)
		}
		gotIDs[e.EventID] = true
		if !seen[e.EventID] {
			t.Fatalf("Query returned an EventID not among this test's own Append results: %s", e.EventID)
		}
	}
}
