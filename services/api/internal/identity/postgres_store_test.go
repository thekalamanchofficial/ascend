package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/ascend/services/api/internal/platform"
	"github.com/jackc/pgx/v5"
)

// This file exercises PostgresStore against a real Postgres database. It
// assumes internal/platform/migrations/0002_identities.up.sql has already
// been applied to that database — by `go run .` (main.go runs migrations
// automatically at startup, see internal/platform/platform.go's New) or by
// whatever else set up the test database. This file deliberately does NOT
// call platform.RunMigrations itself: running migrations is the
// composition root's job, not a test's.
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
		t.Skip("DATABASE_URL not set; skipping Postgres-backed identity store tests — run `docker compose up -d` from the repo root first")
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
// to tag every identity_ref a test writes so its rows can never collide
// with another concurrent or prior run's rows — including any left behind
// by a prior run whose cleanup could not run (see cleanupIdentities below).
func uniqueRunID(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generating unique run id: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// cleanupIdentities best-effort deletes the given identity_refs after a
// test finishes, via MIGRATIONS_DATABASE_URL (the elevated admin
// connection), never via DATABASE_URL — migration 0002 grants only SELECT/
// INSERT/UPDATE on `identities` to ascend_app (the role DATABASE_URL
// authenticates as), with no DELETE grant (Store's interface has no delete
// method), so this cleanup could not use the app's own runtime credentials
// even if it wanted to.
//
// If MIGRATIONS_DATABASE_URL isn't set (only DATABASE_URL is required to
// run these tests at all — see requirePostgres), cleanup is skipped with a
// logged note; every test's own assertions are still correct regardless,
// because they scope every read through a uniqueRunID-tagged identity_ref
// rather than depending on the table being empty.
func cleanupIdentities(t *testing.T, refs []string) {
	t.Helper()
	if len(refs) == 0 {
		return
	}
	adminURL := os.Getenv("MIGRATIONS_DATABASE_URL")
	if adminURL == "" {
		t.Logf("MIGRATIONS_DATABASE_URL not set; skipping cleanup of %d test row(s) — identities has no DELETE grant for the DATABASE_URL role by design, so only the admin connection can remove them. Leftover rows are harmless to other tests (each test scopes its own reads to a uniqueRunID-tagged identity_ref) but will persist in the database.", len(refs))
		return
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Logf("cleanup: connecting via MIGRATIONS_DATABASE_URL: %v", err)
		return
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "DELETE FROM identities WHERE identity_ref = ANY($1)", refs); err != nil {
		t.Logf("cleanup: deleting test rows: %v", err)
	}
}

func testRecord(run string) IdentityRecord {
	return IdentityRecord{
		IdentityRef: "identity-" + run,
		DisplayName: "Alice-" + run,
		PublicKey:   []byte{0x01, 0x02, 0x03, 0xFF},
		Devices: []Device{
			{
				DeviceID:     "device-1-" + run,
				Name:         "Alice's Phone",
				PublicKey:    []byte{0xAA, 0xBB},
				AddedAtUnix:  1000,
				LastSeenUnix: 1000,
			},
			{
				DeviceID:     "device-2-" + run,
				Name:         "Alice's Laptop",
				PublicKey:    []byte{0xCC, 0xDD, 0xEE},
				AddedAtUnix:  2000,
				LastSeenUnix: 2500,
			},
		},
		CreatedAtUnix: 500,
		Epoch:         0,
	}
}

func assertRecordsEqual(t *testing.T, got, want IdentityRecord) {
	t.Helper()
	if got.IdentityRef != want.IdentityRef {
		t.Errorf("IdentityRef: got %q, want %q", got.IdentityRef, want.IdentityRef)
	}
	if got.DisplayName != want.DisplayName {
		t.Errorf("DisplayName: got %q, want %q", got.DisplayName, want.DisplayName)
	}
	if !bytes.Equal(got.PublicKey, want.PublicKey) {
		t.Errorf("PublicKey: got %x, want %x", got.PublicKey, want.PublicKey)
	}
	if got.CreatedAtUnix != want.CreatedAtUnix {
		t.Errorf("CreatedAtUnix: got %d, want %d", got.CreatedAtUnix, want.CreatedAtUnix)
	}
	if got.Epoch != want.Epoch {
		t.Errorf("Epoch: got %d, want %d", got.Epoch, want.Epoch)
	}
	if len(got.Devices) != len(want.Devices) {
		t.Fatalf("Devices: got %d devices, want %d", len(got.Devices), len(want.Devices))
	}
	for i := range want.Devices {
		g, w := got.Devices[i], want.Devices[i]
		if g.DeviceID != w.DeviceID {
			t.Errorf("Devices[%d].DeviceID: got %q, want %q", i, g.DeviceID, w.DeviceID)
		}
		if g.Name != w.Name {
			t.Errorf("Devices[%d].Name: got %q, want %q", i, g.Name, w.Name)
		}
		if !bytes.Equal(g.PublicKey, w.PublicKey) {
			t.Errorf("Devices[%d].PublicKey: got %x, want %x", i, g.PublicKey, w.PublicKey)
		}
		if g.AddedAtUnix != w.AddedAtUnix {
			t.Errorf("Devices[%d].AddedAtUnix: got %d, want %d", i, g.AddedAtUnix, w.AddedAtUnix)
		}
		if g.LastSeenUnix != w.LastSeenUnix {
			t.Errorf("Devices[%d].LastSeenUnix: got %d, want %d", i, g.LastSeenUnix, w.LastSeenUnix)
		}
	}
}

func TestPostgresStore_CreateGetRoundTrip(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	rec := testRecord(run)

	if err := store.Create(rec); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { cleanupIdentities(t, []string{rec.IdentityRef}) })

	got, err := store.Get(rec.IdentityRef)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	assertRecordsEqual(t, got, rec)
}

func TestPostgresStore_CreateDuplicateReturnsInvalidArgument(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	rec := testRecord(run)

	if err := store.Create(rec); err != nil {
		t.Fatalf("first create: %v", err)
	}
	t.Cleanup(func() { cleanupIdentities(t, []string{rec.IdentityRef}) })

	err := store.Create(rec)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("duplicate create: got %v, want ErrInvalidArgument", err)
	}
}

func TestPostgresStore_GetNotFound(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)

	_, err := store.Get("does-not-exist-" + run)
	if !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("get nonexistent: got %v, want ErrIdentityNotFound", err)
	}
}

func TestPostgresStore_ReplaceUpdatesExistingRecord(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	rec := testRecord(run)

	if err := store.Create(rec); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { cleanupIdentities(t, []string{rec.IdentityRef}) })

	updated := rec
	updated.DisplayName = "Alice Renamed-" + run
	updated.Epoch = 1
	// A different set of devices entirely — proves Replace overwrites the
	// whole devices column, not merges into it (only the first device
	// survives, and a brand-new third device is added).
	updated.Devices = []Device{
		rec.Devices[0],
		{
			DeviceID:     "device-3-" + run,
			Name:         "Alice's Tablet",
			PublicKey:    []byte{0x11, 0x22, 0x33},
			AddedAtUnix:  3000,
			LastSeenUnix: 3100,
		},
	}

	if err := store.Replace(updated); err != nil {
		t.Fatalf("replace: %v", err)
	}

	got, err := store.Get(rec.IdentityRef)
	if err != nil {
		t.Fatalf("get after replace: %v", err)
	}
	assertRecordsEqual(t, got, updated)
}

func TestPostgresStore_ReplaceNotFound(t *testing.T) {
	store := newTestPostgresStore(t)
	run := uniqueRunID(t)
	rec := testRecord(run)

	err := store.Replace(rec)
	if !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("replace nonexistent: got %v, want ErrIdentityNotFound", err)
	}
}
