package identity

import (
	"context"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/ascend/services/api/internal/platform"
	"github.com/jackc/pgx/v5"
)

// This file exercises PostgresPrekeyStore against a real Postgres
// database — same gating discipline as postgres_store_test.go
// (DATABASE_URL-gated, t.Skip if unset; migration
// 0009_identity_prekeys.up.sql is assumed already applied, which
// platform.New/`go run .` does automatically at startup).
//
// TestClaimOneOneTimePrekey_ConcurrentClaimsNeverDoubleIssue is the
// single most important test in this file — it is the concurrency proof
// charter §6/§7 requires ("required regardless of exact SQL chosen:
// single-statement atomicity, plus a concurrency test proving two
// simultaneous fetches for the same device's last remaining one-time
// prekey never both succeed"), run against the real Postgres backend,
// not a mock.

func newTestPostgresPrekeyStore(t *testing.T) *PostgresPrekeyStore {
	t.Helper()
	url := requirePostgres(t)
	pool, err := platform.NewPostgresPool(context.Background(), url)
	if err != nil {
		t.Fatalf("connecting to postgres (is `docker compose up -d` running, and have migrations been applied?): %v", err)
	}
	t.Cleanup(pool.Close)
	return NewPostgresPrekeyStore(pool)
}

// cleanupPrekeys best-effort deletes every row this test's identityRef
// touched, via MIGRATIONS_DATABASE_URL — mirrors cleanupIdentities'
// (postgres_store_test.go) exact reasoning: identity_one_time_prekeys DOES
// have a DELETE grant for ascend_app (the atomic claim needs it), but
// identity_signed_prekeys does not, so cleanup still requires the admin
// connection for a full teardown. Every test scopes its own reads/writes
// to a uniqueRunID-tagged identity_ref regardless, so skipped cleanup
// leaves harmless, non-interfering rows behind.
func cleanupPrekeys(t *testing.T, identityRef string) {
	t.Helper()
	adminURL := os.Getenv("MIGRATIONS_DATABASE_URL")
	if adminURL == "" {
		t.Logf("MIGRATIONS_DATABASE_URL not set; skipping cleanup of prekey rows for %q", identityRef)
		return
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Logf("cleanup: connecting via MIGRATIONS_DATABASE_URL: %v", err)
		return
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "DELETE FROM identity_one_time_prekeys WHERE identity_ref = $1", identityRef); err != nil {
		t.Logf("cleanup: deleting one_time_prekeys rows: %v", err)
	}
	if _, err := conn.Exec(ctx, "DELETE FROM identity_signed_prekeys WHERE identity_ref = $1", identityRef); err != nil {
		t.Logf("cleanup: deleting signed_prekeys row: %v", err)
	}
}

func TestPostgresPrekeyStore_PublishBundle_RotatesSignedPrekey_AdditiveOneTime(t *testing.T) {
	store := newTestPostgresPrekeyStore(t)
	run := uniqueRunID(t)
	identityRef := "identity-" + run
	deviceID := "device-" + run
	t.Cleanup(func() { cleanupPrekeys(t, identityRef) })

	published, err := store.PublishBundle(identityRef, deviceID, testSignedPrekey("spk-1-"+run), []byte("dh-pub-"+run), []byte("dh-sig-"+run), []OneTimePrekeyPublic{
		{PrekeyID: "otp-1-" + run, PublicKey: []byte{1}},
		{PrekeyID: "otp-2-" + run, PublicKey: []byte{2}},
	})
	if err != nil {
		t.Fatalf("first PublishBundle: %v", err)
	}
	if published != 2 {
		t.Fatalf("expected 2 published, got %d", published)
	}

	// Rotation: replaces the signed prekey, additively appends one more
	// one-time prekey.
	published, err = store.PublishBundle(identityRef, deviceID, testSignedPrekey("spk-2-"+run), []byte("dh-pub-"+run), []byte("dh-sig-"+run), []OneTimePrekeyPublic{
		{PrekeyID: "otp-3-" + run, PublicKey: []byte{3}},
	})
	if err != nil {
		t.Fatalf("second PublishBundle: %v", err)
	}
	if published != 1 {
		t.Fatalf("expected 1 newly published on rotation call, got %d", published)
	}

	current, dhPub, dhSig, found, err := store.GetSignedPrekey(identityRef, deviceID)
	if err != nil || !found {
		t.Fatalf("GetSignedPrekey: found=%v err=%v", found, err)
	}
	if string(dhPub) != "dh-pub-"+run || string(dhSig) != "dh-sig-"+run {
		t.Fatalf("expected the most recently published identity_dh_public_key/signature, got %q/%q", dhPub, dhSig)
	}
	if current.PrekeyID != "spk-2-"+run {
		t.Fatalf("expected rotation to replace signed prekey, got %q", current.PrekeyID)
	}

	count, err := store.CountUnconsumedOneTimePrekeys(identityRef, deviceID)
	if err != nil {
		t.Fatalf("CountUnconsumedOneTimePrekeys: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 one-time prekeys still available (additive across both publishes), got %d", count)
	}
}

func TestPostgresPrekeyStore_PublishBundle_DuplicatePrekeyIDIsIdempotentNoOp(t *testing.T) {
	store := newTestPostgresPrekeyStore(t)
	run := uniqueRunID(t)
	identityRef := "identity-" + run
	deviceID := "device-" + run
	t.Cleanup(func() { cleanupPrekeys(t, identityRef) })

	otpID := "otp-dup-" + run
	if _, err := store.PublishBundle(identityRef, deviceID, testSignedPrekey("spk-"+run), []byte("dh-pub-"+run), []byte("dh-sig-"+run), []OneTimePrekeyPublic{
		{PrekeyID: otpID, PublicKey: []byte{9}},
	}); err != nil {
		t.Fatalf("first publish: %v", err)
	}

	published, err := store.PublishBundle(identityRef, deviceID, testSignedPrekey("spk-"+run), []byte("dh-pub-"+run), []byte("dh-sig-"+run), []OneTimePrekeyPublic{
		{PrekeyID: otpID, PublicKey: []byte{9}}, // same prekey_id again
	})
	if err != nil {
		t.Fatalf("second publish (duplicate prekey_id): %v", err)
	}
	if published != 0 {
		t.Fatalf("expected 0 newly published for a duplicate prekey_id, got %d", published)
	}

	count, err := store.CountUnconsumedOneTimePrekeys(identityRef, deviceID)
	if err != nil {
		t.Fatalf("CountUnconsumedOneTimePrekeys: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 one-time prekey (duplicate must not create a second row), got %d", count)
	}
}

func TestPostgresPrekeyStore_GetSignedPrekey_NotFound(t *testing.T) {
	store := newTestPostgresPrekeyStore(t)
	run := uniqueRunID(t)

	_, _, _, found, err := store.GetSignedPrekey("no-such-identity-"+run, "no-such-device-"+run)
	if err != nil {
		t.Fatalf("GetSignedPrekey: %v", err)
	}
	if found {
		t.Fatalf("expected found=false for a device that has never published a bundle")
	}
}

// TestPostgresPrekeyStore_GetSignedPrekey_FailsClosedWhenDhPairMissing is
// the store-level proof of the key-separation fix's fail-closed
// requirement (charter §3/§6): a signed_prekey row present but with an
// empty identity_dh_public_key/identity_dh_public_key_signature pair (not
// NULL — the schema's NOT NULL constraint alone does not forbid an empty,
// zero-length bytea — see 0010_identity_prekeys_dh_key.up.sql's own doc
// comment on why this defense-in-depth check exists rather than trusting
// the constraint alone) must report found=false, identical to "never
// published at all". Bypasses Service.PublishPrekeyBundle's own
// request-level validation (which would reject empty DH bytes before ever
// reaching this store) by calling the store directly — the only way to
// construct this state at all, given that validation.
func TestPostgresPrekeyStore_GetSignedPrekey_FailsClosedWhenDhPairMissing(t *testing.T) {
	store := newTestPostgresPrekeyStore(t)
	run := uniqueRunID(t)
	identityRef := "identity-" + run
	deviceID := "device-" + run
	t.Cleanup(func() { cleanupPrekeys(t, identityRef) })

	if _, err := store.PublishBundle(identityRef, deviceID, testSignedPrekey("spk-"+run), []byte{}, []byte{}, nil); err != nil {
		t.Fatalf("PublishBundle with empty DH pair: %v", err)
	}

	_, _, _, found, err := store.GetSignedPrekey(identityRef, deviceID)
	if err != nil {
		t.Fatalf("GetSignedPrekey: %v", err)
	}
	if found {
		t.Fatalf("expected found=false when identity_dh_public_key/signature are empty even though a signed_prekey row exists (fail-closed)")
	}
}

func TestPostgresPrekeyStore_ClaimOneOneTimePrekey_DeletesRow_ExhaustionIsNotAnError(t *testing.T) {
	store := newTestPostgresPrekeyStore(t)
	run := uniqueRunID(t)
	identityRef := "identity-" + run
	deviceID := "device-" + run
	t.Cleanup(func() { cleanupPrekeys(t, identityRef) })

	if _, err := store.PublishBundle(identityRef, deviceID, testSignedPrekey("spk-"+run), []byte("dh-pub-"+run), []byte("dh-sig-"+run), []OneTimePrekeyPublic{
		{PrekeyID: "otp-only-" + run, PublicKey: []byte{7}},
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	claimed, found, err := store.ClaimOneOneTimePrekey(identityRef, deviceID)
	if err != nil {
		t.Fatalf("ClaimOneOneTimePrekey: %v", err)
	}
	if !found || claimed.PrekeyID != "otp-only-"+run {
		t.Fatalf("expected to claim otp-only-%s, got found=%v claimed=%+v", run, found, claimed)
	}

	// Pool is now empty — a second claim must return found=false, not an
	// error (charter §3's exhaustion-fallback case), and the row must be
	// genuinely GONE (Art. 8 anti-retention), not marked consumed.
	_, found, err = store.ClaimOneOneTimePrekey(identityRef, deviceID)
	if err != nil {
		t.Fatalf("second ClaimOneOneTimePrekey: %v", err)
	}
	if found {
		t.Fatalf("expected found=false once the pool is exhausted")
	}

	count, err := store.CountUnconsumedOneTimePrekeys(identityRef, deviceID)
	if err != nil {
		t.Fatalf("CountUnconsumedOneTimePrekeys: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 remaining rows after the claim (deleted, not marked), got %d", count)
	}
}

// TestClaimOneOneTimePrekey_ConcurrentClaimsNeverDoubleIssue is the
// concurrency proof charter §6/§7 requires: two simultaneous
// ClaimOneOneTimePrekey calls against a device with EXACTLY ONE remaining
// one-time prekey must never both receive it. Run 50 independent trials
// (fresh device/single prekey each time, real goroutines, a barrier
// channel forcing both goroutines to fire as close to simultaneously as
// possible) against the real Postgres backend — not mocked, not serialized
// by accident.
func TestClaimOneOneTimePrekey_ConcurrentClaimsNeverDoubleIssue(t *testing.T) {
	store := newTestPostgresPrekeyStore(t)
	run := uniqueRunID(t)
	identityRef := "identity-concurrent-" + run
	t.Cleanup(func() { cleanupPrekeys(t, identityRef) })

	const trials = 50
	for trial := 0; trial < trials; trial++ {
		deviceID := "device-" + run + "-" + strconv.Itoa(trial)
		prekeyID := "otp-" + run + "-" + strconv.Itoa(trial)

		if _, err := store.PublishBundle(identityRef, deviceID, testSignedPrekey("spk-"+deviceID), []byte("dh-pub-"+run), []byte("dh-sig-"+run), []OneTimePrekeyPublic{
			{PrekeyID: prekeyID, PublicKey: []byte{byte(trial)}},
		}); err != nil {
			t.Fatalf("trial %d: publish: %v", trial, err)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		results := make([]struct {
			found bool
			id    string
			err   error
		}, 2)

		for i := 0; i < 2; i++ {
			i := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start // both goroutines block here until released together
				claimed, found, err := store.ClaimOneOneTimePrekey(identityRef, deviceID)
				results[i].found = found
				results[i].id = claimed.PrekeyID
				results[i].err = err
			}()
		}
		close(start) // release both goroutines as simultaneously as the Go runtime allows

		wg.Wait()

		successes := 0
		for i, r := range results {
			if r.err != nil {
				t.Fatalf("trial %d: goroutine %d: ClaimOneOneTimePrekey error: %v", trial, i, r.err)
			}
			if r.found {
				successes++
				if r.id != prekeyID {
					t.Fatalf("trial %d: goroutine %d claimed unexpected prekey_id %q, want %q", trial, i, r.id, prekeyID)
				}
			}
		}
		if successes != 1 {
			t.Fatalf("trial %d: expected EXACTLY ONE of the two concurrent claims to succeed, got %d successes (results=%+v) — double-issuance or total-loss of the last remaining one-time prekey", trial, successes, results)
		}

		count, err := store.CountUnconsumedOneTimePrekeys(identityRef, deviceID)
		if err != nil {
			t.Fatalf("trial %d: CountUnconsumedOneTimePrekeys: %v", trial, err)
		}
		if count != 0 {
			t.Fatalf("trial %d: expected 0 remaining after exactly one claim succeeded, got %d", trial, count)
		}
	}
}
