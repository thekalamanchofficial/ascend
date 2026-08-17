package sessionauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ascend/services/api/internal/platform"
)

// This file exercises RedisNonceStore against a real Redis instance. Gate:
// every test here is skipped (visibly, via t.Skip) unless REDIS_URL is set.
// Deliberately checks REDIS_URL specifically, not the full
// platform.ConfigFromEnv() (which also requires Postgres/S3 configured) —
// a test exercising only this store shouldn't require unrelated
// infrastructure to be present. Run `docker compose up -d` from the repo
// root first, with a populated .env (see .env.example), then set REDIS_URL
// before `go test`.

// requireRedis skips the calling test if REDIS_URL is not set, and
// otherwise returns it.
func requireRedis(t *testing.T) string {
	t.Helper()
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set; skipping Redis-backed nonce store tests — run `docker compose up -d` from the repo root first")
	}
	return url
}

// newTestRedisNonceStore constructs a real RedisNonceStore against
// REDIS_URL, closing the client when the test completes.
func newTestRedisNonceStore(t *testing.T) *RedisNonceStore {
	t.Helper()
	url := requireRedis(t)
	client, err := platform.NewRedisClient(context.Background(), url)
	if err != nil {
		t.Fatalf("connecting to redis (is `docker compose up -d` running?): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return NewRedisNonceStore(client)
}

// uniqueNonce returns a nonce value distinct to this single test
// invocation, so concurrent test runs against a shared Redis instance never
// collide on the same key.
func uniqueNonce(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generating unique nonce: %v", err)
	}
	return "test-" + hex.EncodeToString(b[:])
}

// cleanupNonceKey deletes the given nonce's Redis key regardless of test
// outcome, so a failed assertion never leaves a key behind for a later test
// run to trip over (per this task's explicit cleanup requirement).
func cleanupNonceKey(t *testing.T, store *RedisNonceStore, nonce string) {
	t.Helper()
	t.Cleanup(func() {
		if err := store.client.Del(context.Background(), nonceKey(nonce)).Err(); err != nil {
			t.Logf("cleanup: deleting nonce key: %v", err)
		}
	})
}

func TestRedisNonceStore_PutThenPeek_Hit(t *testing.T) {
	store := newTestRedisNonceStore(t)
	nonce := uniqueNonce(t)
	cleanupNonceKey(t, store, nonce)

	now := time.Now()
	store.put(nonce, nonceRecord{
		IdentityRef:   "identity:alice",
		DeviceID:      "device:1",
		ExpiresAtUnix: now.Add(1 * time.Minute).Unix(),
	})

	if !store.peek(nonce, "identity:alice", "device:1", now) {
		t.Fatal("expected peek to report the freshly put nonce as valid")
	}
}

func TestRedisNonceStore_Peek_WrongBinding_ReturnsFalse_NonceStillConsumable(t *testing.T) {
	store := newTestRedisNonceStore(t)
	nonce := uniqueNonce(t)
	cleanupNonceKey(t, store, nonce)

	now := time.Now()
	store.put(nonce, nonceRecord{
		IdentityRef:   "identity:alice",
		DeviceID:      "device:1",
		ExpiresAtUnix: now.Add(1 * time.Minute).Unix(),
	})

	if store.peek(nonce, "identity:mallory", "device:1", now) {
		t.Fatal("expected peek with wrong identity to report false")
	}
	if store.peek(nonce, "identity:alice", "device:evil", now) {
		t.Fatal("expected peek with wrong device to report false")
	}

	// peek must be non-destructive: the nonce is still consumable
	// afterward with the correct binding.
	if !store.consumeIfValid(nonce, "identity:alice", "device:1", now) {
		t.Fatal("expected the nonce to still be consumable after mismatched peek attempts")
	}
}

func TestRedisNonceStore_ConsumeIfValid_HappyPath_OneTimeOnly(t *testing.T) {
	store := newTestRedisNonceStore(t)
	nonce := uniqueNonce(t)
	cleanupNonceKey(t, store, nonce)

	now := time.Now()
	store.put(nonce, nonceRecord{
		IdentityRef:   "identity:alice",
		DeviceID:      "device:1",
		ExpiresAtUnix: now.Add(1 * time.Minute).Unix(),
	})

	if !store.consumeIfValid(nonce, "identity:alice", "device:1", now) {
		t.Fatal("expected first consumeIfValid call to succeed")
	}
	if store.consumeIfValid(nonce, "identity:alice", "device:1", now) {
		t.Fatal("expected second consumeIfValid call for the same nonce to fail (one-time consumption)")
	}
}

func TestRedisNonceStore_ConsumeIfValid_WrongBinding_DoesNotDeleteNonce(t *testing.T) {
	store := newTestRedisNonceStore(t)
	nonce := uniqueNonce(t)
	cleanupNonceKey(t, store, nonce)

	now := time.Now()
	store.put(nonce, nonceRecord{
		IdentityRef:   "identity:alice",
		DeviceID:      "device:1",
		ExpiresAtUnix: now.Add(1 * time.Minute).Unix(),
	})

	if store.consumeIfValid(nonce, "identity:mallory", "device:1", now) {
		t.Fatal("expected consumeIfValid with wrong identity to fail")
	}
	if store.consumeIfValid(nonce, "identity:alice", "device:evil", now) {
		t.Fatal("expected consumeIfValid with wrong device to fail")
	}

	// The nonce must still be present/consumable afterward with the
	// CORRECT binding — a mismatch must not have deleted it.
	if !store.consumeIfValid(nonce, "identity:alice", "device:1", now) {
		t.Fatal("expected the nonce to still be consumable with the correct binding after mismatched attempts")
	}
}

// TestRedisNonceStore_ConsumeIfValid_ConcurrentReplay_ExactlyOneWins is the
// direct proof that a single Lua EVAL genuinely closes the same race
// InMemoryNonceStore.consumeIfValid's mutex closed: N goroutines racing
// consumeIfValid on the same nonce, exactly one must return true.
func TestRedisNonceStore_ConsumeIfValid_ConcurrentReplay_ExactlyOneWins(t *testing.T) {
	store := newTestRedisNonceStore(t)
	nonce := uniqueNonce(t)
	cleanupNonceKey(t, store, nonce)

	now := time.Now()
	store.put(nonce, nonceRecord{
		IdentityRef:   "identity:alice",
		DeviceID:      "device:1",
		ExpiresAtUnix: now.Add(1 * time.Minute).Unix(),
	})

	const n = 25
	var successCount int64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if store.consumeIfValid(nonce, "identity:alice", "device:1", now) {
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 of %d concurrent consumeIfValid calls to succeed, got %d", n, successCount)
	}
}

// TestRedisNonceStore_Expiry_RealTTL_BecomesUnusable proves expiry using a
// short real TTL and a real, bounded sleep — RedisNonceStore cannot use
// Service's fake-clock testing seam (Redis's own TTL runs on real wall-clock
// time regardless of what Service.now is overridden to), per this
// capability's documented testing decision (docs/DECISION_LOG.md, "Batch C
// (Session/Request Authentication) design").
func TestRedisNonceStore_Expiry_RealTTL_BecomesUnusable(t *testing.T) {
	store := newTestRedisNonceStore(t)
	nonce := uniqueNonce(t)
	cleanupNonceKey(t, store, nonce)

	now := time.Now()
	store.put(nonce, nonceRecord{
		IdentityRef:   "identity:alice",
		DeviceID:      "device:1",
		ExpiresAtUnix: now.Add(300 * time.Millisecond).Unix(),
	})

	// Confirm it's usable immediately after put.
	if !store.peek(nonce, "identity:alice", "device:1", time.Now()) {
		t.Fatal("expected the freshly put nonce to be valid immediately")
	}

	// Sleep well past the real TTL Redis actually applies here.
	// ExpiresAtUnix is whole-second granularity (Unix() truncates
	// fractional seconds), so a "300ms from now" expiry can round to
	// anywhere from a hair above 0 up to roughly 1.3s of real TTL
	// depending on where `now` falls within its current second (and put's
	// own defensive <=0 clamp guarantees at least 1s regardless). 2.5s of
	// real sleep comfortably clears every case.
	time.Sleep(2500 * time.Millisecond)

	if store.peek(nonce, "identity:alice", "device:1", time.Now()) {
		t.Fatal("expected the nonce to have expired via Redis's own TTL")
	}
	if store.consumeIfValid(nonce, "identity:alice", "device:1", time.Now()) {
		t.Fatal("expected consumeIfValid to fail for an expired nonce")
	}
}
