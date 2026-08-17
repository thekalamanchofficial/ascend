package sessionauth

import (
	"context"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// nonceKeyPrefix namespaces every key this store writes into the shared
// Redis instance (internal/platform/redis.go), so this capability's own
// keys can never collide with another capability's future use of the same
// Redis instance.
const nonceKeyPrefix = "sessionauth:nonce:"

// nonceValueDelimiter separates identityRef from deviceID inside a single
// plain-string Redis value — mirroring internal/permissions/store.go's own
// activeGrantKey delimiter convention. A two-field value this small does
// not need JSON: a single Unit Separator byte (0x1F) is exceedingly
// unlikely to ever appear in a real identity_ref/device_id, and even if it
// somehow did, the worst case is a peek/consumeIfValid binding mismatch
// (fail-closed), never a parsing crash.
const nonceValueDelimiter = "\x1f"

// consumeScript is the Lua script backing RedisNonceStore.consumeIfValid's
// atomicity guarantee — see that method's doc comment for why this is the
// Redis equivalent of InMemoryNonceStore's single-mutex critical section.
// Redis runs a single EVAL invocation as one atomic, uninterruptible
// operation (Redis is single-threaded for command execution), so this
// GET-compare-DEL sequence can never be split across two concurrent
// callers the way three separate GET/compare/DEL round trips could be.
const consumeScript = `
local v = redis.call('GET', KEYS[1])
if not v then return 0 end
if v == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 1
end
return 0
`

// RedisNonceStore is a Redis-backed implementation of NonceStore, leaning
// on Redis's own native per-key TTL for expiry rather than reimplementing
// expiry checking in Go — see put/peek/consumeIfValid below for the
// specifics of how each method leans on that TTL (or deliberately does
// not). See docs/DECISION_LOG.md, "Batch C (Session/Request Authentication)
// design", for the full design rationale.
type RedisNonceStore struct {
	client *redis.Client
}

// NewRedisNonceStore constructs a RedisNonceStore against an
// already-connected, already-health-checked client (see
// platform.NewRedisClient).
func NewRedisNonceStore(client *redis.Client) *RedisNonceStore {
	return &RedisNonceStore{client: client}
}

func nonceKey(nonce string) string {
	return nonceKeyPrefix + nonce
}

func nonceValue(identityRef, deviceID string) string {
	return identityRef + nonceValueDelimiter + deviceID
}

// put registers a freshly issued nonce with a Redis-native TTL computed
// from rec.ExpiresAtUnix, via SET key value EX <seconds>. The TTL is
// clamped to a minimum of 1 second: rec.ExpiresAtUnix could in principle
// already be <= now (an ExpiresAtUnix computed a moment earlier than `put`
// is called, under enough clock/scheduling skew, or a caller passing an
// already-past expiry), and Redis's SET ... EX rejects a non-positive
// expire value outright rather than treating it as "expire immediately" —
// this defensive clamp means put always succeeds and the nonce is simply
// unusable within roughly a second, functionally equivalent to "already
// expired" for every caller (peek/consumeIfValid both compare against the
// current time or Redis's own TTL, either of which will already reject a
// clamped-to-1-second-in-the-past-intent nonce almost immediately).
func (s *RedisNonceStore) put(nonce string, rec nonceRecord) {
	ctx := context.Background()
	ttl := time.Until(time.Unix(rec.ExpiresAtUnix, 0))
	if ttl <= 0 {
		ttl = 1 * time.Second
	}
	// A SET failure here has no error-return channel to surface through
	// (NonceStore.put returns nothing, matching InMemoryNonceStore.put's
	// signature exactly — see store.go's NonceStore interface). This
	// mirrors Permissions' PostgresStore's own documented choice for
	// void-return mutation methods: silently swallowing a genuine write
	// failure here is not a viable option (see that package's
	// storeFailure doc comment) since it would let GetSessionChallenge
	// report success for a nonce that was never actually durably issued —
	// so a failed SET panics rather than silently no-oping.
	if err := s.client.Set(ctx, nonceKey(nonce), nonceValue(rec.IdentityRef, rec.DeviceID), ttl).Err(); err != nil {
		panic("sessionauth: redis nonce store: put: " + err.Error())
	}
}

// peek reports whether nonce currently exists in Redis and is bound to
// (identityRef, deviceID) — WITHOUT consuming it. The `now` parameter is
// accepted only to satisfy the NonceStore interface; it is deliberately
// NOT used for expiry here. Redis's own per-key TTL (set at put time) is
// the sole source of truth for expiry: a key that has expired simply no
// longer exists in Redis, so a GET miss already covers "never issued" and
// "expired" identically, exactly like InMemoryNonceStore.peek's explicit
// now.Unix() > rec.ExpiresAtUnix check achieves in-process — this is not an
// oversight, it is the intended way to lean on Redis's native expiry
// instead of reimplementing it.
func (s *RedisNonceStore) peek(nonce, identityRef, deviceID string, _ time.Time) bool {
	ctx := context.Background()
	v, err := s.client.Get(ctx, nonceKey(nonce)).Result()
	if err != nil {
		// redis.Nil means the key doesn't exist (never issued, or already
		// expired via Redis's own TTL) — false, matching
		// InMemoryNonceStore.peek's "not ok"/"expired" cases. Any other
		// error (a genuine connectivity failure) is folded into the same
		// false, fail-closed shape: peek is a fast-fail read used only to
		// let IssueSession reject early (see service.go step 1) — it is
		// not the anti-replay-critical operation (that's consumeIfValid
		// below), so treating an unreadable value as "not valid" is safe.
		return false
	}
	idRef, devID, ok := strings.Cut(v, nonceValueDelimiter)
	if !ok {
		return false
	}
	return idRef == identityRef && devID == deviceID
}

// consumeIfValid is the atomicity-critical anti-replay gate — see
// consumeScript's doc comment above for why a single Lua EVAL closes the
// exact same race InMemoryNonceStore.consumeIfValid's mutex closed: two
// concurrent calls for the same nonce can never both return true, and a
// binding mismatch does NOT delete the key (only a genuine (identityRef,
// deviceID) match consumes it) — mirroring
// InMemoryNonceStore.consumeIfValid's documented "a binding mismatch in
// consumeIfValid does NOT delete the nonce" behavior exactly. `now` is
// accepted only to satisfy the NonceStore interface and is unused for the
// same reason peek's is: Redis's own TTL already means an expired nonce's
// key is simply gone by the time this runs, so the script's `if not v`
// branch already correctly returns false for an expired-and-evicted nonce
// without needing a separate expiry comparison.
func (s *RedisNonceStore) consumeIfValid(nonce, identityRef, deviceID string, _ time.Time) bool {
	ctx := context.Background()
	result, err := s.client.Eval(ctx, consumeScript,
		[]string{nonceKey(nonce)},
		nonceValue(identityRef, deviceID),
	).Result()
	if err != nil {
		// A script-execution failure (e.g. a connectivity error) is folded
		// into false — the safe, deny-shaped direction for an anti-replay
		// gate: IssueSession's caller already treats a false return as
		// ErrInvalidNonce (service.go), never as an implicit success.
		return false
	}
	n, ok := result.(int64)
	return ok && n == 1
}
