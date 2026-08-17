package sessionauth

import (
	"sync"
	"time"
)

// Storage for this capability splits across two different backends per a
// documented decision (docs/DECISION_LOG.md, "Batch C (Session/Request
// Authentication) design"): challenge nonces are pure ephemeral, single-use
// state with no durability/export requirement (Redis, see
// redis_nonce_store.go), while sessions are durable and must survive a
// restart — ExportSessions must be able to show expired-but-not-yet-revoked
// sessions, which a pure TTL store would evict and lose (Postgres, see
// postgres_session_store.go). Both concrete backends satisfy the two
// exported interfaces below (NonceStore, SessionStore) — Service
// (service.go) is written against those interfaces and does not know or
// care which concrete implementation actually backs it. InMemoryNonceStore/
// InMemorySessionStore below are the original, still-supported in-memory
// implementations (e.g. for tests), following the same
// "in-memory first pass, swap internals later" precedent Identity/
// Permissions/Audit each established.
//
// Two separate stores exist (rather than one shared store) because they
// have genuinely different shapes and lifetimes: nonces are short-lived and
// consumed exactly once (no history retained — see DATA_MANIFEST.md, "not
// retained once consumed or expired"); sessions are longer-lived, looked up
// by token on every request, and enumerated/exported by identity. Sharing
// one map/mutex (or one backend) between the two would couple two
// operations (nonce consumption under concurrent replay, and session
// issuance/lookup) that don't need to serialize against each other, logged
// as a documented decision in docs/DECISION_LOG.md.

// NonceStore is the persistence boundary Service depends on for challenge
// nonces. Its three unexported methods match InMemoryNonceStore's own
// pre-existing method set exactly (kept unexported — only types in this
// package, sessionauth, can implement it: InMemoryNonceStore here and
// RedisNonceStore in redis_nonce_store.go). Exported as a named type
// (unlike Permissions'/Storage's unexported-method-interface convention)
// because NewService's signature must name it directly — see
// docs/DECISION_LOG.md's Batch C entry.
type NonceStore interface {
	put(nonce string, rec nonceRecord)
	peek(nonce, identityRef, deviceID string, now time.Time) bool
	consumeIfValid(nonce, identityRef, deviceID string, now time.Time) bool
}

// SessionStore is the persistence boundary Service depends on for issued
// sessions. Its unexported methods match InMemorySessionStore's own
// pre-existing method set exactly (kept unexported — only types in this
// package can implement it: InMemorySessionStore here and
// PostgresSessionStore in postgres_session_store.go).
//
// currentDeviceGeneration/putIfDeviceGenerationUnchanged/revokeAllForDevice
// (added 2026-08-17, RevokeSessionsForDevice amendment) are the atomicity
// primitive charter §3's amendment requires: "a per-device serialization
// point... or a revoked-at watermark for the device that IssueSession
// checks as part of its own commit." See revokeAllForDevice's doc comment
// below for the full design — a monotonically increasing per-(identity_ref,
// device_id) generation counter, mirroring Identity's own `epoch` counter
// (services/api/internal/identity/sign.go), checked-and-incremented
// atomically by revokeAllForDevice and checked-and-compared atomically by
// putIfDeviceGenerationUnchanged, with the two operations mutually
// exclusive against each other per device (InMemorySessionStore: the same
// single mutex every other method already uses; PostgresSessionStore: a
// transaction holding a `SELECT ... FOR UPDATE` row lock on the device's
// generation row — see that file).
type SessionStore interface {
	put(sess Session)
	get(token string) (Session, bool)
	touchLastUsed(token string, nowUnix int64)
	delete(token string)
	deleteAllForIdentity(identityRef string) int
	listActiveForIdentity(identityRef string, nowUnix int64) []Session
	listAllForIdentity(identityRef string) []Session

	// currentDeviceGeneration reads the current generation for
	// (identityRef, deviceID) WITHOUT taking the per-device serialization
	// lock or mutating anything — a plain, non-atomic read. Used by
	// IssueSession (service.go) to capture "my view of the world" shortly
	// before attempting to commit; the actual correctness guarantee comes
	// from putIfDeviceGenerationUnchanged's atomic re-check at commit time,
	// not from this read being fresh. A device with no revocation history
	// yet has generation 0 (the Go zero value / SQL DEFAULT 0 — see
	// 0007_sessionauth_device_generations.up.sql), never an error.
	currentDeviceGeneration(identityRef, deviceID string) int64

	// putIfDeviceGenerationUnchanged is IssueSession's atomic commit gate
	// (the "revoked-at watermark... checked as part of its own commit"
	// half of the charter's two named options): atomically re-reads the
	// current generation for (sess.IdentityRef, sess.DeviceID) and, ONLY IF
	// it still equals expectedGeneration, inserts sess and returns true.
	// Returns false, WITHOUT inserting, if the generation has moved on —
	// meaning a RevokeSessionsForDevice call for this device committed
	// (and already returned success to its own caller) at some point
	// between when this caller captured expectedGeneration and this call.
	// This is what makes revokeAllForDevice's "sessions_revoked is a
	// completion guarantee, not a point-in-time snapshot" claim true even
	// when a concurrently in-flight IssueSession call reaches this final
	// commit step AFTER a RevokeSessionsForDevice call for the same device
	// has already fully committed and returned.
	putIfDeviceGenerationUnchanged(sess Session, expectedGeneration int64) bool

	// revokeAllForDevice atomically (a) increments the generation for
	// (identityRef, deviceID) and (b) deletes every session currently
	// stored for that exact (identityRef, deviceID) pair, as ONE
	// serialized unit against any concurrent putIfDeviceGenerationUnchanged
	// call for the same device — see that method's doc comment and
	// PostgresSessionStore's implementation for why serialization (not
	// just "eventually consistent" ordering) is required. Returns the
	// number of sessions deleted. Backs RevokeSessionsForDevice
	// (service.go): whichever of the two operations' critical sections
	// runs first for a given device, the other is guaranteed to observe
	// its effect — either the new session is caught by THIS delete (it
	// existed by the time revokeAllForDevice's critical section ran), or
	// putIfDeviceGenerationUnchanged's own generation check rejects the
	// insert (this call already bumped the generation before that check
	// ran) — so no session for the device can survive a revokeAllForDevice
	// call that has already returned, regardless of interleaving.
	revokeAllForDevice(identityRef, deviceID string) int
}

// --- nonce store ---

type nonceRecord struct {
	IdentityRef   string
	DeviceID      string
	ExpiresAtUnix int64
	// Consumed is intentionally NOT a field here: a consumed nonce is
	// deleted outright (see consumeIfValid), not marked and retained — this
	// is what DATA_MANIFEST.md's "not retained once consumed or expired"
	// commitment means concretely, and it also means the nonce map cannot
	// grow unboundedly from consumed-but-kept entries.
}

// InMemoryNonceStore is a goroutine-safe, process-local store for
// outstanding challenge nonces.
type InMemoryNonceStore struct {
	mu     sync.Mutex
	nonces map[string]nonceRecord
}

func NewInMemoryNonceStore() *InMemoryNonceStore {
	return &InMemoryNonceStore{nonces: make(map[string]nonceRecord)}
}

// put registers a freshly issued nonce. Overwriting an existing key would
// only happen on an astronomically unlikely CSPRNG collision (see
// token.go); it is allowed here (last write wins) rather than treated as
// an error, since a collision would already mean an issued-but-unconsumed
// nonce's identity/device binding is unrelated to the birthday-paradox
// analysis a capability engineer would need to treat this as a real risk.
func (s *InMemoryNonceStore) put(nonce string, rec nonceRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[nonce] = rec
}

// peek reports whether nonce currently exists, is unexpired, and is bound
// to (identityRef, deviceID) — WITHOUT consuming it. Used for charter §3's
// step 1 ("look up challenge_nonce — must exist, be unexpired, and not
// already consumed. Reject otherwise") so IssueSession can fail fast,
// before resolving the device or verifying a signature, on a nonce that is
// obviously already invalid. This is deliberately NOT the operation that
// provides the anti-replay guarantee — see consumeIfValid below for that.
func (s *InMemoryNonceStore) peek(nonce, identityRef, deviceID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.nonces[nonce]
	if !ok {
		return false
	}
	if now.Unix() > rec.ExpiresAtUnix {
		return false
	}
	return rec.IdentityRef == identityRef && rec.DeviceID == deviceID
}

// consumeIfValid is the single atomic gate charter §3 step 4 requires:
// consuming the nonce "must happen atomically with, or immediately after,
// successful verification, such that a captured, already-used IssueSession
// request can never succeed twice, even under concurrent replay attempts."
// It
// re-validates existence/expiry/identity-device-binding AND marks the nonce
// consumed (by deleting it) in one critical section. Called by
// Service.IssueSession only AFTER ed25519 signature verification has
// already succeeded (step 3) — so two concurrent requests racing to replay
// the exact same (nonce, proof) pair can both pass steps 1-3 (verification
// is a pure function, not gated by store state), but only one of them can
// ever win this call; the loser gets a false return and IssueSession
// rejects it with ErrInvalidNonce, never issuing a second session for the
// same proof.
func (s *InMemoryNonceStore) consumeIfValid(nonce, identityRef, deviceID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.nonces[nonce]
	if !ok {
		return false
	}
	if now.Unix() > rec.ExpiresAtUnix {
		delete(s.nonces, nonce)
		return false
	}
	if rec.IdentityRef != identityRef || rec.DeviceID != deviceID {
		return false
	}
	delete(s.nonces, nonce)
	return true
}

// --- session store ---

// InMemorySessionStore is a goroutine-safe, process-local store for issued
// sessions, keyed by session_token, plus (added 2026-08-17,
// RevokeSessionsForDevice amendment) a per-(identity_ref, device_id)
// generation counter backing the atomicity guarantee described on
// SessionStore's currentDeviceGeneration/putIfDeviceGenerationUnchanged/
// revokeAllForDevice doc comments above. Deliberately guarded by the SAME
// mutex (s.mu) as sessions itself, not a second lock — that single mutex
// is exactly the "per-device serialization point" (in this in-memory
// implementation, serialization is coarser than per-device — the whole
// store serializes on one mutex, same as every other InMemorySessionStore
// method already does — but that is still strictly sufficient: mutual
// exclusion across ALL devices trivially implies mutual exclusion for any
// ONE device).
type InMemorySessionStore struct {
	mu                sync.Mutex
	sessions          map[string]Session
	deviceGenerations map[string]int64
}

func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{
		sessions:          make(map[string]Session),
		deviceGenerations: make(map[string]int64),
	}
}

// deviceGenerationKey mirrors fakeDeviceResolver's own identityRef+"|"+deviceID
// test-double convention (service_test.go) — a plain delimited string is
// sufficient here since this is purely an in-process map key, never
// serialized or compared across a process boundary.
func deviceGenerationKey(identityRef, deviceID string) string {
	return identityRef + "\x00" + deviceID
}

func (s *InMemorySessionStore) put(sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.SessionToken] = sess
}

// get returns the session record for token, if any exists — regardless of
// whether it has expired (expiry is a Service-level, not store-level,
// concern: ValidateSession/resolveCaller check ExpiresAtUnix against the
// current time; ExportSessions deliberately wants even expired-but-not-
// revoked sessions, see listAllForIdentity).
func (s *InMemorySessionStore) get(token string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	return sess, ok
}

// touchLastUsed updates LastUsedAtUnix for an existing session. A no-op if
// the token is unknown (defensive; callers only invoke this after a
// successful get/validate).
func (s *InMemorySessionStore) touchLastUsed(token string, nowUnix int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return
	}
	sess.LastUsedAtUnix = nowUnix
	s.sessions[token] = sess
}

// delete removes a session outright — revocation is real and immediate
// (Art. 7): once deleted, no subsequent ValidateSession call can ever
// resolve this token again, not "valid until natural expiry."
func (s *InMemorySessionStore) delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

// deleteAllForIdentity removes every session belonging to identityRef and
// reports how many were removed — backs RevokeAllSessions.
func (s *InMemorySessionStore) deleteAllForIdentity(identityRef string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for token, sess := range s.sessions {
		if sess.IdentityRef == identityRef {
			delete(s.sessions, token)
			count++
		}
	}
	return count
}

// listActiveForIdentity returns every currently-unexpired session for
// identityRef — backs ListActiveSessions, which is explicitly a "currently
// active" transparency view (charter §3), not a full history.
func (s *InMemorySessionStore) listActiveForIdentity(identityRef string, nowUnix int64) []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Session
	for _, sess := range s.sessions {
		if sess.IdentityRef == identityRef && sess.ExpiresAtUnix >= nowUnix {
			out = append(out, sess)
		}
	}
	return out
}

// listAllForIdentity returns every session record this store currently
// holds for identityRef, active or expired (but not yet revoked/deleted) —
// backs ExportSessions, which per charter §3 exports "every one of the
// caller's own sessions" as a durable record, not just the live/active
// subset ListActiveSessions shows.
func (s *InMemorySessionStore) listAllForIdentity(identityRef string) []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Session
	for _, sess := range s.sessions {
		if sess.IdentityRef == identityRef {
			out = append(out, sess)
		}
	}
	return out
}

// currentDeviceGeneration returns the current generation for (identityRef,
// deviceID), 0 if none has ever been recorded (a device that has never had
// RevokeSessionsForDevice called for it). See SessionStore's doc comment
// for the full atomicity design this is one third of.
func (s *InMemorySessionStore) currentDeviceGeneration(identityRef, deviceID string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deviceGenerations[deviceGenerationKey(identityRef, deviceID)]
}

// putIfDeviceGenerationUnchanged is IssueSession's atomic commit gate — see
// SessionStore's doc comment. Holding s.mu across both the generation
// comparison and the session insert is what makes this atomic with respect
// to a concurrent revokeAllForDevice call (below), which holds the exact
// same mutex across its own generation-bump-and-delete.
func (s *InMemorySessionStore) putIfDeviceGenerationUnchanged(sess Session, expectedGeneration int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.deviceGenerations[deviceGenerationKey(sess.IdentityRef, sess.DeviceID)]
	if current != expectedGeneration {
		return false
	}
	s.sessions[sess.SessionToken] = sess
	return true
}

// revokeAllForDevice atomically bumps (identityRef, deviceID)'s generation
// and deletes every session currently stored for that exact pair — see
// SessionStore's doc comment for why this must be one atomic unit (not two
// separate operations) and why it correctly closes the race against a
// concurrent putIfDeviceGenerationUnchanged call for the same device.
func (s *InMemorySessionStore) revokeAllForDevice(identityRef, deviceID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := deviceGenerationKey(identityRef, deviceID)
	s.deviceGenerations[key] = s.deviceGenerations[key] + 1

	count := 0
	for token, sess := range s.sessions {
		if sess.IdentityRef == identityRef && sess.DeviceID == deviceID {
			delete(s.sessions, token)
			count++
		}
	}
	return count
}
