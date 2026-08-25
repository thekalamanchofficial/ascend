package identity

import "sync"

// PrekeyStore is the persistence seam PublishPrekeyBundle/FetchPrekeyBundle
// build against (charter §3/§6, amendment gated 2026-08-20). Split out from
// Store (store.go) rather than folded into it — mirrors
// internal/sessionauth's own two-seam design (NonceStore/SessionStore,
// see sessionauth/service.go's NewService doc comment for the "store(s)
// first" convention this follows): Store's Create/Get/Replace model a
// single whole-record replace, which is the wrong shape for a scarce,
// individually-claimable resource pool where the core requirement is a
// single atomic claim-and-delete on ONE row, not a replace of the whole
// aggregate (charter §6/§7 — explicitly NOT the "acquire a lock, read,
// mutate, write back" shape Storage's lockBlob used, see
// postgres_prekey_store.go's doc comment).
//
// Two implementations exist, exactly like Store: InMemoryPrekeyStore below
// (unit tests, and NewService's nil-safe default) and PostgresPrekeyStore
// (postgres_prekey_store.go, production wiring).
type PrekeyStore interface {
	// PublishBundle replaces (identityRef, deviceID)'s current signed
	// prekey (rotation) and additively inserts oneTime into that device's
	// pool. Returns the count of one_time_prekeys entries genuinely newly
	// stored — re-publishing an already-known prekey_id is a no-op, not
	// an error and not double-counted (see PostgresPrekeyStore.PublishBundle's
	// doc comment for why).
	//
	// identityDhPublicKey/identityDhPublicKeySignature (added 2026-08-21,
	// key-separation fix — identity.proto's PublishPrekeyBundleRequest
	// fields 5/6) are stable, non-rotating per-device values, but stored
	// alongside signed on every call anyway — this package has no way to
	// derive them independently (identity.proto's own comment on why).
	PublishBundle(identityRef, deviceID string, signed SignedPrekey, identityDhPublicKey, identityDhPublicKeySignature []byte, oneTime []OneTimePrekeyPublic) (publishedCount int32, err error)

	// GetSignedPrekey returns (identityRef, deviceID)'s current signed
	// prekey plus its device's stable identity_dh_public_key/
	// identity_dh_public_key_signature pair, or found=false if this device
	// has never published a bundle at all (charter §3/§7's
	// brand-new-identity edge case) OR — fail-closed, charter §3/§6 — the
	// identity_dh_public_key/identity_dh_public_key_signature pair is
	// missing even though a signed prekey exists. Implementations must
	// treat "signed prekey present but DH pair absent" identically to
	// "nothing published at all": found=false, not a partial result.
	GetSignedPrekey(identityRef, deviceID string) (prekey SignedPrekey, identityDhPublicKey, identityDhPublicKeySignature []byte, found bool, err error)

	// ClaimOneOneTimePrekey atomically claims and permanently deletes ONE
	// available one-time prekey for (identityRef, deviceID), or
	// found=false if the pool is currently empty (the exhaustion-fallback
	// case, charter §3). Two concurrent calls for the same
	// (identityRef, deviceID) pair with exactly one prekey remaining must
	// never both return found=true for the same prekey_id — see
	// postgres_prekey_store.go for the single-statement construction that
	// guarantees this for the real implementation.
	ClaimOneOneTimePrekey(identityRef, deviceID string) (prekey OneTimePrekeyPublic, found bool, err error)

	// CountUnconsumedOneTimePrekeys returns the current pool size for
	// (identityRef, deviceID) — backs ListDevices'
	// unconsumed_one_time_prekey_count (charter §4 — a derived count, not
	// a new persisted field).
	CountUnconsumedOneTimePrekeys(identityRef, deviceID string) (int32, error)
}

// InMemoryPrekeyStore is a goroutine-safe, process-local PrekeyStore —
// same durability caveat as InMemoryStore (store.go): no guarantee across
// restarts, used for unit tests and as NewService's nil-safe default.
//
// Its ClaimOneOneTimePrekey is safe under concurrent use (guarded by mu,
// the same single-mutex-per-store shape InMemoryStore already uses) but is
// NOT the implementation this capability's charter §6/§7 concurrency
// requirement is graded against — that requirement (a single atomic
// database statement, proven by a real concurrency test against actual
// contention) is specifically about PostgresPrekeyStore, the only
// implementation multiple real OS processes/connections can ever contend
// against. This type exists so Service's unit tests (service_test.go) can
// exercise PublishPrekeyBundle/FetchPrekeyBundle's business logic without
// requiring a live Postgres instance.
type InMemoryPrekeyStore struct {
	mu sync.Mutex

	// signed is keyed by identityRef+"\x00"+deviceID.
	signed map[string]storedSignedPrekeyRow
	// oneTime is keyed the same way; each device's pool is a plain slice,
	// claimed from the front (FIFO — no ordering guarantee is part of this
	// capability's contract, any available prekey satisfies charter §3).
	oneTime map[string][]OneTimePrekeyPublic
	// oneTimeIDs enforces prekey_id global uniqueness across every device/
	// identity, mirroring PostgresPrekeyStore's real primary-key
	// constraint on identity_one_time_prekeys.prekey_id.
	oneTimeIDs map[string]struct{}
}

// storedSignedPrekeyRow bundles a device's current signed prekey with its
// stable identity_dh_public_key/identity_dh_public_key_signature pair —
// mirrors identity_signed_prekeys' real column layout (one row, both
// rotatable and stable fields together, see
// 0010_identity_prekeys_dh_key.up.sql's doc comment for why they live in
// the same row rather than a separate table).
type storedSignedPrekeyRow struct {
	prekey                       SignedPrekey
	identityDhPublicKey          []byte
	identityDhPublicKeySignature []byte
}

func NewInMemoryPrekeyStore() *InMemoryPrekeyStore {
	return &InMemoryPrekeyStore{
		signed:     make(map[string]storedSignedPrekeyRow),
		oneTime:    make(map[string][]OneTimePrekeyPublic),
		oneTimeIDs: make(map[string]struct{}),
	}
}

func prekeyStoreKey(identityRef, deviceID string) string {
	return identityRef + "\x00" + deviceID
}

func (s *InMemoryPrekeyStore) PublishBundle(identityRef, deviceID string, signedPrekey SignedPrekey, identityDhPublicKey, identityDhPublicKeySignature []byte, oneTime []OneTimePrekeyPublic) (int32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := prekeyStoreKey(identityRef, deviceID)
	s.signed[key] = storedSignedPrekeyRow{
		prekey:                       cloneSignedPrekey(signedPrekey),
		identityDhPublicKey:          append([]byte(nil), identityDhPublicKey...),
		identityDhPublicKeySignature: append([]byte(nil), identityDhPublicKeySignature...),
	}

	var published int32
	for _, otp := range oneTime {
		if _, exists := s.oneTimeIDs[otp.PrekeyID]; exists {
			continue // idempotent no-op, matches PostgresPrekeyStore's ON CONFLICT DO NOTHING
		}
		s.oneTimeIDs[otp.PrekeyID] = struct{}{}
		s.oneTime[key] = append(s.oneTime[key], cloneOneTimePrekey(otp))
		published++
	}
	return published, nil
}

func (s *InMemoryPrekeyStore) GetSignedPrekey(identityRef, deviceID string) (SignedPrekey, []byte, []byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	row, ok := s.signed[prekeyStoreKey(identityRef, deviceID)]
	if !ok {
		return SignedPrekey{}, nil, nil, false, nil
	}
	// Fail-closed (charter §3/§6): a signed prekey present but the DH pair
	// missing must be treated identically to nothing published at all —
	// see PrekeyStore.GetSignedPrekey's doc comment.
	if len(row.identityDhPublicKey) == 0 || len(row.identityDhPublicKeySignature) == 0 {
		return SignedPrekey{}, nil, nil, false, nil
	}
	return cloneSignedPrekey(row.prekey),
		append([]byte(nil), row.identityDhPublicKey...),
		append([]byte(nil), row.identityDhPublicKeySignature...),
		true, nil
}

func (s *InMemoryPrekeyStore) ClaimOneOneTimePrekey(identityRef, deviceID string) (OneTimePrekeyPublic, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := prekeyStoreKey(identityRef, deviceID)
	pool := s.oneTime[key]
	if len(pool) == 0 {
		return OneTimePrekeyPublic{}, false, nil
	}
	claimed := pool[0]
	s.oneTime[key] = pool[1:]
	delete(s.oneTimeIDs, claimed.PrekeyID)
	return cloneOneTimePrekey(claimed), true, nil
}

func (s *InMemoryPrekeyStore) CountUnconsumedOneTimePrekeys(identityRef, deviceID string) (int32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int32(len(s.oneTime[prekeyStoreKey(identityRef, deviceID)])), nil
}

func cloneSignedPrekey(p SignedPrekey) SignedPrekey {
	return SignedPrekey{
		PrekeyID:      p.PrekeyID,
		PublicKey:     append([]byte(nil), p.PublicKey...),
		Signature:     append([]byte(nil), p.Signature...),
		CreatedAtUnix: p.CreatedAtUnix,
	}
}

func cloneOneTimePrekey(p OneTimePrekeyPublic) OneTimePrekeyPublic {
	return OneTimePrekeyPublic{
		PrekeyID:  p.PrekeyID,
		PublicKey: append([]byte(nil), p.PublicKey...),
	}
}
