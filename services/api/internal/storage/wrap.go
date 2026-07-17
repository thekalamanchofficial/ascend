package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// This file implements the ONE cryptographic primitive Storage itself
// owns: a second, outer AEAD envelope around the already-opaque,
// already-end-to-end-encrypted bytes a caller hands to StoreBlob.
//
// IMPORTANT — read before touching anything in this file: the key this
// file generates and manages is NOT end-to-end encryption, is NOT a
// second layer of content confidentiality the user should rely on, and
// must NEVER be described to a user as either. Storage never holds the
// real end-to-end content key (the client holds that, via Cryptography &
// Keys — see charter §3) and cannot shred it. What Storage CAN do is
// generate and hold a key of its own; destroying that self-owned key is a
// real, mechanical way to render the outer-wrapped bytes permanently
// unrecoverable on a backend that can't guarantee true byte-level erasure
// (e.g. some replicated object-storage backends). This is purely a
// backend-operational deletion-guarantee mechanism. See
// docs/DECISION_LOG.md, 2026-07-17 "Storage interface frozen; crypto-shred
// fallback resolved as a Storage-owned wrapping key, not the content key."
//
// Construction: AES-256-GCM (Go standard library only — crypto/aes +
// crypto/cipher — per this capability's spawn brief, which explicitly
// allows either chacha20poly1305 or stdlib AES-GCM; AES-GCM was chosen
// specifically to avoid adding golang.org/x/crypto as a new go.mod
// dependency for a backend-internal, non-end-to-end concern — see
// docs/DECISION_LOG.md for the full rationale). Every blob gets its own
// freshly generated 256-bit key (not one shared global wrapping key) —
// see docs/DECISION_LOG.md for why per-blob keys were chosen over one
// service-wide key.

const (
	// wrappingKeySize is 32 bytes: AES-256.
	wrappingKeySize = 32
)

// generateWrappingKey returns a fresh, random 256-bit AES key, sourced
// from crypto/rand (the OS CSPRNG) — the only entropy source used
// anywhere in this package, matching Cryptography & Keys' "single audited
// CSPRNG entry point" convention (docs/DECISION_LOG.md, 2026-07-16).
func generateWrappingKey() ([]byte, error) {
	key := make([]byte, wrappingKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// sealOuterEnvelope wraps data (already-opaque ciphertext from Storage's
// point of view — see charter §3) under key, producing nonce||ciphertext
// (GCM's authentication tag is appended to the ciphertext by
// cipher.AEAD.Seal, per its standard contract).
func sealOuterEnvelope(key, data []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, data, nil)
	return append(nonce, sealed...), nil
}

// openOuterEnvelope reverses sealOuterEnvelope. It fails (returns an
// error, no partial output) if key is wrong or sealed has been tampered
// with — GCM authenticates the ciphertext, it does not merely obscure it.
func openOuterEnvelope(key, sealed []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("storage: sealed envelope shorter than nonce size")
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// zeroBytes overwrites b in place before it is discarded, so a destroyed
// wrapping key does not linger as a stale, readable value in memory any
// longer than necessary (defense in depth — Go's GC does not guarantee
// prompt reclamation, let alone zeroing, of freed memory).
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// wrappingKeyFingerprint is used only for audit-metadata-safe debugging —
// never logged with the key itself, and never persisted. It is a
// truncated SHA-256 digest of the key (never the raw key bytes
// themselves, which would defeat the point), matching Cryptography &
// Keys' auditFingerprint construction (docs/DECISION_LOG.md, 2026-07-16,
// "Fix: hash SecureLocalStore key names before they reach audit
// metadata") — the same "never log the sensitive value itself" discipline
// applied here to a key this package generates rather than one it names.
func wrappingKeyFingerprint(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}
