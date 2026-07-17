package sessionauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// sessionTokenBytes/challengeNonceBytes are the amount of CSPRNG-sourced
// entropy behind each opaque credential this capability issues. 32 bytes
// (256 bits) for the session token — a long-lived-relative-to-a-nonce
// bearer credential — and 24 bytes (192 bits) for the challenge nonce,
// which only needs to be unpredictable and single-use, not resistant to
// years of offline guessing. Both are comfortably beyond any brute-force
// concern; the exact byte counts are an implementation decision, logged in
// docs/DECISION_LOG.md.
const (
	sessionTokenBytes   = 32
	challengeNonceBytes = 24
)

// generateOpaqueToken returns a CSPRNG-sourced, base64url-encoded (no
// padding), unguessable random string. Used for both session tokens and
// challenge nonces (different byte lengths — see above) — deliberately NOT
// derived from identity_ref/device_id/time or any other guessable input,
// per charter §4's "carries no embedded identity data (unlike a JWT,
// deliberately)".
func generateOpaqueToken(numBytes int) string {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing indicates a broken host CSPRNG — there is no
		// safe way to continue issuing credentials at that point (mirrors
		// identity/idgen.go's identical precedent).
		panic("sessionauth: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateSessionToken() string {
	return generateOpaqueToken(sessionTokenBytes)
}

func generateChallengeNonce() string {
	return generateOpaqueToken(challengeNonceBytes)
}

// tokenFingerprint returns a truncated SHA-256 hash of a sensitive opaque
// value (a session_token), hex-encoded, for use ONLY in audit
// metadata/resource identifiers — never the raw token. This mirrors
// Cryptography & Keys' auditFingerprint precedent (docs/DECISION_LOG.md,
// 2026-07-16, "Fix: hash SecureLocalStore key names before they reach audit
// metadata"): a live bearer credential must never appear in the audit trail
// verbatim, since the audit trail itself is not a secret store, but a
// truncated hash is still enough to correlate repeated failures against the
// same token without being invertible back to the live credential.
func tokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}
