package sessionauth

import (
	"bytes"
	"crypto/ed25519"
)

// buildIssueSessionMessage constructs the exact byte sequence that must be
// signed to authorize IssueSession, per charter §3 (frozen, not this
// capability-engineer's discretion — see sessionauth.proto's own file
// header comment, which already states the byte layout verbatim):
//
//	"ascend.session.v1.IssueSession" || 0x00 ||
//	identity_ref || 0x00 ||
//	device_id || 0x00 ||
//	challenge_nonce
//
// This mirrors identity/sign.go's buildDeviceBindingMessage construction
// style exactly (NUL-byte-separated fields after a fixed domain-separation
// prefix) per the charter's explicit instruction to stay consistent with
// that file. The domain-separation prefix is distinct from Identity's
// "ascend.identity.v1.BindDevice" — this is what guarantees a signature
// produced for BindDevice can never be replayed as a valid IssueSession
// proof, and vice versa, even though both ultimately sign
// identity/device-shaped data with the same device key. NUL bytes are safe
// field separators here because none of identity_ref, device_id, or
// challenge_nonce (this package's own base64url-encoded output, see
// token.go) can contain a raw NUL byte in valid usage.
func buildIssueSessionMessage(identityRef, deviceID, challengeNonce string) []byte {
	var buf bytes.Buffer
	buf.WriteString("ascend.session.v1.IssueSession")
	buf.WriteByte(0)
	buf.WriteString(identityRef)
	buf.WriteByte(0)
	buf.WriteString(deviceID)
	buf.WriteByte(0)
	buf.WriteString(challengeNonce)
	return buf.Bytes()
}

// verifyProof checks `sig` over `message` against a single candidate
// Ed25519 public key, via unmodified crypto/ed25519.Verify — no custom
// crypto (same "verification with an already-known public key via an
// unmodified stdlib primitive is not 'implementing crypto'" reasoning
// identity/sign.go documents, per docs/DECISION_LOG.md, 2026-07-16,
// "Crypto & Keys contract gains Sign; signature verification is not 'own
// crypto'").
func verifyProof(publicKey, message, sig []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, message, sig)
}
