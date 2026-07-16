package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strconv"
)

// buildDeviceBindingMessage constructs the exact byte sequence that must be
// signed to authorize BindDevice, per charter §3/§6: "proof of possession"
// from either an already-bound device or a recovery-derived assertion.
//
// The frozen identity.proto contract does not itself define a canonical
// signing payload (BindDeviceRequest just carries opaque
// authorization_proof bytes) — this is a real, logged decision (see
// docs/DECISION_LOG.md, this capability's "BindDevice signing payload"
// entry), not an assumption silently baked into the wire format. Any
// client computing authorization_proof (mobile, via Cryptography & Keys'
// Sign RPC) MUST sign exactly this byte sequence for verification to
// succeed:
//
//	"ascend.identity.v1.BindDevice" || 0x00 ||
//	identityRef || 0x00 ||
//	base64(devicePublicKey) || 0x00 ||
//	deviceName || 0x00 ||
//	decimal(epoch)
//
// A fixed domain-separation prefix ("ascend.identity.v1.BindDevice") is
// included so a signature produced for this operation can never be
// replayed as a valid signature for a different operation that happens to
// sign a byte-compatible payload. NUL bytes are used as field separators
// because none of the four variable-length/formatted fields (identity_ref,
// base64 public key, device name, decimal epoch) can contain a raw NUL
// byte in valid UTF-8/base64/decimal-digit input, so this cannot be
// exploited by choosing field values that shift a later field into an
// earlier one.
//
// `epoch` is the anti-replay / freshness input required by the 2026-07-16
// Security Steward merge-gate veto ("BindDevice replay: revoked device's
// original authorization_proof remains valid forever"). It is
// IdentityRecord.Epoch — a monotonically increasing, server-held,
// per-identity counter incremented on every successful BindDevice AND
// RevokeDevice (service.go). Binding it into the signed message means any
// proof computed against a given epoch value stops verifying the instant
// that epoch changes for any reason, including a revoke that later
// happens to return the bound-device set to a prior-looking membership —
// unlike a hash of current device-ID-set membership (the charter's other
// suggested option), a monotonic counter never revisits a previously-valid
// value, which a bind-then-revoke-the-same-device round trip would
// otherwise produce (see docs/DECISION_LOG.md, this capability's
// "BindDevice replay" fix entry, for why the device-ID-set-hash
// alternative was rejected as insufficient for exactly the required
// regression scenario).
//
// Known, flagged discoverability limitation: identity.proto's response
// messages (PublicIdentity, Device, ListDevicesResponse) are frozen and
// expose no epoch field, so a caller cannot fetch "the current epoch" via
// any RPC before signing. The signer (an already-bound device, or the
// recovery-derived key) is expected to track epoch locally, starting at 0
// at CreateIdentity time and incrementing by 1 on every bind/revoke IT
// itself observes/performs. If a different device changed the topology in
// the interim, this device's local epoch goes stale and its next
// BindDevice attempt correctly, safely fails closed (ErrInvalidSignature)
// rather than silently succeeding on a wrong assumption — a fail-closed
// safety property, not a silent hole. Full resolution (e.g. exposing
// epoch via a future contract revision to ResolveIdentity/ListDevices for
// genuine multi-device concurrent-modification UX) is a contract change
// outside this capability-engineer's authority to make unilaterally;
// flagged for the Chief Architect.
func buildDeviceBindingMessage(identityRef string, devicePublicKey []byte, deviceName string, epoch int64) []byte {
	var buf bytes.Buffer
	buf.WriteString("ascend.identity.v1.BindDevice")
	buf.WriteByte(0)
	buf.WriteString(identityRef)
	buf.WriteByte(0)
	buf.WriteString(base64.StdEncoding.EncodeToString(devicePublicKey))
	buf.WriteByte(0)
	buf.WriteString(deviceName)
	buf.WriteByte(0)
	buf.WriteString(strconv.FormatInt(epoch, 10))
	return buf.Bytes()
}

// verifyBindingSignature checks `sig` over `message` against a single
// candidate Ed25519 public key. It is a thin, direct call into the Go
// standard library's crypto/ed25519 — no custom crypto, per charter §3's
// "Identity never implements its own crypto" (verification with an
// already-known public key via an unmodified stdlib primitive is not
// "implementing crypto"; see docs/DECISION_LOG.md, 2026-07-16, "Crypto &
// Keys contract gains Sign; signature verification is not 'own crypto'").
func verifyBindingSignature(publicKey, message, sig []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, message, sig)
}

// authorizesBinding reports whether `proof` is a valid Ed25519 signature
// over the canonical binding message for (identityRef, devicePublicKey,
// deviceName, record's CURRENT epoch), checked against every key that is
// currently allowed to authorize a new device on this identity: the
// identity's own root public key (the recovery-derived self-signed path,
// charter §3/§7) or any currently-bound device's public key (the
// already-bound-device path). Using record.Epoch as it stands at
// verification time — never a caller-supplied epoch value — is what makes
// this genuinely anti-replay: a proof signed against a now-stale epoch
// cannot verify no matter what epoch value the caller claims, because the
// caller never gets to supply one; it's derived solely from server state.
//
// Per charter §3 and §7, if the proof verifies against the identity's root
// key (the recovery path), this function — and BindDevice above it — has
// no further discretionary authority to reject it; relaying and
// audit-logging is the whole of this service's job on that path.
func authorizesBinding(record IdentityRecord, devicePublicKey []byte, deviceName string, proof []byte) bool {
	message := buildDeviceBindingMessage(record.IdentityRef, devicePublicKey, deviceName, record.Epoch)

	if verifyBindingSignature(record.PublicKey, message, proof) {
		return true
	}
	for _, d := range record.Devices {
		if verifyBindingSignature(d.PublicKey, message, proof) {
			return true
		}
	}
	return false
}
