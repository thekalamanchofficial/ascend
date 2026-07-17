package sessionauth

import "errors"

// Sentinel errors returned by Service methods. http.go maps each to an
// HTTP status code; tests assert against these directly with errors.Is.
var (
	ErrInvalidArgument = errors.New("sessionauth: invalid argument")

	// ErrInvalidNonce covers every reason GetSessionChallenge's nonce fails
	// IssueSession's step-1/step-4 checks: unknown, expired, or already
	// consumed (charter §3 step 1 and the atomic step-4 consume gate). The
	// three cases are deliberately not distinguished in the returned error
	// (they are distinguished in the audit metadata reason field instead) —
	// giving a caller a more specific error for "already used" vs "expired"
	// would leak timing/replay information to whoever is probing, not just
	// to the legitimate device.
	ErrInvalidNonce = errors.New("sessionauth: challenge_nonce is unknown, expired, or already consumed")

	ErrDeviceNotBound         = errors.New("sessionauth: device is not currently bound to this identity")
	ErrDeviceResolutionFailed = errors.New("sessionauth: device resolution failed")
	ErrInvalidSignature       = errors.New("sessionauth: proof does not verify against the device's current public key")
	ErrSessionNotFound        = errors.New("sessionauth: session not found")
	ErrSessionInvalid         = errors.New("sessionauth: session_token is unknown, expired, or revoked")

	errAuditNotConfigured = errors.New("sessionauth: no AuditEmitter configured")
)
