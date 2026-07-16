package identity

import "errors"

// Sentinel errors returned by Service methods. http.go maps each to an
// HTTP status code; tests assert against these directly with errors.Is.
var (
	ErrInvalidArgument    = errors.New("identity: invalid argument")
	ErrIdentityNotFound   = errors.New("identity: identity not found")
	ErrDeviceNotFound     = errors.New("identity: device not found")
	ErrDuplicateDeviceKey = errors.New("identity: device public key already bound to this identity")
	ErrInvalidSignature   = errors.New("identity: authorization_proof does not verify against any known key for this identity")
	errAuditNotConfigured = errors.New("identity: no AuditEmitter configured")
)
