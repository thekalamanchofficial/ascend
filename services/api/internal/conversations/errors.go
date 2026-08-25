package conversations

import "errors"

// Sentinel errors returned by Service methods. http.go maps each to an HTTP
// status code; tests assert against these directly with errors.Is.
var (
	ErrInvalidArgument = errors.New("conversations: invalid argument")

	// ErrPermissionDenied is returned by checkAccess (service.go) for
	// BOTH a nonexistent conversation_id and an existing-but-not-a-
	// participant one — deliberately the SAME sentinel, SAME HTTP status,
	// SAME audit event shape for both cases (charter §3/§6's
	// enumeration-oracle-safe requirement). See checkAccess's own doc
	// comment for why this is automatic by construction, not a
	// separately-maintained branch.
	ErrPermissionDenied = errors.New("conversations: permission denied")

	// ErrMissingCaller indicates this HTTP surface received no verified
	// caller identity at all (the X-Ascend-Actor header was empty/absent)
	// — meaning the composition-root session-auth middleware never ran, or
	// the request was never authenticated. Distinguished (401) from
	// ErrCallerMismatch (403), matching every other capability's existing
	// missing-vs-mismatched-caller convention (e.g.
	// internal/fileobjects/errors.go).
	ErrMissingCaller = errors.New("conversations: missing caller identity")

	// ErrCallerMismatch indicates a verified network caller (from
	// X-Ascend-Actor) named someone else — as creator, sender, or
	// requesting_subject — in a request that requires the caller to act
	// only as themselves. This is the HTTP-layer guard against
	// impersonation; additive to, never a replacement for, Service's own
	// CheckPermission-based authorization. See docs/DECISION_LOG.md and
	// charter §3's blanket caller-identity-binding requirement.
	ErrCallerMismatch = errors.New("conversations: caller does not match the identity named in this request")
)
