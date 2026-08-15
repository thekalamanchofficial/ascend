package storage

import "errors"

// Sentinel errors returned by Service methods. http.go maps each to an
// HTTP status code; tests assert against these directly with errors.Is.
var (
	ErrInvalidArgument    = errors.New("storage: invalid argument")
	ErrUnknownPolicy      = errors.New("storage: unknown or currently unavailable storage policy")
	ErrBlobNotFound       = errors.New("storage: blob not found")
	ErrBlobAlreadyDeleted = errors.New("storage: blob already deleted")
	ErrPermissionDenied   = errors.New("storage: permission denied")
)

// ErrMissingCaller indicates this HTTP surface received no verified caller
// identity at all (the X-Ascend-Actor header was empty/absent) — meaning
// the composition-root session-auth middleware never ran, or the request
// was never authenticated. Distinguished (401) from ErrCallerMismatch
// (403), matching services/api/internal/audit/http.go's and
// services/api/internal/permissions/http.go's existing
// missing-vs-mismatched-caller convention. See docs/DECISION_LOG.md.
var ErrMissingCaller = errors.New("storage: missing caller identity")

// ErrCallerMismatch indicates a verified network caller (from
// X-Ascend-Actor) named someone else — as owner or requesting_subject — in
// a request that requires the caller to act only as themselves. This is
// the HTTP-layer guard against the impersonation path where any caller
// could store/retrieve/move/delete/locate/export blobs by simply naming an
// arbitrary identity in the request body or query string; it is additive
// to, not a replacement for, Service's own CheckPermission-based
// authorization. See docs/DECISION_LOG.md.
var ErrCallerMismatch = errors.New("storage: caller does not match the identity named in this request")
