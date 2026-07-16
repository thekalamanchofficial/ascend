package audit

import "errors"

var (
	// ErrInvalidEvent is returned by Emit when actor or action is empty —
	// both are required to produce a meaningful, explainable event.
	ErrInvalidEvent = errors.New("audit: actor and action are required")
	// ErrMetadataTooLarge is returned by Emit when metadata exceeds the
	// documented size guard — see validateMetadata in service.go.
	ErrMetadataTooLarge = errors.New("audit: metadata exceeds size limits")
	// ErrPermissionDenied is returned by Query, Explain, and
	// ExportAuditTrail when the caller is not the subject of the events
	// requested and PermissionChecker did not authorize the cross-subject
	// access. Fail-closed default: see PermissionChecker doc.
	ErrPermissionDenied = errors.New("audit: permission denied for cross-subject access")
	// ErrNotFound is returned by Explain when no event exists for the
	// given event_id.
	ErrNotFound = errors.New("audit: event not found")
	// ErrMissingCaller is returned by Query, Explain, and
	// ExportAuditTrail when no caller identity was supplied at all —
	// distinct from ErrPermissionDenied, which means a caller identity
	// was supplied but isn't authorized.
	ErrMissingCaller = errors.New("audit: caller identity is required")
)
