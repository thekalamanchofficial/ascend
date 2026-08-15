package fileobjects

import "errors"

// Sentinel errors returned by Service methods. http.go maps each to an
// HTTP status code; tests assert against these directly with errors.Is.
var (
	ErrInvalidArgument         = errors.New("fileobjects: invalid argument")
	ErrFileObjectNotFound      = errors.New("fileobjects: file object not found")
	ErrFileObjectDeleted       = errors.New("fileobjects: file object has been deleted")
	ErrVersionNotFound         = errors.New("fileobjects: version not found")
	ErrPermissionDenied        = errors.New("fileobjects: permission denied")
	ErrInvalidPermissionAction = errors.New(`fileobjects: action must be exactly "fileobjects.read" or "fileobjects.write"`)

	// ErrContentUnavailable is the ONLY error GetFileContent/ExportFile
	// ever return when Storage.RetrieveBlob fails, regardless of the
	// underlying cause (not found, denied, backend failure, ...) — charter
	// §6 point 8(b): Storage's raw error text must never be propagated
	// verbatim, since it could embed a blob_ref. See service.go.
	ErrContentUnavailable = errors.New("fileobjects: content unavailable")

	// ErrMissingCaller indicates this HTTP surface received no verified
	// caller identity at all (the X-Ascend-Actor header was empty/absent)
	// — meaning the composition-root session-auth middleware never ran, or
	// the request was never authenticated. Distinguished (401) from
	// ErrCallerMismatch (403), matching
	// services/api/internal/permissions/errors.go's and
	// services/api/internal/audit/http.go's existing
	// missing-vs-mismatched-caller convention. See docs/DECISION_LOG.md.
	ErrMissingCaller = errors.New("fileobjects: missing caller identity")

	// ErrCallerMismatch indicates a verified network caller (from
	// X-Ascend-Actor) named someone else — as requesting_subject, or as
	// owner on CreateFileObject — in a request that requires the caller to
	// act only as themselves. This is the HTTP-layer guard against the
	// impersonation path where any caller could read/write/export/delete
	// any file object, or create a file object owned by an arbitrary
	// identity, by simply naming someone else in the request body; it is
	// additive to, not a replacement for, Service's own
	// CheckPermission-based authorization. See docs/DECISION_LOG.md.
	ErrCallerMismatch = errors.New("fileobjects: caller does not match the identity named in this request")
)
