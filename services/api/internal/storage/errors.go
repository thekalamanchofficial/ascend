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
