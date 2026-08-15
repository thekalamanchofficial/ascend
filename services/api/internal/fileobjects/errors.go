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
)
