package fileobjects

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// callerHeader is where the composition-root session-auth middleware
// (Chief-Architect-owned, in main.go/wiring.go) makes the network caller's
// verified identity available, after validating the caller's bearer
// session token against the real Session/Request Authentication service.
// This mirrors services/api/internal/audit/http.go's and
// services/api/internal/permissions/http.go's existing callerHeader
// convention exactly — same header name, same "the middleware already
// verified this; we just trust the header" contract at this layer. Used
// below to enforce that a caller may only act as themselves (as
// requesting_subject, or as owner on CreateFileObject), never as an
// arbitrary named identity (see docs/DECISION_LOG.md, "Storage and File
// Objects wiring design").
const callerHeader = "X-Ascend-Actor"

// requireCaller reads and returns the verified caller identity from
// callerHeader, writing a 401 (via ErrMissingCaller) and returning ok=false
// if it is missing/empty — i.e. the composition-root auth middleware never
// ran or the request was never authenticated at all. This is a distinct
// failure mode from "authenticated but not who they claim to be"
// (ErrCallerMismatch, checked separately by each handler below). Mirrors
// services/api/internal/permissions/http.go's requireCaller exactly.
func requireCaller(w http.ResponseWriter, r *http.Request) (string, bool) {
	caller := r.Header.Get(callerHeader)
	if caller == "" {
		writeError(w, http.StatusUnauthorized, ErrMissingCaller)
		return "", false
	}
	return caller, true
}

// Mount wires this capability's HTTP surface onto r, under /file-objects.
// Called from services/api/main.go's newRouter() (docs/DECISION_LOG.md,
// 2026-08-16, "Storage and File Objects network wiring: composition and
// verification") — this package is network-live.
//
// This signature is unchanged (no middleware parameter) — unlike
// Permissions' Mount, which gained one. Composition-root session-auth
// middleware is applied externally, via r.Group, exactly as it already is
// for Audit; every handler below reads callerHeader directly and enforces
// its own caller-identity check as defense-in-depth regardless of what, if
// anything, wraps this router externally.
func Mount(r chi.Router, svc *Service) {
	r.Route("/file-objects", func(r chi.Router) {
		r.Post("/", handleCreateFileObject(svc))
		r.Post("/versions", handleCreateVersion(svc))
		r.Post("/content", handleGetFileContent(svc))
		r.Post("/versions/list", handleListVersions(svc))
		r.Post("/history", handleGetFileHistory(svc))
		r.Post("/permissions", handleSetFilePermissions(svc))
		r.Post("/metadata/get", handleGetFileMetadata(svc))
		r.Post("/metadata/set", handleSetFileMetadata(svc))
		r.Post("/export", handleExportFile(svc))
		r.Post("/delete", handleDeleteFileObject(svc))
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// statusFor maps this package's sentinel errors to HTTP status codes;
// anything else is a 400 (bad request/validation) by default. Errors
// wrapping ErrContentUnavailable/ErrPermissionDenied are matched via
// errors.Is so a "mutation landed but audit failed"-style wrapped error
// still falls through to 500, never masquerading as a clean 4xx.
func statusFor(err error) int {
	switch {
	case errors.Is(err, ErrMissingCaller):
		return http.StatusUnauthorized
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, ErrCallerMismatch):
		return http.StatusForbidden
	case errors.Is(err, ErrFileObjectNotFound), errors.Is(err, ErrVersionNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrInvalidArgument), errors.Is(err, ErrInvalidPermissionAction), errors.Is(err, ErrFileObjectDeleted):
		return http.StatusBadRequest
	case errors.Is(err, ErrContentUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func handleCreateFileObject(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req CreateFileObjectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// A network caller may only act as themselves, and may only create
		// a file object owned by themselves — mirrors Storage's own
		// StoreBlob decision (docs/DECISION_LOG.md, "Storage and File
		// Objects wiring design"): an arbitrary caller must not be able to
		// create a file object owned by someone else.
		if req.RequestingSubject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		if req.Owner != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.CreateFileObject(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

func handleCreateVersion(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req CreateVersionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.CreateVersion(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

func handleGetFileContent(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req GetFileContentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.GetFileContent(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleListVersions(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req ListVersionsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.ListVersions(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleGetFileHistory(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req GetFileHistoryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.GetFileHistory(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleSetFilePermissions(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req SetFilePermissionsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.SetFilePermissions(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleGetFileMetadata(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req GetFileMetadataRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.GetFileMetadata(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleSetFileMetadata(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req SetFileMetadataRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.SetFileMetadata(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleExportFile(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req ExportFileRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.ExportFile(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleDeleteFileObject(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req DeleteFileObjectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.DeleteFileObject(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
