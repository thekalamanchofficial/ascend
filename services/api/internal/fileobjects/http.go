package fileobjects

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Mount wires this capability's HTTP surface onto r, under /file-objects.
// The Chief Architect calls this from services/api/main.go — but per this
// capability's spawn brief, it must NOT be called from main.go yet, and
// this package must not be exposed on any reachable network perimeter,
// until the Chief Architect wires it in (standard pattern, matching
// Storage/Permissions/Identity's own withheld-Mount precedent). This
// package is built and tested in full regardless.
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
	case errors.Is(err, ErrPermissionDenied):
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
		var req CreateFileObjectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req CreateVersionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req GetFileContentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req ListVersionsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req GetFileHistoryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req SetFilePermissionsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req GetFileMetadataRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req SetFileMetadataRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req ExportFileRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req DeleteFileObjectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
