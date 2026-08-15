package storage

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
// below to enforce that a caller may only store/retrieve/move/delete/
// locate/export blobs as themselves, never as an arbitrary named identity
// (see docs/DECISION_LOG.md, "Storage and File Objects wiring design").
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

// Mount wires this capability's HTTP surface onto r, under /storage. Every
// handler below additionally requires a verified caller identity (via
// requireCaller) and, where the request names an owner/requesting subject,
// requires that field to equal the verified caller — additive HTTP-edge
// defense-in-depth, in front of each Service method's own
// CheckPermission-based authorization, not a replacement for it. Mount's
// signature is unchanged (no middleware parameter) — the composition root
// applies session-auth middleware externally via r.Group, exactly as it
// already does for Audit. See docs/DECISION_LOG.md, "Storage and File
// Objects wiring design".
func Mount(r chi.Router, svc *Service) {
	r.Route("/storage", func(r chi.Router) {
		r.Post("/blobs", handleStoreBlob(svc))
		r.Post("/blobs/retrieve", handleRetrieveBlob(svc))
		r.Post("/blobs/move", handleMoveBlob(svc))
		r.Post("/blobs/delete", handleDeleteBlob(svc))
		r.Get("/blobs/location", handleGetStorageLocation(svc))
		r.Get("/policies", handleListStoragePolicies(svc))
		r.Get("/export", handleExportAllBlobs(svc))
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
// anything else is a 400 (bad request/validation) by default.
func statusFor(err error) int {
	switch {
	case errors.Is(err, ErrMissingCaller):
		return http.StatusUnauthorized
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, ErrCallerMismatch):
		return http.StatusForbidden
	case errors.Is(err, ErrBlobNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrUnknownPolicy), errors.Is(err, ErrInvalidArgument), errors.Is(err, ErrBlobAlreadyDeleted):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func handleStoreBlob(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req StoreBlobRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// A network caller may only store a blob owned by themselves —
		// mirrors Permissions'/Audit's own-identity-only pattern.
		if req.Owner != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.StoreBlob(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

func handleRetrieveBlob(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req RetrieveBlobRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.RetrieveBlob(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleMoveBlob(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req MoveBlobRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.MoveBlob(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleDeleteBlob(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req DeleteBlobRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.DeleteBlob(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleGetStorageLocation(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		subject := r.URL.Query().Get("requesting_subject")
		// Default to the caller when omitted — deliberately mirrors
		// Audit's ExportAuditTrail default-to-self precedent, not
		// Permissions' stricter no-default precedent. See
		// docs/DECISION_LOG.md, "Storage and File Objects wiring design".
		if subject == "" {
			subject = caller
		}
		if subject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		req := GetStorageLocationRequest{
			BlobRef:           r.URL.Query().Get("blob_ref"),
			RequestingSubject: subject,
		}
		resp, err := svc.GetStorageLocation(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleListStoragePolicies(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireCaller(w, r); !ok {
			return
		}
		resp, err := svc.ListStoragePolicies(ListStoragePoliciesRequest{})
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleExportAllBlobs(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		owner := r.URL.Query().Get("owner")
		// Default to the caller when omitted — same precedent as
		// handleGetStorageLocation above, applied to the owner field
		// instead of requesting_subject.
		if owner == "" {
			owner = caller
		}
		if owner != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		req := ExportAllBlobsRequest{
			Owner:             owner,
			RequestingSubject: r.URL.Query().Get("requesting_subject"),
		}
		resp, err := svc.ExportAllBlobs(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
