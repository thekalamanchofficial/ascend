package storage

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Mount wires this capability's HTTP surface onto r, under /storage. The
// Chief Architect calls this from services/api/main.go — but per this
// capability's spawn brief and docs/CAPABILITY_REGISTRY.md's standing
// rule (docs/DECISION_LOG.md, 2026-07-16 "wave 2"), Storage's
// RetrieveBlob/MoveBlob/DeleteBlob requests all carry an unauthenticated
// `requesting_subject` field, so Mount must NOT actually be called from
// main.go, and this package must not be exposed on any reachable network
// perimeter, until a chartered Session/Request Authentication capability
// exists to authenticate that field. This package is built and tested in
// full regardless — only the real wiring into the running binary is
// withheld.
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
	case errors.Is(err, ErrPermissionDenied):
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
		var req StoreBlobRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req RetrieveBlobRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req MoveBlobRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req DeleteBlobRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		req := GetStorageLocationRequest{
			BlobRef:           r.URL.Query().Get("blob_ref"),
			RequestingSubject: r.URL.Query().Get("requesting_subject"),
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
		req := ExportAllBlobsRequest{
			Owner:             r.URL.Query().Get("owner"),
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
