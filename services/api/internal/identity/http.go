package identity

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Mount attaches this capability's HTTP surface to r, under whatever path
// prefix the caller chooses to mount it at (e.g. r.Route("/v1/identity",
// identity.Mount(svc))). Per this capability's brief, main.go is never
// touched directly by this package — the Chief Architect wires this
// function into services/api/main.go once Identity, Permissions, and
// Audit have all landed.
//
// Route shapes mirror the six IdentityService RPCs one-for-one; request/
// response JSON bodies use the camelCase field names in types.go, matching
// protojson's default output so this surface will not need to change
// shape once real buf-generated codegen replaces the hand-written mirror.
func Mount(svc *Service) http.Handler {
	r := chi.NewRouter()

	r.Post("/", func(w http.ResponseWriter, r *http.Request) {
		var req CreateIdentityRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		resp, err := svc.CreateIdentity(req)
		writeResult(w, resp, err)
	})

	r.Post("/{identityRef}/devices", func(w http.ResponseWriter, r *http.Request) {
		var req BindDeviceRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		req.IdentityRef = chi.URLParam(r, "identityRef")
		resp, err := svc.BindDevice(req)
		writeResult(w, resp, err)
	})

	r.Delete("/{identityRef}/devices/{deviceId}", func(w http.ResponseWriter, r *http.Request) {
		req := RevokeDeviceRequest{
			IdentityRef: chi.URLParam(r, "identityRef"),
			DeviceID:    chi.URLParam(r, "deviceId"),
		}
		resp, err := svc.RevokeDevice(req)
		writeResult(w, resp, err)
	})

	r.Get("/{identityRef}", func(w http.ResponseWriter, r *http.Request) {
		req := ResolveIdentityRequest{IdentityRef: chi.URLParam(r, "identityRef")}
		resp, err := svc.ResolveIdentity(req)
		writeResult(w, resp, err)
	})

	r.Get("/{identityRef}/devices", func(w http.ResponseWriter, r *http.Request) {
		req := ListDevicesRequest{IdentityRef: chi.URLParam(r, "identityRef")}
		resp, err := svc.ListDevices(req)
		writeResult(w, resp, err)
	})

	r.Get("/{identityRef}/export", func(w http.ResponseWriter, r *http.Request) {
		req := ExportIdentityRequest{IdentityRef: chi.URLParam(r, "identityRef")}
		resp, err := svc.ExportIdentity(req)
		writeResult(w, resp, err)
	})

	return r
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil {
		writeError(w, http.StatusBadRequest, ErrInvalidArgument)
		return false
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func writeResult(w http.ResponseWriter, resp any, err error) {
	if err != nil {
		writeError(w, statusForError(err), err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func statusForError(err error) int {
	switch {
	case errors.Is(err, ErrInvalidArgument):
		return http.StatusBadRequest
	case errors.Is(err, ErrIdentityNotFound), errors.Is(err, ErrDeviceNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrDuplicateDeviceKey):
		return http.StatusConflict
	case errors.Is(err, ErrInvalidSignature):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}
