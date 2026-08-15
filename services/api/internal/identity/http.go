package identity

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Mount attaches this capability's HTTP surface to r. requireCallerMatchesIdentity
// is applied only to routes that expose or mutate data scoped to a specific
// identity with no other authorization mechanism of their own (RevokeDevice,
// ListDevices, ExportIdentity) — CreateIdentity, BindDevice, and ResolveIdentity
// stay unwrapped by design (bootstrapping, signature-based authorization already
// enforced inside BindDevice, and an intentionally public lookup, respectively).
// The middleware itself is constructed by whoever wires this capability together
// with Session/Request Authentication in main.go — this package has no
// dependency on that capability and knows nothing about sessions; it only
// calls whatever opaque http.Handler-wrapping function it's given.
//
// Route shapes mirror the six IdentityService RPCs one-for-one; request/
// response JSON bodies use the camelCase field names in types.go, matching
// protojson's default output so this surface will not need to change
// shape once real buf-generated codegen replaces the hand-written mirror.
func Mount(svc *Service, requireCallerMatchesIdentity func(http.Handler) http.Handler) http.Handler {
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

	r.With(requireCallerMatchesIdentity).Delete("/{identityRef}/devices/{deviceId}", func(w http.ResponseWriter, r *http.Request) {
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

	r.With(requireCallerMatchesIdentity).Get("/{identityRef}/devices", func(w http.ResponseWriter, r *http.Request) {
		req := ListDevicesRequest{IdentityRef: chi.URLParam(r, "identityRef")}
		resp, err := svc.ListDevices(req)
		writeResult(w, resp, err)
	})

	r.With(requireCallerMatchesIdentity).Get("/{identityRef}/export", func(w http.ResponseWriter, r *http.Request) {
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
