package identity

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// callerHeader is where the composition-root session-auth middleware
// (Chief-Architect-owned, in main.go/wiring.go) makes the network caller's
// verified identity available for the one route below that needs a
// verified-but-not-self-scoped caller (FetchPrekeyBundle) — mirrors
// services/api/internal/storage/http.go's and services/api/internal/
// audit/http.go's identical callerHeader convention exactly (same header
// name, same "the middleware already verified this; we just trust the
// header" contract at this layer). Every other route in this package is
// gated (if at all) via requireCallerMatchesIdentity/
// requireCallerMatchesIdentityAndDevice instead, which check a URL path
// param against the verified caller rather than merely reading it — this
// header-read path exists ONLY for FetchPrekeyBundle, the one RPC in this
// capability where the verified caller is used as an audit actor but is
// deliberately NOT required to match anything in the request (charter
// §3/§6 — "any authenticated caller may fetch any identity's bundle").
const callerHeader = "X-Ascend-Actor"

// Mount attaches this capability's HTTP surface to r.
// requireCallerMatchesIdentity is applied only to routes that expose or
// mutate data scoped to a specific identity with no other authorization
// mechanism of their own (RevokeDevice, ListDevices, ExportIdentity) —
// CreateIdentity, BindDevice, and ResolveIdentity stay unwrapped by design
// (bootstrapping, signature-based authorization already enforced inside
// BindDevice, and an intentionally public lookup, respectively).
//
// Amended 2026-08-20 (prekey bundle publish/fetch): two more middleware
// parameters were added, rather than reusing requireCallerMatchesIdentity
// for either new route — see wiring.go's requireCallerMatchesIdentityAndDevice
// doc comment for why PublishPrekeyBundle specifically needs a NEW,
// device-level check that requireCallerMatchesIdentity cannot provide
// (charter §6 — "a capability engineer who reuses requireCallerMatchesIdentity
// unmodified... would correctly bind identity but leave device_id
// completely unchecked").
//
//   - requireCallerMatchesIdentityAndDevice gates PublishPrekeyBundle
//     (POST .../devices/{deviceId}/prekeys): identity_ref AND device_id
//     must both equal the verified caller's own (charter §3/§6/Art. 7).
//   - requireVerifiedCaller gates FetchPrekeyBundle
//     (GET .../prekey-bundle): only requires SOME valid, authenticated
//     session — it does not check identity_ref/device_id against
//     anything, since this RPC is deliberately open to any authenticated
//     caller fetching ANY identity's bundle (charter §3/§6). The verified
//     caller becomes this RPC's Art. 5 audit actor (the fetcher, per
//     charter §4), read from callerHeader by handleFetchPrekeyBundle
//     below — the same header-read pattern Storage's/Audit's own
//     http.go files already use, not a new convention.
//
// These are all composition-root-owned wrapping functions (main.go/
// wiring.go) — this package has no dependency on Session/Request
// Authentication and knows nothing about sessions; it only calls whatever
// opaque http.Handler-wrapping function it's given, or reads whatever
// header that middleware already verified and populated.
//
// Route shapes mirror the eight IdentityService RPCs one-for-one; request/
// response JSON bodies use the camelCase field names in types.go, matching
// protojson's default output so this surface will not need to change
// shape once real buf-generated codegen replaces the hand-written mirror.
func Mount(
	svc *Service,
	requireCallerMatchesIdentity func(http.Handler) http.Handler,
	requireCallerMatchesIdentityAndDevice func(http.Handler) http.Handler,
	requireVerifiedCaller func(http.Handler) http.Handler,
) http.Handler {
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

	// PublishPrekeyBundle (charter §3/§6, amendment gated 2026-08-20):
	// identity_ref/device_id come from the URL path, exactly like
	// RevokeDevice above — requireCallerMatchesIdentityAndDevice checks
	// BOTH against the verified caller before this handler ever runs (see
	// wiring.go). The handler still overwrites req.IdentityRef/DeviceID
	// from the path (not the JSON body) for the same reason BindDevice
	// does — the body's copies of these two fields, if present, are never
	// trusted.
	r.With(requireCallerMatchesIdentityAndDevice).Post("/{identityRef}/devices/{deviceId}/prekeys", func(w http.ResponseWriter, r *http.Request) {
		var req PublishPrekeyBundleRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		req.IdentityRef = chi.URLParam(r, "identityRef")
		req.DeviceID = chi.URLParam(r, "deviceId")
		resp, err := svc.PublishPrekeyBundle(req)
		writeResult(w, resp, err)
	})

	// FetchPrekeyBundle (charter §3/§6, amendment gated 2026-08-20): the
	// one deliberately open, non-self-scoped read this capability exposes
	// — requireVerifiedCaller only requires SOME valid session, never
	// checking identity_ref/device_id against anything (see Mount's own
	// doc comment above). device_id is an optional query parameter,
	// matching FetchPrekeyBundleRequest's proto `optional string
	// device_id` field — omitted entirely (not merely empty) resolves to
	// the identity's most-recently-active bound device (charter §3).
	r.With(requireVerifiedCaller).Get("/{identityRef}/prekey-bundle", func(w http.ResponseWriter, r *http.Request) {
		fetcherActor := r.Header.Get(callerHeader)
		req := FetchPrekeyBundleRequest{
			IdentityRef: chi.URLParam(r, "identityRef"),
			DeviceID:    r.URL.Query().Get("deviceId"),
		}
		resp, err := svc.FetchPrekeyBundle(fetcherActor, req)
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
