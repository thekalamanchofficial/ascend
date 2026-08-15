package permissions

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// callerHeader is where the composition-root session-auth middleware
// (Chief-Architect-owned, in main.go/wiring.go) makes the network caller's
// verified identity available, after validating the caller's bearer
// session token against the real Session/Request Authentication service.
// This mirrors services/api/internal/audit/http.go's existing callerHeader
// convention exactly — same header name, same "the middleware already
// verified this; we just trust the header" contract at this layer. Used
// below to enforce that a caller may only grant/revoke/check/list/export
// as themselves, never as an arbitrary named identity (see
// docs/DECISION_LOG.md).
const callerHeader = "X-Ascend-Actor"

// requireCaller reads and returns the verified caller identity from
// callerHeader, writing a 401 (via ErrMissingCaller) and returning ok=false
// if it is missing/empty — i.e. the composition-root auth middleware never
// ran or the request was never authenticated at all. This is a distinct
// failure mode from "authenticated but not who they claim to be"
// (ErrCallerMismatch, checked separately by each handler below).
func requireCaller(w http.ResponseWriter, r *http.Request) (string, bool) {
	caller := r.Header.Get(callerHeader)
	if caller == "" {
		writeError(w, http.StatusUnauthorized, ErrMissingCaller)
		return "", false
	}
	return caller, true
}

// Mount wires this capability's HTTP surface onto r, under /v1/permissions.
// requireVerifiedCaller is the composition-root session-auth middleware
// (constructed in services/api/main.go/wiring.go, Chief-Architect-owned):
// it validates the caller's bearer session token against the real
// Session/Request Authentication service and makes the verified identity
// available via the callerHeader convention above — mirroring the shape
// services/api/internal/identity/http.go's Mount already established for
// its own requireCallerMatchesIdentity parameter. This package has no
// dependency on that capability and knows nothing about sessions; it only
// applies whatever opaque http.Handler-wrapping function it's given, via
// r.With(requireVerifiedCaller), to the five routes below whose handlers
// check the caller's identity against a request field. The per-handler
// requireCaller/header checks in those handlers stay in place as
// defense-in-depth even with this middleware also applied — see the
// handlers themselves.
//
// DefinePolicy ("/policies") and ListGrantsForResource
// ("/grants/resource") are deliberately NOT mounted here at all: neither
// has a legitimate external network caller in this pass (DefinePolicy is
// a capability's own internal bootstrapping call — invoked as a direct Go
// method call, e.g. by Storage's policy registration — and
// ListGrantsForResource's frozen contract has no caller-identity field to
// check at all, tracked separately as a wire-contract amendment). Leaving
// them reachable-but-unauthenticated would defeat the point of excluding
// them, so they are excluded from Mount entirely rather than left
// unguarded; their handler functions (handleDefinePolicy,
// handleListGrantsForResource) are left untouched below for any future
// pass that re-introduces them behind their own contract-appropriate
// guard.
func Mount(r chi.Router, svc *Service, requireVerifiedCaller func(http.Handler) http.Handler) {
	r.Route("/v1/permissions", func(r chi.Router) {
		r.With(requireVerifiedCaller).Post("/check", handleCheckPermission(svc))
		r.With(requireVerifiedCaller).Post("/grants", handleGrantPermission(svc))
		r.With(requireVerifiedCaller).Post("/revoke", handleRevokePermission(svc))
		r.With(requireVerifiedCaller).Get("/grants/subject", handleListGrantsForSubject(svc))
		r.With(requireVerifiedCaller).Get("/export", handleExportPermissions(svc))
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

func handleCheckPermission(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req CheckPermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// A network caller may only check their own permissions — checking
		// "can subject X do Y" for an arbitrary X would be an
		// information-disclosure/enumeration primitive.
		if req.Subject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.CheckPermission(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleGrantPermission(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req GrantPermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// The network caller must be who they claim to be as grantor —
		// additive to, not a replacement for, Service.authorizeGrant's own
		// escalation-rule check below.
		if req.Grantor != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.GrantPermission(req)
		if err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

func handleRevokePermission(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req RevokePermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// The network caller must be who they claim to be as grantor —
		// additive to, not a replacement for, Service.authorizeRevoke's own
		// escalation-rule check below.
		if req.Grantor != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.RevokePermission(req)
		if err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleDefinePolicy(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req DefinePolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		resp, err := svc.DefinePolicy(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleListGrantsForResource(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := ListGrantsForResourceRequest{Resource: ResourceRef{
			ResourceType: r.URL.Query().Get("resource_type"),
			ResourceID:   r.URL.Query().Get("resource_id"),
		}}
		resp, err := svc.ListGrantsForResource(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleListGrantsForSubject(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		subject := r.URL.Query().Get("subject")
		// A caller may only list their own grants — same
		// enumeration-prevention reasoning as CheckPermission's subject
		// check above.
		if subject != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		req := ListGrantsForSubjectRequest{Subject: subject}
		resp, err := svc.ListGrantsForSubject(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleExportPermissions(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		identityRef := r.URL.Query().Get("identity_ref")
		// Export only your own data — matches the pattern already
		// established for Identity/Session Auth/Storage in this build.
		if identityRef != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		req := ExportPermissionsRequest{IdentityRef: identityRef}
		resp, err := svc.ExportPermissions(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
