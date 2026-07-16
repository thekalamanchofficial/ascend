package permissions

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Mount wires this capability's HTTP surface onto r, under /permissions.
// The Chief Architect calls this from services/api/main.go once Identity
// and Audit's real implementations are ready to be injected into
// NewService — this package never touches main.go itself (Art. 10 /
// concurrency rules for this implementation wave).
func Mount(r chi.Router, svc *Service) {
	r.Route("/permissions", func(r chi.Router) {
		r.Post("/check", handleCheckPermission(svc))
		r.Post("/grants", handleGrantPermission(svc))
		r.Post("/revoke", handleRevokePermission(svc))
		r.Post("/policies", handleDefinePolicy(svc))
		r.Get("/grants/resource", handleListGrantsForResource(svc))
		r.Get("/grants/subject", handleListGrantsForSubject(svc))
		r.Get("/export", handleExportPermissions(svc))
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
		var req CheckPermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req GrantPermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		var req RevokePermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
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
		req := ListGrantsForSubjectRequest{Subject: r.URL.Query().Get("subject")}
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
		req := ExportPermissionsRequest{IdentityRef: r.URL.Query().Get("identity_ref")}
		resp, err := svc.ExportPermissions(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
