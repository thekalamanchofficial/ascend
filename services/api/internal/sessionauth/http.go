package sessionauth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Mount attaches this capability's HTTP surface to r, under /v1/sessionauth
// (matching audit's Mount(r chi.Router, svc *Service) shape — see
// internal/audit/http.go — rather than identity's
// Mount(svc *Service) http.Handler shape, since this capability's spawn
// brief names the chi.Router-accepting signature explicitly).
//
// Per this capability's brief, services/api/main.go is never touched by
// this package — the Chief Architect wires Mount into the running server
// once this capability (and the standing gate it's a prerequisite for,
// docs/CAPABILITY_REGISTRY.md) is ready to go on a real network path. This
// function existing and being fully tested is the deliverable; calling it
// from main.go is explicitly out of scope for this task.
//
// Routes:
//
//	POST /v1/sessionauth/challenge         GetSessionChallenge
//	POST /v1/sessionauth/sessions          IssueSession
//	POST /v1/sessionauth/sessions/validate ValidateSession
//	POST /v1/sessionauth/sessions/revoke     RevokeSession
//	POST /v1/sessionauth/sessions/revoke-all RevokeAllSessions
//	GET  /v1/sessionauth/sessions/active     ListActiveSessions
//	GET  /v1/sessionauth/sessions/export     ExportSessions
func Mount(r chi.Router, svc *Service) {
	r.Route("/v1/sessionauth", func(r chi.Router) {
		r.Post("/challenge", handleGetSessionChallenge(svc))
		r.Post("/sessions", handleIssueSession(svc))
		r.Post("/sessions/validate", handleValidateSession(svc))
		r.Post("/sessions/revoke", handleRevokeSession(svc))
		r.Post("/sessions/revoke-all", handleRevokeAllSessions(svc))
		r.Get("/sessions/active", handleListActiveSessions(svc))
		r.Get("/sessions/export", handleExportSessions(svc))
	})
}

func handleGetSessionChallenge(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req GetSessionChallengeRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		resp, err := svc.GetSessionChallenge(req)
		writeResult(w, http.StatusOK, resp, err)
	}
}

func handleIssueSession(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req IssueSessionRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		resp, err := svc.IssueSession(req)
		writeResult(w, http.StatusCreated, resp, err)
	}
}

func handleValidateSession(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ValidateSessionRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		// ValidateSession never itself errors for an invalid token — it
		// reports valid:false (charter §3) — so this handler always
		// returns 200 with the response body's `valid` field carrying the
		// answer, never a 4xx/5xx for "just not valid."
		resp, err := svc.ValidateSession(req)
		writeResult(w, http.StatusOK, resp, err)
	}
}

func handleRevokeSession(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RevokeSessionRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		resp, err := svc.RevokeSession(req)
		writeResult(w, http.StatusOK, resp, err)
	}
}

func handleRevokeAllSessions(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RevokeAllSessionsRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		resp, err := svc.RevokeAllSessions(req)
		writeResult(w, http.StatusOK, resp, err)
	}
}

func handleListActiveSessions(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := ListActiveSessionsRequest{CallerSessionToken: bearerToken(r)}
		resp, err := svc.ListActiveSessions(req)
		writeResult(w, http.StatusOK, resp, err)
	}
}

func handleExportSessions(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := ExportSessionsRequest{CallerSessionToken: bearerToken(r)}
		resp, err := svc.ExportSessions(req)
		if err != nil {
			writeError(w, statusForError(err), err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Ascend-Format-Version", resp.FormatVersion)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp.ExportBlob)
	}
}

// bearerToken reads caller_session_token from a standard Authorization:
// Bearer <token> header for the two GET routes (ListActiveSessions,
// ExportSessions), which carry no JSON body. The POST routes instead take
// caller_session_token/session_token as a JSON body field, matching every
// other capability's existing DTO-decoding convention in this codebase.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) > len(prefix) && auth[:len(prefix)] == prefix {
		return auth[len(prefix):]
	}
	return ""
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

func writeResult(w http.ResponseWriter, okStatus int, resp any, err error) {
	if err != nil {
		writeError(w, statusForError(err), err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(okStatus)
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
	case errors.Is(err, ErrInvalidNonce), errors.Is(err, ErrInvalidSignature), errors.Is(err, ErrDeviceNotBound):
		return http.StatusUnauthorized
	case errors.Is(err, ErrSessionNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrSessionInvalid):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}
