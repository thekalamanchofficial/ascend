package audit

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// callerHeader is the placeholder source of caller identity for this HTTP
// surface. No session/auth middleware exists yet anywhere in services/api
// (main.go currently only mounts /healthz) — this header stands in for
// "whoever authenticated this request told us they are this identity_ref",
// exactly the way the in-process Go callers already pass callerActor
// explicitly. Documented explicitly as a placeholder, not a real auth
// mechanism: a future pass wiring real session/token auth (likely owned by
// Identity) should replace reading this header with reading a verified
// session claim, without changing Service's method signatures.
const callerHeader = "X-Ascend-Actor"

// Mount attaches this capability's HTTP surface to r, under /v1/audit. This
// is the network-reachable half of Emit (and the other three operations) —
// the in-process `audit.Emit(...)` Go call is what other backend
// capabilities use; this HTTP surface is what a non-Go, out-of-process
// caller uses. Concretely, this is what
// apps/mobile/src/capabilities/crypto/audit.ts's `logAuditEvent` stub is
// waiting for a future integration pass to point at (wiring that stub
// itself is out of scope for this capability — see charter/task framing).
//
// Routes:
//
//	POST   /v1/audit/events                  Emit
//	GET    /v1/audit/events                   Query   (query params: subject, resource_type, resource_id, action, since, until)
//	GET    /v1/audit/events/{eventID}/explain  Explain
//	GET    /v1/audit/export                    ExportAuditTrail (query param: identity_ref)
//
// Every route (except none — all four require a caller identity) reads the
// caller's identity from the X-Ascend-Actor header; Emit uses the request
// body's own `actor` field for the emitted event's actor (that is the
// subject of the mutation being recorded, not necessarily the network
// caller — e.g. a backend service emitting on behalf of a user), but still
// requires the header to be present as a minimal "who is calling this
// endpoint at all" guard.
func Mount(r chi.Router, svc *Service) {
	r.Route("/v1/audit", func(r chi.Router) {
		r.Post("/events", handleEmit(svc))
		r.Get("/events", handleQuery(svc))
		r.Get("/events/{eventID}/explain", handleExplain(svc))
		r.Get("/export", handleExport(svc))
	})
}

type emitRequestDTO struct {
	Actor         string            `json:"actor"`
	Action        string            `json:"action"`
	Resource      ResourceRef       `json:"resource"`
	RuleReference string            `json:"rule_reference"`
	Metadata      map[string]string `json:"metadata"`
}

type emitResponseDTO struct {
	EventID string `json:"event_id"`
}

func handleEmit(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(callerHeader) == "" {
			writeError(w, http.StatusUnauthorized, ErrMissingCaller)
			return
		}
		var req emitRequestDTO
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		eventID, err := svc.Emit(req.Actor, req.Action, req.Resource, req.RuleReference, req.Metadata)
		if err != nil {
			writeError(w, statusForError(err), err)
			return
		}
		writeJSON(w, http.StatusCreated, emitResponseDTO{EventID: eventID})
	}
}

type queryResponseDTO struct {
	Events []AuditEvent `json:"events"`
}

func handleQuery(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller := r.Header.Get(callerHeader)
		if caller == "" {
			writeError(w, http.StatusUnauthorized, ErrMissingCaller)
			return
		}
		q := r.URL.Query()
		filter := QueryFilter{
			Subject:            q.Get("subject"),
			ResourceTypeFilter: q.Get("resource_type"),
			ResourceIDFilter:   q.Get("resource_id"),
			ActionFilter:       q.Get("action"),
			SinceUnix:          parseUnixOrZero(q.Get("since")),
			UntilUnix:          parseUnixOrZero(q.Get("until")),
		}
		events, err := svc.Query(caller, filter)
		if err != nil {
			writeError(w, statusForError(err), err)
			return
		}
		writeJSON(w, http.StatusOK, queryResponseDTO{Events: events})
	}
}

type explainResponseDTO struct {
	HumanReadableRationale string `json:"human_readable_rationale"`
}

func handleExplain(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller := r.Header.Get(callerHeader)
		if caller == "" {
			writeError(w, http.StatusUnauthorized, ErrMissingCaller)
			return
		}
		eventID := chi.URLParam(r, "eventID")
		rationale, err := svc.Explain(caller, eventID)
		if err != nil {
			writeError(w, statusForError(err), err)
			return
		}
		writeJSON(w, http.StatusOK, explainResponseDTO{HumanReadableRationale: rationale})
	}
}

func handleExport(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller := r.Header.Get(callerHeader)
		if caller == "" {
			writeError(w, http.StatusUnauthorized, ErrMissingCaller)
			return
		}
		identityRef := r.URL.Query().Get("identity_ref")
		if identityRef == "" {
			identityRef = caller
		}
		bundle, err := svc.ExportAuditTrail(caller, identityRef)
		if err != nil {
			writeError(w, statusForError(err), err)
			return
		}
		blob, err := MarshalBundle(bundle)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Ascend-Format-Version", bundle.FormatVersion)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(blob)
	}
}

func parseUnixOrZero(s string) int64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func statusForError(err error) int {
	switch {
	case errors.Is(err, ErrMissingCaller):
		return http.StatusUnauthorized
	case errors.Is(err, ErrPermissionDenied):
		return http.StatusForbidden
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrInvalidEvent), errors.Is(err, ErrMetadataTooLarge):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

type errorResponseDTO struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, errorResponseDTO{Error: err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
