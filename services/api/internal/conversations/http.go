package conversations

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// callerHeader is where the composition-root session-auth middleware
// (Chief-Architect-owned, in main.go/wiring.go) makes the network caller's
// verified identity available. Mirrors
// services/api/internal/fileobjects/http.go's callerHeader convention
// exactly — same header name, same "the middleware already verified this;
// we just trust the header" contract at this layer.
const callerHeader = "X-Ascend-Actor"

// requireCaller reads and returns the verified caller identity from
// callerHeader, writing a 401 (via ErrMissingCaller) and returning ok=false
// if it is missing/empty. Mirrors fileobjects.requireCaller exactly.
func requireCaller(w http.ResponseWriter, r *http.Request) (string, bool) {
	caller := r.Header.Get(callerHeader)
	if caller == "" {
		writeError(w, http.StatusUnauthorized, ErrMissingCaller)
		return "", false
	}
	return caller, true
}

// Mount wires this capability's HTTP surface onto r, under /conversations.
// Called from services/api/main.go's newRouter(). This signature has no
// middleware parameter — composition-root session-auth middleware is
// applied externally via r.Group, exactly as it already is for Audit/
// Storage/File Objects (see main.go); every handler below reads
// callerHeader directly and enforces its own caller-identity check as
// defense-in-depth regardless of what, if anything, wraps this router
// externally.
func Mount(r chi.Router, svc *Service) {
	r.Route("/conversations", func(r chi.Router) {
		r.Post("/", handleCreateConversation(svc))
		r.Post("/messages", handleSendMessage(svc))
		r.Post("/messages/list", handleListMessages(svc))
		r.Post("/list", handleListConversations(svc))
		r.Post("/get", handleGetConversation(svc))
		r.Post("/export", handleExportConversation(svc))
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
// anything else is a 400 (bad request/validation) by default, unless it's
// unrecognized entirely, in which case 500 — mirroring
// fileobjects.statusFor's identical structure and errors.Is-based matching
// (so an error wrapping a sentinel, e.g. "message sent but audit emit
// failed", still maps correctly).
func statusFor(err error) int {
	switch {
	case errors.Is(err, ErrMissingCaller):
		return http.StatusUnauthorized
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, ErrCallerMismatch):
		return http.StatusForbidden
	case errors.Is(err, ErrInvalidArgument):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func handleCreateConversation(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req CreateConversationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// A network caller may only create a conversation they themselves
		// are creator of (charter §3's blanket caller-identity binding) —
		// participant is deliberately NOT checked against caller here: it
		// names the OTHER party, never asserted to be the caller. Not
		// audited on mismatch — CreateConversation isn't one of the four
		// RPCs charter §4 Art. 5 requires a denial audit for (it's a
		// create, not a participant-gated read/write against an existing
		// resource).
		if req.Creator != caller {
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.CreateConversation(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

func handleSendMessage(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req SendMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.Sender != caller {
			// Same shared denial-audit call site as a service-level
			// checkAccess rejection (charter §4 Art. 5's denial-audit
			// requirement applies to SendMessage regardless of which
			// layer rejects it) — mirrors
			// fileobjects.handleListFileAccess's identical HTTP-level
			// audit-on-mismatch discipline.
			svc.auditAccessDenied(caller, req.ConversationID, "SendMessage")
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.SendMessage(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

func handleListMessages(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req ListMessagesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			svc.auditAccessDenied(caller, req.ConversationID, "ListMessages")
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.ListMessages(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// handleListConversations' HTTP-level requesting_subject == caller check
// is the ONLY authorization check this RPC has (Service.ListConversations
// is deliberately not CheckPermission-gated — see its own doc comment) —
// unlike every other handler in this file, there is no service-level
// second check behind this one, since ListConversationsRequest carries no
// separate "owner"-style field to double-check against (unlike
// fileobjects.ListFileObjectsRequest's Owner/RequestingSubject pair).
func handleListConversations(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req ListConversationsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			svc.auditListConversationsDenied(caller, req.RequestingSubject)
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.ListConversations(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleGetConversation(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req GetConversationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			svc.auditAccessDenied(caller, req.ConversationID, "GetConversation")
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.GetConversation(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleExportConversation(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := requireCaller(w, r)
		if !ok {
			return
		}
		var req ExportConversationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.RequestingSubject != caller {
			svc.auditAccessDenied(caller, req.ConversationID, "ExportConversation")
			writeError(w, http.StatusForbidden, ErrCallerMismatch)
			return
		}
		resp, err := svc.ExportConversation(req)
		if err != nil {
			writeError(w, statusFor(err), err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
