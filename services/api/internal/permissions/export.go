package permissions

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ExportGrant renders a single Grant record as self-describing JSON,
// satisfying Art. 9's per-persisted-type export path requirement for the
// Grant struct (marked ascend:persisted in types.go).
func ExportGrant(g Grant) ([]byte, error) {
	return json.MarshalIndent(g, "", "  ")
}

// ExportHistoryEntry renders a single HistoryEntry record as
// self-describing JSON, satisfying Art. 9's per-persisted-type export
// path requirement for the HistoryEntry struct (marked ascend:persisted
// in types.go).
func ExportHistoryEntry(h HistoryEntry) ([]byte, error) {
	return json.MarshalIndent(h, "", "  ")
}

// exportDocumentFormatVersion is the format_version returned on every
// ExportPermissionsResponse. Bumped whenever exportDocument's shape
// changes in a way a consumer parsing the JSON would need to know about.
const exportDocumentFormatVersion = "ascend-permissions-export-v1"

// exportDocument is the full shape of ExportPermissions' export_blob: an
// identity's complete grant/revoke history plus their currently-effective
// permissions (charter §3: "a user's full grant/revoke history and
// current effective permissions").
type exportDocument struct {
	FormatVersion   string         `json:"format_version"`
	IdentityRef     string         `json:"identity_ref"`
	GeneratedAtUnix int64          `json:"generated_at_unix"`
	ActiveGrants    []Grant        `json:"active_grants"`
	History         []HistoryEntry `json:"history"`
}

// ExportPermissions returns identityRef's full grant/revoke history
// (everywhere identityRef appears as either grantor or subject) and their
// currently-effective active grants, as a versioned JSON blob (Art. 9).
//
// Not marked ascend:mutates (it does not change state) but still emits an
// audit event: disclosing a user's complete permission history is an
// important, sensitive action in its own right (Art. 5 — "nothing
// important happens silently"), even though the mechanical check only
// requires this for state-mutating operations. See docs/DECISION_LOG.md.
func (s *Service) ExportPermissions(req ExportPermissionsRequest) (ExportPermissionsResponse, error) {
	if req.IdentityRef == "" {
		return ExportPermissionsResponse{}, errors.New("identity_ref is required")
	}

	doc := exportDocument{
		FormatVersion:   exportDocumentFormatVersion,
		IdentityRef:     req.IdentityRef,
		GeneratedAtUnix: nowUnix(s),
		ActiveGrants:    s.store.activeGrantsForIdentity(req.IdentityRef),
		History:         s.store.historyForIdentity(req.IdentityRef),
	}
	if doc.ActiveGrants == nil {
		doc.ActiveGrants = []Grant{}
	}
	if doc.History == nil {
		doc.History = []HistoryEntry{}
	}

	blob, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return ExportPermissionsResponse{}, err
	}

	resource := ResourceRef{ResourceType: "permissions_export", ResourceID: req.IdentityRef}

	// Matches Identity's ExportIdentity precedent
	// (services/api/internal/identity/service.go): the export blob has
	// already been produced above, so failing to record that disclosure
	// in the audit trail must surface as a loud error, not a response
	// that quietly hands back the data with no discoverable record of
	// who accessed it.
	if _, err := s.audit.Emit(req.IdentityRef, "permissions.export", resource, "user_requested_export", map[string]string{
		"identity_ref": req.IdentityRef,
	}); err != nil {
		return ExportPermissionsResponse{}, fmt.Errorf("export produced but audit emit failed: %w", err)
	}

	return ExportPermissionsResponse{ExportBlob: blob, FormatVersion: exportDocumentFormatVersion}, nil
}

func nowUnix(s *Service) int64 {
	if s.now != nil {
		return s.now().Unix()
	}
	return time.Now().Unix()
}
