package audit

import (
	"errors"
	"strings"
	"testing"
)

// allowChecker grants ActionQueryOther for a specific (subject, resourceID)
// pair and denies everything else — used to test the "permitted"
// cross-subject path without granting blanket access.
type allowChecker struct {
	allowSubject string
	allowTarget  string
}

func (c allowChecker) CheckPermission(subject, action string, resource ResourceRef) (bool, error) {
	if action != ActionQueryOther {
		return false, nil
	}
	return subject == c.allowSubject && resource.ResourceID == c.allowTarget, nil
}

func TestService_EmitThenQueryOwnTrail(t *testing.T) {
	svc := NewService(NewInMemoryStore(), nil)

	id, err := svc.Emit("identity:alice", "file.viewed", ResourceRef{ResourceType: "file", ResourceID: "f1"}, "permissions.owner_access", map[string]string{"note": "first view"})
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty event id")
	}

	events, err := svc.Query("identity:alice", QueryFilter{})
	if err != nil {
		t.Fatalf("query own trail: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].EventID != id {
		t.Fatalf("expected event id %q, got %q", id, events[0].EventID)
	}
}

func TestService_Emit_RequiresActorAndAction(t *testing.T) {
	svc := NewService(NewInMemoryStore(), nil)
	if _, err := svc.Emit("", "file.viewed", ResourceRef{}, "", nil); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("expected ErrInvalidEvent for empty actor, got %v", err)
	}
	if _, err := svc.Emit("identity:alice", "", ResourceRef{}, "", nil); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("expected ErrInvalidEvent for empty action, got %v", err)
	}
}

func TestService_Emit_RejectsOversizedMetadata(t *testing.T) {
	svc := NewService(NewInMemoryStore(), nil)
	big := strings.Repeat("x", maxMetadataValLength+1)
	if _, err := svc.Emit("identity:alice", "file.viewed", ResourceRef{}, "", map[string]string{"k": big}); !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("expected ErrMetadataTooLarge, got %v", err)
	}
}

func TestService_Query_CrossSubjectDeniedByDefault(t *testing.T) {
	// No checker supplied -> denyAllChecker, the fail-closed default.
	svc := NewService(NewInMemoryStore(), nil)
	if _, err := svc.Emit("identity:alice", "file.viewed", ResourceRef{ResourceType: "file", ResourceID: "f1"}, "", nil); err != nil {
		t.Fatalf("emit: %v", err)
	}

	_, err := svc.Query("identity:bob", QueryFilter{Subject: "identity:alice"})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied for cross-subject query with no checker wired, got %v", err)
	}
}

func TestService_Query_CrossSubjectAllowedWhenPermitted(t *testing.T) {
	checker := allowChecker{allowSubject: "identity:bob", allowTarget: "identity:alice"}
	svc := NewService(NewInMemoryStore(), checker)
	if _, err := svc.Emit("identity:alice", "file.viewed", ResourceRef{ResourceType: "file", ResourceID: "f1"}, "", nil); err != nil {
		t.Fatalf("emit: %v", err)
	}

	events, err := svc.Query("identity:bob", QueryFilter{Subject: "identity:alice"})
	if err != nil {
		t.Fatalf("expected permitted cross-subject query to succeed, got %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// A different, non-permitted target is still denied even with the
	// same checker wired in — proves the grant is scoped, not "anyone bob
	// asks about."
	if _, err := svc.Emit("identity:carol", "file.viewed", ResourceRef{ResourceType: "file", ResourceID: "f2"}, "", nil); err != nil {
		t.Fatalf("emit: %v", err)
	}
	_, err = svc.Query("identity:bob", QueryFilter{Subject: "identity:carol"})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied for non-permitted target, got %v", err)
	}
}

func TestService_Query_RequiresCallerIdentity(t *testing.T) {
	svc := NewService(NewInMemoryStore(), nil)
	if _, err := svc.Query("", QueryFilter{}); !errors.Is(err, ErrMissingCaller) {
		t.Fatalf("expected ErrMissingCaller, got %v", err)
	}
}

func TestService_Explain_SynthesizesFromEventFields(t *testing.T) {
	svc := NewService(NewInMemoryStore(), nil)
	id, err := svc.Emit("identity:alice", "permissions.grant_changed", ResourceRef{ResourceType: "file", ResourceID: "f1"}, "permissions.share_grant", map[string]string{"grantee": "identity:bob"})
	if err != nil {
		t.Fatalf("emit: %v", err)
	}

	rationale, err := svc.Explain("identity:alice", id)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	for _, want := range []string{"identity:alice", "permissions.grant_changed", "file", "f1", "permissions.share_grant", "grantee=identity:bob"} {
		if !strings.Contains(rationale, want) {
			t.Fatalf("expected rationale to contain %q, got: %s", want, rationale)
		}
	}
}

func TestService_Explain_NotFound(t *testing.T) {
	svc := NewService(NewInMemoryStore(), nil)
	if _, err := svc.Explain("identity:alice", "nonexistent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestService_Explain_CrossSubjectDeniedByDefault(t *testing.T) {
	svc := NewService(NewInMemoryStore(), nil)
	id, err := svc.Emit("identity:alice", "file.viewed", ResourceRef{ResourceType: "file", ResourceID: "f1"}, "", nil)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if _, err := svc.Explain("identity:bob", id); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestService_ExportAuditTrail_SelfAndDenied(t *testing.T) {
	svc := NewService(NewInMemoryStore(), nil)
	if _, err := svc.Emit("identity:alice", "file.viewed", ResourceRef{ResourceType: "file", ResourceID: "f1"}, "", nil); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if _, err := svc.Emit("identity:alice", "file.shared", ResourceRef{ResourceType: "file", ResourceID: "f1"}, "", nil); err != nil {
		t.Fatalf("emit: %v", err)
	}

	bundle, err := svc.ExportAuditTrail("identity:alice", "identity:alice")
	if err != nil {
		t.Fatalf("export own trail: %v", err)
	}
	if bundle.FormatVersion != ExportFormatVersion {
		t.Fatalf("expected format version %q, got %q", ExportFormatVersion, bundle.FormatVersion)
	}
	if len(bundle.Events) != 2 {
		t.Fatalf("expected 2 events in bundle, got %d", len(bundle.Events))
	}
	if err := VerifyIntegrity(exportedToAuditEvents(bundle.Events)); err != nil {
		t.Fatalf("expected exported bundle's chain to verify clean, got %v", err)
	}

	if _, err := svc.ExportAuditTrail("identity:bob", "identity:alice"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied for cross-subject export, got %v", err)
	}
}

// exportedToAuditEvents converts export records back to AuditEvent so the
// existing VerifyIntegrity helper can be reused against exported data —
// proving the export bundle itself carries everything needed to
// independently verify the chain, per the "genuinely usable outside this
// module" bar.
func exportedToAuditEvents(records []ExportedEvent) []AuditEvent {
	out := make([]AuditEvent, len(records))
	for i, r := range records {
		out[i] = AuditEvent{
			EventID:        r.EventID,
			PrevHash:       r.PrevHash,
			Actor:          r.Actor,
			Action:         r.Action,
			Resource:       r.Resource,
			RuleReference:  r.RuleReference,
			Metadata:       r.Metadata,
			OccurredAtUnix: r.OccurredAtUnix,
		}
	}
	return out
}
