package identity

import (
	"crypto/ed25519"
	"testing"

	"github.com/ascend/services/api/internal/audit"
)

// audit_integration_test.go proves the real internal/audit.Service can be
// wired into identity.NewService directly, with zero adapter code, now
// that internal/audit exists (it did not when this capability's brief was
// written). *audit.Service's real Emit method has the exact same
// signature as AuditEmitter.Emit because ResourceRef is now a type alias
// to audit.ResourceRef (see audit.go) — this test is the concrete proof,
// not just a comment claiming it works.
func TestRealAuditServiceSatisfiesAuditEmitter(t *testing.T) {
	var _ AuditEmitter = (*audit.Service)(nil) // compile-time assertion

	auditSvc := audit.NewService(audit.NewInMemoryStore(), nil)
	svc := NewService(NewInMemoryStore(), auditSvc)

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate identity key: %v", err)
	}
	devicePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}

	created, err := svc.CreateIdentity(CreateIdentityRequest{
		DisplayName:          "Real Audit Wiring",
		PublicKey:            pub,
		FirstDevicePublicKey: devicePub,
		FirstDeviceName:      "Primary",
	})
	if err != nil {
		t.Fatalf("CreateIdentity with real audit.Service wired in: %v", err)
	}

	events, err := auditSvc.Query(created.PublicIdentity.IdentityRef, audit.QueryFilter{
		Subject: created.PublicIdentity.IdentityRef,
	})
	if err != nil {
		t.Fatalf("Query real audit trail: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Action == "identity.created" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected identity.created to be discoverable via the real Audit capability's own Query; got %+v", events)
	}
}
