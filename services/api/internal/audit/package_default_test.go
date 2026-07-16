package audit

import "testing"

// TestPackageLevelEmit exercises audit.Emit(...) exactly as another
// backend capability would call it — a plain package-qualified function
// call, no Service construction required. This is the literal call the
// mechanical mutating-operation check (see
// scripts/constitution/check-audit-events.sh and its README) greps every
// marked mutating function's body for.
func TestPackageLevelEmit(t *testing.T) {
	// Install a fresh default so this test doesn't depend on / pollute
	// state from other tests in the package.
	original := Default()
	defer SetDefault(original)

	svc := NewService(NewInMemoryStore(), nil)
	SetDefault(svc)

	id, err := Emit("identity:alice", "identity.device_bound", ResourceRef{ResourceType: "device", ResourceID: "d1"}, "identity.bind_device", nil)
	if err != nil {
		t.Fatalf("package-level Emit: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty event id")
	}

	events, err := svc.Query("identity:alice", QueryFilter{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 1 || events[0].EventID != id {
		t.Fatalf("expected the package-level Emit call to be visible via the installed default Service, got %+v", events)
	}
}
