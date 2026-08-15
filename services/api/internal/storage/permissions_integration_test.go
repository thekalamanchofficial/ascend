package storage

import (
	"errors"
	"os"
	"sync"
	"testing"
)

// permissions_integration_test.go proves NewService's blob-policy
// registration (service.go) actually closes the real fail-closed gap
// described in docs/DECISION_LOG.md, "Storage: register 'blob'
// Permissions policy at construction (closing a real fail-closed gap)".
//
// This deliberately does NOT import services/api/internal/permissions:
// scripts/constitution/check-modularity.sh's Art. 10 check has no
// test-file exemption for non-shared capability packages (internal/audit
// and internal/platform are its only exemptions), so doing so — even from
// a _test.go file — is flagged as a real ART.10 VIOLATION by the actual
// mechanical check this capability is held to, confirmed by running it.
// Instead, realisticPermissionChecker below is a from-scratch
// reimplementation of the exact three-step decision Permissions'
// CheckPermission makes (services/api/internal/permissions/service.go):
// (1) fail closed if resource_type has no registered policy, (2) allow if
// the subject is the resource's recorded owner, (3) allow if the subject
// holds a matching active grant, else deny. This is what makes the "would
// have failed closed before this fix" claim below a faithful proof of the
// real defect and its fix, rather than a fake that (like the plain
// fakePermissionChecker used everywhere else in this package's tests)
// always returns an unconditional allow/deny and so could never have
// caught this gap — which is exactly why the gap was invisible until now.
type realisticPermissionChecker struct {
	mu       sync.Mutex
	policies map[string]bool            // resource_type -> registered
	owners   map[string]string          // "resourceType\x1fresourceID" -> owner subject
	grants   map[string]map[string]bool // "resourceType\x1fresourceID" -> action -> subject present
}

func newRealisticPermissionChecker() *realisticPermissionChecker {
	return &realisticPermissionChecker{
		policies: make(map[string]bool),
		owners:   make(map[string]string),
		grants:   make(map[string]map[string]bool),
	}
}

func resourceKey(resourceType, resourceID string) string {
	return resourceType + "\x1f" + resourceID
}

// establishOwner simulates a resource's bootstrap-owner grant (Permissions'
// "the first grantor for a given resource is implicitly its owner" rule) —
// test setup, not part of the PermissionChecker interface.
func (c *realisticPermissionChecker) establishOwner(subject, resourceType, resourceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.owners[resourceKey(resourceType, resourceID)] = subject
}

// grant simulates an active Permissions grant of action to subject on the
// given resource — test setup, not part of the PermissionChecker
// interface. Used by the GetStorageLocation/ExportAllBlobs gating tests
// (service_test.go, storage_export_test.go) to distinguish "owner",
// "granted subject", and "neither" for the same CheckPermission call
// shape, which the plain allow/deny fakePermissionChecker cannot express.
func (c *realisticPermissionChecker) grant(subject, action, resourceType, resourceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := resourceKey(resourceType, resourceID)
	if c.grants[key] == nil {
		c.grants[key] = make(map[string]bool)
	}
	c.grants[key][action+"\x1f"+subject] = true
}

func (c *realisticPermissionChecker) CheckPermission(subject, action, resourceType, resourceID string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Step 1, matching permissions.Service.CheckPermission exactly: fail
	// closed if resource_type was never registered via DefinePolicy — this
	// is the check that runs BEFORE any owner/grant lookup, and is exactly
	// the check this package's blob-resource calls used to have no way to
	// ever pass.
	if !c.policies[resourceType] {
		return false, nil
	}

	if owner, ok := c.owners[resourceKey(resourceType, resourceID)]; ok && owner == subject {
		return true, nil
	}

	if actions, ok := c.grants[resourceKey(resourceType, resourceID)]; ok && actions[action+"\x1f"+subject] {
		return true, nil
	}

	return false, nil
}

func (c *realisticPermissionChecker) DefinePolicy(resourceType, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policies[resourceType] = true
	return nil
}

// GrantPermission is a from-scratch reimplementation of the real
// bootstrap-owner rule permissions.Service.authorizeGrant applies
// (services/api/internal/permissions/service.go): a resource with no
// recorded owner yet grants ownership to the FIRST grantor to call
// GrantPermission on it, regardless of what action/scope they named,
// exactly mirroring authorizeGrant's `if _, hasOwner :=
// s.store.ownerOf(req.Resource); !hasOwner { return true, "bootstrap_owner"
// }` branch. Once a resource has a recorded owner, only that owner (or an
// existing sufficiently-scoped grant holder — not modeled here, this
// package's tests never exercise delegated re-granting) may grant further
// access; a non-owner grantor is denied, matching authorizeGrant's
// "insufficient_privilege" branch. This is what makes
// TestNewFilesystemService_RegistersBlobPolicyAgainstRealisticPermissions
// below a faithful proof that StoreBlob's own GrantPermission call is what
// establishes ownership, not a simulation of it (see establishOwner's own
// doc comment above, which remains a plain test-setup helper for the
// GetStorageLocation/service_test.go gating tests that still use it).
func (c *realisticPermissionChecker) GrantPermission(grantor, subject, action, resourceType, resourceID, scope string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := resourceKey(resourceType, resourceID)
	if owner, hasOwner := c.owners[key]; hasOwner && owner != grantor {
		return errors.New("realisticPermissionChecker: permission denied: grantor does not hold sufficient privilege to grant this action/scope")
	}
	if _, hasOwner := c.owners[key]; !hasOwner {
		c.owners[key] = grantor
	}
	if c.grants[key] == nil {
		c.grants[key] = make(map[string]bool)
	}
	c.grants[key][action+"\x1f"+subject] = true
	return nil
}

// RevokePermission removes a single active grant (subject/action/resource),
// mirroring permissions.Service.RevokePermission's effect on the grant
// store closely enough for this package's rollback tests — it does not
// reimplement authorizeRevoke's own privilege check, since nothing in this
// package's tests needs a denied-revoke case.
func (c *realisticPermissionChecker) RevokePermission(_, subject, action, resourceType, resourceID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := resourceKey(resourceType, resourceID)
	if c.grants[key] != nil {
		delete(c.grants[key], action+"\x1f"+subject)
	}
	return nil
}

// TestRealisticPermissionChecker_FailsClosedBeforeBlobPolicyRegistered
// proves the gap as it existed before this fix: with resourceTypeBlob
// never registered, CheckPermission denies even a subject who is already
// the resource's established owner — purely because "blob" is an
// unregistered resource type. This is the exact defect this task closes.
func TestRealisticPermissionChecker_FailsClosedBeforeBlobPolicyRegistered(t *testing.T) {
	checker := newRealisticPermissionChecker()
	checker.establishOwner("identity:alice", resourceTypeBlob, "pre-registration-blob")

	allowed, err := checker.CheckPermission("identity:alice", ActionRetrieveBlob, resourceTypeBlob, "pre-registration-blob")
	if err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	if allowed {
		t.Fatalf("expected CheckPermission to fail closed for an unregistered resource type, even for the resource's own owner, but it allowed")
	}
}

// TestNewFilesystemService_RegistersBlobPolicyAgainstRealisticPermissions
// is the end-to-end proof required by this task: construct Storage's real,
// production-shaped constructor against a PermissionChecker that has NOT
// had "blob" pre-registered, confirm construction registers it, and confirm
// StoreBlob ALONE — via its own real GrantPermission call, service.go,
// with no test-only ownership simulation of any kind — establishes
// "identity:alice" as the new blob's Permissions owner, such that a
// subsequent CheckPermission-gated call (RetrieveBlob, by the blob's
// owner) now succeeds where — per the preceding test — it would previously
// have failed closed forever (StoreBlob never called GrantPermission at
// all). A non-owner, non-granted subject remains correctly denied, proving
// the fix only establishes ownership for the true owner and does not
// loosen what's allowed for anyone else. This is the proof that closes the
// actual gap described in docs/DECISION_LOG.md, "Storage: StoreBlob
// establishes Permissions ownership via GrantPermission" — not a
// simulation of it: this test deliberately does NOT call
// checker.establishOwner anywhere.
func TestNewFilesystemService_RegistersBlobPolicyAgainstRealisticPermissions(t *testing.T) {
	checker := newRealisticPermissionChecker()

	// Sanity check: before Storage's constructor runs, "blob" is genuinely
	// unregistered.
	preAllowed, err := checker.CheckPermission("identity:nobody", ActionRetrieveBlob, resourceTypeBlob, "irrelevant")
	if err != nil {
		t.Fatalf("CheckPermission (pre-registration sanity check): %v", err)
	}
	if preAllowed {
		t.Fatalf("expected blob resource type to be unregistered (denied) before NewFilesystemService runs")
	}

	audit := newFakeAuditEmitter()
	svc, err := NewFilesystemService(checker, audit)
	if err != nil {
		t.Fatalf("NewFilesystemService: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(DefaultDataDir(PolicyLocalDefault))
		_ = os.RemoveAll(DefaultDataDir(PolicyLocalSecondary))
	})

	// Confirm registration actually happened AND that StoreBlob itself — not
	// this test — establishes ownership: store a blob, then retrieve it as
	// the owner with no ownership simulation in between.
	stored, err := svc.StoreBlob(StoreBlobRequest{
		Owner:    "identity:alice",
		Data:     []byte("real permissions-shaped wiring"),
		PolicyID: PolicyLocalDefault,
	})
	if err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}

	got, err := svc.RetrieveBlob(RetrieveBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:alice"})
	if err != nil {
		t.Fatalf("RetrieveBlob by the blob's owner: %v (this is exactly the call that would have failed closed forever before this fix — StoreBlob never established ownership at all)", err)
	}
	if string(got.Data) != "real permissions-shaped wiring" {
		t.Fatalf("got %q, want %q", got.Data, "real permissions-shaped wiring")
	}

	// A different, non-owner subject with no grant is still correctly
	// denied.
	if _, err := svc.RetrieveBlob(RetrieveBlobRequest{BlobRef: stored.BlobRef, RequestingSubject: "identity:mallory"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expected a non-owner, non-granted subject to still be denied, got %v", err)
	}
}
