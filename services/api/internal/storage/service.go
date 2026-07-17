package storage

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Service implements the seven StorageService RPCs against an in-memory
// Store, a set of currently-honorable Policy backends, an injected
// PermissionChecker, and an injected AuditEmitter.
//
// The `audit` field is deliberately named `audit` (not e.g. `auditClient`
// or `emitter`) so every call site reads as `s.audit.Emit(...)` — this is
// a textual-match requirement, not just a style preference:
// scripts/constitution/check-audit-events.sh greps function bodies for the
// literal substring `audit.Emit(`, and this package does not import
// services/api/internal/audit directly (see AuditEmitter in types.go).
// Documented in docs/DECISION_LOG.md, following Permissions' precedent.
type Service struct {
	store    *Store
	policies map[string]Policy
	order    []string // policy IDs in registration order, for deterministic ListStoragePolicies
	checker  PermissionChecker
	audit    AuditEmitter
	now      func() time.Time
	genRef   func() (string, error)
}

// NewService constructs a Service. policies must be non-empty and every
// entry's Backend must be non-nil — Storage never advertises a policy it
// cannot currently honor (charter §5/§6), so an empty or malformed policy
// set is a construction-time error, not a runtime surprise discovered
// later via ListStoragePolicies.
func NewService(policies []Policy, checker PermissionChecker, audit AuditEmitter) (*Service, error) {
	if len(policies) == 0 {
		return nil, errors.New("storage: at least one storage policy is required")
	}
	if checker == nil {
		return nil, errors.New("storage: a PermissionChecker is required")
	}
	if audit == nil {
		return nil, errors.New("storage: an AuditEmitter is required")
	}

	m := make(map[string]Policy, len(policies))
	order := make([]string, 0, len(policies))
	for _, p := range policies {
		if p.ID == "" || p.Backend == nil {
			return nil, fmt.Errorf("storage: policy %q is missing an ID or a Backend", p.ID)
		}
		if _, dup := m[p.ID]; dup {
			return nil, fmt.Errorf("storage: duplicate policy ID %q", p.ID)
		}
		m[p.ID] = p
		order = append(order, p.ID)
	}

	return &Service{
		store:    NewStore(),
		policies: m,
		order:    order,
		checker:  checker,
		audit:    audit,
		now:      time.Now,
		genRef:   generateBlobRef,
	}, nil
}

func (s *Service) nowUnix() int64 { return s.now().Unix() }

// ListStoragePolicies returns exactly the policies this Service was
// constructed with — every one of them is backed by a real, working
// Backend (enforced in NewService), so this never advertises a location
// choice this instance cannot currently honor.
func (s *Service) ListStoragePolicies(_ ListStoragePoliciesRequest) (ListStoragePoliciesResponse, error) {
	out := make([]StoragePolicy, 0, len(s.order))
	for _, id := range s.order {
		p := s.policies[id]
		out = append(out, StoragePolicy{PolicyID: p.ID, DisplayName: p.DisplayName, Description: p.Description})
	}
	return ListStoragePoliciesResponse{Policies: out}, nil
}

// StoreBlob persists an already-opaque, already-end-to-end-encrypted blob
// under a declared, currently-honorable storage policy, returning an
// opaque blob_ref. It never observes plaintext (charter §3) — req.Data is
// treated as opaque bytes throughout.
//
// ascend:mutates
func (s *Service) StoreBlob(req StoreBlobRequest) (StoreBlobResponse, error) {
	if req.Owner == "" {
		return StoreBlobResponse{}, fmt.Errorf("%w: owner is required", ErrInvalidArgument)
	}
	if len(req.Data) == 0 {
		return StoreBlobResponse{}, fmt.Errorf("%w: data must not be empty", ErrInvalidArgument)
	}
	policy, ok := s.policies[req.PolicyID]
	if !ok {
		return StoreBlobResponse{}, fmt.Errorf("%w: %q", ErrUnknownPolicy, req.PolicyID)
	}

	blobRef, err := s.genRef()
	if err != nil {
		return StoreBlobResponse{}, fmt.Errorf("storage: generating blob_ref: %w", err)
	}

	key, err := generateWrappingKey()
	if err != nil {
		return StoreBlobResponse{}, fmt.Errorf("storage: generating wrapping key: %w", err)
	}

	sealed, err := sealOuterEnvelope(key, req.Data)
	if err != nil {
		return StoreBlobResponse{}, fmt.Errorf("storage: sealing outer envelope: %w", err)
	}

	if err := policy.Backend.Store(blobRef, sealed); err != nil {
		return StoreBlobResponse{}, fmt.Errorf("storage: backend store failed: %w", err)
	}

	record := BlobRecord{
		BlobRef:       blobRef,
		Owner:         req.Owner,
		PolicyID:      req.PolicyID,
		SizeBytes:     int64(len(req.Data)),
		CreatedAtUnix: s.nowUnix(),
		Location:      policy.Backend.Location(blobRef),
	}
	s.store.put(record)
	s.store.putWrappingKey(blobRef, key)

	resource := ResourceRef{ResourceType: resourceTypeBlob, ResourceID: blobRef}
	metadata := map[string]string{
		"policy_id":  req.PolicyID,
		"size_bytes": strconv.FormatInt(record.SizeBytes, 10),
	}

	// blob_ref is the ONLY handle req.Owner will ever receive to this
	// data — unlike Permissions'/Identity's own "audit failed after a
	// mutation already landed" precedent (where the caller already knows
	// conceptually what happened even without a fresh audit record), a
	// failed audit emit here would leave a genuinely undiscoverable,
	// unreachable blob: an Art. 15 hidden-state hazard strictly worse than
	// the cases that precedent tolerates. So StoreBlob rolls the write
	// back rather than reporting success (or a "succeeded but unaudited"
	// partial state) when the audit emit fails. See docs/DECISION_LOG.md.
	if _, err := s.audit.Emit(req.Owner, "storage.store_blob", resource, "owner_requested_store", metadata); err != nil {
		_ = policy.Backend.Delete(blobRef)
		s.store.delete(blobRef)
		s.store.destroyWrappingKey(blobRef)
		return StoreBlobResponse{}, fmt.Errorf("storage: store rolled back, audit emit failed: %w", err)
	}

	return StoreBlobResponse{BlobRef: blobRef}, nil
}

// RetrieveBlob returns a blob's bytes, but only after the requesting
// subject passes a permission check (charter §3: "RetrieveBlob checks
// CheckPermission before returning data"). A denial returns a clear
// error, never data. Not marked ascend:mutates (it does not change
// state), but every attempt — allowed or denied, and the eventual
// disclosure itself — is still audited: who accessed (or was refused)
// which blob is exactly the kind of "important action" Art. 5 requires
// stay discoverable, following Permissions' ExportPermissions and
// Identity's ExportIdentity precedent of auditing a sensitive read even
// though the mechanical check only requires it for ascend:mutates
// functions.
func (s *Service) RetrieveBlob(req RetrieveBlobRequest) (RetrieveBlobResponse, error) {
	if req.BlobRef == "" || req.RequestingSubject == "" {
		return RetrieveBlobResponse{}, fmt.Errorf("%w: blob_ref and requesting_subject are required", ErrInvalidArgument)
	}
	resource := ResourceRef{ResourceType: resourceTypeBlob, ResourceID: req.BlobRef}

	allowed, err := s.checker.CheckPermission(req.RequestingSubject, ActionRetrieveBlob, resource.ResourceType, resource.ResourceID)
	if err != nil {
		return RetrieveBlobResponse{}, fmt.Errorf("storage: permission check failed: %w", err)
	}
	if !allowed {
		_, _ = s.audit.Emit(req.RequestingSubject, "storage.retrieve_blob_denied", resource, "permission_denied", nil)
		return RetrieveBlobResponse{}, ErrPermissionDenied
	}

	record, found := s.store.get(req.BlobRef)
	if !found || record.Deleted {
		_, _ = s.audit.Emit(req.RequestingSubject, "storage.retrieve_blob_failed", resource, "not_found", nil)
		return RetrieveBlobResponse{}, ErrBlobNotFound
	}

	policy, ok := s.policies[record.PolicyID]
	if !ok {
		return RetrieveBlobResponse{}, fmt.Errorf("storage: blob %s references unknown policy %q", req.BlobRef, record.PolicyID)
	}

	sealed, err := policy.Backend.Retrieve(req.BlobRef)
	if err != nil {
		return RetrieveBlobResponse{}, fmt.Errorf("storage: backend retrieve failed: %w", err)
	}
	key, ok := s.store.wrappingKey(req.BlobRef)
	if !ok {
		return RetrieveBlobResponse{}, fmt.Errorf("storage: no wrapping key available for blob %s", req.BlobRef)
	}
	data, err := openOuterEnvelope(key, sealed)
	if err != nil {
		return RetrieveBlobResponse{}, fmt.Errorf("storage: outer envelope failed to open: %w", err)
	}

	// The read already happened by this point (data is in hand) — per
	// Permissions' ExportPermissions/Identity's ExportIdentity precedent,
	// a failed audit emit here must withhold the data rather than return
	// it un-audited, since disclosure is the sensitive event being
	// recorded.
	if _, err := s.audit.Emit(req.RequestingSubject, "storage.retrieve_blob", resource, "permission_check_passed", nil); err != nil {
		return RetrieveBlobResponse{}, fmt.Errorf("storage: blob retrieved but audit emit failed, withholding: %w", err)
	}

	return RetrieveBlobResponse{Data: data}, nil
}

// MoveBlob relocates a blob to a new storage policy: an explicit,
// user-visible action, never a silent background migration (charter §3).
// It is atomic and auditable — no window where both the old and new
// locations hold a copy after this method reports success (charter §6
// "location integrity"): the new copy is written and confirmed BEFORE the
// old copy is removed, and if removing the old copy fails, the new copy
// is rolled back rather than ever reporting success with two live copies.
//
// ascend:mutates
func (s *Service) MoveBlob(req MoveBlobRequest) (MoveBlobResponse, error) {
	if req.BlobRef == "" || req.NewPolicyID == "" || req.RequestingSubject == "" {
		return MoveBlobResponse{}, fmt.Errorf("%w: blob_ref, new_policy_id, and requesting_subject are required", ErrInvalidArgument)
	}
	resource := ResourceRef{ResourceType: resourceTypeBlob, ResourceID: req.BlobRef}

	allowed, err := s.checker.CheckPermission(req.RequestingSubject, ActionMoveBlob, resource.ResourceType, resource.ResourceID)
	if err != nil {
		return MoveBlobResponse{}, fmt.Errorf("storage: permission check failed: %w", err)
	}
	if !allowed {
		_, _ = s.audit.Emit(req.RequestingSubject, "storage.move_blob_denied", resource, "permission_denied", nil)
		return MoveBlobResponse{}, ErrPermissionDenied
	}

	record, found := s.store.get(req.BlobRef)
	if !found || record.Deleted {
		_, _ = s.audit.Emit(req.RequestingSubject, "storage.move_blob_failed", resource, "not_found", nil)
		return MoveBlobResponse{}, ErrBlobNotFound
	}

	newPolicy, ok := s.policies[req.NewPolicyID]
	if !ok {
		return MoveBlobResponse{}, fmt.Errorf("%w: %q", ErrUnknownPolicy, req.NewPolicyID)
	}
	oldPolicy, ok := s.policies[record.PolicyID]
	if !ok {
		return MoveBlobResponse{}, fmt.Errorf("storage: blob %s references unknown policy %q", req.BlobRef, record.PolicyID)
	}

	oldPolicyID := record.PolicyID

	if oldPolicyID == req.NewPolicyID {
		// Nothing to relocate, but MoveBlob was still explicitly invoked —
		// treat as a real, auditable no-op rather than silently
		// succeeding with no record, or erroring on an otherwise valid
		// request.
		newLocation := oldPolicy.Backend.Location(req.BlobRef)
		metadata := map[string]string{"old_policy_id": oldPolicyID, "new_policy_id": req.NewPolicyID, "no_op": "true"}
		if _, err := s.audit.Emit(req.RequestingSubject, "storage.move_blob", resource, "requested_relocation", metadata); err != nil {
			return MoveBlobResponse{}, fmt.Errorf("storage: move (no-op) but audit emit failed: %w", err)
		}
		return MoveBlobResponse{NewLocation: newLocation}, nil
	}

	sealed, err := oldPolicy.Backend.Retrieve(req.BlobRef)
	if err != nil {
		return MoveBlobResponse{}, fmt.Errorf("storage: could not read blob from current location: %w", err)
	}

	if err := newPolicy.Backend.Store(req.BlobRef, sealed); err != nil {
		// New write failed: old copy is untouched. No dual copy, no lost
		// copy.
		return MoveBlobResponse{}, fmt.Errorf("storage: could not write blob to new location, move aborted: %w", err)
	}

	if err := oldPolicy.Backend.Delete(req.BlobRef); err != nil {
		// Both copies now exist — exactly the state charter §6 forbids
		// ever reporting as success. Roll back the new copy so the
		// failure mode is "operation visibly failed, old copy remains the
		// sole copy" rather than "operation silently succeeded with two
		// copies."
		if rollbackErr := newPolicy.Backend.Delete(req.BlobRef); rollbackErr != nil {
			return MoveBlobResponse{}, fmt.Errorf("storage: move failed and rollback of new copy ALSO failed — a duplicate copy may now exist and requires manual intervention: original error %v, rollback error %v", err, rollbackErr)
		}
		return MoveBlobResponse{}, fmt.Errorf("storage: could not remove blob from old location after copying to new location; move aborted and rolled back: %w", err)
	}

	newLocation := newPolicy.Backend.Location(req.BlobRef)
	record.PolicyID = req.NewPolicyID
	record.Location = newLocation
	s.store.put(record)

	metadata := map[string]string{"old_policy_id": oldPolicyID, "new_policy_id": req.NewPolicyID}
	if _, err := s.audit.Emit(req.RequestingSubject, "storage.move_blob", resource, "requested_relocation", metadata); err != nil {
		return MoveBlobResponse{}, fmt.Errorf("storage: blob moved but audit emit failed: %w", err)
	}

	return MoveBlobResponse{NewLocation: newLocation}, nil
}

// DeleteBlob permanently removes a blob: atomic, audited, no residual
// copy surviving under the blob's declared policy (charter §3/§6). The
// primary, preferred mechanism is true physical byte-level erasure
// (Backend.SupportsPhysicalDelete() == true); where a backend cannot
// guarantee that, the crypto-shred fallback destroys this blob's
// Storage-owned outer wrapping key instead (see wrap.go — NOT the
// end-to-end content key, which Storage never holds). Either way, the
// actual mechanism used is recorded on the blob's tombstone record, so it
// stays inspectable later rather than a hidden implementation detail
// (Art. 15).
//
// ascend:mutates
func (s *Service) DeleteBlob(req DeleteBlobRequest) (DeleteBlobResponse, error) {
	if req.BlobRef == "" || req.RequestingSubject == "" {
		return DeleteBlobResponse{}, fmt.Errorf("%w: blob_ref and requesting_subject are required", ErrInvalidArgument)
	}
	resource := ResourceRef{ResourceType: resourceTypeBlob, ResourceID: req.BlobRef}

	allowed, err := s.checker.CheckPermission(req.RequestingSubject, ActionDeleteBlob, resource.ResourceType, resource.ResourceID)
	if err != nil {
		return DeleteBlobResponse{}, fmt.Errorf("storage: permission check failed: %w", err)
	}
	if !allowed {
		_, _ = s.audit.Emit(req.RequestingSubject, "storage.delete_blob_denied", resource, "permission_denied", nil)
		return DeleteBlobResponse{}, ErrPermissionDenied
	}

	record, found := s.store.get(req.BlobRef)
	if !found {
		_, _ = s.audit.Emit(req.RequestingSubject, "storage.delete_blob_failed", resource, "not_found", nil)
		return DeleteBlobResponse{}, ErrBlobNotFound
	}
	if record.Deleted {
		_, _ = s.audit.Emit(req.RequestingSubject, "storage.delete_blob_failed", resource, "already_deleted", nil)
		return DeleteBlobResponse{}, ErrBlobAlreadyDeleted
	}

	policy, ok := s.policies[record.PolicyID]
	if !ok {
		return DeleteBlobResponse{}, fmt.Errorf("storage: blob %s references unknown policy %q", req.BlobRef, record.PolicyID)
	}

	var mechanism string
	if policy.Backend.SupportsPhysicalDelete() {
		if err := policy.Backend.Delete(req.BlobRef); err != nil {
			return DeleteBlobResponse{}, fmt.Errorf("storage: physical delete failed: %w", err)
		}
		// Nothing left to protect — drop the wrapping key too, as
		// housekeeping (Art. 15: no unnecessary retained secret
		// material), though it is not the mechanism of record here.
		s.store.destroyWrappingKey(req.BlobRef)
		mechanism = DeletionMechanismPhysical
	} else {
		if !s.store.destroyWrappingKey(req.BlobRef) {
			return DeleteBlobResponse{}, errors.New("storage: crypto-shred failed: wrapping key already absent")
		}
		// Best-effort physical delete too, even on a backend that doesn't
		// guarantee it — never leave an erasure opportunity unused just
		// because it isn't this backend's guaranteed mechanism.
		_ = policy.Backend.Delete(req.BlobRef)
		mechanism = DeletionMechanismCryptoShred
	}

	record.Deleted = true
	record.DeletedAtUnix = s.nowUnix()
	record.DeletionMechanism = mechanism
	s.store.put(record)

	metadata := map[string]string{"deletion_mechanism": mechanism}
	if _, err := s.audit.Emit(req.RequestingSubject, "storage.delete_blob", resource, "requested_deletion", metadata); err != nil {
		// The deletion itself already happened and is irreversible either
		// way — there is nothing to roll back. Surface the audit failure
		// loudly rather than silently, per Art. 5, but the delete stands.
		return DeleteBlobResponse{}, fmt.Errorf("storage: blob deleted but audit emit failed: %w", err)
	}

	return DeleteBlobResponse{}, nil
}

// GetStorageLocation answers "where does this blob live" for any blob
// that exists, including deleted ones (Art. 15 — no data, and no fact
// about data, should be in an unqueryable location). For a live blob it
// returns the current physical location; for a deleted one it returns a
// description of how and when it was deleted, so the deletion mechanism
// stays inspectable rather than a hidden implementation detail. Not
// marked ascend:mutates (no state change) and not audited per call — high
// call volume expected (any "where's my data" UI polls this), matching
// Permissions' CheckPermission precedent for why per-call auditing of a
// high-volume read is impractical.
func (s *Service) GetStorageLocation(req GetStorageLocationRequest) (GetStorageLocationResponse, error) {
	if req.BlobRef == "" {
		return GetStorageLocationResponse{}, fmt.Errorf("%w: blob_ref is required", ErrInvalidArgument)
	}
	record, found := s.store.get(req.BlobRef)
	if !found {
		return GetStorageLocationResponse{}, ErrBlobNotFound
	}
	if record.Deleted {
		deletedAt := time.Unix(record.DeletedAtUnix, 0).UTC().Format(time.RFC3339)
		return GetStorageLocationResponse{HumanReadableLocation: fmt.Sprintf(
			"deleted via %s at %s (was: %s)", record.DeletionMechanism, deletedAt, record.Location,
		)}, nil
	}
	return GetStorageLocationResponse{HumanReadableLocation: record.Location}, nil
}
