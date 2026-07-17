// Package storage implements the Storage capability: a pure blob substrate
// where the user chooses (or is told, with an excellent default) where
// their encrypted data physically lives, with no hidden remote copies.
//
// Frozen from docs/capabilities/storage.charter.md §3 and
// packages/contracts/proto/ascend/storage/v1/storage.proto.
//
// TEMPORARY MIRROR (by choice, not necessity — see docs/DECISION_LOG.md,
// "Storage: hand-mirrored types, not buf-generated"): this capability's
// engineer had the option to implement directly against buf-generated Go
// types (packages/contracts/README.md's updated workflow for
// post-2026-07-16 capabilities) but chose to hand-mirror instead, for the
// reasons recorded in that entry. The types below are a hand-written
// mirror of the frozen .proto messages, field-for-field, and must be kept
// in sync with the .proto if it ever changes.
//
// PLAINTEXT BOUNDARY (charter §3): `data` in StoreBlobRequest is already
// end-to-end encrypted by the caller (via Cryptography & Keys) before it
// ever reaches this package. Storage never observes plaintext, for any
// policy, at any point. Storage does not implement or call any
// end-to-end/content encryption — see wrap.go for the one cryptographic
// primitive this package DOES own, which is a completely different,
// non-end-to-end concern.
//
// MODULARITY (Art. 10): this package never imports
// services/api/internal/identity, services/api/internal/permissions, or
// services/api/internal/audit directly. `owner`/`requesting_subject` are
// opaque identity-reference strings (Identity's format, by convention,
// never validated here). Permission checks and audit emission are done via
// the two small interfaces below, satisfied by dependency injection (see
// NewService) — the Chief Architect wires the real implementations in once
// a Session/Request Authentication capability exists to gate network
// exposure (see docs/DECISION_LOG.md, 2026-07-16 "wave 2" entry, and this
// capability's own charter-spawn brief).
package storage

// ResourceRef identifies the resource a permission check or audit event is
// about. Shape matches Permissions'/Audit's ResourceRef by convention —
// this package does not import either directly to get it.
type ResourceRef struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

// PermissionChecker is the local interface this package depends on instead
// of importing services/api/internal/permissions directly. Satisfied via
// constructor injection (see NewService); the Chief Architect wires the
// real permissions.Service in later behind an adapter matching this exact
// shape (permissions.Service.CheckPermission's own signature takes a
// request/response struct pair — this narrower, capability-owned shape is
// the boundary Storage itself depends on, not permissions' wire shape).
//
// Action-name convention (documented per this capability's spawn brief):
// resourceType is always the literal string "blob"; action is always one
// of the ActionRetrieveBlob / ActionMoveBlob / ActionDeleteBlob constants
// below, mirroring how Permissions' own resource_type/action fields are
// free-form strings each owning capability defines (see
// internal/permissions/types.go's ResourceRef doc comment).
type PermissionChecker interface {
	CheckPermission(subject, action string, resourceType, resourceID string) (bool, error)
}

// AuditEmitter is the local interface this package depends on instead of
// importing services/api/internal/audit directly. Signature matches
// Audit's real Emit method exactly (services/api/internal/audit/service.go)
// so the Chief Architect can wire the real audit.Service in directly,
// unadapted. Field is named `audit` at every call site (see service.go) so
// `s.audit.Emit(` satisfies scripts/constitution/check-audit-events.sh's
// textual match, per this capability's spawn brief.
type AuditEmitter interface {
	Emit(actor, action string, resource ResourceRef, ruleReference string, metadata map[string]string) (eventID string, err error)
}

// --- Permission-check action-name convention (see PermissionChecker doc). ---

const (
	ActionRetrieveBlob = "storage.retrieve_blob"
	ActionMoveBlob     = "storage.move_blob"
	ActionDeleteBlob   = "storage.delete_blob"

	resourceTypeBlob = "blob"
)

// --- Deletion-mechanism values (Art. 15 — must be inspectable, never a
// hidden implementation detail). See docs/DECISION_LOG.md, 2026-07-17
// "Storage interface frozen; crypto-shred fallback resolved..." and
// wrap.go for what "crypto_shred" actually destroys (a Storage-owned
// outer wrapping key, never the end-to-end content key). ---

const (
	DeletionMechanismNone        = ""
	DeletionMechanismPhysical    = "physical_delete"
	DeletionMechanismCryptoShred = "crypto_shred"
)

// BlobRecord is the metadata this capability persists per blob (see
// DATA_MANIFEST.md for the documented purpose of every field). Storage
// never persists or exports the blob's actual bytes as part of this
// struct — only export.go's ExportAllBlobs bundles content, and only for
// blobs that are not (yet) deleted.
//
// A deleted blob's BlobRecord is retained as a tombstone (Deleted=true,
// DeletionMechanism/DeletedAtUnix populated, Location left as the blob's
// last-known-good physical location for historical context) rather than
// removed outright — this is what makes GetStorageLocation's answer for a
// deleted blob still honest and inspectable (Art. 15) instead of a plain
// "not found" that erases the fact a deletion ever happened. The tombstone
// carries no recoverable content — see wrap.go/service.go for why.
//
// ascend:persisted
type BlobRecord struct {
	BlobRef           string `json:"blob_ref"`
	Owner             string `json:"owner"`
	PolicyID          string `json:"policy_id"`
	SizeBytes         int64  `json:"size_bytes"`
	CreatedAtUnix     int64  `json:"created_at_unix"`
	Location          string `json:"location"`
	Deleted           bool   `json:"deleted"`
	DeletedAtUnix     int64  `json:"deleted_at_unix,omitempty"`
	DeletionMechanism string `json:"deletion_mechanism,omitempty"`
}

// Policy pairs a StoragePolicy's public metadata with the concrete Backend
// that currently, genuinely backs it. Only policies that are honestly
// backed by a real, working Backend belong here — see
// docs/DECISION_LOG.md ("Storage: two named local-filesystem policies")
// for why ListStoragePolicies must never advertise a policy this service
// cannot currently honor (charter §5/§6).
type Policy struct {
	ID          string
	DisplayName string
	Description string
	Backend     Backend
}

// --- Request/response types, mirroring storage.proto messages. ---

type StoragePolicy struct {
	PolicyID    string `json:"policy_id"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

type StoreBlobRequest struct {
	Owner    string
	Data     []byte
	PolicyID string
}

type StoreBlobResponse struct {
	BlobRef string
}

type RetrieveBlobRequest struct {
	BlobRef           string
	RequestingSubject string
}

type RetrieveBlobResponse struct {
	Data []byte
}

type MoveBlobRequest struct {
	BlobRef           string
	NewPolicyID       string
	RequestingSubject string
}

type MoveBlobResponse struct {
	NewLocation string
}

type DeleteBlobRequest struct {
	BlobRef           string
	RequestingSubject string
}

type DeleteBlobResponse struct{}

type GetStorageLocationRequest struct {
	BlobRef string
}

type GetStorageLocationResponse struct {
	HumanReadableLocation string
}

type ListStoragePoliciesRequest struct{}

type ListStoragePoliciesResponse struct {
	Policies []StoragePolicy
}

type ExportAllBlobsRequest struct {
	Owner string
}

type ExportAllBlobsResponse struct {
	ExportBlob    []byte
	FormatVersion string
}
