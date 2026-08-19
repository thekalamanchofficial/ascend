// Package fileobjects implements the File Objects capability: files as
// first-class citizens — every file carries identity, ownership, versions,
// metadata, history, and lifecycle, never a disposable attachment (Art. 2).
//
// Frozen from docs/capabilities/file-objects.charter.md and
// packages/contracts/proto/ascend/fileobjects/v1/fileobjects.proto. This
// charter took three full guardian re-gate rounds — the resolved design in
// charter §6 is load-bearing and is implemented here exactly, not
// simplified. Read the charter's §6 in full before changing anything in
// this package.
//
// TEMPORARY MIRROR: no protoc-gen-go toolchain output exists for this
// contract yet, same as every other hand-mirrored capability in this build
// (docs/DECISION_LOG.md, 2026-07-16 "Identity, Permissions, Audit /
// Explainability interfaces frozen..."). The types below are a
// hand-written mirror of the frozen .proto messages, field-for-field.
//
// MODULARITY (Art. 10): this package never imports
// services/api/internal/{identity,permissions,audit,storage,sessionauth}
// directly — it depends on Storage, Permissions, and Audit exclusively
// through the small, capability-owned DI interfaces below (StorageClient,
// PermissionsClient, AuditEmitter), satisfied by dependency injection at
// server-composition time (owned by the Chief Architect). This is the same
// discipline Session/Request Authentication applied more strictly than the
// mechanical check requires (internal/audit is check-modularity.sh-exempt,
// but this package still depends on it only via a local interface) — see
// docs/DECISION_LOG.md for this capability's own entry recording the same
// choice.
//
// IDENTITY: like Storage and Permissions, this package treats `owner` and
// `requesting_subject` as opaque identity-reference strings (Identity's
// format, by convention) and never resolves or validates them against
// Identity at runtime — see docs/DECISION_LOG.md, "File Objects: no
// runtime Identity dependency", for why this charter-listed "consumes"
// relationship does not translate into a Go-level dependency, mirroring
// Storage's and Permissions' own real implementations.
package fileobjects

// ResourceRef mirrors Permissions'/Audit's ResourceRef shape by convention
// (same two fields) — this package does not import either directly to get
// it.
type ResourceRef struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

// --- Local, capability-owned dependency-injection interfaces ---
//
// This package never imports services/api/internal/{storage,permissions,
// identity,audit} directly (Art. 10). The Chief Architect wires real
// adapters over storage.Service / permissions.Service / audit.Service
// (Audit exempted from the mechanical check, but still accessed only
// through this narrow interface per this capability's spawn brief) into
// these three interfaces once this package is composed into the running
// binary.

// StorageClient is the local interface this package depends on for content
// storage/retrieval instead of importing internal/storage directly.
// File Objects never routes around Storage's own independent
// CheckPermission gate on resource type "blob" with a synthetic/service
// subject (charter §6, the confused-deputy prohibition Permissions' own
// charter forbids) — every call here passes the true requesting_subject
// straight through.
//
// DeleteBlob is required even though it isn't literally read back by
// GetFileContent/ExportFile: DeleteFileObject's content-unreachability
// guarantee (charter §3, "no longer retrievable is a real guarantee") has
// no other mechanism to call Storage's own DeleteBlob/crypto-shred path.
type StorageClient interface {
	// StoreBlob persists data as a new, opaque blob and returns its
	// blob_ref. owner is the blob's Permissions-level owner-to-be (the
	// file object's real owner — see charter §6 point 3 for why this must
	// never be a non-owner requesting_subject).
	StoreBlob(owner string, data []byte) (blobRef string, err error)

	// RetrieveBlob returns blobRef's bytes, gated by Storage's own
	// independent CheckPermission against resource type "blob"
	// (defense-in-depth per charter §6 points 5-7) — requestingSubject
	// must be the true acting subject, never a synthetic identity.
	RetrieveBlob(blobRef, requestingSubject string) ([]byte, error)

	// DeleteBlob permanently destroys blobRef's content (physical delete
	// or crypto-shred fallback, Storage's own charter-committed
	// guarantee), backing DeleteFileObject's content-unreachability
	// promise.
	DeleteBlob(blobRef, requestingSubject string) error
}

// PermissionGrant is the local, capability-owned mirror of one active
// Permissions grant — just enough shape (Subject/Action/Scope) for this
// package's mirroring logic (charter §6 points 3-4) to walk every
// currently-active grant on a resource without importing
// internal/permissions' own Grant type.
//
// GrantedAtUnix was added 2026-08-18 alongside ListFileAccess (charter §3)
// — previously dropped in translation by services/api/wiring.go's
// fileobjectsPermissionsClientAdapter.ListGrantsForResource, a plumbing gap
// Security Steward named explicitly at the charter gate as required work,
// not something to leave unbacked. CreateVersion's/SetFilePermissions'
// existing mirroring loops (charter §6 points 3-4) ignore this field; only
// ListFileAccess's response projection (below) reads it.
type PermissionGrant struct {
	Subject       string
	Action        string
	Scope         string
	GrantedAtUnix int64
}

// PermissionsClient is the local interface this package depends on for
// every access-control decision instead of importing internal/permissions
// directly. File Objects never decides allow/deny itself anywhere in this
// service (charter §6 point 5) — every allow/deny comes from
// CheckPermission; Grant/RevokePermission calls here are bookkeeping that
// keeps Permissions' own "file_object" and "blob" resource namespaces in
// sync, never a second access-control decision.
type PermissionsClient interface {
	CheckPermission(subject, action, resourceType, resourceID string) (bool, error)
	GrantPermission(grantor, subject, action, resourceType, resourceID, scope string) error
	RevokePermission(grantor, subject, action, resourceType, resourceID string) error
	// DefinePolicy registers resourceType's default policy at this
	// package's own construction (charter §6 point 0) — File Objects
	// registers its own resource type, "file_object"; it never registers
	// "blob" on Storage's behalf (that would be exactly the Art. 10
	// boundary encroachment Constitution Warden's charter-gate finding
	// warned against — Storage owns registering its own resource type).
	DefinePolicy(resourceType, defaultRules string) error
	// ListGrantsForResource answers "who currently has active grants on
	// this resource" — used by CreateVersion's read-mirroring loop
	// (charter §6 point 3), SetFilePermissions' version-mirroring loop
	// (charter §6 point 4), DeleteFileObject's grant-cleanup step, and now
	// ListFileAccess (charter §3, added 2026-08-18), always called with
	// resourceType hardcoded to the literal resourceTypeFileObject constant
	// — never a caller-influenced value — per that RPC's resource-type
	// invariant.
	ListGrantsForResource(resourceType, resourceID string) ([]PermissionGrant, error)
}

// AuditEmitter is the local interface this package depends on for its
// Art. 5 obligation instead of importing internal/audit directly. Field is
// named `audit` at every call site (see service.go) so `s.audit.Emit(`
// satisfies scripts/constitution/check-audit-events.sh's textual match on
// every // ascend:mutates-marked function, matching every prior
// capability's convention in this build.
type AuditEmitter interface {
	Emit(actor, action string, resource ResourceRef, ruleReference string, metadata map[string]string) (eventID string, err error)
}

// --- Permission action / resource-type vocabulary (charter §6 point 1) ---

const (
	// ActionRead gates GetFileContent, ListVersions, GetFileMetadata,
	// GetFileHistory, and ExportFile — one action, one CheckPermission
	// call site (charter §6 point 1).
	ActionRead = "fileobjects.read"
	// ActionWrite gates CreateVersion and SetFileMetadata. This
	// implementation also gates DeleteFileObject on ActionWrite — see
	// docs/DECISION_LOG.md, "File Objects: DeleteFileObject gated by
	// fileobjects.write", for why (the charter defines exactly two
	// actions and forbids inventing a third; write is the closest-fit,
	// already-defined authority for a destructive file-level operation).
	ActionWrite = "fileobjects.write"

	// resourceTypeFileObject is File Objects' single, primary Permissions
	// resource type (charter §6 point 1), keyed by file_object_id.
	resourceTypeFileObject = "file_object"

	// fileObjectDefaultRules is the free-form default_rules string this
	// capability registers for resourceTypeFileObject via
	// PermissionsClient.DefinePolicy at construction (charter §6 point 0).
	// Mirrors Storage's own blobDefaultRules convention exactly — a
	// human-readable statement of intent (deny by default; the resource's
	// owner, via Permissions' bootstrap-owner mechanism, always has
	// access; explicit grants extend access beyond the owner), not a
	// string Permissions parses/evaluates in this implementation wave.
	fileObjectDefaultRules = "deny_by_default_owner_and_explicit_grant_only"

	// resourceTypeBlob/storageRetrieveBlobAction mirror Storage's own
	// resourceTypeBlob/ActionRetrieveBlob constants BY VALUE — this
	// package cannot import internal/storage to reference them directly
	// (Art. 10), so these are documented, convention-matching string
	// literals instead (charter §6 points 2-4 name "blob" /
	// "storage.retrieve_blob" explicitly).
	resourceTypeBlob          = "blob"
	storageRetrieveBlobAction = "storage.retrieve_blob"

	// scopeFull is the scope used for every bootstrap/mirror grant this
	// package establishes on the "blob" namespace on the owner's behalf
	// (charter §6 points 2-3) — the owner's own access is never scope-
	// limited by File Objects' own bookkeeping.
	scopeFull = "full"
)

// --- Persisted records ---
//
// FileObjectRecord is this capability's primary persisted aggregate — the
// // ascend:file-object-marked struct scripts/constitution/
// check-file-objects.sh requires (Art. 2: every file object carries
// identity, owner, and history). Detailed history lives in this package's
// own event log (store.go) and in Audit, not duplicated inline — but
// LastHistoryEventID is the field that cross-references it, satisfying the
// mechanical check's "History" field-name-substring requirement by
// construction (charter §4).
//
// A deleted FileObjectRecord is retained as a tombstone (Deleted=true,
// DeletedAtUnix populated) rather than removed outright — this is what
// keeps GetFileHistory/GetFileMetadata/ListVersions still honestly
// answerable after deletion (charter §3: "the file object's identity and
// history entries remain resolvable... but never the content"), mirroring
// Storage's own BlobRecord tombstone precedent exactly.
//
// ascend:file-object
type FileObjectRecord struct {
	FileObjectID       string
	Owner              string
	CurrentVersionRef  string
	Name               string
	MimeType           string
	Tags               []string
	SizeBytes          int64
	CreatedAtUnix      int64
	Deleted            bool
	DeletedAtUnix      int64
	LastHistoryEventID string
}

func (r FileObjectRecord) toFileObject() FileObject {
	return FileObject{
		FileObjectID:      r.FileObjectID,
		Owner:             r.Owner,
		CurrentVersionRef: r.CurrentVersionRef,
		Name:              r.Name,
		MimeType:          r.MimeType,
		Tags:              append([]string(nil), r.Tags...),
		SizeBytes:         r.SizeBytes,
		CreatedAtUnix:     r.CreatedAtUnix,
	}
}

// VersionRecord is this capability's per-version persisted record. It is a
// genuinely distinct persisted data type from FileObjectRecord (Art. 9
// applies to it independently — see export.go's ExportVersionRecord and
// version_record_export_test.go), so it carries its own
// // ascend:persisted marker rather than being folded into
// FileObjectRecord's own marker (the two markers cannot both be mechanically
// effective on the same struct declaration — see docs/DECISION_LOG.md,
// "File Objects: why FileObjectRecord and VersionRecord carry separate
// Art. 2 / Art. 9 markers").
//
// BlobRef is this record's only field that is NEVER part of any exported
// or returned representation (charter §6 point 8) — see export.go.
//
// ascend:persisted
type VersionRecord struct {
	VersionRef    string
	FileObjectID  string
	BlobRef       string
	CreatedAtUnix int64
	CreatedBy     string
	SizeBytes     int64
}

func (v VersionRecord) toSummary() VersionSummary {
	return VersionSummary{
		VersionRef:    v.VersionRef,
		CreatedAtUnix: v.CreatedAtUnix,
		CreatedBy:     v.CreatedBy,
		SizeBytes:     v.SizeBytes,
	}
}

// FileEvent is this package's own local record of one of its own emitted
// audit events (CreateFileObject/CreateVersion/SetFilePermissions/
// SetFileMetadata/DeleteFileObject) — kept independently of Audit's own
// store so GetFileHistory/ExportFile can answer "full lifecycle history"
// from EXACTLY this package's own emitted events (charter §6 point 8a),
// never a raw aggregation of the Permissions/Storage calls this package
// happens to make internally. Not marked ascend:persisted: it is a
// derived, in-process mirror of events already durably persisted by Audit
// itself (this package's own audit.Emit calls), not an independent source
// of truth requiring its own export path — GetFileHistory/ExportFile ARE
// its export/read paths.
type FileEvent struct {
	EventID        string
	Action         string
	Actor          string
	OccurredAtUnix int64
	Metadata       map[string]string
}

// --- Request/response DTOs, one per RPC in fileobjects.proto ---

type FileObject struct {
	FileObjectID      string
	Owner             string
	CurrentVersionRef string
	Name              string
	MimeType          string
	Tags              []string
	SizeBytes         int64
	CreatedAtUnix     int64
}

type VersionSummary struct {
	VersionRef    string
	CreatedAtUnix int64
	CreatedBy     string
	SizeBytes     int64
}

type CreateFileObjectRequest struct {
	Owner             string
	RequestingSubject string
	InitialContent    []byte
	Name              string
	MimeType          string
}

type CreateFileObjectResponse struct {
	FileObject FileObject
}

type CreateVersionRequest struct {
	FileObjectID      string
	RequestingSubject string
	Content           []byte
}

type CreateVersionResponse struct {
	VersionRef string
}

type GetFileContentRequest struct {
	FileObjectID      string
	RequestingSubject string
	VersionRef        string // optional; empty = current
}

type GetFileContentResponse struct {
	Content []byte
}

type ListVersionsRequest struct {
	FileObjectID      string
	RequestingSubject string
}

type ListVersionsResponse struct {
	Versions []VersionSummary
}

type GetFileHistoryRequest struct {
	FileObjectID      string
	RequestingSubject string
}

type GetFileHistoryResponse struct {
	Events []FileEvent
}

type SetFilePermissionsRequest struct {
	FileObjectID      string
	RequestingSubject string
	Grant             bool // true = grant, false = revoke
	Subject           string
	Action            string // exactly ActionRead or ActionWrite
	Scope             string
}

type SetFilePermissionsResponse struct{}

type GetFileMetadataRequest struct {
	FileObjectID      string
	RequestingSubject string
}

type GetFileMetadataResponse struct {
	Name      string
	MimeType  string
	Tags      []string
	SizeBytes int64
}

type SetFileMetadataRequest struct {
	FileObjectID      string
	RequestingSubject string
	Name              *string
	MimeType          *string
	Tags              []string
}

type SetFileMetadataResponse struct{}

type ExportFileRequest struct {
	FileObjectID      string
	RequestingSubject string
}

type ExportFileResponse struct {
	ExportBlob    []byte
	FormatVersion string
}

type DeleteFileObjectRequest struct {
	FileObjectID      string
	RequestingSubject string
}

type DeleteFileObjectResponse struct{}

// ListFileObjectsRequest/Response back the ListFileObjects RPC (charter §3,
// added 2026-08-18) — a self-only "what do I own" inventory listing,
// deliberately not CheckPermission-gated (mirrors Storage's ExportAllBlobs
// precedent exactly). Owner and RequestingSubject are BOTH request fields,
// but per the charter's corrected authorization discipline neither is ever
// trusted as self-asserted: Service.ListFileObjects rejects unless
// RequestingSubject == Owner, and http.go's handler independently rejects
// unless RequestingSubject == the verified network caller, before Service
// logic ever runs. See docs/DECISION_LOG.md, 2026-08-18, "ListFileObjects:
// Security Steward veto and fix" for why both checks are required.
type ListFileObjectsRequest struct {
	Owner             string
	RequestingSubject string
}

// ListFileObjectsResponse reuses the existing FileObject shape unchanged —
// no BlobRef field exists on it (charter §3: "introduces no new field and
// therefore reopens none of §6 point 8's three closed leak paths").
type ListFileObjectsResponse struct {
	FileObjects []FileObject
}

// ListFileAccessRequest backs the ListFileAccess RPC (charter §3, proposed
// 2026-08-18, frozen after two guardian gate rounds — see
// docs/DECISION_LOG.md, "File Objects contract amendment: ListFileAccess,
// round 1"/"round 2"). Deliberately carries NO Owner field, unlike
// ListFileObjectsRequest above — this is a required, permanent property of
// this request shape (Security Steward gate finding): the service-level
// check resolves the file object's real owner via a server-side lookup of
// FileObjectRecord.Owner for FileObjectID, never from a caller-supplied
// value. Adding an Owner field "for symmetry" with ListFileObjects would
// reopen exactly the self-asserted-owner bypass that RPC was originally
// vetoed for.
type ListFileAccessRequest struct {
	FileObjectID      string
	RequestingSubject string
}

// AccessGrant is ListFileAccess's response shape (charter §3): a transient
// pass-through of Permissions.Grant's already-manifested fields minus
// Grantor and Resource (both always identical on every row — the file's
// owner, and this file, respectively — redundant, not withheld for privacy
// reasons). Never BlobRef — impossible by construction, since
// Service.ListFileAccess always calls PermissionsClient.ListGrantsForResource
// with resourceType hardcoded to the literal "file_object" (charter §3's
// resource-type invariant), which cannot return a "blob"-namespaced grant
// regardless of what a caller supplies. File Objects stores nothing new to
// serve this RPC (Art. 8 closure — no new persisted field, no
// DATA_MANIFEST.md change).
type AccessGrant struct {
	Subject       string
	Action        string
	Scope         string
	GrantedAtUnix int64
}

type ListFileAccessResponse struct {
	Grants []AccessGrant
}
