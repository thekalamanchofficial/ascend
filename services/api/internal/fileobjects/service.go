package fileobjects

import (
	"fmt"
	"strconv"
	"sync"
	"time"
)

// Service implements the ten FileObjectsService RPCs against an in-memory
// Store and three injected DI seams: StorageClient, PermissionsClient, and
// AuditEmitter (types.go). The `audit` field is deliberately named `audit`
// (not e.g. `auditClient`) so every call site reads as `s.audit.Emit(...)`
// — the literal substring scripts/constitution/check-audit-events.sh
// greps for on every // ascend:mutates-marked function.
type Service struct {
	store   Store
	storage StorageClient
	perms   PermissionsClient
	audit   AuditEmitter

	// mu serializes CreateVersion's grant-mirroring critical section
	// (charter §6 point 3) against SetFilePermissions' grant-mirroring
	// critical section (charter §6 point 4) and against DeleteFileObject's
	// teardown — all three read-then-mutate Permissions' "blob" namespace
	// across possibly-many calls, and interleaving them is exactly the
	// TOCTOU race charter §6 point 8's closing paragraph describes as
	// "real... contained" rather than eliminated. Serializing these
	// specific critical sections in this single Go process closes it
	// further than the charter strictly requires — see
	// docs/DECISION_LOG.md, "File Objects: mutex-serialized mirror
	// critical sections".
	mu sync.Mutex

	now        func() time.Time
	genFileID  func() (string, error)
	genVersion func() (string, error)
}

// NewService constructs a Service and registers "file_object"'s own
// default Permissions policy at construction (charter §6 point 0) —
// File Objects' own resource type, no boundary question. It does NOT
// register "blob"'s policy; that is Storage's own construction-time
// responsibility (see NewService's doc block in
// services/api/internal/storage/service.go, which this capability's
// prerequisite check confirmed is already in place).
//
// store is accepted as the first parameter, mirroring Permissions' own
// NewService(store Store, ...) parameter ordering (internal/permissions/
// service.go) after its identical Store-interface introduction — reading
// "construct this Service against this persistence layer, plus these DI
// seams" left-to-right, store first, matches that precedent rather than
// inventing a new convention.
func NewService(store Store, storage StorageClient, perms PermissionsClient, audit AuditEmitter) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("fileobjects: a Store is required")
	}
	if storage == nil {
		return nil, fmt.Errorf("fileobjects: a StorageClient is required")
	}
	if perms == nil {
		return nil, fmt.Errorf("fileobjects: a PermissionsClient is required")
	}
	if audit == nil {
		return nil, fmt.Errorf("fileobjects: an AuditEmitter is required")
	}
	if err := perms.DefinePolicy(resourceTypeFileObject, fileObjectDefaultRules); err != nil {
		return nil, fmt.Errorf("fileobjects: registering default policy for resource type %q: %w", resourceTypeFileObject, err)
	}

	return &Service{
		store:      store,
		storage:    storage,
		perms:      perms,
		audit:      audit,
		now:        time.Now,
		genFileID:  generateFileObjectID,
		genVersion: generateVersionRef,
	}, nil
}

func (s *Service) nowUnix() int64 { return s.now().Unix() }

// checkRead is the SINGLE shared CheckPermission call site for every read
// RPC (GetFileContent, ListVersions, GetFileMetadata, GetFileHistory,
// ExportFile — charter §6 point 1, §4 Art. 5 obligation). A denial emits
// exactly one shared audit event, "fileobjects.access_denied", naming
// which RPC was attempted, so "someone tried to read a file they don't
// have access to" stays discoverable regardless of which of the five read
// operations triggered it — CheckPermission itself has no audit side
// effect of its own (verified against permissions.Service.CheckPermission),
// so without this, a denied read would be invisible everywhere.
func (s *Service) checkRead(subject, fileObjectID, rpcName string) error {
	if subject == "" || fileObjectID == "" {
		return fmt.Errorf("%w: file_object_id and requesting_subject are required", ErrInvalidArgument)
	}
	allowed, err := s.perms.CheckPermission(subject, ActionRead, resourceTypeFileObject, fileObjectID)
	if err != nil {
		return fmt.Errorf("fileobjects: permission check failed: %w", err)
	}
	if !allowed {
		_, _ = s.audit.Emit(subject, "fileobjects.access_denied",
			ResourceRef{ResourceType: resourceTypeFileObject, ResourceID: fileObjectID},
			"permission_denied",
			map[string]string{"rpc": rpcName})
		return ErrPermissionDenied
	}
	return nil
}

// listDeniedAction is the audit action emitted on every ListFileObjects
// rejection — service-level (requesting_subject != owner) or HTTP-level
// (requesting_subject != verified caller, http.go) — per charter §3/§4's
// broadened denial-auditing requirement (docs/DECISION_LOG.md, 2026-08-18,
// "ListFileObjects: Security Steward veto and fix"). Named "file.list_..."
// rather than "fileobjects...." to match the charter bullet's own literal
// example action name.
const listDeniedAction = "file.list_denied"

// auditListDenied is ListFileObjects' single shared denial-audit call
// site — deliberately callable from both this file (the service-level
// requesting_subject/owner mismatch) and http.go (the HTTP-level
// caller/requesting_subject mismatch), same package, so both rejection
// reasons funnel through identical audit vocabulary (mirrors checkRead's
// "one shared call site" discipline above). resource is always
// ("identity", owner) — naming whose inventory was targeted, never a
// file_object_id (charter §3: this is an account-level enumeration
// attempt, not a single-file access attempt).
func (s *Service) auditListDenied(actor, owner string) {
	_, _ = s.audit.Emit(actor, listDeniedAction,
		ResourceRef{ResourceType: "identity", ResourceID: owner},
		"requesting_subject_mismatch", nil)
}

// ListFileObjects returns every FileObject owner has ever created —
// deliberately NOT CheckPermission-gated (charter §3, mirroring Storage's
// ExportAllBlobs precedent exactly): this is a self-only,
// right-to-see-your-own-stuff inventory listing, not a shareable read.
// Tombstoned (deleted) file objects are excluded — a "my files" listing
// should show what a caller actually still has, not entries whose content
// has already been irreversibly destroyed; GetFileHistory remains reachable
// for a deleted file object if its file_object_id is already known by other
// means (charter §3's own precedent for what stays resolvable post-delete).
//
// AUTHORIZATION (charter §3, corrected 2026-08-18 after Security Steward's
// veto of the original draft — see docs/DECISION_LOG.md): this
// requesting_subject == owner check is only ONE of two independent checks
// required to actually close the authorization bypass caught at charter
// stage. The second, EQUALLY REQUIRED check — requesting_subject == the
// verified network caller — lives in http.go's handler and runs BEFORE this
// method is ever called. Neither check alone is sufficient: this check
// alone (as the charter's first draft specified) trusts both Owner and
// RequestingSubject as self-asserted request fields, binding neither to who
// is actually, verifiably making the call — a caller could send
// owner=requesting_subject=<victim> and this check alone would pass.
func (s *Service) ListFileObjects(req ListFileObjectsRequest) (ListFileObjectsResponse, error) {
	if req.Owner == "" || req.RequestingSubject == "" {
		return ListFileObjectsResponse{}, fmt.Errorf("%w: owner and requesting_subject are required", ErrInvalidArgument)
	}
	if req.RequestingSubject != req.Owner {
		s.auditListDenied(req.RequestingSubject, req.Owner)
		return ListFileObjectsResponse{}, ErrPermissionDenied
	}

	records := s.store.listFileObjectsByOwner(req.Owner)
	out := make([]FileObject, 0, len(records))
	for _, r := range records {
		if r.Deleted {
			continue
		}
		out = append(out, r.toFileObject())
	}
	return ListFileObjectsResponse{FileObjects: out}, nil
}

// CreateFileObject allocates identity, stores version 1's content, and
// bootstraps both Permissions resource namespaces this capability owns
// (charter §6 point 2): the owner's first grant on
// ("file_object", file_object_id) — bootstrapping ownership per
// Permissions' own first-grantor rule — plus fileobjects.write, plus a
// matching "storage.retrieve_blob" grant on ("blob", blob_ref) for the
// version-1 blob. file_object_id is the only handle the caller will ever
// receive to this resource (mirroring Storage's own StoreBlob precedent
// exactly), so any failure after the blob is stored rolls the whole
// operation back rather than leaving an unreachable, ungoverned resource —
// an Art. 15 hidden-state hazard.
//
// ascend:mutates
func (s *Service) CreateFileObject(req CreateFileObjectRequest) (CreateFileObjectResponse, error) {
	if req.Owner == "" || req.RequestingSubject == "" {
		return CreateFileObjectResponse{}, fmt.Errorf("%w: owner and requesting_subject are required", ErrInvalidArgument)
	}
	if len(req.InitialContent) == 0 {
		return CreateFileObjectResponse{}, fmt.Errorf("%w: initial_content must not be empty", ErrInvalidArgument)
	}

	blobRef, err := s.storage.StoreBlob(req.Owner, req.InitialContent)
	if err != nil {
		return CreateFileObjectResponse{}, fmt.Errorf("fileobjects: storing initial content failed: %w", err)
	}

	rollbackBlob := func() { _ = s.storage.DeleteBlob(blobRef, req.Owner) }

	fileObjectID, err := s.genFileID()
	if err != nil {
		rollbackBlob()
		return CreateFileObjectResponse{}, fmt.Errorf("fileobjects: generating file_object_id: %w", err)
	}
	versionRef, err := s.genVersion()
	if err != nil {
		rollbackBlob()
		return CreateFileObjectResponse{}, fmt.Errorf("fileobjects: generating version_ref: %w", err)
	}

	// Bootstrap grants (charter §6 point 2). The owner's first-ever grant
	// on the new "file_object" resource makes them its implicit owner
	// (Permissions' own bootstrap rule) — order between read/write/blob
	// grants doesn't carry the same hazard CreateVersion's mirroring does
	// (charter §6 point 3), because every one of these three calls has the
	// SAME grantor/subject (the owner) and is the resource's first-ever
	// grant regardless of order.
	if err := s.perms.GrantPermission(req.Owner, req.Owner, ActionRead, resourceTypeFileObject, fileObjectID, scopeFull); err != nil {
		rollbackBlob()
		return CreateFileObjectResponse{}, fmt.Errorf("fileobjects: bootstrapping owner read grant failed: %w", err)
	}
	if err := s.perms.GrantPermission(req.Owner, req.Owner, ActionWrite, resourceTypeFileObject, fileObjectID, scopeFull); err != nil {
		rollbackBlob()
		_ = s.perms.RevokePermission(req.Owner, req.Owner, ActionRead, resourceTypeFileObject, fileObjectID)
		return CreateFileObjectResponse{}, fmt.Errorf("fileobjects: bootstrapping owner write grant failed: %w", err)
	}
	if err := s.perms.GrantPermission(req.Owner, req.Owner, storageRetrieveBlobAction, resourceTypeBlob, blobRef, scopeFull); err != nil {
		rollbackBlob()
		_ = s.perms.RevokePermission(req.Owner, req.Owner, ActionRead, resourceTypeFileObject, fileObjectID)
		_ = s.perms.RevokePermission(req.Owner, req.Owner, ActionWrite, resourceTypeFileObject, fileObjectID)
		return CreateFileObjectResponse{}, fmt.Errorf("fileobjects: bootstrapping owner blob-retrieve grant failed: %w", err)
	}

	now := s.nowUnix()
	rec := FileObjectRecord{
		FileObjectID:      fileObjectID,
		Owner:             req.Owner,
		CurrentVersionRef: versionRef,
		Name:              req.Name,
		MimeType:          req.MimeType,
		SizeBytes:         int64(len(req.InitialContent)),
		CreatedAtUnix:     now,
	}
	version := VersionRecord{
		VersionRef:    versionRef,
		FileObjectID:  fileObjectID,
		BlobRef:       blobRef,
		CreatedAtUnix: now,
		CreatedBy:     req.RequestingSubject,
		SizeBytes:     int64(len(req.InitialContent)),
	}

	metadata := map[string]string{
		"version_ref": versionRef,
		"name":        req.Name,
		"mime_type":   req.MimeType,
		"size_bytes":  strconv.FormatInt(rec.SizeBytes, 10),
	}
	eventID, err := s.audit.Emit(req.RequestingSubject, "fileobjects.create_file_object",
		ResourceRef{ResourceType: resourceTypeFileObject, ResourceID: fileObjectID}, "owner_requested_create", metadata)
	if err != nil {
		// file_object_id is the only handle the caller will ever get —
		// same reachability hazard as Storage's own StoreBlob, so roll
		// back rather than report success/partial-success.
		rollbackBlob()
		_ = s.perms.RevokePermission(req.Owner, req.Owner, ActionRead, resourceTypeFileObject, fileObjectID)
		_ = s.perms.RevokePermission(req.Owner, req.Owner, ActionWrite, resourceTypeFileObject, fileObjectID)
		_ = s.perms.RevokePermission(req.Owner, req.Owner, storageRetrieveBlobAction, resourceTypeBlob, blobRef)
		return CreateFileObjectResponse{}, fmt.Errorf("fileobjects: create rolled back, audit emit failed: %w", err)
	}
	rec.LastHistoryEventID = eventID

	s.store.putFileObject(rec)
	s.store.addVersion(fileObjectID, version)
	s.store.addEvent(fileObjectID, FileEvent{EventID: eventID, Action: "fileobjects.create_file_object", Actor: req.RequestingSubject, OccurredAtUnix: now, Metadata: metadata})

	return CreateFileObjectResponse{FileObject: rec.toFileObject()}, nil
}

// CreateVersion creates a brand-new blob and version, never overwriting an
// existing one. Charter §6 point 3 (the most important correctness
// requirement in this charter): the new blob has no Permissions owner yet,
// so the file object's ACTUAL owner (from the FileObjectRecord, never
// requesting_subject) must receive the first-ever GrantPermission call on
// it, unconditionally, before mirroring any other subject's grant — or a
// non-owner collaborator calling this RPC could become the new blob's
// permanent, unrevocable Permissions-owner via bootstrap_owner semantics.
//
// ascend:mutates
func (s *Service) CreateVersion(req CreateVersionRequest) (CreateVersionResponse, error) {
	if req.FileObjectID == "" || req.RequestingSubject == "" {
		return CreateVersionResponse{}, fmt.Errorf("%w: file_object_id and requesting_subject are required", ErrInvalidArgument)
	}
	if len(req.Content) == 0 {
		return CreateVersionResponse{}, fmt.Errorf("%w: content must not be empty", ErrInvalidArgument)
	}

	allowed, err := s.perms.CheckPermission(req.RequestingSubject, ActionWrite, resourceTypeFileObject, req.FileObjectID)
	if err != nil {
		return CreateVersionResponse{}, fmt.Errorf("fileobjects: permission check failed: %w", err)
	}
	if !allowed {
		return CreateVersionResponse{}, ErrPermissionDenied
	}

	fo, found := s.store.getFileObject(req.FileObjectID)
	if !found {
		return CreateVersionResponse{}, ErrFileObjectNotFound
	}
	if fo.Deleted {
		return CreateVersionResponse{}, ErrFileObjectDeleted
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	newBlobRef, err := s.storage.StoreBlob(fo.Owner, req.Content)
	if err != nil {
		return CreateVersionResponse{}, fmt.Errorf("fileobjects: storing new version content failed: %w", err)
	}

	// Required order, no exceptions (charter §6 point 3): the file
	// object's ACTUAL owner, first, unconditionally — regardless of who
	// called CreateVersion.
	if err := s.perms.GrantPermission(fo.Owner, fo.Owner, storageRetrieveBlobAction, resourceTypeBlob, newBlobRef, scopeFull); err != nil {
		_ = s.storage.DeleteBlob(newBlobRef, fo.Owner)
		return CreateVersionResponse{}, fmt.Errorf("fileobjects: establishing owner grant on new version failed: %w", err)
	}

	// Only now, mirror every OTHER currently-active fileobjects.read
	// subject onto the new blob (charter §6 point 3) — grantor is still
	// the file's owner, never requesting_subject.
	grants, err := s.perms.ListGrantsForResource(resourceTypeFileObject, req.FileObjectID)
	if err != nil {
		return CreateVersionResponse{}, fmt.Errorf("fileobjects: new version content stored and owner access established for file_object_id %s, but listing existing grants to mirror failed: %w", req.FileObjectID, err)
	}
	var mirrorFailed []string
	for _, g := range grants {
		if g.Action != ActionRead || g.Subject == fo.Owner {
			continue
		}
		if err := s.perms.GrantPermission(fo.Owner, g.Subject, storageRetrieveBlobAction, resourceTypeBlob, newBlobRef, g.Scope); err != nil {
			mirrorFailed = append(mirrorFailed, g.Subject)
		}
	}

	now := s.nowUnix()
	versionRef, err := s.genVersion()
	if err != nil {
		return CreateVersionResponse{}, fmt.Errorf("fileobjects: generating version_ref: %w", err)
	}
	version := VersionRecord{
		VersionRef:    versionRef,
		FileObjectID:  req.FileObjectID,
		BlobRef:       newBlobRef,
		CreatedAtUnix: now,
		CreatedBy:     req.RequestingSubject,
		SizeBytes:     int64(len(req.Content)),
	}
	s.store.addVersion(req.FileObjectID, version)

	fo.CurrentVersionRef = versionRef
	fo.SizeBytes = version.SizeBytes

	metadata := map[string]string{
		"version_ref": versionRef,
		"size_bytes":  strconv.FormatInt(version.SizeBytes, 10),
	}
	eventID, err := s.audit.Emit(req.RequestingSubject, "fileobjects.create_version",
		ResourceRef{ResourceType: resourceTypeFileObject, ResourceID: req.FileObjectID}, "requested_new_version", metadata)
	if err != nil {
		s.store.putFileObject(fo)
		return CreateVersionResponse{}, fmt.Errorf("version created but audit emit failed: %w", err)
	}
	fo.LastHistoryEventID = eventID
	s.store.putFileObject(fo)
	s.store.addEvent(req.FileObjectID, FileEvent{EventID: eventID, Action: "fileobjects.create_version", Actor: req.RequestingSubject, OccurredAtUnix: now, Metadata: metadata})

	if len(mirrorFailed) > 0 {
		return CreateVersionResponse{VersionRef: versionRef}, fmt.Errorf(
			"fileobjects: version %s created and owner access established, but mirroring read access to subject(s) %v failed — those subjects' access to this specific version may lag until resolved",
			versionRef, mirrorFailed)
	}

	return CreateVersionResponse{VersionRef: versionRef}, nil
}

// GetFileContent returns one version's bytes — current version if
// version_ref is omitted (charter §5's only version-resolution behavior in
// the default path). fileobjects.read is checked unconditionally on every
// call regardless of version_ref (charter §6 point 6) — no exception for
// "current" vs. "old" versions.
func (s *Service) GetFileContent(req GetFileContentRequest) (GetFileContentResponse, error) {
	if err := s.checkRead(req.RequestingSubject, req.FileObjectID, "GetFileContent"); err != nil {
		return GetFileContentResponse{}, err
	}
	fo, found := s.store.getFileObject(req.FileObjectID)
	if !found {
		return GetFileContentResponse{}, ErrFileObjectNotFound
	}

	versionRef := req.VersionRef
	if versionRef == "" {
		versionRef = fo.CurrentVersionRef
	}
	v, found := s.store.getVersion(req.FileObjectID, versionRef)
	if !found {
		return GetFileContentResponse{}, ErrVersionNotFound
	}

	data, err := s.storage.RetrieveBlob(v.BlobRef, req.RequestingSubject)
	if err != nil {
		// Charter §6 point 8(b): never propagate Storage's raw error text
		// (it could embed the blob_ref) — always the same generic,
		// content-free sentinel.
		return GetFileContentResponse{}, ErrContentUnavailable
	}
	return GetFileContentResponse{Content: data}, nil
}

// ListVersions returns version_ref/created_at/created_by/size per version
// — never blob_ref (charter §6 point 8).
func (s *Service) ListVersions(req ListVersionsRequest) (ListVersionsResponse, error) {
	if err := s.checkRead(req.RequestingSubject, req.FileObjectID, "ListVersions"); err != nil {
		return ListVersionsResponse{}, err
	}
	if _, found := s.store.getFileObject(req.FileObjectID); !found {
		return ListVersionsResponse{}, ErrFileObjectNotFound
	}
	versions := s.store.listVersions(req.FileObjectID)
	out := make([]VersionSummary, 0, len(versions))
	for _, v := range versions {
		out = append(out, v.toSummary())
	}
	return ListVersionsResponse{Versions: out}, nil
}

// GetFileHistory returns EXACTLY File Objects' own emitted events
// (CreateFileObject/CreateVersion/SetFilePermissions/SetFileMetadata/
// DeleteFileObject) — never a raw aggregation of the Permissions/Storage
// calls this package makes internally (charter §6 point 8a). This is
// structurally guaranteed, not just a promise: this package's local
// AuditEmitter interface exposes only Emit, never a Query method, so there
// is no code path by which this function COULD read Permissions'/Storage's
// own audit trails even if it wanted to — it can only ever read from
// store.go's own events map, populated exclusively by this package's own
// audit.Emit call sites.
func (s *Service) GetFileHistory(req GetFileHistoryRequest) (GetFileHistoryResponse, error) {
	if err := s.checkRead(req.RequestingSubject, req.FileObjectID, "GetFileHistory"); err != nil {
		return GetFileHistoryResponse{}, err
	}
	if _, found := s.store.getFileObject(req.FileObjectID); !found {
		return GetFileHistoryResponse{}, ErrFileObjectNotFound
	}
	return GetFileHistoryResponse{Events: s.store.eventsForFileObject(req.FileObjectID)}, nil
}

// SetFilePermissions grants or revokes subject's access to the file
// object via Permissions' own Grant/RevokePermission (requesting_subject
// must already hold grant/revoke authority per Permissions' own escalation
// rule — File Objects invents no separate check here, charter §6 point 5).
// action must be exactly ActionRead or ActionWrite (charter §6 point 1).
//
// A fileobjects.read grant/revoke also mirrors onto every existing
// version's underlying blob (charter §6 point 4), grantor always the
// file's owner. This loop fails loudly, naming which version(s) failed to
// mirror, rather than ever reporting success on a partial mirror — a
// silently-partial revoke would leave a subject able to read specific old
// versions directly via Storage.RetrieveBlob even though the file-object-
// level grant is gone. fileobjects.write needs no blob-level mirroring at
// all (charter §6 point 4).
//
// ascend:mutates
func (s *Service) SetFilePermissions(req SetFilePermissionsRequest) (SetFilePermissionsResponse, error) {
	if req.FileObjectID == "" || req.RequestingSubject == "" || req.Subject == "" {
		return SetFilePermissionsResponse{}, fmt.Errorf("%w: file_object_id, requesting_subject, and subject are required", ErrInvalidArgument)
	}
	if req.Action != ActionRead && req.Action != ActionWrite {
		return SetFilePermissionsResponse{}, ErrInvalidPermissionAction
	}

	fo, found := s.store.getFileObject(req.FileObjectID)
	if !found {
		return SetFilePermissionsResponse{}, ErrFileObjectNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if req.Grant {
		if err := s.perms.GrantPermission(req.RequestingSubject, req.Subject, req.Action, resourceTypeFileObject, req.FileObjectID, req.Scope); err != nil {
			return SetFilePermissionsResponse{}, fmt.Errorf("fileobjects: grant failed: %w", err)
		}
	} else {
		if err := s.perms.RevokePermission(req.RequestingSubject, req.Subject, req.Action, resourceTypeFileObject, req.FileObjectID); err != nil {
			return SetFilePermissionsResponse{}, fmt.Errorf("fileobjects: revoke failed: %w", err)
		}
	}

	var mirrorFailedVersions []string
	if req.Action == ActionRead {
		versions := s.store.listVersions(req.FileObjectID)
		for _, v := range versions {
			var mirrorErr error
			if req.Grant {
				mirrorErr = s.perms.GrantPermission(fo.Owner, req.Subject, storageRetrieveBlobAction, resourceTypeBlob, v.BlobRef, req.Scope)
			} else {
				mirrorErr = s.perms.RevokePermission(fo.Owner, req.Subject, storageRetrieveBlobAction, resourceTypeBlob, v.BlobRef)
			}
			if mirrorErr != nil {
				mirrorFailedVersions = append(mirrorFailedVersions, v.VersionRef)
			}
		}
	}

	changeAction := "fileobjects.permission_granted"
	if !req.Grant {
		changeAction = "fileobjects.permission_revoked"
	}
	metadata := map[string]string{"subject": req.Subject, "action": req.Action, "scope": req.Scope}
	now := s.nowUnix()
	eventID, err := s.audit.Emit(req.RequestingSubject, changeAction,
		ResourceRef{ResourceType: resourceTypeFileObject, ResourceID: req.FileObjectID}, "grantor_authorized_by_permissions", metadata)
	if err != nil {
		return SetFilePermissionsResponse{}, fmt.Errorf("permission change applied but audit emit failed: %w", err)
	}
	fo.LastHistoryEventID = eventID
	s.store.putFileObject(fo)
	s.store.addEvent(req.FileObjectID, FileEvent{EventID: eventID, Action: changeAction, Actor: req.RequestingSubject, OccurredAtUnix: now, Metadata: metadata})

	if len(mirrorFailedVersions) > 0 {
		return SetFilePermissionsResponse{}, fmt.Errorf(
			"fileobjects: file-object-level permission change succeeded and was audited, but mirroring to version(s) %v failed — access is inconsistent across versions until resolved",
			mirrorFailedVersions)
	}

	return SetFilePermissionsResponse{}, nil
}

// GetFileMetadata returns the fixed field set (name, mime_type, tags,
// size) — size is always derived from the current version, never
// caller-settable.
func (s *Service) GetFileMetadata(req GetFileMetadataRequest) (GetFileMetadataResponse, error) {
	if err := s.checkRead(req.RequestingSubject, req.FileObjectID, "GetFileMetadata"); err != nil {
		return GetFileMetadataResponse{}, err
	}
	fo, found := s.store.getFileObject(req.FileObjectID)
	if !found {
		return GetFileMetadataResponse{}, ErrFileObjectNotFound
	}
	return GetFileMetadataResponse{
		Name:      fo.Name,
		MimeType:  fo.MimeType,
		Tags:      append([]string(nil), fo.Tags...),
		SizeBytes: fo.SizeBytes,
	}, nil
}

// SetFileMetadata updates name/mime_type/tags — never size, which is
// always derived (charter §3).
//
// ascend:mutates
func (s *Service) SetFileMetadata(req SetFileMetadataRequest) (SetFileMetadataResponse, error) {
	if req.FileObjectID == "" || req.RequestingSubject == "" {
		return SetFileMetadataResponse{}, fmt.Errorf("%w: file_object_id and requesting_subject are required", ErrInvalidArgument)
	}

	allowed, err := s.perms.CheckPermission(req.RequestingSubject, ActionWrite, resourceTypeFileObject, req.FileObjectID)
	if err != nil {
		return SetFileMetadataResponse{}, fmt.Errorf("fileobjects: permission check failed: %w", err)
	}
	if !allowed {
		return SetFileMetadataResponse{}, ErrPermissionDenied
	}

	fo, found := s.store.getFileObject(req.FileObjectID)
	if !found {
		return SetFileMetadataResponse{}, ErrFileObjectNotFound
	}

	metadata := map[string]string{}
	if req.Name != nil {
		fo.Name = *req.Name
		metadata["name"] = *req.Name
	}
	if req.MimeType != nil {
		fo.MimeType = *req.MimeType
		metadata["mime_type"] = *req.MimeType
	}
	if req.Tags != nil {
		fo.Tags = append([]string(nil), req.Tags...)
	}

	now := s.nowUnix()
	eventID, err := s.audit.Emit(req.RequestingSubject, "fileobjects.set_file_metadata",
		ResourceRef{ResourceType: resourceTypeFileObject, ResourceID: req.FileObjectID}, "owner_or_delegate_requested", metadata)
	if err != nil {
		return SetFileMetadataResponse{}, fmt.Errorf("metadata updated but audit emit failed: %w", err)
	}
	fo.LastHistoryEventID = eventID
	s.store.putFileObject(fo)
	s.store.addEvent(req.FileObjectID, FileEvent{EventID: eventID, Action: "fileobjects.set_file_metadata", Actor: req.RequestingSubject, OccurredAtUnix: now, Metadata: metadata})

	return SetFileMetadataResponse{}, nil
}

// ExportFile checks fileobjects.read once (same shared call site as every
// other read RPC), then loops Storage.RetrieveBlob per version (charter §6
// point 7) — never Storage's ExportAllBlobs, which carries its own tracked,
// unrelated caller-identity gap (charter §6, final bullet). Bundles all
// versions' content, full metadata, and File Objects' own event history
// (never Permissions'/Storage's, charter §6 point 8a) into one portable,
// versioned, self-describing document (Art. 9).
func (s *Service) ExportFile(req ExportFileRequest) (ExportFileResponse, error) {
	if err := s.checkRead(req.RequestingSubject, req.FileObjectID, "ExportFile"); err != nil {
		return ExportFileResponse{}, err
	}
	fo, found := s.store.getFileObject(req.FileObjectID)
	if !found {
		return ExportFileResponse{}, ErrFileObjectNotFound
	}

	versions := s.store.listVersions(req.FileObjectID)
	exportedVersions := make([]exportedVersion, 0, len(versions))
	for _, v := range versions {
		data, err := s.storage.RetrieveBlob(v.BlobRef, req.RequestingSubject)
		if err != nil {
			// Same non-leak discipline as GetFileContent (charter §6 point 8b).
			return ExportFileResponse{}, ErrContentUnavailable
		}
		// toExportedVersionSummary (export.go) is the same blob_ref-free
		// projection ExportVersionRecord renders — reused directly here
		// rather than round-tripped through JSON, but see
		// version_record_export_test.go for the proof that
		// ExportVersionRecord itself (the Art. 9 mechanical export path for
		// VersionRecord) renders the identical, blob_ref-free shape.
		exportedVersions = append(exportedVersions, exportedVersion{
			exportedVersionSummary: toExportedVersionSummary(v),
			Content:                data,
		})
	}

	events := s.store.eventsForFileObject(req.FileObjectID)

	blob, err := buildExportDocument(fo, exportedVersions, events, s.nowUnix())
	if err != nil {
		return ExportFileResponse{}, err
	}

	return ExportFileResponse{ExportBlob: blob, FormatVersion: exportFormatVersion}, nil
}

// DeleteFileObject terminates the file object's lifecycle: destroys every
// version's underlying content via Storage's DeleteBlob (charter §3), then
// (charter §7's grant-cleanup decision — see docs/DECISION_LOG.md) revokes
// every active grant on both the file-object resource and every version's
// blob resource, best-effort. Content deletion is required to succeed for
// every version before the file object is marked deleted — a partial
// content-deletion failure must not be reported as success. The
// FileObjectRecord itself is retained as a tombstone (Deleted=true) so
// GetFileHistory/GetFileMetadata/ListVersions remain honestly answerable
// afterward (charter §3: "identity and history entries remain resolvable
// ... but never the content").
//
// ascend:mutates
func (s *Service) DeleteFileObject(req DeleteFileObjectRequest) (DeleteFileObjectResponse, error) {
	if req.FileObjectID == "" || req.RequestingSubject == "" {
		return DeleteFileObjectResponse{}, fmt.Errorf("%w: file_object_id and requesting_subject are required", ErrInvalidArgument)
	}

	allowed, err := s.perms.CheckPermission(req.RequestingSubject, ActionWrite, resourceTypeFileObject, req.FileObjectID)
	if err != nil {
		return DeleteFileObjectResponse{}, fmt.Errorf("fileobjects: permission check failed: %w", err)
	}
	if !allowed {
		return DeleteFileObjectResponse{}, ErrPermissionDenied
	}

	fo, found := s.store.getFileObject(req.FileObjectID)
	if !found {
		return DeleteFileObjectResponse{}, ErrFileObjectNotFound
	}
	if fo.Deleted {
		return DeleteFileObjectResponse{}, ErrFileObjectDeleted
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	versions := s.store.listVersions(req.FileObjectID)

	var deleteFailedVersions []string
	for _, v := range versions {
		if err := s.storage.DeleteBlob(v.BlobRef, fo.Owner); err != nil {
			deleteFailedVersions = append(deleteFailedVersions, v.VersionRef)
		}
	}
	if len(deleteFailedVersions) > 0 {
		return DeleteFileObjectResponse{}, fmt.Errorf(
			"fileobjects: failed to delete content for version(s) %v — file object NOT marked deleted, content-unreachability guarantee not yet met",
			deleteFailedVersions)
	}

	// Grant cleanup (charter §7): best-effort, not fail-loud. Every
	// version's content is already irreversibly destroyed above regardless
	// of whether this succeeds, so a lingering grant record poses no
	// residual content-access risk (mirroring Storage's own
	// DeleteBlob/crypto-shred reasoning, which this decision explicitly
	// relies on) — see docs/DECISION_LOG.md, "File Objects:
	// grant-cleanup-on-delete".
	if grants, err := s.perms.ListGrantsForResource(resourceTypeFileObject, req.FileObjectID); err == nil {
		for _, g := range grants {
			_ = s.perms.RevokePermission(fo.Owner, g.Subject, g.Action, resourceTypeFileObject, req.FileObjectID)
		}
	}
	for _, v := range versions {
		if grants, err := s.perms.ListGrantsForResource(resourceTypeBlob, v.BlobRef); err == nil {
			for _, g := range grants {
				_ = s.perms.RevokePermission(fo.Owner, g.Subject, g.Action, resourceTypeBlob, v.BlobRef)
			}
		}
	}

	now := s.nowUnix()
	metadata := map[string]string{"versions_deleted": strconv.Itoa(len(versions))}
	eventID, err := s.audit.Emit(req.RequestingSubject, "fileobjects.delete_file_object",
		ResourceRef{ResourceType: resourceTypeFileObject, ResourceID: req.FileObjectID}, "owner_or_delegate_requested_deletion", metadata)
	if err != nil {
		return DeleteFileObjectResponse{}, fmt.Errorf("content deleted but audit emit failed: %w", err)
	}

	fo.Deleted = true
	fo.DeletedAtUnix = now
	fo.LastHistoryEventID = eventID
	s.store.putFileObject(fo)
	s.store.addEvent(req.FileObjectID, FileEvent{EventID: eventID, Action: "fileobjects.delete_file_object", Actor: req.RequestingSubject, OccurredAtUnix: now, Metadata: metadata})

	return DeleteFileObjectResponse{}, nil
}
