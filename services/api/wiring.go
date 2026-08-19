package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ascend/services/api/internal/audit"
	"github.com/ascend/services/api/internal/fileobjects"
	"github.com/ascend/services/api/internal/identity"
	"github.com/ascend/services/api/internal/permissions"
	"github.com/ascend/services/api/internal/sessionauth"
	"github.com/ascend/services/api/internal/storage"
)

// This file holds the composition-root wiring code that connects real
// (non-fake) capability instances together and to the HTTP layer. It is
// deliberately Chief-Architect-owned, not any single capability's package —
// see docs/DECISION_LOG.md, 2026-08-16, "Identity wiring design," for the
// full rationale. No capability package imports another's package directly
// here beyond what each capability's own frozen contract/DI interfaces
// already allow; this file is the one place in the whole service that is
// allowed to know about all of them at once, which is exactly what a
// composition root is for.
//
// Note for whoever wires the next capability (Storage, File Objects,
// Permissions): every capability wired so far (Identity, Session/Request
// Authentication) is connected to Audit via constructor-injected DI (an
// AuditEmitter interface passed into NewService), exactly like this file
// does below — never via internal/audit's package-level Default()/
// SetDefault() mechanism, which is currently wired to nothing anywhere in
// this service. Follow the constructor-DI pattern already established
// here, not the package-level one (Constitution Warden, 2026-08-16 merge
// gate).

// auditEmitterAdapter satisfies sessionauth.AuditEmitter by forwarding to a
// real *audit.Service, converting sessionauth's own local ResourceRef shape
// into audit's (identity.AuditEmitter needs no such adapter — it already
// uses a type alias to audit.ResourceRef directly, see
// internal/identity/audit.go).
type auditEmitterAdapter struct {
	audit *audit.Service
}

func (a auditEmitterAdapter) Emit(actor, action string, resource sessionauth.ResourceRef, ruleReference string, metadata map[string]string) (string, error) {
	return a.audit.Emit(actor, action, audit.ResourceRef{
		ResourceType: resource.ResourceType,
		ResourceID:   resource.ResourceID,
	}, ruleReference, metadata)
}

// permissionsAuditEmitterAdapter satisfies permissions.AuditEmitter by
// forwarding to a real *audit.Service, converting permissions' own local
// ResourceRef shape into audit's — same pattern as auditEmitterAdapter
// above, for the same reason (permissions.ResourceRef and audit.ResourceRef
// are distinct local types, not a shared alias).
type permissionsAuditEmitterAdapter struct {
	audit *audit.Service
}

func (a permissionsAuditEmitterAdapter) Emit(actor, action string, resource permissions.ResourceRef, ruleReference string, metadata map[string]string) (string, error) {
	return a.audit.Emit(actor, action, audit.ResourceRef{
		ResourceType: resource.ResourceType,
		ResourceID:   resource.ResourceID,
	}, ruleReference, metadata)
}

// storagePermissionCheckerAdapter satisfies storage.PermissionChecker by
// forwarding to a real *permissions.Service — same narrowing-adapter shape
// as permissionsAuditEmitterAdapter above, for the same reason (Storage's
// own local PermissionChecker interface is a narrower, capability-owned
// shape than Permissions' request/response wire types). Storage's own
// NewService calls DefinePolicy on this exactly once, at construction, to
// register the "blob" resource type's default policy before any real
// caller can reach CheckPermission — see storage/service.go's NewService
// doc comment and docs/CAPABILITY_REGISTRY.md's "Known gap" note this
// resolves.
type storagePermissionCheckerAdapter struct {
	perms *permissions.Service
}

func (a storagePermissionCheckerAdapter) CheckPermission(subject, action, resourceType, resourceID string) (bool, error) {
	resp, err := a.perms.CheckPermission(permissions.CheckPermissionRequest{
		Subject:  subject,
		Action:   action,
		Resource: permissions.ResourceRef{ResourceType: resourceType, ResourceID: resourceID},
	})
	if err != nil {
		return false, err
	}
	return resp.Allowed, nil
}

func (a storagePermissionCheckerAdapter) DefinePolicy(resourceType, defaultRules string) error {
	_, err := a.perms.DefinePolicy(permissions.DefinePolicyRequest{ResourceType: resourceType, DefaultRules: defaultRules})
	return err
}

// GrantPermission/RevokePermission satisfy the two methods Storage's local
// PermissionChecker interface gained in the "Storage: StoreBlob establishes
// Permissions ownership via GrantPermission" fix (docs/DECISION_LOG.md,
// 2026-08-16) — StoreBlob's own bootstrap-ownership grant on each new blob,
// and its rollback path's best-effort revoke if a later step in the same
// call fails. Same forwarding shape as
// fileobjectsPermissionsClientAdapter's equivalent methods below.
func (a storagePermissionCheckerAdapter) GrantPermission(grantor, subject, action, resourceType, resourceID, scope string) error {
	_, err := a.perms.GrantPermission(permissions.GrantPermissionRequest{
		Grantor:  grantor,
		Subject:  subject,
		Action:   action,
		Resource: permissions.ResourceRef{ResourceType: resourceType, ResourceID: resourceID},
		Scope:    scope,
	})
	return err
}

func (a storagePermissionCheckerAdapter) RevokePermission(grantor, subject, action, resourceType, resourceID string) error {
	_, err := a.perms.RevokePermission(permissions.RevokePermissionRequest{
		Grantor:  grantor,
		Subject:  subject,
		Action:   action,
		Resource: permissions.ResourceRef{ResourceType: resourceType, ResourceID: resourceID},
	})
	return err
}

// storageAuditEmitterAdapter satisfies storage.AuditEmitter by forwarding to
// a real *audit.Service, converting storage's own local ResourceRef shape
// into audit's — same pattern as auditEmitterAdapter/
// permissionsAuditEmitterAdapter above.
type storageAuditEmitterAdapter struct {
	audit *audit.Service
}

func (a storageAuditEmitterAdapter) Emit(actor, action string, resource storage.ResourceRef, ruleReference string, metadata map[string]string) (string, error) {
	return a.audit.Emit(actor, action, audit.ResourceRef{
		ResourceType: resource.ResourceType,
		ResourceID:   resource.ResourceID,
	}, ruleReference, metadata)
}

// fileobjectsStorageClientAdapter satisfies fileobjects.StorageClient by
// forwarding to a real *storage.Service. File Objects' own local interface
// is narrower than Storage's request/response wire shape (charter §6's
// confused-deputy prohibition — the true requesting_subject is always
// passed straight through, never a synthetic service identity), so this
// adapter's job is purely shape-translation, not policy. StoreBlob always
// uses storage.PolicyLocalDefault: File Objects' own frozen contract
// (types.go) has no policy-selection parameter of its own — every file
// object's content lands in Storage's default policy unless/until a future
// contract amendment adds one.
type fileobjectsStorageClientAdapter struct {
	storage *storage.Service
}

func (a fileobjectsStorageClientAdapter) StoreBlob(owner string, data []byte) (string, error) {
	resp, err := a.storage.StoreBlob(storage.StoreBlobRequest{Owner: owner, Data: data, PolicyID: storage.PolicyLocalDefault})
	if err != nil {
		return "", err
	}
	return resp.BlobRef, nil
}

func (a fileobjectsStorageClientAdapter) RetrieveBlob(blobRef, requestingSubject string) ([]byte, error) {
	resp, err := a.storage.RetrieveBlob(storage.RetrieveBlobRequest{BlobRef: blobRef, RequestingSubject: requestingSubject})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (a fileobjectsStorageClientAdapter) DeleteBlob(blobRef, requestingSubject string) error {
	_, err := a.storage.DeleteBlob(storage.DeleteBlobRequest{BlobRef: blobRef, RequestingSubject: requestingSubject})
	return err
}

// fileobjectsPermissionsClientAdapter satisfies fileobjects.PermissionsClient
// by forwarding to a real *permissions.Service. File Objects never decides
// allow/deny itself (charter §6 point 5) — every method here is a direct,
// unmediated forward to Permissions' own decision, plus the bookkeeping
// Grant/Revoke/DefinePolicy/ListGrantsForResource calls File Objects' own
// mirroring logic (service.go) makes. File Objects' own NewService calls
// DefinePolicy on this exactly once, at construction, to register the
// "file_object" resource type's default policy — mirrors Storage's own
// "blob" registration exactly, see storagePermissionCheckerAdapter above.
type fileobjectsPermissionsClientAdapter struct {
	perms *permissions.Service
}

func (a fileobjectsPermissionsClientAdapter) CheckPermission(subject, action, resourceType, resourceID string) (bool, error) {
	resp, err := a.perms.CheckPermission(permissions.CheckPermissionRequest{
		Subject:  subject,
		Action:   action,
		Resource: permissions.ResourceRef{ResourceType: resourceType, ResourceID: resourceID},
	})
	if err != nil {
		return false, err
	}
	return resp.Allowed, nil
}

func (a fileobjectsPermissionsClientAdapter) GrantPermission(grantor, subject, action, resourceType, resourceID, scope string) error {
	_, err := a.perms.GrantPermission(permissions.GrantPermissionRequest{
		Grantor:  grantor,
		Subject:  subject,
		Action:   action,
		Resource: permissions.ResourceRef{ResourceType: resourceType, ResourceID: resourceID},
		Scope:    scope,
	})
	return err
}

func (a fileobjectsPermissionsClientAdapter) RevokePermission(grantor, subject, action, resourceType, resourceID string) error {
	_, err := a.perms.RevokePermission(permissions.RevokePermissionRequest{
		Grantor:  grantor,
		Subject:  subject,
		Action:   action,
		Resource: permissions.ResourceRef{ResourceType: resourceType, ResourceID: resourceID},
	})
	return err
}

func (a fileobjectsPermissionsClientAdapter) DefinePolicy(resourceType, defaultRules string) error {
	_, err := a.perms.DefinePolicy(permissions.DefinePolicyRequest{ResourceType: resourceType, DefaultRules: defaultRules})
	return err
}

func (a fileobjectsPermissionsClientAdapter) ListGrantsForResource(resourceType, resourceID string) ([]fileobjects.PermissionGrant, error) {
	resp, err := a.perms.ListGrantsForResource(permissions.ListGrantsForResourceRequest{
		Resource: permissions.ResourceRef{ResourceType: resourceType, ResourceID: resourceID},
	})
	if err != nil {
		return nil, err
	}
	out := make([]fileobjects.PermissionGrant, 0, len(resp.Grants))
	for _, g := range resp.Grants {
		// GrantedAtUnix is carried through as of the ListFileAccess
		// amendment (docs/DECISION_LOG.md, 2026-08-18) — previously dropped
		// here, a plumbing gap Security Steward named explicitly as
		// required work at the charter gate. CreateVersion's/
		// SetFilePermissions' own mirroring loops (service.go) ignore this
		// field; only ListFileAccess's response projection reads it.
		out = append(out, fileobjects.PermissionGrant{
			Subject:       g.Subject,
			Action:        g.Action,
			Scope:         g.Scope,
			GrantedAtUnix: g.GrantedAtUnix,
		})
	}
	return out, nil
}

// fileobjectsAuditEmitterAdapter satisfies fileobjects.AuditEmitter by
// forwarding to a real *audit.Service, converting fileobjects' own local
// ResourceRef shape into audit's — same pattern as every other *AuditEmitter
// adapter in this file.
type fileobjectsAuditEmitterAdapter struct {
	audit *audit.Service
}

func (a fileobjectsAuditEmitterAdapter) Emit(actor, action string, resource fileobjects.ResourceRef, ruleReference string, metadata map[string]string) (string, error) {
	return a.audit.Emit(actor, action, audit.ResourceRef{
		ResourceType: resource.ResourceType,
		ResourceID:   resource.ResourceID,
	}, ruleReference, metadata)
}

// deviceResolverAdapter satisfies sessionauth.DeviceResolver by forwarding
// to a real *identity.Service. Identity has no dedicated single-device
// lookup method — ListDevices is the closest fit, so this adapter fetches
// the full device list and scans for the requested device_id. Fine for an
// in-memory first pass; if this becomes a hot path once a real datastore
// is wired, revisit with a dedicated lookup on Identity's side rather than
// optimizing this adapter around a linear scan.
type deviceResolverAdapter struct {
	identity *identity.Service
}

func (d deviceResolverAdapter) ResolveDevicePublicKey(identityRef, deviceID string) ([]byte, bool, error) {
	resp, err := d.identity.ListDevices(identity.ListDevicesRequest{IdentityRef: identityRef})
	if err != nil {
		return nil, false, err
	}
	for _, dev := range resp.Devices {
		if dev.DeviceID == deviceID {
			return dev.PublicKey, true, nil
		}
	}
	return nil, false, nil
}

// lateBoundPermissionChecker satisfies audit.PermissionChecker by
// forwarding to a real *permissions.Service — but, unlike every other
// adapter in this file, it can't simply hold that pointer from
// construction time, because Permissions and Audit each depend on the
// other (Audit needs Permissions to gate cross-subject Query/Explain;
// Permissions needs Audit to log its own grants/revokes) and Go structs
// can't be constructed out of this kind of real cycle directly.
//
// This is the concrete, in-code form of the "opaque reference, lazy
// resolution" design decided at charter time (docs/DECISION_LOG.md,
// 2026-07-06, "Foundation contracts composition") — a struct field that
// starts nil and is patched in immediately after both services exist,
// never invoked before that patch happens (nothing calls CheckPermission
// during either constructor). If svc is somehow still nil when this is
// called — which would be a real construction-order bug, not a normal
// runtime state — it fails closed rather than panicking or allowing.
type lateBoundPermissionChecker struct {
	svc *permissions.Service
}

func (p *lateBoundPermissionChecker) CheckPermission(subject, action string, resource audit.ResourceRef) (bool, error) {
	if p.svc == nil {
		return false, nil
	}
	resp, err := p.svc.CheckPermission(permissions.CheckPermissionRequest{
		Subject: subject,
		Action:  action,
		Resource: permissions.ResourceRef{
			ResourceType: resource.ResourceType,
			ResourceID:   resource.ResourceID,
		},
	})
	if err != nil {
		return false, err
	}
	return resp.Allowed, nil
}

// requireCallerMatchesIdentity builds the middleware Identity's Mount
// applies to RevokeDevice/ListDevices/ExportIdentity (see
// docs/DECISION_LOG.md, 2026-08-16). It validates the caller's bearer
// session token against the real Session/Request Authentication service
// and rejects unless the resulting identity_ref matches the {identityRef}
// path parameter — a caller may only act on their own identity through
// these three routes, never another's, regardless of what identity_ref
// value they might otherwise supply.
//
// Identity's own package never sees this function's implementation or
// imports sessionauth — it only receives the finished
// func(http.Handler) http.Handler, preserving Art. 10 modularity.
func requireCallerMatchesIdentity(sessions *sessionauth.Service, pathParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r)
			if token == "" {
				writeJSONError(w, http.StatusUnauthorized, "missing bearer session token")
				return
			}
			resp, err := sessions.ValidateSession(sessionauth.ValidateSessionRequest{SessionToken: token})
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "session validation failed")
				return
			}
			if !resp.Valid {
				writeJSONError(w, http.StatusUnauthorized, "invalid or expired session")
				return
			}
			pathIdentityRef := chi.URLParam(r, pathParam)
			if pathIdentityRef == "" || pathIdentityRef != resp.IdentityRef {
				writeJSONError(w, http.StatusForbidden, "caller's session does not match the requested identity")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// verifiedCallerHeader is the header name Audit's and Permissions' HTTP
// handlers already read caller identity from (internal/audit/http.go's
// callerHeader constant, and the same convention Permissions' handlers were
// dispatched to adopt — see docs/DECISION_LOG.md, 2026-08-16, "Permissions
// and Audit wiring design"). It must match exactly, or requireVerifiedCaller
// below would be setting a header neither package ever looks at.
const verifiedCallerHeader = "X-Ascend-Actor"

// requireVerifiedCaller builds the middleware mounted in front of Audit's
// and Permissions' network routes (see docs/DECISION_LOG.md, 2026-08-16,
// "Permissions and Audit wiring design"). Unlike
// requireCallerMatchesIdentity above (which gates on a URL path parameter),
// these two capabilities' handlers derive the acting identity entirely from
// the verifiedCallerHeader value — so this middleware's job is simpler:
// validate the bearer session token, then unconditionally overwrite the
// header with the verified identity before the request reaches the
// handler.
//
// The header is deleted first, then set — never merely set — specifically
// so a caller cannot pre-supply their own X-Ascend-Actor value and have it
// survive if this middleware were ever accidentally skipped or
// misconfigured for a given route; there is exactly one place in the
// running server that is allowed to produce a trusted value for this
// header, and this is it.
func requireVerifiedCaller(sessions *sessionauth.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Del(verifiedCallerHeader)

			token := bearerToken(r)
			if token == "" {
				writeJSONError(w, http.StatusUnauthorized, "missing bearer session token")
				return
			}
			resp, err := sessions.ValidateSession(sessionauth.ValidateSessionRequest{SessionToken: token})
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "session validation failed")
				return
			}
			if !resp.Valid {
				writeJSONError(w, http.StatusUnauthorized, "invalid or expired session")
				return
			}

			r.Header.Set(verifiedCallerHeader, resp.IdentityRef)
			next.ServeHTTP(w, r)
		})
	}
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, prefix) {
		return strings.TrimPrefix(auth, prefix)
	}
	return ""
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
