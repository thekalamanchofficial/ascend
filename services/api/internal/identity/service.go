package identity

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strconv"
	"time"
)

// Service implements the eight IdentityService RPCs (identity.proto)
// against a Store, a PrekeyStore, and an AuditEmitter, all
// dependency-injected via NewService — see docs/DECISION_LOG.md for why
// (storage seam + audit seam decisions; prekeys is a second, separate
// storage seam added by the 2026-08-20 prekey bundle publish/fetch
// amendment, see prekey_store.go's doc comment for why it's not folded
// into Store).
type Service struct {
	store   Store
	prekeys PrekeyStore
	audit   AuditEmitter
}

// NewService wires a Service. `store` is this capability's original
// persistence seam — pass NewInMemoryStore() for this pass (see
// docs/DECISION_LOG.md); a nil store defaults to a fresh in-memory store
// so callers can't construct a Service that panics on first use.
// `prekeys` is the second persistence seam PublishPrekeyBundle/
// FetchPrekeyBundle build against; a nil prekeys defaults to a fresh
// NewInMemoryPrekeyStore(), the same nil-safe-default discipline as
// `store`. `emitter` is the Art. 5 audit seam (see AuditEmitter in
// audit.go); production wiring must supply a real emitter — a nil emitter
// defaults to NoopAuditEmitter, which fails loudly (returns an error)
// rather than silently dropping audit events.
func NewService(store Store, prekeys PrekeyStore, emitter AuditEmitter) *Service {
	if store == nil {
		store = NewInMemoryStore()
	}
	if prekeys == nil {
		prekeys = NewInMemoryPrekeyStore()
	}
	if emitter == nil {
		emitter = NoopAuditEmitter{}
	}
	return &Service{store: store, prekeys: prekeys, audit: emitter}
}

// ascend:mutates
func (s *Service) CreateIdentity(req CreateIdentityRequest) (CreateIdentityResponse, error) {
	if req.DisplayName == "" {
		return CreateIdentityResponse{}, fmt.Errorf("%w: display_name is required", ErrInvalidArgument)
	}
	if len(req.PublicKey) != ed25519.PublicKeySize {
		return CreateIdentityResponse{}, fmt.Errorf("%w: public_key must be a %d-byte Ed25519 key", ErrInvalidArgument, ed25519.PublicKeySize)
	}
	if len(req.FirstDevicePublicKey) != ed25519.PublicKeySize {
		return CreateIdentityResponse{}, fmt.Errorf("%w: first_device_public_key must be a %d-byte Ed25519 key", ErrInvalidArgument, ed25519.PublicKeySize)
	}
	if req.FirstDeviceName == "" {
		return CreateIdentityResponse{}, fmt.Errorf("%w: first_device_name is required", ErrInvalidArgument)
	}

	now := time.Now().Unix()
	identityRef := newID()
	firstDevice := Device{
		DeviceID:     newID(),
		Name:         req.FirstDeviceName,
		PublicKey:    req.FirstDevicePublicKey,
		AddedAtUnix:  now,
		LastSeenUnix: now,
	}
	record := IdentityRecord{
		IdentityRef:   identityRef,
		DisplayName:   req.DisplayName,
		PublicKey:     req.PublicKey,
		Devices:       []Device{firstDevice},
		CreatedAtUnix: now,
		// Epoch starts at 0 by construction (Go zero value, made explicit
		// here) — see sign.go's doc comment on buildDeviceBindingMessage
		// for why this is the anti-replay input every BindDevice proof
		// must be signed against, and why signers are expected to know
		// this starting value without a dedicated RPC field.
		Epoch: 0,
	}

	if err := s.store.Create(record); err != nil {
		return CreateIdentityResponse{}, err
	}

	if _, err := s.audit.Emit(identityRef, "identity.created",
		ResourceRef{ResourceType: "identity", ResourceID: identityRef},
		"identity.create_identity",
		map[string]string{
			"display_name":      req.DisplayName,
			"first_device_id":   firstDevice.DeviceID,
			"first_device_name": firstDevice.Name,
		}); err != nil {
		return CreateIdentityResponse{}, fmt.Errorf("identity created but audit emit failed: %w", err)
	}

	return CreateIdentityResponse{
		PublicIdentity: PublicIdentity{
			IdentityRef: identityRef,
			DisplayName: req.DisplayName,
			PublicKey:   req.PublicKey,
			DeviceCount: 1,
			Epoch:       record.Epoch,
		},
		FirstDevice: firstDevice,
	}, nil
}

// ascend:mutates
func (s *Service) BindDevice(req BindDeviceRequest) (BindDeviceResponse, error) {
	if req.IdentityRef == "" {
		return BindDeviceResponse{}, fmt.Errorf("%w: identity_ref is required", ErrInvalidArgument)
	}
	if len(req.DevicePublicKey) != ed25519.PublicKeySize {
		return BindDeviceResponse{}, fmt.Errorf("%w: device_public_key must be a %d-byte Ed25519 key", ErrInvalidArgument, ed25519.PublicKeySize)
	}
	if req.DeviceName == "" {
		return BindDeviceResponse{}, fmt.Errorf("%w: device_name is required", ErrInvalidArgument)
	}

	record, err := s.store.Get(req.IdentityRef)
	if err != nil {
		return BindDeviceResponse{}, err
	}

	for _, d := range record.Devices {
		if bytes.Equal(d.PublicKey, req.DevicePublicKey) {
			_, _ = s.audit.Emit(req.IdentityRef, "identity.device_bind_rejected",
				ResourceRef{ResourceType: "identity", ResourceID: req.IdentityRef},
				"identity.bind_device.duplicate_key",
				map[string]string{"reason": "duplicate_device_public_key", "device_name": req.DeviceName})
			return BindDeviceResponse{}, ErrDuplicateDeviceKey
		}
	}

	// Threat model (charter §6, device spoofing): binding requires a real
	// cryptographic proof of possession, verified against either the
	// identity's root key (recovery path) or a currently-bound device's
	// key (already-bound-device path) — see sign.go. On the recovery
	// path, per charter §3/§7, this service has no discretionary
	// authority beyond this verification step: a validly-signed
	// recovery-derived assertion is relayed and audit-logged, never
	// second-guessed.
	if !authorizesBinding(record, req.DevicePublicKey, req.DeviceName, req.AuthorizationProof) {
		_, _ = s.audit.Emit(req.IdentityRef, "identity.device_bind_rejected",
			ResourceRef{ResourceType: "identity", ResourceID: req.IdentityRef},
			"identity.bind_device.invalid_signature",
			map[string]string{"reason": "invalid_signature", "device_name": req.DeviceName})
		return BindDeviceResponse{}, ErrInvalidSignature
	}

	now := time.Now().Unix()
	device := Device{
		DeviceID:     newID(),
		Name:         req.DeviceName,
		PublicKey:    req.DevicePublicKey,
		AddedAtUnix:  now,
		LastSeenUnix: now,
	}
	record.Devices = append(record.Devices, device)
	// Anti-replay (2026-07-16 Security Steward merge-gate veto fix): every
	// successful device-topology change advances the epoch, so the proof
	// that authorized THIS bind — and any other proof signed against the
	// pre-bind epoch — can never verify again. See sign.go.
	record.Epoch++
	if err := s.store.Replace(record); err != nil {
		return BindDeviceResponse{}, err
	}

	if _, err := s.audit.Emit(req.IdentityRef, "identity.device_bound",
		ResourceRef{ResourceType: "identity_device", ResourceID: device.DeviceID},
		"identity.bind_device.signature_verified",
		map[string]string{
			"identity_ref": req.IdentityRef,
			"device_name":  device.Name,
		}); err != nil {
		return BindDeviceResponse{}, fmt.Errorf("device bound but audit emit failed: %w", err)
	}

	return BindDeviceResponse{Device: device, Epoch: record.Epoch}, nil
}

// ascend:mutates
func (s *Service) RevokeDevice(req RevokeDeviceRequest) (RevokeDeviceResponse, error) {
	if req.IdentityRef == "" {
		return RevokeDeviceResponse{}, fmt.Errorf("%w: identity_ref is required", ErrInvalidArgument)
	}
	if req.DeviceID == "" {
		return RevokeDeviceResponse{}, fmt.Errorf("%w: device_id is required", ErrInvalidArgument)
	}

	record, err := s.store.Get(req.IdentityRef)
	if err != nil {
		return RevokeDeviceResponse{}, err
	}

	idx := -1
	for i, d := range record.Devices {
		if d.DeviceID == req.DeviceID {
			idx = i
			break
		}
	}
	if idx == -1 {
		return RevokeDeviceResponse{}, ErrDeviceNotFound
	}

	removed := record.Devices[idx]
	record.Devices = append(append([]Device{}, record.Devices[:idx]...), record.Devices[idx+1:]...)
	// Anti-replay (2026-07-16 Security Steward merge-gate veto fix): a
	// revoke must invalidate every previously-signed BindDevice proof for
	// this identity, including one that would otherwise still verify
	// because device-set membership happened to return to a prior-looking
	// state (e.g. bind X then revoke X) — see sign.go's doc comment for
	// why a monotonic counter, not a device-set-membership hash, is what
	// actually closes that case.
	record.Epoch++
	if err := s.store.Replace(record); err != nil {
		return RevokeDeviceResponse{}, err
	}

	if _, err := s.audit.Emit(req.IdentityRef, "identity.device_revoked",
		ResourceRef{ResourceType: "identity_device", ResourceID: removed.DeviceID},
		"identity.revoke_device",
		map[string]string{
			"identity_ref": req.IdentityRef,
			"device_name":  removed.Name,
		}); err != nil {
		return RevokeDeviceResponse{}, fmt.Errorf("device revoked but audit emit failed: %w", err)
	}

	return RevokeDeviceResponse{Epoch: record.Epoch}, nil
}

// ResolveIdentity is a read-only public lookup — it does not mutate state,
// so it is not marked with this package's audit-obligation comment and
// does not call the audit seam, consistent with charter §3/§4 scoping the
// audit obligation to BindDevice, RevokeDevice, and ExportIdentity.
func (s *Service) ResolveIdentity(req ResolveIdentityRequest) (ResolveIdentityResponse, error) {
	if req.IdentityRef == "" {
		return ResolveIdentityResponse{}, fmt.Errorf("%w: identity_ref is required", ErrInvalidArgument)
	}
	record, err := s.store.Get(req.IdentityRef)
	if err != nil {
		return ResolveIdentityResponse{}, err
	}
	return ResolveIdentityResponse{PublicIdentity: PublicIdentity{
		IdentityRef: record.IdentityRef,
		DisplayName: record.DisplayName,
		PublicKey:   record.PublicKey,
		DeviceCount: int32(len(record.Devices)),
		Epoch:       record.Epoch,
	}}, nil
}

// ListDevices is a read-only enumeration — same non-mutating reasoning as
// ResolveIdentity above.
//
// Amended 2026-08-20 (prekey bundle publish/fetch amendment, charter §3/§4/
// §6's "Prekey exhaustion as an abuse vector" mitigation): each returned
// Device now carries its real, freshly-computed
// UnconsumedOneTimePrekeyCount — a derived count, not a stored field (see
// types.go's Device doc comment for why the persisted copy stays at zero
// and only this in-memory response slice is overwritten). One
// CountUnconsumedOneTimePrekeys call per device, not a single batch query
// — this capability's own devices-per-identity count is small (a handful
// at most) and ListDevices is not a hot path, the same "fine for now,
// revisit if it becomes one" judgment call this package's
// deviceResolverAdapter precedent (wiring.go) already makes for an
// analogous per-device scan.
func (s *Service) ListDevices(req ListDevicesRequest) (ListDevicesResponse, error) {
	if req.IdentityRef == "" {
		return ListDevicesResponse{}, fmt.Errorf("%w: identity_ref is required", ErrInvalidArgument)
	}
	record, err := s.store.Get(req.IdentityRef)
	if err != nil {
		return ListDevicesResponse{}, err
	}

	devices := make([]Device, len(record.Devices))
	copy(devices, record.Devices)
	for i := range devices {
		count, err := s.prekeys.CountUnconsumedOneTimePrekeys(req.IdentityRef, devices[i].DeviceID)
		if err != nil {
			return ListDevicesResponse{}, err
		}
		devices[i].UnconsumedOneTimePrekeyCount = count
	}
	return ListDevicesResponse{Devices: devices}, nil
}

// ExportIdentity does not mutate stored state, but charter §3 explicitly
// requires it to emit an audit event ("every bind/revoke/export emits an
// audit event") — so it is deliberately marked with this package's
// audit-obligation comment anyway, broadening the mechanical check's
// coverage beyond its literal three-function scope rather than relying on
// an unenforced charter sentence. See docs/DECISION_LOG.md.
//
// ascend:mutates
func (s *Service) ExportIdentity(req ExportIdentityRequest) (ExportIdentityResponse, error) {
	if req.IdentityRef == "" {
		return ExportIdentityResponse{}, fmt.Errorf("%w: identity_ref is required", ErrInvalidArgument)
	}
	record, err := s.store.Get(req.IdentityRef)
	if err != nil {
		return ExportIdentityResponse{}, err
	}

	blob, formatVersion, err := ExportIdentityRecord(record)
	if err != nil {
		return ExportIdentityResponse{}, err
	}

	if _, err := s.audit.Emit(req.IdentityRef, "identity.exported",
		ResourceRef{ResourceType: "identity", ResourceID: req.IdentityRef},
		"identity.export_identity",
		map[string]string{"format_version": formatVersion}); err != nil {
		return ExportIdentityResponse{}, fmt.Errorf("export produced but audit emit failed: %w", err)
	}

	return ExportIdentityResponse{ExportBlob: blob, FormatVersion: formatVersion}, nil
}

// deviceIndexByID returns the index of deviceID within devices, or -1 if
// not present — the same "is this device really bound to this identity"
// check RevokeDevice already performs, factored out so
// PublishPrekeyBundle/FetchPrekeyBundle share it exactly rather than
// re-implementing it slightly differently.
func deviceIndexByID(devices []Device, deviceID string) int {
	for i, d := range devices {
		if d.DeviceID == deviceID {
			return i
		}
	}
	return -1
}

// mostRecentlyActiveDeviceID implements charter §3/§7's default-device-
// selection rule for FetchPrekeyBundle when device_id is omitted: the
// identity's most-recently-active bound device, by LastSeenUnix (the same
// field ListDevices already exposes). Returns "" if devices is empty (an
// identity with zero devices — should not happen in practice since
// CreateIdentity always creates a first device, but handled without a
// panic regardless). Charter §4 names this as a real, narrow Art. 10
// exception: Identity choosing which device's bytes to relay, not pure
// storage/relay of already-signed bytes — disclosed here in code as well
// as in the charter, not silently exercised.
func mostRecentlyActiveDeviceID(devices []Device) string {
	if len(devices) == 0 {
		return ""
	}
	best := devices[0]
	for _, d := range devices[1:] {
		if d.LastSeenUnix > best.LastSeenUnix {
			best = d
		}
	}
	return best.DeviceID
}

// PublishPrekeyBundle replaces (req.IdentityRef, req.DeviceID)'s current
// signed prekey (rotation) and additively appends req.OneTimePrekeys to
// that device's pool (charter §3). Caller-binding (identity_ref/device_id
// == the verified network caller's own identity AND device) is enforced
// at the HTTP layer by wiring.go's requireCallerMatchesIdentityAndDevice
// — see http.go's Mount doc comment. This method independently re-checks
// that device_id is actually bound to identity_ref (defense in depth, and
// the same "an operation must not blindly trust HTTP-layer enforcement
// alone" discipline RevokeDevice already follows) — a caller whose device
// was revoked between session-issue and this call, or who reused a stale
// device_id, gets ErrDeviceNotFound rather than corrupting a stranger
// device's trust root.
//
// This service never generates, signs, or touches private key material
// here — signed_prekey/one_time_prekeys are already-public, already-signed
// bytes Cryptography & Keys' own GeneratePrekeyBundle produced (charter
// §3/§4/§10); this method's only job is validating shape (non-empty
// required fields) and storing/relaying those bytes unmodified (charter
// §6, "Signature integrity in storage").
//
// ascend:mutates
func (s *Service) PublishPrekeyBundle(req PublishPrekeyBundleRequest) (PublishPrekeyBundleResponse, error) {
	if req.IdentityRef == "" {
		return PublishPrekeyBundleResponse{}, fmt.Errorf("%w: identity_ref is required", ErrInvalidArgument)
	}
	if req.DeviceID == "" {
		return PublishPrekeyBundleResponse{}, fmt.Errorf("%w: device_id is required", ErrInvalidArgument)
	}
	if req.SignedPrekey.PrekeyID == "" || len(req.SignedPrekey.PublicKey) == 0 || len(req.SignedPrekey.Signature) == 0 || req.SignedPrekey.CreatedAtUnix <= 0 {
		return PublishPrekeyBundleResponse{}, fmt.Errorf("%w: signed_prekey requires a non-empty prekey_id, public_key, signature, and a positive created_at_unix", ErrInvalidArgument)
	}
	// identity_dh_public_key/identity_dh_public_key_signature (charter §3,
	// key-separation fix) are required on every call, same discipline as
	// signed_prekey above — this is what makes the fail-closed guarantee
	// (charter §3/§6: FetchPrekeyBundle must never observe a signed prekey
	// without a DH pair) hold by construction rather than by luck, since a
	// legitimate publish can never leave one populated without the other.
	if len(req.IdentityDhPublicKey) == 0 {
		return PublishPrekeyBundleResponse{}, fmt.Errorf("%w: identity_dh_public_key is required", ErrInvalidArgument)
	}
	if len(req.IdentityDhPublicKeySignature) == 0 {
		return PublishPrekeyBundleResponse{}, fmt.Errorf("%w: identity_dh_public_key_signature is required", ErrInvalidArgument)
	}
	for i, otp := range req.OneTimePrekeys {
		if otp.PrekeyID == "" || len(otp.PublicKey) == 0 {
			return PublishPrekeyBundleResponse{}, fmt.Errorf("%w: one_time_prekeys[%d] requires a non-empty prekey_id and public_key", ErrInvalidArgument, i)
		}
	}

	record, err := s.store.Get(req.IdentityRef)
	if err != nil {
		return PublishPrekeyBundleResponse{}, err
	}
	if deviceIndexByID(record.Devices, req.DeviceID) == -1 {
		return PublishPrekeyBundleResponse{}, ErrDeviceNotFound
	}

	publishedCount, err := s.prekeys.PublishBundle(req.IdentityRef, req.DeviceID, req.SignedPrekey, req.IdentityDhPublicKey, req.IdentityDhPublicKeySignature, req.OneTimePrekeys)
	if err != nil {
		return PublishPrekeyBundleResponse{}, err
	}

	if _, err := s.audit.Emit(req.IdentityRef, "identity.prekey_bundle_published",
		ResourceRef{ResourceType: "identity_device", ResourceID: req.DeviceID},
		"identity.publish_prekey_bundle",
		map[string]string{
			"identity_ref":               req.IdentityRef,
			"device_id":                  req.DeviceID,
			"signed_prekey_id":           req.SignedPrekey.PrekeyID,
			"one_time_prekeys_published": strconv.Itoa(int(publishedCount)),
			// Never key bytes — public or otherwise (charter §4/Art. 8:
			// "matching Cryptography & Keys' own 'never the key material
			// itself' discipline even though these particular keys are
			// public").
		}); err != nil {
		return PublishPrekeyBundleResponse{}, fmt.Errorf("prekey bundle published but audit emit failed: %w", err)
	}

	return PublishPrekeyBundleResponse{PublishedCount: publishedCount}, nil
}

// FetchPrekeyBundle is the one deliberately open, non-self-scoped read
// this capability exposes (charter §3/§6) — any authenticated caller may
// fetch any identity's bundle. fetcherActor is the network-verified
// caller's own identity_ref, supplied by the HTTP layer (http.go) from the
// session-auth-verified caller header — NOT part of the frozen
// FetchPrekeyBundleRequest wire shape (identity_ref/device_id only), the
// same "actor as a side-channel parameter, not a request field" shape
// internal/audit's Service.Query/Explain/ExportAuditTrail already
// establish for their own callerActor parameter. It is never validated
// against req.IdentityRef — this RPC's entire point is that a caller may
// fetch a DIFFERENT identity's bundle. It is used only as the Art. 5 audit
// actor (charter §4: "actor is the fetcher, not the target device's owner").
//
// Marked ascend:mutates despite being framed as a "fetch"/read, per
// charter §6's own explicit point: this is "an open-to-any-caller 'read'
// with a real, resource-depleting write side effect" — it atomically
// deletes a one-time prekey from the target's pool on a successful claim.
// The mechanical Art. 5 check (scripts/constitution/check-audit-events.sh)
// is therefore correctly applicable here, not skipped for being a nominal
// "read" — though the audit call itself is only reached on the branch that
// actually consumed a prekey, see below. The marker comment itself must sit
// on the line immediately above func (the mechanical check's own
// assumption — verified against the real script, not assumed), so this
// explanatory paragraph is placed before it, not after.
//
// ascend:mutates
func (s *Service) FetchPrekeyBundle(fetcherActor string, req FetchPrekeyBundleRequest) (FetchPrekeyBundleResponse, error) {
	if req.IdentityRef == "" {
		return FetchPrekeyBundleResponse{}, fmt.Errorf("%w: identity_ref is required", ErrInvalidArgument)
	}

	// A nonexistent identity_ref is a genuine error (ErrIdentityNotFound),
	// not folded into PrekeyBundleStatusNotPublished — identity_ref
	// existence is already discoverable via the equally-open
	// ResolveIdentity (a plain 404 for an unknown ref), so returning a
	// distinct error here discloses nothing ResolveIdentity doesn't
	// already. The enumeration oracle this amendment closes (charter §6)
	// is specifically about device_id values WITHIN a known identity_ref,
	// not about identity_ref existence itself — see
	// docs/DECISION_LOG.md for this distinction stated as a real decision.
	record, err := s.store.Get(req.IdentityRef)
	if err != nil {
		return FetchPrekeyBundleResponse{}, err
	}

	deviceID := req.DeviceID
	if deviceID == "" {
		deviceID = mostRecentlyActiveDeviceID(record.Devices)
	}

	// Enumeration-oracle closure (charter §6, Security Steward gate
	// finding round 1): a caller-supplied device_id not bound to
	// identity_ref at all produces the EXACT SAME response as "device_id
	// is bound but has never published a bundle" — both fall through to
	// the identical PrekeyBundleStatusNotPublished return below, with
	// every other field left at Go zero-value. Never branch differently
	// between these two cases beyond this point.
	if deviceID == "" || deviceIndexByID(record.Devices, deviceID) == -1 {
		return FetchPrekeyBundleResponse{Status: PrekeyBundleStatusNotPublished}, nil
	}

	signedPrekey, identityDhPublicKey, identityDhPublicKeySignature, published, err := s.prekeys.GetSignedPrekey(req.IdentityRef, deviceID)
	if err != nil {
		return FetchPrekeyBundleResponse{}, err
	}
	if !published {
		// Brand-new-identity edge case (charter §3/§7): a real, bound
		// device that has simply never called PublishPrekeyBundle yet — OR
		// (fail-closed, charter §3/§6, key-separation fix) a signed prekey
		// exists but the identity_dh_public_key/identity_dh_public_key_signature
		// pair is missing — both collapse into found=false at the store
		// layer (PrekeyStore.GetSignedPrekey's doc comment) and so both
		// produce byte-for-byte the same response shape as the
		// unbound-device_id case immediately above, by construction (same
		// status value, every other field already at zero-value).
		return FetchPrekeyBundleResponse{Status: PrekeyBundleStatusNotPublished}, nil
	}

	resp := FetchPrekeyBundleResponse{
		Status:              PrekeyBundleStatusAvailable,
		IdentityDhPublicKey: identityDhPublicKey,
		DeviceID:            deviceID,
		SignedPrekey:        signedPrekey,
		// IdentitySigningPublicKey (proto field 6, key-separation fix):
		// sourced from the identity record itself — the same Ed25519
		// signing key ResolveIdentity returns — NOT from the prekey table.
		// Genuinely distinct from identityDhPublicKey above.
		IdentitySigningPublicKey:     record.PublicKey,
		IdentityDhPublicKeySignature: identityDhPublicKeySignature,
	}

	// The atomic claim (charter §6's core requirement — see
	// postgres_prekey_store.go's ClaimOneOneTimePrekey doc comment for the
	// single-statement construction). found=false is the exhaustion-
	// fallback case (charter §3), not an error: one_time_prekey is simply
	// left absent (nil pointer, per types.go's FetchPrekeyBundleResponse
	// doc comment), and no audit event is emitted for this branch — Art. 5
	// scopes the audit obligation to consuming calls specifically (charter
	// §4: "every one-time-prekey-consuming FetchPrekeyBundle call"), not
	// every call that merely reaches AVAILABLE status.
	claimed, claimedOK, err := s.prekeys.ClaimOneOneTimePrekey(req.IdentityRef, deviceID)
	if err != nil {
		return FetchPrekeyBundleResponse{}, err
	}
	if !claimedOK {
		return resp, nil
	}
	resp.OneTimePrekey = &claimed

	if _, err := s.audit.Emit(fetcherActor, "identity.prekey_bundle_fetched",
		ResourceRef{ResourceType: "identity_device", ResourceID: deviceID},
		"identity.fetch_prekey_bundle.one_time_prekey_consumed",
		map[string]string{
			"identity_ref":                req.IdentityRef,
			"device_id":                   deviceID,
			"one_time_prekey_id_consumed": claimed.PrekeyID,
			// Never key bytes — public or otherwise. Never logs the
			// fetcher's own identity to the TARGET's own trail by a
			// different rule — this is the same single audit event
			// resolvable by actor=fetcherActor (charter §4: "the target
			// identity does not automatically see 'someone fetched my
			// bundle' unless a future capability explicitly surfaces
			// it" — that's Audit's own actor-scoped Query visibility
			// doing its job, not a second suppression mechanism here).
		}); err != nil {
		return FetchPrekeyBundleResponse{}, fmt.Errorf("prekey bundle fetched but audit emit failed: %w", err)
	}

	return resp, nil
}
