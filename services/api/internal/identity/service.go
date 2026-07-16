package identity

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"time"
)

// Service implements the six IdentityService RPCs (identity.proto) against
// a Store and an AuditEmitter, both dependency-injected via NewService —
// see docs/DECISION_LOG.md for why (storage seam + audit seam decisions).
type Service struct {
	store Store
	audit AuditEmitter
}

// NewService wires a Service. `store` is this capability's persistence
// seam — pass NewInMemoryStore() for this pass (see docs/DECISION_LOG.md);
// a nil store defaults to a fresh in-memory store so callers can't
// construct a Service that panics on first use. `emitter` is the Art. 5
// audit seam (see AuditEmitter in audit.go); production wiring must supply
// a real emitter — a nil emitter defaults to NoopAuditEmitter, which fails
// loudly (returns an error) rather than silently dropping audit events.
func NewService(store Store, emitter AuditEmitter) *Service {
	if store == nil {
		store = NewInMemoryStore()
	}
	if emitter == nil {
		emitter = NoopAuditEmitter{}
	}
	return &Service{store: store, audit: emitter}
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
func (s *Service) ListDevices(req ListDevicesRequest) (ListDevicesResponse, error) {
	if req.IdentityRef == "" {
		return ListDevicesResponse{}, fmt.Errorf("%w: identity_ref is required", ErrInvalidArgument)
	}
	record, err := s.store.Get(req.IdentityRef)
	if err != nil {
		return ListDevicesResponse{}, err
	}
	return ListDevicesResponse{Devices: record.Devices}, nil
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
