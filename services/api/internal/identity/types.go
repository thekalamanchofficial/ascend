// Package identity implements the Identity capability
// (docs/capabilities/identity.charter.md) against the frozen contract at
// packages/contracts/proto/ascend/identity/v1/identity.proto.
//
// No codegen toolchain is wired up yet (see docs/DECISION_LOG.md,
// 2026-07-16, "Identity, Permissions, Audit / Explainability interfaces
// frozen..."), so the types below are a hand-written mirror of the proto
// messages, following the precedent set by Cryptography & Keys. Field names
// use camelCase JSON tags to match protojson's default output, so the HTTP
// surface in http.go will not need to change shape once real codegen lands.
package identity

// Device mirrors the `Device` proto message. It never carries private key
// material — only the public key needed to verify a signature made by this
// device (see sign.go) and the metadata a user needs to recognize it.
//
// ascend:persisted
type Device struct {
	DeviceID     string `json:"deviceId"`
	Name         string `json:"name"`
	PublicKey    []byte `json:"publicKey"`
	AddedAtUnix  int64  `json:"addedAtUnix"`
	LastSeenUnix int64  `json:"lastSeenUnix"`
}

// PublicIdentity mirrors the `PublicIdentity` proto message — the
// read-only, public-facing projection other capabilities (Permissions'
// subject resolution, Audit's actor resolution) resolve via
// ResolveIdentity.
//
// Epoch (proto field 5, added 2026-07-16) is the discoverability fix for
// the anti-replay mechanism in sign.go/service.go: a client must sign a
// BindDevice authorization_proof against the identity's *current* epoch,
// and this is the field that lets it fetch that value (via CreateIdentity
// or ResolveIdentity) immediately before signing, rather than having to
// track it via local bookkeeping.
type PublicIdentity struct {
	IdentityRef string `json:"identityRef"`
	DisplayName string `json:"displayName"`
	PublicKey   []byte `json:"publicKey"`
	DeviceCount int32  `json:"deviceCount"`
	Epoch       int64  `json:"epoch"`
}

// IdentityRecord is this capability's full persisted aggregate: the public
// identity record plus every currently-bound device. It is the source of
// truth ExportIdentity, ResolveIdentity, and ListDevices all read from.
//
// Per the Art. 8 data manifest (DATA_MANIFEST.md), every field here is one
// of the documented fields (display_name, public_key(s), device.name,
// device.added_at, device.last_seen, created_at, epoch) plus the
// identity_ref this service itself issues as an opaque handle — no other
// data is collected at this layer.
//
// Epoch is a monotonically increasing device-topology version counter, not
// user-supplied data — see sign.go's doc comment and docs/DECISION_LOG.md
// (2026-07-16, "Fix: BindDevice replay — monotonic per-identity epoch
// bound into the signed message") for why it exists: it is the
// anti-replay input bound into every BindDevice authorization_proof, and
// is incremented on every successful BindDevice/RevokeDevice so a proof
// captured before a topology change (including a revoke) can never verify
// again afterward.
//
// ascend:persisted
type IdentityRecord struct {
	IdentityRef   string   `json:"identityRef"`
	DisplayName   string   `json:"displayName"`
	PublicKey     []byte   `json:"publicKey"`
	Devices       []Device `json:"devices"`
	CreatedAtUnix int64    `json:"createdAtUnix"`
	Epoch         int64    `json:"epoch"`
}

// --- Request/response DTOs, one per RPC in identity.proto ---

type CreateIdentityRequest struct {
	DisplayName          string `json:"displayName"`
	PublicKey            []byte `json:"publicKey"`
	FirstDevicePublicKey []byte `json:"firstDevicePublicKey"`
	FirstDeviceName      string `json:"firstDeviceName"`
}

type CreateIdentityResponse struct {
	PublicIdentity PublicIdentity `json:"publicIdentity"`
	FirstDevice    Device         `json:"firstDevice"`
}

type BindDeviceRequest struct {
	IdentityRef        string `json:"identityRef"`
	DevicePublicKey    []byte `json:"devicePublicKey"`
	DeviceName         string `json:"deviceName"`
	AuthorizationProof []byte `json:"authorizationProof"`
}

type BindDeviceResponse struct {
	Device Device `json:"device"`
	// Epoch (proto field 2, added 2026-07-16) is the identity's epoch
	// *after* this bind (already advanced) — lets a client binding
	// several devices in one flow sign the next proof without a
	// round-trip back through ResolveIdentity.
	Epoch int64 `json:"epoch"`
}

type RevokeDeviceRequest struct {
	IdentityRef string `json:"identityRef"`
	DeviceID    string `json:"deviceId"`
}

type RevokeDeviceResponse struct {
	// Epoch (proto field 1, added 2026-07-16) is the identity's epoch
	// *after* this revoke — same rationale as BindDeviceResponse.Epoch.
	Epoch int64 `json:"epoch"`
}

type ResolveIdentityRequest struct {
	IdentityRef string `json:"identityRef"`
}

type ResolveIdentityResponse struct {
	PublicIdentity PublicIdentity `json:"publicIdentity"`
}

type ListDevicesRequest struct {
	IdentityRef string `json:"identityRef"`
}

type ListDevicesResponse struct {
	Devices []Device `json:"devices"`
}

type ExportIdentityRequest struct {
	IdentityRef string `json:"identityRef"`
}

type ExportIdentityResponse struct {
	ExportBlob    []byte `json:"exportBlob"`
	FormatVersion string `json:"formatVersion"`
}
