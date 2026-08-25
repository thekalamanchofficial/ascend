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
// UnconsumedOneTimePrekeyCount (proto field 6, added 2026-08-20, prekey
// bundle publish/fetch amendment) is deliberately NOT marked
// ascend:persisted-relevant the way the rest of this struct is: it is a
// derived count (charter §4 — "a derived count, not a new persisted
// field... computed from the same pool" the SignedPrekey/
// OneTimePrekeyPublic types below cover), never itself written with a real
// value to the `identities` table's JSONB devices column.
// PostgresStore.Create/Replace (postgres_store.go) marshal this field like
// any other on Device, but every Device this package ever constructs
// before persisting (CreateIdentity, BindDevice) leaves it at its Go zero
// value (0) — correct anyway, since a brand-new/just-bound device has
// never published a bundle. Service.ListDevices (service.go) is the only
// place that overwrites this field with the real, freshly-computed count,
// on the in-memory response slice only, immediately before returning —
// never written back to the store. See service.go's ListDevices doc
// comment for why.
//
// ascend:persisted
type Device struct {
	DeviceID                     string `json:"deviceId"`
	Name                         string `json:"name"`
	PublicKey                    []byte `json:"publicKey"`
	AddedAtUnix                  int64  `json:"addedAtUnix"`
	LastSeenUnix                 int64  `json:"lastSeenUnix"`
	UnconsumedOneTimePrekeyCount int32  `json:"unconsumedOneTimePrekeyCount"`
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

// --- Prekey bundle publish/fetch (charter §3/§4/§6, amendment gated
// 2026-08-20; identity.proto AMENDED 2026-08-20). Pure storage/relay for
// public prekey material Cryptography & Keys already generated and signed
// — this package never generates, signs, or touches private key material
// here either. Deliberately NOT marked ascend:persisted (see
// 0009_identity_prekeys.up.sql's doc comment and export.go's
// exportedDevice comment): charter §4 explicitly excludes prekey state
// from ExportIdentity's output as ephemeral, auto-regenerating routing
// infrastructure, so the mechanical Art. 9 export-path check is correctly
// not triggered for these two types. ---

// SignedPrekey mirrors ascend.identity.v1.SignedPrekey exactly (which
// itself mirrors ascend.crypto.v1.SignedPrekey — see identity.proto's own
// comment on why it's duplicated rather than imported). This service
// stores/relays the signature byte-for-byte as published and never
// regenerates, re-signs, or reformats it (charter §6, "Signature integrity
// in storage").
type SignedPrekey struct {
	PrekeyID      string `json:"prekeyId"`
	PublicKey     []byte `json:"publicKey"`
	Signature     []byte `json:"signature"`
	CreatedAtUnix int64  `json:"createdAtUnix"`
}

// OneTimePrekeyPublic mirrors ascend.identity.v1.OneTimePrekeyPublic.
type OneTimePrekeyPublic struct {
	PrekeyID  string `json:"prekeyId"`
	PublicKey []byte `json:"publicKey"`
}

// PrekeyBundleStatus mirrors the `PrekeyBundleStatus` proto enum. Encoded
// as its declared string name, not an integer — this is this codebase's
// first hand-mirrored proto enum (identity.proto's own contract-freezing
// comment on PrekeyBundleStatus), and protojson's default enum encoding is
// the string name, not the numeric value; using a Go string type (which
// encoding/json marshals as a plain JSON string automatically, no custom
// MarshalJSON needed) is what actually matches that default output, per
// this package's established "camelCase JSON tags matching protojson's
// default output" convention (see this file's header comment). Logged as
// a real decision in docs/DECISION_LOG.md.
type PrekeyBundleStatus string

const (
	PrekeyBundleStatusUnspecified PrekeyBundleStatus = "PREKEY_BUNDLE_STATUS_UNSPECIFIED"
	PrekeyBundleStatusAvailable   PrekeyBundleStatus = "PREKEY_BUNDLE_STATUS_AVAILABLE"
	// PrekeyBundleStatusNotPublished covers BOTH "no bundle ever published
	// for this device" AND "device_id not bound to identity_ref" —
	// deliberately the same value, deliberately indistinguishable to the
	// caller (charter §3/§6, closing the device-ID enumeration oracle both
	// guardians found in round 1 of this amendment's gate). Every caller
	// that reaches this status MUST produce a byte-for-byte identical
	// FetchPrekeyBundleResponse regardless of which of those two cases
	// produced it — see service.go's FetchPrekeyBundle.
	PrekeyBundleStatusNotPublished PrekeyBundleStatus = "PREKEY_BUNDLE_STATUS_NOT_PUBLISHED"
)

// PublishPrekeyBundleRequest mirrors PublishPrekeyBundleRequest.
// IdentityRef/DeviceID are carried in the URL path by the real RPC (POST
// /v1/identity/{identityRef}/devices/{deviceId}/prekeys — see http.go),
// not the JSON body, mirroring BindDeviceRequest's own precedent — the
// HTTP handler overwrites whatever the body sends for these two fields
// with the path params, which is also what the device-binding middleware
// (wiring.go's requireCallerMatchesIdentityAndDevice) checks against.
//
// IdentityDhPublicKey/IdentityDhPublicKeySignature (proto fields 5/6, added
// 2026-08-21, the key-separation fix — identity.proto's own comment on
// PublishPrekeyBundleRequest) are the device's genuinely separate,
// DH-only X25519 key and its Ed25519 signature over that key. Stable,
// non-rotating per device, but republished/upserted on every call anyway —
// this service has no way to derive them independently. Stored/relayed
// verbatim, exactly like SignedPrekey — never generated, signed, or
// verified here.
type PublishPrekeyBundleRequest struct {
	IdentityRef                  string                `json:"identityRef"`
	DeviceID                     string                `json:"deviceId"`
	SignedPrekey                 SignedPrekey          `json:"signedPrekey"`
	OneTimePrekeys               []OneTimePrekeyPublic `json:"oneTimePrekeys"`
	IdentityDhPublicKey          []byte                `json:"identityDhPublicKey"`
	IdentityDhPublicKeySignature []byte                `json:"identityDhPublicKeySignature"`
}

type PublishPrekeyBundleResponse struct {
	// PublishedCount is the number of one_time_prekeys entries genuinely
	// newly stored by this call (charter §3's "additively appends" —
	// re-publishing an already-known prekey_id is a no-op, not counted
	// again; see postgres_prekey_store.go's PublishBundle doc comment).
	// The signed prekey rotation itself is not counted here — it is
	// always exactly one replace per call, not a pool size.
	PublishedCount int32 `json:"publishedCount"`
}

// FetchPrekeyBundleRequest mirrors FetchPrekeyBundleRequest. DeviceID is a
// Go string, not a pointer/optional wrapper — the proto field is
// `optional string device_id`, and an empty string and "omitted" are the
// same observable case for this RPC's purposes (a real device_id is never
// legitimately empty — see idgen.go), so a plain zero-value string is
// sufficient to detect "omitted" without introducing a nilable type this
// package's other hand-mirrored request types don't use.
type FetchPrekeyBundleRequest struct {
	IdentityRef string `json:"identityRef"`
	DeviceID    string `json:"deviceId,omitempty"`
}

// FetchPrekeyBundleResponse mirrors FetchPrekeyBundleResponse. Fields
// below IdentityDhPublicKey..OneTimePrekey are populated only when
// Status == PrekeyBundleStatusAvailable; left at Go zero-value otherwise
// (identity.proto's own comment on FetchPrekeyBundleResponse), so a
// NOT_PUBLISHED response is byte-for-byte identical regardless of which
// NOT_PUBLISHED case produced it.
//
// IdentityDhPublicKey (renamed from IdentityPublicKey, 2026-08-21
// key-separation fix — identity.proto's own comment on this field) is the
// target device's stored X25519 DH-capable key (proto field 2) — NEVER
// record.PublicKey (the Ed25519 signing key). IdentitySigningPublicKey
// (proto field 6, NEW) and IdentityDhPublicKeySignature (proto field 7,
// NEW) were added by the same fix so a caller can verify
// IdentityDhPublicKey/SignedPrekey's signatures without a second round
// trip through ResolveIdentity — see service.go's FetchPrekeyBundle for
// where each is sourced from.
type FetchPrekeyBundleResponse struct {
	Status              PrekeyBundleStatus `json:"status"`
	IdentityDhPublicKey []byte             `json:"identityDhPublicKey,omitempty"`
	DeviceID            string             `json:"deviceId,omitempty"`
	SignedPrekey        SignedPrekey       `json:"signedPrekey"`
	// OneTimePrekey is a pointer so its absence (exhaustion-fallback case,
	// charter §3 — distinct from NOT_PUBLISHED) is a real, distinguishable
	// JSON `null`/absent value, matching the proto's `optional
	// OneTimePrekeyPublic one_time_prekey = 5` field-presence semantics —
	// every other []byte/struct field in this package's hand-mirrored
	// types uses zero-value-means-absent, but this is the one field where
	// "present with zero-value contents" (an empty prekey_id/public_key)
	// is NOT the same observable case as "absent", so a pointer is used
	// deliberately here and nowhere else in this file.
	OneTimePrekey *OneTimePrekeyPublic `json:"oneTimePrekey,omitempty"`
	// IdentitySigningPublicKey (proto field 6, NEW 2026-08-21) is the
	// identity's Ed25519 SIGNING public key — sourced from the identity
	// record itself (the same value ResolveIdentity returns), NOT from the
	// prekey table. Genuinely distinct from IdentityDhPublicKey above.
	IdentitySigningPublicKey []byte `json:"identitySigningPublicKey,omitempty"`
	// IdentityDhPublicKeySignature (proto field 7, NEW 2026-08-21) is the
	// target device's stored Ed25519 signature over IdentityDhPublicKey —
	// verified by the caller against IdentitySigningPublicKey before
	// IdentityDhPublicKey is used in any DH computation.
	IdentityDhPublicKeySignature []byte `json:"identityDhPublicKeySignature,omitempty"`
}
