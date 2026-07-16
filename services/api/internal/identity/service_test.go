package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

// fakeAuditEmitter is the test double for AuditEmitter described in this
// capability's brief ("Write your own tests against a fake implementing
// that interface"). It records every call so tests can assert Art. 5
// coverage (every bind/revoke/export — and, here, every rejected bind
// attempt too — produces a discoverable event).
type fakeAuditEmitter struct {
	mu     sync.Mutex
	events []fakeAuditEvent
}

type fakeAuditEvent struct {
	Actor         string
	Action        string
	Resource      ResourceRef
	RuleReference string
	Metadata      map[string]string
}

func (f *fakeAuditEmitter) Emit(actor, action string, resource ResourceRef, ruleReference string, metadata map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, fakeAuditEvent{
		Actor: actor, Action: action, Resource: resource,
		RuleReference: ruleReference, Metadata: metadata,
	})
	return newID(), nil
}

func (f *fakeAuditEmitter) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.events))
	for i, e := range f.events {
		out[i] = e.Action
	}
	return out
}

func newTestService() (*Service, *fakeAuditEmitter) {
	emitter := &fakeAuditEmitter{}
	svc := NewService(NewInMemoryStore(), emitter)
	return svc, emitter
}

func mustGenerateKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func createTestIdentity(t *testing.T, svc *Service) (CreateIdentityResponse, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	identityPub, identityPriv := mustGenerateKey(t)
	devicePub, devicePriv := mustGenerateKey(t)

	resp, err := svc.CreateIdentity(CreateIdentityRequest{
		DisplayName:          "Ada Lovelace",
		PublicKey:            identityPub,
		FirstDevicePublicKey: devicePub,
		FirstDeviceName:      "Ada's Laptop",
	})
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	return resp, identityPriv, devicePriv
}

// --- Full happy-path flow: CreateIdentity -> BindDevice (valid signature,
// already-bound-device path) -> ListDevices -> RevokeDevice. ---

func TestFullFlow_CreateBindListRevoke(t *testing.T) {
	svc, emitter := newTestService()

	created, _, firstDevicePriv := createTestIdentity(t, svc)
	identityRef := created.PublicIdentity.IdentityRef

	if created.PublicIdentity.DeviceCount != 1 {
		t.Fatalf("expected device_count 1 after CreateIdentity, got %d", created.PublicIdentity.DeviceCount)
	}

	// Bind a second device, authorized by the first (already-bound)
	// device's private key.
	secondPub, _ := mustGenerateKey(t)
	message := buildDeviceBindingMessage(identityRef, secondPub, "Ada's Phone", 0) // epoch 0: fresh identity, no bind/revoke yet
	proof := ed25519.Sign(firstDevicePriv, message)

	bindResp, err := svc.BindDevice(BindDeviceRequest{
		IdentityRef:        identityRef,
		DevicePublicKey:    secondPub,
		DeviceName:         "Ada's Phone",
		AuthorizationProof: proof,
	})
	if err != nil {
		t.Fatalf("BindDevice: %v", err)
	}
	if bindResp.Device.Name != "Ada's Phone" {
		t.Fatalf("unexpected bound device name: %q", bindResp.Device.Name)
	}

	listResp, err := svc.ListDevices(ListDevicesRequest{IdentityRef: identityRef})
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(listResp.Devices) != 2 {
		t.Fatalf("expected 2 devices after bind, got %d", len(listResp.Devices))
	}

	resolveResp, err := svc.ResolveIdentity(ResolveIdentityRequest{IdentityRef: identityRef})
	if err != nil {
		t.Fatalf("ResolveIdentity: %v", err)
	}
	if resolveResp.PublicIdentity.DeviceCount != 2 {
		t.Fatalf("expected device_count 2, got %d", resolveResp.PublicIdentity.DeviceCount)
	}

	// Revoke the first device.
	firstDeviceID := created.FirstDevice.DeviceID
	if _, err := svc.RevokeDevice(RevokeDeviceRequest{IdentityRef: identityRef, DeviceID: firstDeviceID}); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}

	listResp, err = svc.ListDevices(ListDevicesRequest{IdentityRef: identityRef})
	if err != nil {
		t.Fatalf("ListDevices after revoke: %v", err)
	}
	if len(listResp.Devices) != 1 {
		t.Fatalf("expected 1 device after revoke, got %d", len(listResp.Devices))
	}
	if listResp.Devices[0].DeviceID == firstDeviceID {
		t.Fatalf("revoked device %q is still present", firstDeviceID)
	}

	// Art. 5: every mutation above must be discoverable in the audit
	// trail.
	actions := emitter.actions()
	wantSeen := map[string]bool{
		"identity.created":        false,
		"identity.device_bound":   false,
		"identity.device_revoked": false,
	}
	for _, a := range actions {
		if _, ok := wantSeen[a]; ok {
			wantSeen[a] = true
		}
	}
	for action, seen := range wantSeen {
		if !seen {
			t.Errorf("expected audit action %q to have been emitted; got actions %v", action, actions)
		}
	}
}

// BindDevice via the recovery path: a self-signed assertion derived from
// the identity's own root key (standing in for Cryptography & Keys'
// RestoreFromRecoveryPhrase + Sign, per charter §3/§7). Per charter §3/§7
// this service has no discretionary authority to reject a validly-signed
// recovery assertion — it must be accepted exactly like a device-signed
// one.
func TestBindDevice_RecoveryPathSelfSignedAssertion(t *testing.T) {
	svc, _ := newTestService()
	created, identityPriv, _ := createTestIdentity(t, svc)
	identityRef := created.PublicIdentity.IdentityRef

	newDevicePub, _ := mustGenerateKey(t)
	message := buildDeviceBindingMessage(identityRef, newDevicePub, "Recovered Device", 0)
	proof := ed25519.Sign(identityPriv, message)

	resp, err := svc.BindDevice(BindDeviceRequest{
		IdentityRef:        identityRef,
		DevicePublicKey:    newDevicePub,
		DeviceName:         "Recovered Device",
		AuthorizationProof: proof,
	})
	if err != nil {
		t.Fatalf("BindDevice via recovery path should succeed: %v", err)
	}
	if resp.Device.Name != "Recovered Device" {
		t.Fatalf("unexpected device name: %q", resp.Device.Name)
	}
}

// A forged/invalid signature must be rejected — the device-spoofing threat
// charter §6 names explicitly — and the rejection itself must be
// audit-logged (a user can discover an attempted, failed binding).
func TestBindDevice_InvalidSignatureRejected(t *testing.T) {
	svc, emitter := newTestService()
	created, _, _ := createTestIdentity(t, svc)
	identityRef := created.PublicIdentity.IdentityRef

	newDevicePub, _ := mustGenerateKey(t)
	// Signed by an unrelated keypair, not the identity root key or any
	// bound device's key — this must not authorize a binding.
	_, unrelatedPriv := mustGenerateKey(t)
	message := buildDeviceBindingMessage(identityRef, newDevicePub, "Attacker Device", 0)
	forgedProof := ed25519.Sign(unrelatedPriv, message)

	_, err := svc.BindDevice(BindDeviceRequest{
		IdentityRef:        identityRef,
		DevicePublicKey:    newDevicePub,
		DeviceName:         "Attacker Device",
		AuthorizationProof: forgedProof,
	})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}

	listResp, _ := svc.ListDevices(ListDevicesRequest{IdentityRef: identityRef})
	if len(listResp.Devices) != 1 {
		t.Fatalf("rejected bind must not add a device; got %d devices", len(listResp.Devices))
	}

	found := false
	for _, a := range emitter.actions() {
		if a == "identity.device_bind_rejected" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a device_bind_rejected audit event; got actions %v", emitter.actions())
	}
}

// A garbage (wrong-length) authorization_proof must also be rejected, not
// panic.
func TestBindDevice_MalformedProofRejected(t *testing.T) {
	svc, _ := newTestService()
	created, _, _ := createTestIdentity(t, svc)
	newDevicePub, _ := mustGenerateKey(t)

	_, err := svc.BindDevice(BindDeviceRequest{
		IdentityRef:        created.PublicIdentity.IdentityRef,
		DevicePublicKey:    newDevicePub,
		DeviceName:         "Bad Proof Device",
		AuthorizationProof: []byte("not-a-real-signature"),
	})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for malformed proof, got %v", err)
	}
}

func TestBindDevice_DuplicatePublicKeyRejected(t *testing.T) {
	svc, _ := newTestService()
	created, _, firstDevicePriv := createTestIdentity(t, svc)
	identityRef := created.PublicIdentity.IdentityRef

	// Attempt to bind the already-bound first device's own public key
	// again.
	message := buildDeviceBindingMessage(identityRef, created.FirstDevice.PublicKey, "Duplicate", 0)
	proof := ed25519.Sign(firstDevicePriv, message)

	_, err := svc.BindDevice(BindDeviceRequest{
		IdentityRef:        identityRef,
		DevicePublicKey:    created.FirstDevice.PublicKey,
		DeviceName:         "Duplicate",
		AuthorizationProof: proof,
	})
	if !errors.Is(err, ErrDuplicateDeviceKey) {
		t.Fatalf("expected ErrDuplicateDeviceKey, got %v", err)
	}
}

// Regression test required by the 2026-07-16 Security Steward merge-gate
// veto: a device's original, unmodified authorization_proof must stop
// working the instant that device is revoked — otherwise anyone holding a
// copy of a previously-valid proof (e.g. from logs, or a compromised
// operator with access to past traffic) could replay it forever to
// silently re-add a device the user explicitly revoked, which the server
// would have no discretionary authority to refuse per charter §3/§7's
// "no gatekeeping a validly-signed proof" rule. The fix (sign.go) binds
// IdentityRecord.Epoch — incremented on every successful BindDevice AND
// RevokeDevice — into the signed message, so this exact scenario is what
// it exists to prevent. This test also exercises the follow-up
// discoverability fix (2026-07-16, epoch exposed on PublicIdentity/
// BindDeviceResponse/RevokeDeviceResponse): every epoch value used below
// is read from a response field, never hardcoded, proving a real caller
// can discover the correct epoch to sign against without local
// bookkeeping.
func TestBindDevice_RevokedDeviceOriginalProofReplayRejected(t *testing.T) {
	svc, _ := newTestService()
	created, _, firstDevicePriv := createTestIdentity(t, svc)
	identityRef := created.PublicIdentity.IdentityRef

	if created.PublicIdentity.Epoch != 0 {
		t.Fatalf("expected epoch 0 on a freshly created identity, got %d", created.PublicIdentity.Epoch)
	}

	// Bind device X against the epoch CreateIdentity reported — no
	// hardcoded value, no separate ResolveIdentity round-trip needed.
	xPub, _ := mustGenerateKey(t)
	originalMessage := buildDeviceBindingMessage(identityRef, xPub, "Device X", created.PublicIdentity.Epoch)
	originalProof := ed25519.Sign(firstDevicePriv, originalMessage)

	bindResp, err := svc.BindDevice(BindDeviceRequest{
		IdentityRef:        identityRef,
		DevicePublicKey:    xPub,
		DeviceName:         "Device X",
		AuthorizationProof: originalProof,
	})
	if err != nil {
		t.Fatalf("initial BindDevice for X: %v", err)
	}
	if bindResp.Epoch != 1 {
		t.Fatalf("expected epoch 1 after the first bind, got %d", bindResp.Epoch)
	}

	// Revoke X.
	revokeResp, err := svc.RevokeDevice(RevokeDeviceRequest{IdentityRef: identityRef, DeviceID: bindResp.Device.DeviceID})
	if err != nil {
		t.Fatalf("RevokeDevice for X: %v", err)
	}
	if revokeResp.Epoch != 2 {
		t.Fatalf("expected epoch 2 after the revoke, got %d", revokeResp.Epoch)
	}

	// Replay the exact, original, unmodified authorization_proof — same
	// device_public_key, same device_name, same proof bytes. This must now
	// be rejected: device-set membership is back to exactly what it was
	// before X was ever bound (only the first device), which is precisely
	// the scenario a naive "hash of current bound-device-ID set" freshness
	// check would fail to catch — the monotonic epoch counter must still
	// catch it, because epoch never reverts to a prior value.
	_, err = svc.BindDevice(BindDeviceRequest{
		IdentityRef:        identityRef,
		DevicePublicKey:    xPub,
		DeviceName:         "Device X",
		AuthorizationProof: originalProof,
	})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected replayed post-revoke proof to be rejected with ErrInvalidSignature, got %v", err)
	}

	listResp, _ := svc.ListDevices(ListDevicesRequest{IdentityRef: identityRef})
	if len(listResp.Devices) != 1 {
		t.Fatalf("replayed proof must not have re-added device X; got %d devices", len(listResp.Devices))
	}

	// Sanity check the fix isn't overbroad: a FRESH proof, signed against
	// the epoch RevokeDevice just reported, must still succeed —
	// legitimate re-binding after a revoke is not itself the thing being
	// prevented. Confirm discoverability via ResolveIdentity too, not just
	// the mutation responses.
	resolveResp, err := svc.ResolveIdentity(ResolveIdentityRequest{IdentityRef: identityRef})
	if err != nil {
		t.Fatalf("ResolveIdentity: %v", err)
	}
	if resolveResp.PublicIdentity.Epoch != revokeResp.Epoch {
		t.Fatalf("ResolveIdentity epoch (%d) disagrees with RevokeDevice's reported epoch (%d)", resolveResp.PublicIdentity.Epoch, revokeResp.Epoch)
	}

	freshMessage := buildDeviceBindingMessage(identityRef, xPub, "Device X", resolveResp.PublicIdentity.Epoch)
	freshProof := ed25519.Sign(firstDevicePriv, freshMessage)
	if _, err := svc.BindDevice(BindDeviceRequest{
		IdentityRef:        identityRef,
		DevicePublicKey:    xPub,
		DeviceName:         "Device X",
		AuthorizationProof: freshProof,
	}); err != nil {
		t.Fatalf("expected a freshly-signed, current-epoch proof to succeed after revoke, got %v", err)
	}
}

func TestRevokeDevice_UnknownDeviceOrIdentity(t *testing.T) {
	svc, _ := newTestService()
	created, _, _ := createTestIdentity(t, svc)

	if _, err := svc.RevokeDevice(RevokeDeviceRequest{IdentityRef: created.PublicIdentity.IdentityRef, DeviceID: "does-not-exist"}); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("expected ErrDeviceNotFound, got %v", err)
	}
	if _, err := svc.RevokeDevice(RevokeDeviceRequest{IdentityRef: "does-not-exist", DeviceID: created.FirstDevice.DeviceID}); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("expected ErrIdentityNotFound, got %v", err)
	}
}

func TestCreateIdentity_ValidationErrors(t *testing.T) {
	svc, _ := newTestService()
	pub, _ := mustGenerateKey(t)

	cases := []CreateIdentityRequest{
		{DisplayName: "", PublicKey: pub, FirstDevicePublicKey: pub, FirstDeviceName: "d"},
		{DisplayName: "Ada", PublicKey: []byte("short"), FirstDevicePublicKey: pub, FirstDeviceName: "d"},
		{DisplayName: "Ada", PublicKey: pub, FirstDevicePublicKey: []byte("short"), FirstDeviceName: "d"},
		{DisplayName: "Ada", PublicKey: pub, FirstDevicePublicKey: pub, FirstDeviceName: ""},
	}
	for i, c := range cases {
		if _, err := svc.CreateIdentity(c); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("case %d: expected ErrInvalidArgument, got %v", i, err)
		}
	}
}

// ExportIdentity must produce a complete, parseable record (Art. 9), and
// must itself emit an audit event per charter §3/§4.
func TestExportIdentity_ProducesCompleteParseableRecord(t *testing.T) {
	svc, emitter := newTestService()
	created, identityPriv, firstDevicePriv := createTestIdentity(t, svc)
	identityRef := created.PublicIdentity.IdentityRef

	secondPub, _ := mustGenerateKey(t)
	message := buildDeviceBindingMessage(identityRef, secondPub, "Second Device", 0)
	proof := ed25519.Sign(firstDevicePriv, message)
	if _, err := svc.BindDevice(BindDeviceRequest{
		IdentityRef: identityRef, DevicePublicKey: secondPub,
		DeviceName: "Second Device", AuthorizationProof: proof,
	}); err != nil {
		t.Fatalf("BindDevice: %v", err)
	}
	_ = identityPriv // used above only to derive resp; kept for clarity of ownership

	exportResp, err := svc.ExportIdentity(ExportIdentityRequest{IdentityRef: identityRef})
	if err != nil {
		t.Fatalf("ExportIdentity: %v", err)
	}
	if exportResp.FormatVersion != ExportFormatVersion {
		t.Fatalf("unexpected format_version: %q", exportResp.FormatVersion)
	}

	var parsed exportedIdentityRecord
	if err := json.Unmarshal(exportResp.ExportBlob, &parsed); err != nil {
		t.Fatalf("export_blob is not valid JSON: %v", err)
	}
	if parsed.IdentityRef != identityRef {
		t.Fatalf("exported identityRef mismatch: got %q want %q", parsed.IdentityRef, identityRef)
	}
	if parsed.DisplayName != "Ada Lovelace" {
		t.Fatalf("exported displayName mismatch: %q", parsed.DisplayName)
	}
	if len(parsed.Devices) != 2 {
		t.Fatalf("expected 2 devices in export, got %d", len(parsed.Devices))
	}

	found := false
	for _, a := range emitter.actions() {
		if a == "identity.exported" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an identity.exported audit event; got actions %v", emitter.actions())
	}
}

func TestResolveIdentity_NotFound(t *testing.T) {
	svc, _ := newTestService()
	if _, err := svc.ResolveIdentity(ResolveIdentityRequest{IdentityRef: "nope"}); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("expected ErrIdentityNotFound, got %v", err)
	}
}

// NoopAuditEmitter must fail loudly, never silently, if a caller forgets
// to wire a real emitter — Art. 5 must not degrade into a silent no-op.
func TestNoopAuditEmitter_FailsLoudly(t *testing.T) {
	svc := NewService(NewInMemoryStore(), nil)
	pub, _ := mustGenerateKey(t)
	_, err := svc.CreateIdentity(CreateIdentityRequest{
		DisplayName: "No Audit", PublicKey: pub,
		FirstDevicePublicKey: pub, FirstDeviceName: "d",
	})
	if err == nil {
		t.Fatal("expected an error when no AuditEmitter is configured, got nil")
	}
}
