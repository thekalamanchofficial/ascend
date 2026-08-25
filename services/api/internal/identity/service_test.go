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
	svc := NewService(NewInMemoryStore(), NewInMemoryPrekeyStore(), emitter)
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
	svc := NewService(NewInMemoryStore(), NewInMemoryPrekeyStore(), nil)
	pub, _ := mustGenerateKey(t)
	_, err := svc.CreateIdentity(CreateIdentityRequest{
		DisplayName: "No Audit", PublicKey: pub,
		FirstDevicePublicKey: pub, FirstDeviceName: "d",
	})
	if err == nil {
		t.Fatal("expected an error when no AuditEmitter is configured, got nil")
	}
}

// ---------------------------------------------------------------------------
// Prekey bundle publish/fetch (charter §3/§4/§6, amendment gated
// 2026-08-20). Unit tests against InMemoryPrekeyStore — the real
// concurrency requirement (charter §6/§7) is tested separately against a
// live Postgres instance, see postgres_prekey_store_test.go.
// ---------------------------------------------------------------------------

func testSignedPrekey(id string) SignedPrekey {
	return SignedPrekey{
		PrekeyID:      id,
		PublicKey:     []byte{0x01, 0x02, 0x03},
		Signature:     []byte{0xAA, 0xBB, 0xCC, 0xDD},
		CreatedAtUnix: 1_700_000_000,
	}
}

// testDhKeyMaterial returns deterministic, distinguishable
// identity_dh_public_key/identity_dh_public_key_signature test bytes
// (key-separation fix, charter §3/§6) — this package never generates or
// verifies real signatures for these values (pure storage/relay), so
// plain tagged bytes are sufficient and let assertions confirm the exact
// bytes round-tripped rather than merely "some bytes came back".
func testDhKeyMaterial(id string) (identityDhPublicKey, identityDhPublicKeySignature []byte) {
	return []byte("dh-pub-" + id), []byte("dh-sig-" + id)
}

func TestPublishPrekeyBundle_HappyPath_ReplacesSignedPrekey_AdditiveOneTime(t *testing.T) {
	svc, emitter := newTestService()
	created, _, _ := createTestIdentity(t, svc)
	identityRef := created.PublicIdentity.IdentityRef
	deviceID := created.FirstDevice.DeviceID

	dhPub, dhSig := testDhKeyMaterial(deviceID)

	resp1, err := svc.PublishPrekeyBundle(PublishPrekeyBundleRequest{
		IdentityRef:                  identityRef,
		DeviceID:                     deviceID,
		SignedPrekey:                 testSignedPrekey("spk-1"),
		IdentityDhPublicKey:          dhPub,
		IdentityDhPublicKeySignature: dhSig,
		OneTimePrekeys: []OneTimePrekeyPublic{
			{PrekeyID: "otp-1", PublicKey: []byte{1}},
			{PrekeyID: "otp-2", PublicKey: []byte{2}},
		},
	})
	if err != nil {
		t.Fatalf("first PublishPrekeyBundle: %v", err)
	}
	if resp1.PublishedCount != 2 {
		t.Fatalf("expected published_count 2, got %d", resp1.PublishedCount)
	}

	// Rotation: a second publish call with a NEW signed prekey and one
	// MORE one-time prekey must replace the signed prekey and additively
	// append (never remove/replace) the existing pool (charter §3).
	// identity_dh_public_key/signature are stable, non-rotating (charter
	// §3) — republished with the SAME bytes here, as a real client would.
	resp2, err := svc.PublishPrekeyBundle(PublishPrekeyBundleRequest{
		IdentityRef:                  identityRef,
		DeviceID:                     deviceID,
		SignedPrekey:                 testSignedPrekey("spk-2"),
		IdentityDhPublicKey:          dhPub,
		IdentityDhPublicKeySignature: dhSig,
		OneTimePrekeys: []OneTimePrekeyPublic{
			{PrekeyID: "otp-3", PublicKey: []byte{3}},
		},
	})
	if err != nil {
		t.Fatalf("second PublishPrekeyBundle: %v", err)
	}
	if resp2.PublishedCount != 1 {
		t.Fatalf("expected published_count 1 on rotation call, got %d", resp2.PublishedCount)
	}

	current, currentDhPub, currentDhSig, found, err := svc.prekeys.GetSignedPrekey(identityRef, deviceID)
	if err != nil || !found {
		t.Fatalf("GetSignedPrekey: found=%v err=%v", found, err)
	}
	if current.PrekeyID != "spk-2" {
		t.Fatalf("expected rotation to replace signed prekey with spk-2, got %q", current.PrekeyID)
	}
	if string(currentDhPub) != string(dhPub) || string(currentDhSig) != string(dhSig) {
		t.Fatalf("expected identity_dh_public_key/signature to remain the stable, republished values across rotation")
	}

	count, err := svc.prekeys.CountUnconsumedOneTimePrekeys(identityRef, deviceID)
	if err != nil {
		t.Fatalf("CountUnconsumedOneTimePrekeys: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 one-time prekeys still available (additive across both calls), got %d", count)
	}

	found = false
	for _, a := range emitter.actions() {
		if a == "identity.prekey_bundle_published" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an identity.prekey_bundle_published audit event; got actions %v", emitter.actions())
	}
}

func TestPublishPrekeyBundle_ValidationErrors(t *testing.T) {
	svc, _ := newTestService()
	created, _, _ := createTestIdentity(t, svc)
	identityRef := created.PublicIdentity.IdentityRef
	deviceID := created.FirstDevice.DeviceID

	dhPub, dhSig := testDhKeyMaterial("valid")

	cases := []PublishPrekeyBundleRequest{
		{IdentityRef: "", DeviceID: deviceID, SignedPrekey: testSignedPrekey("x"), IdentityDhPublicKey: dhPub, IdentityDhPublicKeySignature: dhSig},
		{IdentityRef: identityRef, DeviceID: "", SignedPrekey: testSignedPrekey("x"), IdentityDhPublicKey: dhPub, IdentityDhPublicKeySignature: dhSig},
		{IdentityRef: identityRef, DeviceID: deviceID, SignedPrekey: SignedPrekey{}, IdentityDhPublicKey: dhPub, IdentityDhPublicKeySignature: dhSig},
		// identity_dh_public_key/identity_dh_public_key_signature required,
		// key-separation fix (charter §3) — same discipline as signed_prekey
		// above, exercised as its own two cases.
		{IdentityRef: identityRef, DeviceID: deviceID, SignedPrekey: testSignedPrekey("x"), IdentityDhPublicKey: nil, IdentityDhPublicKeySignature: dhSig},
		{IdentityRef: identityRef, DeviceID: deviceID, SignedPrekey: testSignedPrekey("x"), IdentityDhPublicKey: dhPub, IdentityDhPublicKeySignature: nil},
		{IdentityRef: identityRef, DeviceID: deviceID, SignedPrekey: testSignedPrekey("x"), IdentityDhPublicKey: dhPub, IdentityDhPublicKeySignature: dhSig, OneTimePrekeys: []OneTimePrekeyPublic{{PrekeyID: "", PublicKey: []byte{1}}}},
		{IdentityRef: identityRef, DeviceID: deviceID, SignedPrekey: testSignedPrekey("x"), IdentityDhPublicKey: dhPub, IdentityDhPublicKeySignature: dhSig, OneTimePrekeys: []OneTimePrekeyPublic{{PrekeyID: "p", PublicKey: nil}}},
	}
	for i, c := range cases {
		if _, err := svc.PublishPrekeyBundle(c); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("case %d: expected ErrInvalidArgument, got %v", i, err)
		}
	}
}

// A device_id not actually bound to identity_ref must be rejected — this
// is the caller-binding defense-in-depth check PublishPrekeyBundle
// performs independently of the HTTP-layer device-binding middleware
// (charter §6).
func TestPublishPrekeyBundle_UnknownDevice(t *testing.T) {
	svc, _ := newTestService()
	created, _, _ := createTestIdentity(t, svc)

	dhPub, dhSig := testDhKeyMaterial("unknown-device")
	_, err := svc.PublishPrekeyBundle(PublishPrekeyBundleRequest{
		IdentityRef:                  created.PublicIdentity.IdentityRef,
		DeviceID:                     "not-a-real-device",
		SignedPrekey:                 testSignedPrekey("x"),
		IdentityDhPublicKey:          dhPub,
		IdentityDhPublicKeySignature: dhSig,
	})
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("expected ErrDeviceNotFound, got %v", err)
	}
}

// The core enumeration-oracle closure requirement (charter §3/§6, Security
// Steward gate finding round 1): "device never published a bundle",
// "device_id not bound to identity_ref at all", AND (key-separation fix,
// same section) "a signed prekey was published but its
// identity_dh_public_key/identity_dh_public_key_signature pair is
// missing" must all produce a byte-for-byte identical
// FetchPrekeyBundleResponse. Compared via json.Marshal, not just
// reflect.DeepEqual on the Go struct, to actually prove the wire bytes —
// what a real caller observes — are identical, not merely the in-memory
// value.
func TestFetchPrekeyBundle_NeverPublishedAndUnboundDevice_ByteIdenticalResponses(t *testing.T) {
	svc, _ := newTestService()
	created, _, _ := createTestIdentity(t, svc)
	identityRef := created.PublicIdentity.IdentityRef
	realDeviceID := created.FirstDevice.DeviceID // real, bound, but has never published

	neverPublishedResp, err := svc.FetchPrekeyBundle("some-fetcher", FetchPrekeyBundleRequest{
		IdentityRef: identityRef,
		DeviceID:    realDeviceID,
	})
	if err != nil {
		t.Fatalf("FetchPrekeyBundle (never published): %v", err)
	}
	unboundResp, err := svc.FetchPrekeyBundle("some-fetcher", FetchPrekeyBundleRequest{
		IdentityRef: identityRef,
		DeviceID:    "device-that-does-not-exist-at-all",
	})
	if err != nil {
		t.Fatalf("FetchPrekeyBundle (unbound device_id): %v", err)
	}

	if neverPublishedResp.Status != PrekeyBundleStatusNotPublished {
		t.Fatalf("expected NOT_PUBLISHED for never-published device, got %v", neverPublishedResp.Status)
	}
	if unboundResp.Status != PrekeyBundleStatusNotPublished {
		t.Fatalf("expected NOT_PUBLISHED for unbound device_id, got %v", unboundResp.Status)
	}

	neverPublishedJSON, err := json.Marshal(neverPublishedResp)
	if err != nil {
		t.Fatalf("marshal neverPublishedResp: %v", err)
	}
	unboundJSON, err := json.Marshal(unboundResp)
	if err != nil {
		t.Fatalf("marshal unboundResp: %v", err)
	}
	if string(neverPublishedJSON) != string(unboundJSON) {
		t.Fatalf("responses are NOT byte-for-byte identical (enumeration oracle reopened):\n  never-published: %s\n  unbound device:  %s", neverPublishedJSON, unboundJSON)
	}

	// Key-separation fix's own fail-closed case: a device with a genuinely
	// published signed_prekey but an EMPTY identity_dh_public_key/signature
	// pair — constructed by calling the store directly (bypassing
	// Service.PublishPrekeyBundle's own request validation, which would
	// reject empty DH bytes before ever reaching the store; this is the
	// only way to produce this state at all) — must be indistinguishable
	// from both cases above.
	created2, _, _ := createTestIdentity(t, svc)
	identityRef2 := created2.PublicIdentity.IdentityRef
	deviceID2 := created2.FirstDevice.DeviceID
	if _, err := svc.prekeys.PublishBundle(identityRef2, deviceID2, testSignedPrekey("spk-missing-dh"), nil, nil, nil); err != nil {
		t.Fatalf("PublishBundle (bypassing service validation) with empty DH pair: %v", err)
	}
	missingDhResp, err := svc.FetchPrekeyBundle("some-fetcher", FetchPrekeyBundleRequest{
		IdentityRef: identityRef2,
		DeviceID:    deviceID2,
	})
	if err != nil {
		t.Fatalf("FetchPrekeyBundle (missing DH pair): %v", err)
	}
	if missingDhResp.Status != PrekeyBundleStatusNotPublished {
		t.Fatalf("expected NOT_PUBLISHED when identity_dh_public_key/signature are missing (fail-closed), got %v", missingDhResp.Status)
	}
	missingDhJSON, err := json.Marshal(missingDhResp)
	if err != nil {
		t.Fatalf("marshal missingDhResp: %v", err)
	}
	if string(missingDhJSON) != string(neverPublishedJSON) {
		t.Fatalf("missing-DH-pair response is NOT byte-for-byte identical to never-published (fail-closed enumeration oracle reopened):\n  missing DH pair: %s\n  never-published: %s", missingDhJSON, neverPublishedJSON)
	}
}

func TestFetchPrekeyBundle_UnknownIdentityRef_IsARealError(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.FetchPrekeyBundle("some-fetcher", FetchPrekeyBundleRequest{IdentityRef: "does-not-exist"})
	if !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("expected ErrIdentityNotFound for an unknown identity_ref, got %v", err)
	}
}

// A successful fetch that consumes a one-time prekey must emit an audit
// event with the FETCHER as actor (charter §4), never the target's own
// identity_ref, and never any key bytes in metadata.
func TestFetchPrekeyBundle_ConsumesOneTimePrekey_AuditsFetcherAsActor(t *testing.T) {
	svc, emitter := newTestService()
	created, _, _ := createTestIdentity(t, svc)
	identityRef := created.PublicIdentity.IdentityRef
	deviceID := created.FirstDevice.DeviceID

	dhPub, dhSig := testDhKeyMaterial(deviceID)
	if _, err := svc.PublishPrekeyBundle(PublishPrekeyBundleRequest{
		IdentityRef:                  identityRef,
		DeviceID:                     deviceID,
		SignedPrekey:                 testSignedPrekey("spk-1"),
		IdentityDhPublicKey:          dhPub,
		IdentityDhPublicKeySignature: dhSig,
		OneTimePrekeys:               []OneTimePrekeyPublic{{PrekeyID: "otp-1", PublicKey: []byte{9}}},
	}); err != nil {
		t.Fatalf("PublishPrekeyBundle: %v", err)
	}

	fetchResp, err := svc.FetchPrekeyBundle("fetcher-identity-ref", FetchPrekeyBundleRequest{
		IdentityRef: identityRef,
		DeviceID:    deviceID,
	})
	if err != nil {
		t.Fatalf("FetchPrekeyBundle: %v", err)
	}
	if fetchResp.Status != PrekeyBundleStatusAvailable {
		t.Fatalf("expected AVAILABLE, got %v", fetchResp.Status)
	}
	if fetchResp.OneTimePrekey == nil || fetchResp.OneTimePrekey.PrekeyID != "otp-1" {
		t.Fatalf("expected one_time_prekey otp-1 in response, got %+v", fetchResp.OneTimePrekey)
	}
	if fetchResp.SignedPrekey.PrekeyID != "spk-1" {
		t.Fatalf("unexpected signed_prekey in response: %+v", fetchResp.SignedPrekey)
	}
	// identity_dh_public_key/signature (key-separation fix): the DEVICE's
	// stored DH key/signature, NEVER the identity's Ed25519 signing key.
	if string(fetchResp.IdentityDhPublicKey) != string(dhPub) {
		t.Fatalf("identity_dh_public_key mismatch: got %q, want %q", fetchResp.IdentityDhPublicKey, dhPub)
	}
	if string(fetchResp.IdentityDhPublicKeySignature) != string(dhSig) {
		t.Fatalf("identity_dh_public_key_signature mismatch: got %q, want %q", fetchResp.IdentityDhPublicKeySignature, dhSig)
	}
	// identity_signing_public_key (proto field 6, NEW): sourced from the
	// identity record itself — the same value ResolveIdentity returns —
	// and genuinely distinct from identity_dh_public_key above.
	if string(fetchResp.IdentitySigningPublicKey) != string(created.PublicIdentity.PublicKey) {
		t.Fatalf("identity_signing_public_key mismatch")
	}
	if string(fetchResp.IdentitySigningPublicKey) == string(fetchResp.IdentityDhPublicKey) {
		t.Fatalf("identity_signing_public_key and identity_dh_public_key must never be the same bytes")
	}

	var consumeEvent *fakeAuditEvent
	for i := range emitter.events {
		if emitter.events[i].Action == "identity.prekey_bundle_fetched" {
			consumeEvent = &emitter.events[i]
		}
	}
	if consumeEvent == nil {
		t.Fatalf("expected an identity.prekey_bundle_fetched audit event; got actions %v", emitter.actions())
	}
	if consumeEvent.Actor != "fetcher-identity-ref" {
		t.Errorf("expected actor to be the fetcher, got %q", consumeEvent.Actor)
	}
	for k, v := range consumeEvent.Metadata {
		if k == "identity_ref" || k == "device_id" || k == "one_time_prekey_id_consumed" {
			continue
		}
		t.Errorf("unexpected audit metadata key %q=%q — only identifiers/counts are permitted, never key bytes", k, v)
	}

	// The pool is now empty — a second fetch must hit the exhaustion
	// fallback (AVAILABLE, but no one_time_prekey, and no second consuming
	// audit event).
	eventsBefore := len(emitter.events)
	secondFetch, err := svc.FetchPrekeyBundle("fetcher-identity-ref", FetchPrekeyBundleRequest{
		IdentityRef: identityRef,
		DeviceID:    deviceID,
	})
	if err != nil {
		t.Fatalf("second FetchPrekeyBundle: %v", err)
	}
	if secondFetch.Status != PrekeyBundleStatusAvailable {
		t.Fatalf("expected AVAILABLE even when the one-time-prekey pool is exhausted, got %v", secondFetch.Status)
	}
	if secondFetch.OneTimePrekey != nil {
		t.Fatalf("expected no one_time_prekey once the pool is exhausted, got %+v", secondFetch.OneTimePrekey)
	}
	if len(emitter.events) != eventsBefore {
		t.Errorf("exhaustion-fallback fetch must not emit a new audit event; event count went from %d to %d", eventsBefore, len(emitter.events))
	}
}

// device_id omitted resolves to the identity's most-recently-active bound
// device, by last_seen_unix (charter §3).
func TestFetchPrekeyBundle_DefaultsToMostRecentlyActiveDevice(t *testing.T) {
	svc, _ := newTestService()
	created, _, firstDevicePriv := createTestIdentity(t, svc)
	identityRef := created.PublicIdentity.IdentityRef

	// Bind a second device — InMemoryStore sets LastSeenUnix to "now" at
	// bind time for both devices, and BindDevice runs strictly after
	// CreateIdentity, so the second device is (at worst, tied but
	// deterministically) at least as recently seen. To make the ordering
	// unambiguous regardless of clock resolution, publish bundles for BOTH
	// devices and assert the response targets the SECOND (most recently
	// bound/seen) device specifically.
	secondPub, _ := mustGenerateKey(t)
	message := buildDeviceBindingMessage(identityRef, secondPub, "Second Device", created.PublicIdentity.Epoch)
	proof := ed25519.Sign(firstDevicePriv, message)
	bindResp, err := svc.BindDevice(BindDeviceRequest{
		IdentityRef: identityRef, DevicePublicKey: secondPub,
		DeviceName: "Second Device", AuthorizationProof: proof,
	})
	if err != nil {
		t.Fatalf("BindDevice: %v", err)
	}

	// Force an unambiguous last-seen ordering directly against the store,
	// since both devices may share a last_seen_unix value from the same
	// wall-clock second in a fast-running test.
	record, err := svc.store.Get(identityRef)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	for i := range record.Devices {
		if record.Devices[i].DeviceID == created.FirstDevice.DeviceID {
			record.Devices[i].LastSeenUnix = 1000
		} else {
			record.Devices[i].LastSeenUnix = 2000
		}
	}
	if err := svc.store.Replace(record); err != nil {
		t.Fatalf("store.Replace: %v", err)
	}

	for _, deviceID := range []string{created.FirstDevice.DeviceID, bindResp.Device.DeviceID} {
		dhPub, dhSig := testDhKeyMaterial(deviceID)
		if _, err := svc.PublishPrekeyBundle(PublishPrekeyBundleRequest{
			IdentityRef:                  identityRef,
			DeviceID:                     deviceID,
			SignedPrekey:                 testSignedPrekey("spk-" + deviceID),
			IdentityDhPublicKey:          dhPub,
			IdentityDhPublicKeySignature: dhSig,
		}); err != nil {
			t.Fatalf("PublishPrekeyBundle for %s: %v", deviceID, err)
		}
	}

	resp, err := svc.FetchPrekeyBundle("fetcher", FetchPrekeyBundleRequest{IdentityRef: identityRef}) // device_id omitted
	if err != nil {
		t.Fatalf("FetchPrekeyBundle: %v", err)
	}
	if resp.DeviceID != bindResp.Device.DeviceID {
		t.Fatalf("expected default resolution to pick the most-recently-active device %q, got %q", bindResp.Device.DeviceID, resp.DeviceID)
	}
}

// ListDevices' unconsumed_one_time_prekey_count (charter §4/§6) must
// reflect the real, current pool size, and must NOT itself be a stale
// persisted value (types.go's Device doc comment).
func TestListDevices_UnconsumedOneTimePrekeyCount(t *testing.T) {
	svc, _ := newTestService()
	created, _, _ := createTestIdentity(t, svc)
	identityRef := created.PublicIdentity.IdentityRef
	deviceID := created.FirstDevice.DeviceID

	listResp, err := svc.ListDevices(ListDevicesRequest{IdentityRef: identityRef})
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if listResp.Devices[0].UnconsumedOneTimePrekeyCount != 0 {
		t.Fatalf("expected 0 unconsumed one-time prekeys before any publish, got %d", listResp.Devices[0].UnconsumedOneTimePrekeyCount)
	}

	dhPub, dhSig := testDhKeyMaterial(deviceID)
	if _, err := svc.PublishPrekeyBundle(PublishPrekeyBundleRequest{
		IdentityRef:                  identityRef,
		DeviceID:                     deviceID,
		SignedPrekey:                 testSignedPrekey("spk-1"),
		IdentityDhPublicKey:          dhPub,
		IdentityDhPublicKeySignature: dhSig,
		OneTimePrekeys: []OneTimePrekeyPublic{
			{PrekeyID: "otp-1", PublicKey: []byte{1}},
			{PrekeyID: "otp-2", PublicKey: []byte{2}},
		},
	}); err != nil {
		t.Fatalf("PublishPrekeyBundle: %v", err)
	}

	listResp, err = svc.ListDevices(ListDevicesRequest{IdentityRef: identityRef})
	if err != nil {
		t.Fatalf("ListDevices after publish: %v", err)
	}
	if listResp.Devices[0].UnconsumedOneTimePrekeyCount != 2 {
		t.Fatalf("expected 2 unconsumed one-time prekeys after publish, got %d", listResp.Devices[0].UnconsumedOneTimePrekeyCount)
	}

	if _, err := svc.FetchPrekeyBundle("fetcher", FetchPrekeyBundleRequest{IdentityRef: identityRef, DeviceID: deviceID}); err != nil {
		t.Fatalf("FetchPrekeyBundle: %v", err)
	}

	listResp, err = svc.ListDevices(ListDevicesRequest{IdentityRef: identityRef})
	if err != nil {
		t.Fatalf("ListDevices after fetch: %v", err)
	}
	if listResp.Devices[0].UnconsumedOneTimePrekeyCount != 1 {
		t.Fatalf("expected 1 unconsumed one-time prekey after one fetch consumed one, got %d", listResp.Devices[0].UnconsumedOneTimePrekeyCount)
	}
}
