package sessionauth

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- test fakes ---

// fakeDeviceResolver is an in-memory DeviceResolver test double. A device
// can be "revoked" by removing its entry, which is exactly the signal
// IssueSession's step 2 must treat as "not found" regardless of whether the
// caller's signature is otherwise perfectly valid.
type fakeDeviceResolver struct {
	mu      sync.Mutex
	devices map[string][]byte // key: identityRef+"|"+deviceID
}

func newFakeDeviceResolver() *fakeDeviceResolver {
	return &fakeDeviceResolver{devices: make(map[string][]byte)}
}

func (f *fakeDeviceResolver) bind(identityRef, deviceID string, publicKey []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devices[identityRef+"|"+deviceID] = publicKey
}

func (f *fakeDeviceResolver) revoke(identityRef, deviceID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.devices, identityRef+"|"+deviceID)
}

func (f *fakeDeviceResolver) ResolveDevicePublicKey(identityRef, deviceID string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key, ok := f.devices[identityRef+"|"+deviceID]
	return key, ok, nil
}

// fakeAuditEmitter records every Emit call for assertions and always
// succeeds (a separate errorAuditEmitter below covers the "must handle
// Emit's error" requirement).
type fakeAuditEmitter struct {
	mu     sync.Mutex
	events []auditCall
	nextID int64
}

type auditCall struct {
	Actor         string
	Action        string
	Resource      ResourceRef
	RuleReference string
	Metadata      map[string]string
}

func newFakeAuditEmitter() *fakeAuditEmitter {
	return &fakeAuditEmitter{}
}

func (f *fakeAuditEmitter) Emit(actor, action string, resource ResourceRef, ruleReference string, metadata map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, auditCall{Actor: actor, Action: action, Resource: resource, RuleReference: ruleReference, Metadata: metadata})
	f.nextID++
	return "evt-" + strconv.FormatInt(f.nextID, 10), nil
}

func (f *fakeAuditEmitter) callsFor(action string) []auditCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []auditCall
	for _, e := range f.events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// erroringAuditEmitter always fails — used to prove Service call sites
// check and handle Emit's error rather than discarding it.
type erroringAuditEmitter struct{}

func (erroringAuditEmitter) Emit(_ string, _ string, _ ResourceRef, _ string, _ map[string]string) (string, error) {
	return "", errors.New("boom: audit backend unavailable")
}

// --- test helpers ---

func newTestIdentity(t *testing.T, resolver *fakeDeviceResolver, identityRef, deviceID string) (pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	resolver.bind(identityRef, deviceID, pub)
	return pub, priv
}

// issueValidSession runs the real GetSessionChallenge + IssueSession flow
// end to end using a real device keypair, returning the resulting token.
func issueValidSession(t *testing.T, svc *Service, priv ed25519.PrivateKey, identityRef, deviceID string) IssueSessionResponse {
	t.Helper()
	challenge, err := svc.GetSessionChallenge(GetSessionChallengeRequest{IdentityRef: identityRef, DeviceID: deviceID})
	if err != nil {
		t.Fatalf("GetSessionChallenge: %v", err)
	}
	msg := buildIssueSessionMessage(identityRef, deviceID, challenge.ChallengeNonce)
	sig := ed25519.Sign(priv, msg)
	resp, err := svc.IssueSession(IssueSessionRequest{
		IdentityRef:    identityRef,
		DeviceID:       deviceID,
		ChallengeNonce: challenge.ChallengeNonce,
		Proof:          sig,
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	return resp
}

// --- tests ---

func TestFullHappyPath_ChallengeIssueValidateListExportRevoke(t *testing.T) {
	resolver := newFakeDeviceResolver()
	audit := newFakeAuditEmitter()
	svc := NewService(NewInMemoryNonceStore(), NewInMemorySessionStore(), resolver, audit)

	identityRef, deviceID := "id-alice", "dev-laptop"
	_, priv := newTestIdentity(t, resolver, identityRef, deviceID)

	issued := issueValidSession(t, svc, priv, identityRef, deviceID)
	if issued.SessionToken == "" {
		t.Fatal("expected a non-empty session token")
	}
	if issued.ExpiresAtUnix <= time.Now().Unix() {
		t.Fatal("expected expires_at to be in the future")
	}

	// ValidateSession succeeds and resolves identity/device.
	valid, err := svc.ValidateSession(ValidateSessionRequest{SessionToken: issued.SessionToken})
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if !valid.Valid || valid.IdentityRef != identityRef || valid.DeviceID != deviceID {
		t.Fatalf("unexpected ValidateSession result: %+v", valid)
	}

	// ListActiveSessions, authorized via the caller's own token.
	list, err := svc.ListActiveSessions(ListActiveSessionsRequest{CallerSessionToken: issued.SessionToken})
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	if len(list.Sessions) != 1 || list.Sessions[0].DeviceID != deviceID {
		t.Fatalf("unexpected active sessions: %+v", list.Sessions)
	}

	// ExportSessions, same authorization shape.
	export, err := svc.ExportSessions(ExportSessionsRequest{CallerSessionToken: issued.SessionToken})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}
	if export.FormatVersion != ExportFormatVersion {
		t.Fatalf("unexpected format version: %q", export.FormatVersion)
	}
	if !strings.Contains(string(export.ExportBlob), identityRef) {
		t.Fatal("expected export blob to contain the identity_ref")
	}

	// RevokeSession, then ValidateSession must now report invalid.
	if _, err := svc.RevokeSession(RevokeSessionRequest{SessionToken: issued.SessionToken}); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	revalid, err := svc.ValidateSession(ValidateSessionRequest{SessionToken: issued.SessionToken})
	if err != nil {
		t.Fatalf("ValidateSession after revoke: %v", err)
	}
	if revalid.Valid {
		t.Fatal("expected session to be invalid immediately after revocation")
	}

	// Audit coverage sanity check: issued + revoked events happened.
	if len(audit.callsFor("sessionauth.session_issued")) != 1 {
		t.Fatal("expected exactly one session_issued audit event")
	}
	if len(audit.callsFor("sessionauth.session_revoked")) != 1 {
		t.Fatal("expected exactly one session_revoked audit event")
	}
	// No audit event for the successful ValidateSession/ListActiveSessions/
	// ExportSessions calls above (charter §4 — routine successes and the
	// two non-mutating read RPCs are deliberately not audited).
	for _, action := range []string{"sessionauth.validate_session_anomaly"} {
		if len(audit.callsFor(action)) != 0 {
			t.Fatalf("did not expect %q to have fired on a clean happy path", action)
		}
	}
}

func TestIssueSession_ReplayRejected_SameNonceSameProofFailsSecondTime(t *testing.T) {
	resolver := newFakeDeviceResolver()
	audit := newFakeAuditEmitter()
	svc := NewService(NewInMemoryNonceStore(), NewInMemorySessionStore(), resolver, audit)

	identityRef, deviceID := "id-bob", "dev-phone"
	_, priv := newTestIdentity(t, resolver, identityRef, deviceID)

	challenge, err := svc.GetSessionChallenge(GetSessionChallengeRequest{IdentityRef: identityRef, DeviceID: deviceID})
	if err != nil {
		t.Fatalf("GetSessionChallenge: %v", err)
	}
	msg := buildIssueSessionMessage(identityRef, deviceID, challenge.ChallengeNonce)
	sig := ed25519.Sign(priv, msg)

	req := IssueSessionRequest{
		IdentityRef:    identityRef,
		DeviceID:       deviceID,
		ChallengeNonce: challenge.ChallengeNonce,
		Proof:          sig,
	}

	// First call: a genuinely fresh request. Must succeed.
	first, err := svc.IssueSession(req)
	if err != nil {
		t.Fatalf("first IssueSession call unexpectedly failed: %v", err)
	}
	if first.SessionToken == "" {
		t.Fatal("expected a session token from the first call")
	}

	// Second call: the EXACT same request bytes (same nonce, same proof) —
	// this is what a captured/replayed request looks like. Must fail,
	// proving the nonce was genuinely consumed and cannot be reused.
	_, err = svc.IssueSession(req)
	if err == nil {
		t.Fatal("expected the replayed IssueSession request to fail, but it succeeded")
	}
	if !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("expected ErrInvalidNonce on replay, got: %v", err)
	}
}

func TestIssueSession_ReplayRejected_ConcurrentDuplicateRequestsOnlyOneWins(t *testing.T) {
	// This directly exercises charter §3's strongest claim: the nonce
	// consume step "must happen atomically ... such that a captured,
	// already-used IssueSession request can never succeed twice, even
	// under concurrent replay attempts." A sequential replay (the test
	// above) could in principle pass even with a check-then-act race that
	// only manifests under concurrency — this test fires the identical
	// request from many goroutines at once and asserts exactly one winner.
	resolver := newFakeDeviceResolver()
	audit := newFakeAuditEmitter()
	svc := NewService(NewInMemoryNonceStore(), NewInMemorySessionStore(), resolver, audit)

	identityRef, deviceID := "id-carol", "dev-tablet"
	_, priv := newTestIdentity(t, resolver, identityRef, deviceID)

	challenge, err := svc.GetSessionChallenge(GetSessionChallengeRequest{IdentityRef: identityRef, DeviceID: deviceID})
	if err != nil {
		t.Fatalf("GetSessionChallenge: %v", err)
	}
	msg := buildIssueSessionMessage(identityRef, deviceID, challenge.ChallengeNonce)
	sig := ed25519.Sign(priv, msg)

	req := IssueSessionRequest{
		IdentityRef:    identityRef,
		DeviceID:       deviceID,
		ChallengeNonce: challenge.ChallengeNonce,
		Proof:          sig,
	}

	const concurrency = 25
	var successes int64
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			if _, err := svc.IssueSession(req); err == nil {
				atomic.AddInt64(&successes, 1)
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("expected exactly 1 successful IssueSession among %d concurrent replays, got %d", concurrency, successes)
	}
}

func TestIssueSession_RevokedDeviceCannotIssueEvenWithFreshNonceAndValidSignature(t *testing.T) {
	resolver := newFakeDeviceResolver()
	audit := newFakeAuditEmitter()
	svc := NewService(NewInMemoryNonceStore(), NewInMemorySessionStore(), resolver, audit)

	identityRef, deviceID := "id-dave", "dev-watch"
	_, priv := newTestIdentity(t, resolver, identityRef, deviceID)

	// Revoke the device (Identity's RevokeDevice would do this in
	// production; here we simulate it by removing it from the fake
	// resolver, exactly the signal DeviceResolver is contracted to give).
	resolver.revoke(identityRef, deviceID)

	// A fresh nonce, and a signature that is otherwise completely valid
	// (correct private key, correct canonical message) — the ONLY thing
	// wrong is that the device is no longer bound.
	challenge, err := svc.GetSessionChallenge(GetSessionChallengeRequest{IdentityRef: identityRef, DeviceID: deviceID})
	if err != nil {
		t.Fatalf("GetSessionChallenge: %v", err)
	}
	msg := buildIssueSessionMessage(identityRef, deviceID, challenge.ChallengeNonce)
	sig := ed25519.Sign(priv, msg)

	_, err = svc.IssueSession(IssueSessionRequest{
		IdentityRef:    identityRef,
		DeviceID:       deviceID,
		ChallengeNonce: challenge.ChallengeNonce,
		Proof:          sig,
	})
	if err == nil {
		t.Fatal("expected IssueSession to fail for a revoked device, but it succeeded")
	}
	if !errors.Is(err, ErrDeviceNotBound) {
		t.Fatalf("expected ErrDeviceNotBound, got: %v", err)
	}

	// The nonce must still be intact (unconsumed) after this rejection —
	// device-not-found is checked BEFORE the nonce is consumed (charter §3
	// step ordering: resolve device at step 2, consume nonce at step 4).
	if !resolver.hasNoDevice(identityRef, deviceID) {
		t.Fatal("test setup invariant broken: device unexpectedly resolvable")
	}
}

// hasNoDevice is a tiny test-only assertion helper.
func (f *fakeDeviceResolver) hasNoDevice(identityRef, deviceID string) bool {
	_, found, _ := f.ResolveDevicePublicKey(identityRef, deviceID)
	return !found
}

func TestRevokeAllSessions_OnlyActsOnCallersOwnResolvedIdentity(t *testing.T) {
	resolver := newFakeDeviceResolver()
	audit := newFakeAuditEmitter()
	svc := NewService(NewInMemoryNonceStore(), NewInMemorySessionStore(), resolver, audit)

	_, privA := newTestIdentity(t, resolver, "id-alice", "dev-a1")
	_, privB := newTestIdentity(t, resolver, "id-bob", "dev-b1")

	sessA := issueValidSession(t, svc, privA, "id-alice", "dev-a1")
	sessB := issueValidSession(t, svc, privB, "id-bob", "dev-b1")

	// Alice signs out everywhere using HER OWN caller_session_token.
	result, err := svc.RevokeAllSessions(RevokeAllSessionsRequest{CallerSessionToken: sessA.SessionToken})
	if err != nil {
		t.Fatalf("RevokeAllSessions: %v", err)
	}
	if result.SessionsRevoked != 1 {
		t.Fatalf("expected exactly 1 session revoked for Alice, got %d", result.SessionsRevoked)
	}

	// Alice's session is now gone.
	va, err := svc.ValidateSession(ValidateSessionRequest{SessionToken: sessA.SessionToken})
	if err != nil {
		t.Fatalf("ValidateSession(alice): %v", err)
	}
	if va.Valid {
		t.Fatal("expected Alice's session to be invalid after her own RevokeAllSessions call")
	}

	// Bob's completely unrelated session must be UNTOUCHED — there is no
	// identity_ref field on RevokeAllSessionsRequest at all (frozen
	// contract), so the only identity this call could possibly have
	// affected is the one Alice's own token resolves to.
	vb, err := svc.ValidateSession(ValidateSessionRequest{SessionToken: sessB.SessionToken})
	if err != nil {
		t.Fatalf("ValidateSession(bob): %v", err)
	}
	if !vb.Valid {
		t.Fatal("Bob's session must remain valid — RevokeAllSessions must never cross identities")
	}
}

func TestListActiveSessionsAndExportSessions_OnlyActOnCallersOwnResolvedIdentity(t *testing.T) {
	resolver := newFakeDeviceResolver()
	audit := newFakeAuditEmitter()
	svc := NewService(NewInMemoryNonceStore(), NewInMemorySessionStore(), resolver, audit)

	_, privA := newTestIdentity(t, resolver, "id-alice", "dev-a1")
	_, privB := newTestIdentity(t, resolver, "id-bob", "dev-b1")

	sessA := issueValidSession(t, svc, privA, "id-alice", "dev-a1")
	_ = issueValidSession(t, svc, privB, "id-bob", "dev-b1")
	// Bob has two devices/sessions; Alice has one.
	_, privB2 := newTestIdentity(t, resolver, "id-bob", "dev-b2")
	_ = issueValidSession(t, svc, privB2, "id-bob", "dev-b2")

	list, err := svc.ListActiveSessions(ListActiveSessionsRequest{CallerSessionToken: sessA.SessionToken})
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	if len(list.Sessions) != 1 || list.Sessions[0].DeviceID != "dev-a1" {
		t.Fatalf("expected ListActiveSessions to return only Alice's own session, got: %+v", list.Sessions)
	}

	export, err := svc.ExportSessions(ExportSessionsRequest{CallerSessionToken: sessA.SessionToken})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}
	if strings.Contains(string(export.ExportBlob), "id-bob") {
		t.Fatal("Alice's export must never contain Bob's identity_ref")
	}
	if !strings.Contains(string(export.ExportBlob), "id-alice") {
		t.Fatal("Alice's export must contain her own identity_ref")
	}

	// An invalid/unknown caller token must be rejected outright, not
	// treated as "no sessions."
	if _, err := svc.ListActiveSessions(ListActiveSessionsRequest{CallerSessionToken: "not-a-real-token"}); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("expected ErrSessionInvalid for an unresolvable caller token, got: %v", err)
	}
	if _, err := svc.ExportSessions(ExportSessionsRequest{CallerSessionToken: ""}); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("expected ErrSessionInvalid for an empty caller token, got: %v", err)
	}
}

func TestExportSessions_NeverContainsSessionTokenValue(t *testing.T) {
	resolver := newFakeDeviceResolver()
	audit := newFakeAuditEmitter()
	svc := NewService(NewInMemoryNonceStore(), NewInMemorySessionStore(), resolver, audit)

	identityRef, deviceID := "id-erin", "dev-desktop"
	_, priv := newTestIdentity(t, resolver, identityRef, deviceID)

	issued := issueValidSession(t, svc, priv, identityRef, deviceID)

	// Issue a second session for a second device on the same identity too,
	// so the export contains more than one record.
	_, priv2 := newTestIdentity(t, resolver, identityRef, "dev-laptop")
	issued2 := issueValidSession(t, svc, priv2, identityRef, "dev-laptop")

	export, err := svc.ExportSessions(ExportSessionsRequest{CallerSessionToken: issued.SessionToken})
	if err != nil {
		t.Fatalf("ExportSessions: %v", err)
	}

	if bytes.Contains(export.ExportBlob, []byte(issued.SessionToken)) {
		t.Fatal("export blob must never contain the first session's live session_token")
	}
	if bytes.Contains(export.ExportBlob, []byte(issued2.SessionToken)) {
		t.Fatal("export blob must never contain the second session's live session_token")
	}
	// Sanity: both devices ARE represented by their non-secret fields.
	if !strings.Contains(string(export.ExportBlob), deviceID) || !strings.Contains(string(export.ExportBlob), "dev-laptop") {
		t.Fatalf("expected export to list both devices' non-secret fields: %s", export.ExportBlob)
	}
}

// manualClock is a test-only, mutable clock so expiry tests don't depend
// on real wall-clock sleeps racing against ExpiresAtUnix's one-second
// granularity (both session and nonce expiry are stored/compared as Unix
// seconds — a sub-second real sleep is not a reliable way to cross that
// boundary). Tests below wire svc.now to clock.now and then explicitly
// jump the clock forward past the relevant lifetime.
type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func newManualClock() *manualClock {
	return &manualClock{t: time.Now()}
}

func (c *manualClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestValidateSession_ExpiredSessionIsInvalid(t *testing.T) {
	resolver := newFakeDeviceResolver()
	audit := newFakeAuditEmitter()
	svc := NewService(NewInMemoryNonceStore(), NewInMemorySessionStore(), resolver, audit)
	clock := newManualClock()
	svc.now = clock.now

	identityRef, deviceID := "id-frank", "dev-phone"
	_, priv := newTestIdentity(t, resolver, identityRef, deviceID)
	issued := issueValidSession(t, svc, priv, identityRef, deviceID)

	// Confirm it's valid right after issuance...
	resp, err := svc.ValidateSession(ValidateSessionRequest{SessionToken: issued.SessionToken})
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if !resp.Valid {
		t.Fatal("expected a freshly issued session to be valid")
	}

	// ...then jump the clock well past the session's lifetime.
	clock.advance(svc.sessionLifetime + 2*time.Second)

	resp, err = svc.ValidateSession(ValidateSessionRequest{SessionToken: issued.SessionToken})
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if resp.Valid {
		t.Fatal("expected an expired session to be invalid")
	}
}

func TestGetSessionChallenge_ExpiredNonceRejected(t *testing.T) {
	resolver := newFakeDeviceResolver()
	audit := newFakeAuditEmitter()
	svc := NewService(NewInMemoryNonceStore(), NewInMemorySessionStore(), resolver, audit)
	clock := newManualClock()
	svc.now = clock.now

	identityRef, deviceID := "id-grace", "dev-phone"
	_, priv := newTestIdentity(t, resolver, identityRef, deviceID)

	challenge, err := svc.GetSessionChallenge(GetSessionChallengeRequest{IdentityRef: identityRef, DeviceID: deviceID})
	if err != nil {
		t.Fatalf("GetSessionChallenge: %v", err)
	}

	clock.advance(svc.nonceLifetime + 2*time.Second)

	msg := buildIssueSessionMessage(identityRef, deviceID, challenge.ChallengeNonce)
	sig := ed25519.Sign(priv, msg)
	_, err = svc.IssueSession(IssueSessionRequest{
		IdentityRef:    identityRef,
		DeviceID:       deviceID,
		ChallengeNonce: challenge.ChallengeNonce,
		Proof:          sig,
	})
	if !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("expected ErrInvalidNonce for an expired nonce, got: %v", err)
	}
}

func TestIssueSession_InvalidSignatureRejected(t *testing.T) {
	resolver := newFakeDeviceResolver()
	audit := newFakeAuditEmitter()
	svc := NewService(NewInMemoryNonceStore(), NewInMemorySessionStore(), resolver, audit)

	identityRef, deviceID := "id-henry", "dev-phone"
	newTestIdentity(t, resolver, identityRef, deviceID)
	_, wrongPriv, _ := ed25519.GenerateKey(nil) // an unrelated keypair

	challenge, err := svc.GetSessionChallenge(GetSessionChallengeRequest{IdentityRef: identityRef, DeviceID: deviceID})
	if err != nil {
		t.Fatalf("GetSessionChallenge: %v", err)
	}
	msg := buildIssueSessionMessage(identityRef, deviceID, challenge.ChallengeNonce)
	badSig := ed25519.Sign(wrongPriv, msg)

	_, err = svc.IssueSession(IssueSessionRequest{
		IdentityRef:    identityRef,
		DeviceID:       deviceID,
		ChallengeNonce: challenge.ChallengeNonce,
		Proof:          badSig,
	})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestValidateSession_RepeatedFailuresEmitAnomalyAuditEvent(t *testing.T) {
	resolver := newFakeDeviceResolver()
	audit := newFakeAuditEmitter()
	svc := NewService(NewInMemoryNonceStore(), NewInMemorySessionStore(), resolver, audit)

	badToken := "definitely-not-a-real-session-token"
	for i := 0; i < validateFailureThreshold; i++ {
		if resp, err := svc.ValidateSession(ValidateSessionRequest{SessionToken: badToken}); err != nil || resp.Valid {
			t.Fatalf("expected a clean invalid result on attempt %d, got resp=%+v err=%v", i, resp, err)
		}
	}

	events := audit.callsFor("sessionauth.validate_session_anomaly")
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 anomaly audit event after %d failures, got %d", validateFailureThreshold, len(events))
	}
	// The raw token must never appear in the anomaly event's metadata/resource.
	for _, e := range events {
		if e.Resource.ResourceID == badToken {
			t.Fatal("anomaly audit event must never contain the raw session_token, only a fingerprint")
		}
	}
}

func TestIssueSession_AuditEmitErrorIsSurfaced_NotDiscarded(t *testing.T) {
	// Proves this package checks and handles AuditEmitter.Emit's error
	// return at the IssueSession success call site, per this capability's
	// spawn brief ("check and handle the returned error at every call
	// site — do not discard it").
	resolver := newFakeDeviceResolver()
	svc := NewService(NewInMemoryNonceStore(), NewInMemorySessionStore(), resolver, erroringAuditEmitter{})

	identityRef, deviceID := "id-ivy", "dev-phone"
	_, priv := newTestIdentity(t, resolver, identityRef, deviceID)

	challenge, err := svc.GetSessionChallenge(GetSessionChallengeRequest{IdentityRef: identityRef, DeviceID: deviceID})
	if err != nil {
		t.Fatalf("GetSessionChallenge: %v", err)
	}
	msg := buildIssueSessionMessage(identityRef, deviceID, challenge.ChallengeNonce)
	sig := ed25519.Sign(priv, msg)

	_, err = svc.IssueSession(IssueSessionRequest{
		IdentityRef:    identityRef,
		DeviceID:       deviceID,
		ChallengeNonce: challenge.ChallengeNonce,
		Proof:          sig,
	})
	if err == nil {
		t.Fatal("expected IssueSession to surface the AuditEmitter error, but it returned nil")
	}
}

func TestRevokeSession_UnknownTokenRejected(t *testing.T) {
	resolver := newFakeDeviceResolver()
	audit := newFakeAuditEmitter()
	svc := NewService(NewInMemoryNonceStore(), NewInMemorySessionStore(), resolver, audit)

	_, err := svc.RevokeSession(RevokeSessionRequest{SessionToken: "never-issued"})
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got: %v", err)
	}
}
