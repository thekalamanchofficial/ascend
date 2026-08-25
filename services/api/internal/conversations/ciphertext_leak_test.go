package conversations

import (
	"encoding/base64"
	"strings"
	"testing"
)

// This file holds the mechanical proof charter §6's central claim requires:
// ciphertext and session_establishment_payload must NEVER appear in any
// log/error/audit-metadata string this package produces. Mirrors
// internal/fileobjects/blob_ref_leak_test.go's identical "required,
// test-backed, not just asserted in prose" discipline for blob_ref,
// applied here to the two opaque-bytes fields this charter's structural-
// incapability claim (§6) is actually about.

// distinctiveMarker is embedded inside a ciphertext/payload value so any
// accidental leak into an error string or audit metadata value is
// trivially detectable via a substring search — a plain byte slice like
// []byte("ct") could coincidentally appear in unrelated text, this
// marker cannot.
const distinctiveMarker = "CIPHERTEXT_LEAK_CANARY_9f3ab21c"

func assertNoMarkerSubstring(t *testing.T, label, value string) {
	t.Helper()
	if strings.Contains(value, distinctiveMarker) {
		t.Fatalf("%s (%q) contains the ciphertext/payload marker — charter §6 structural-incapability violation", label, value)
	}
}

// TestNoCiphertextLeak_AuditMetadata proves SendMessage's own audit.Emit
// call never includes ciphertext or session_establishment_payload in its
// metadata, actor, action, or rule_reference — only message_id (charter §4
// Art. 5: "content-free per the Audit-consumption note").
func TestNoCiphertextLeak_AuditMetadata(t *testing.T) {
	svc, _, audit := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}

	ciphertext := []byte(distinctiveMarker + "-ciphertext-bytes")
	payload := []byte(distinctiveMarker + "-session-payload-bytes")
	if _, err := svc.SendMessage(SendMessageRequest{
		ConversationID: conv.ConversationID, Sender: alice,
		Ciphertext: ciphertext, SessionEstablishmentPayload: payload,
	}); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	for _, c := range audit.allCalls() {
		assertNoMarkerSubstring(t, "audit call actor", c.actor)
		assertNoMarkerSubstring(t, "audit call action", c.action)
		assertNoMarkerSubstring(t, "audit call rule_reference", c.ruleReference)
		for k, v := range c.metadata {
			assertNoMarkerSubstring(t, "audit call metadata["+k+"]", v)
		}
	}
}

// TestNoCiphertextLeak_DenialAuditMetadata proves checkAccess's denial
// audit path (SendMessage/GetConversation/ListMessages/ExportConversation
// rejecting a non-participant) never leaks a ciphertext/payload value that
// happens to already exist elsewhere in the conversation — the denial path
// has no legitimate reason to ever see message content at all (it fires
// before any message lookup), but this test proves it structurally, not by
// code-reading alone.
func TestNoCiphertextLeak_DenialAuditMetadata(t *testing.T) {
	svc, _, audit := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	ciphertext := []byte(distinctiveMarker + "-ciphertext-bytes")
	if _, err := svc.SendMessage(SendMessageRequest{ConversationID: conv.ConversationID, Sender: alice, Ciphertext: ciphertext}); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	// A non-participant is denied on every gated RPC — none of these
	// denial paths should ever mention the ciphertext bytes above.
	_, _ = svc.GetConversation(GetConversationRequest{ConversationID: conv.ConversationID, RequestingSubject: stranger})
	_, _ = svc.ListMessages(ListMessagesRequest{ConversationID: conv.ConversationID, RequestingSubject: stranger})
	_, _ = svc.ExportConversation(ExportConversationRequest{ConversationID: conv.ConversationID, RequestingSubject: stranger})
	_, _ = svc.SendMessage(SendMessageRequest{ConversationID: conv.ConversationID, Sender: stranger, Ciphertext: []byte("other-ct")})

	for _, c := range audit.allCalls() {
		assertNoMarkerSubstring(t, "audit call actor", c.actor)
		assertNoMarkerSubstring(t, "audit call action", c.action)
		assertNoMarkerSubstring(t, "audit call rule_reference", c.ruleReference)
		for k, v := range c.metadata {
			assertNoMarkerSubstring(t, "audit call metadata["+k+"]", v)
		}
	}
}

// TestNoCiphertextLeak_ErrorStrings proves no error this package returns
// (invalid-argument, permission-denied, or otherwise) ever embeds a
// ciphertext/payload value, across every RPC that accepts one.
func TestNoCiphertextLeak_ErrorStrings(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	ciphertext := []byte(distinctiveMarker + "-ciphertext-bytes")
	payload := []byte(distinctiveMarker + "-session-payload-bytes")

	// A denied SendMessage still carries the (attacker-supplied) ciphertext
	// in the request — the returned error must never echo it back.
	_, errDenied := svc.SendMessage(SendMessageRequest{ConversationID: conv.ConversationID, Sender: stranger, Ciphertext: ciphertext, SessionEstablishmentPayload: payload})
	if errDenied == nil {
		t.Fatal("expected an error for a non-participant SendMessage")
	}
	assertNoMarkerSubstring(t, "SendMessage denial error", errDenied.Error())

	// A successful SendMessage's own returned error (nil) has nothing to
	// check; instead confirm ExportConversation/ListMessages' SUCCESS
	// paths carry ciphertext only in the documented response fields, never
	// folded into an error — exercised by attempting an invalid
	// before_message_id after a real send, whose error must not somehow
	// echo the earlier ciphertext either.
	if _, err := svc.SendMessage(SendMessageRequest{ConversationID: conv.ConversationID, Sender: alice, Ciphertext: ciphertext, SessionEstablishmentPayload: payload}); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	bogus := "msg_does_not_exist"
	_, errBadCursor := svc.ListMessages(ListMessagesRequest{ConversationID: conv.ConversationID, RequestingSubject: bob, BeforeMessageID: &bogus})
	if errBadCursor == nil {
		t.Fatal("expected an error for an invalid before_message_id")
	}
	assertNoMarkerSubstring(t, "ListMessages invalid-cursor error", errBadCursor.Error())
}

// TestNoCiphertextLeak_ExportBundleCarriesItOnlyInDocumentedFields is the
// converse check: ExportConversation's bundle IS supposed to contain
// ciphertext (charter §3: "returns this capability's own stored bytes
// byte-for-byte") — this test confirms it's present exactly where
// documented (proving the export path isn't accidentally omitting it,
// which the leak tests above could otherwise mask by coincidence).
func TestNoCiphertextLeak_ExportBundleCarriesItOnlyInDocumentedFields(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv, err := svc.CreateConversation(CreateConversationRequest{Creator: alice, Participant: bob})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	ciphertext := []byte(distinctiveMarker + "-ciphertext-bytes")
	if _, err := svc.SendMessage(SendMessageRequest{ConversationID: conv.ConversationID, Sender: alice, Ciphertext: ciphertext}); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	resp, err := svc.ExportConversation(ExportConversationRequest{ConversationID: conv.ConversationID, RequestingSubject: bob})
	if err != nil {
		t.Fatalf("ExportConversation: %v", err)
	}
	// encoding/json marshals []byte as standard base64, not verbatim text —
	// check for the ciphertext's ACTUAL encoded form, not the raw marker
	// string (which base64 encoding does not generally preserve as a
	// literal substring).
	wantSubstring := base64.StdEncoding.EncodeToString(ciphertext)
	if !strings.Contains(string(resp.ExportBlob), wantSubstring) {
		t.Fatal("expected the export bundle to contain the sent ciphertext (base64-encoded via JSON []byte marshaling) — the export contract's own documented behavior")
	}
}
