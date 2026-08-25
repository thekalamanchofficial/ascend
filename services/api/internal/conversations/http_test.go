package conversations

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// newHTTPTestServer mounts svc's HTTP surface with no external middleware
// (Mount's signature is unchanged — composition-root session-auth
// middleware is applied externally via r.Group, not threaded through
// Mount's parameters). Tests set callerHeader directly on each request,
// mirroring internal/fileobjects/http_test.go's approach, so these tests
// exercise exactly this package's own requireCaller/caller-match checks
// (the handler-level defense-in-depth).
func newHTTPTestServer(svc *Service) *httptest.Server {
	r := chi.NewRouter()
	Mount(r, svc)
	return httptest.NewServer(r)
}

func doJSON(t *testing.T, method, url, caller string, body any) *http.Response {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if caller != "" {
		req.Header.Set(callerHeader, caller)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// createTestConversation creates a real conversation via the real Service
// (not the HTTP layer) — a test setup helper, not itself under test.
func createTestConversation(t *testing.T, svc *Service, creator, participant string) CreateConversationResponse {
	t.Helper()
	resp, err := svc.CreateConversation(CreateConversationRequest{Creator: creator, Participant: participant})
	if err != nil {
		t.Fatalf("CreateConversation: %v", err)
	}
	return resp
}

// --- CreateConversation ---

func TestHTTP_CreateConversation_CreatorMismatchRejected(t *testing.T) {
	svc, _, _ := newTestService(t)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/conversations/", bob, CreateConversationRequest{Creator: alice, Participant: bob})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for creator/caller mismatch, got %d", resp.StatusCode)
	}
}

func TestHTTP_CreateConversation_CallerMatchSucceeds(t *testing.T) {
	svc, _, _ := newTestService(t)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/conversations/", alice, CreateConversationRequest{Creator: alice, Participant: bob})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 when creator matches caller, got %d", resp.StatusCode)
	}
	var out CreateConversationResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.ConversationID == "" {
		t.Fatal("expected a non-empty conversation_id")
	}
}

func TestHTTP_CreateConversation_ParticipantIsNeverCheckedAgainstCaller(t *testing.T) {
	svc, _, _ := newTestService(t)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	// alice (the caller) creates a conversation naming bob as the OTHER
	// party — participant must never be required to equal the caller.
	resp := doJSON(t, http.MethodPost, ts.URL+"/conversations/", alice, CreateConversationRequest{Creator: alice, Participant: bob})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

// --- SendMessage ---

func TestHTTP_SendMessage_SenderMismatchRejected(t *testing.T) {
	svc, _, audit := newTestService(t)
	conv := createTestConversation(t, svc, alice, bob)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	before := audit.callCount()
	resp := doJSON(t, http.MethodPost, ts.URL+"/conversations/messages", bob, SendMessageRequest{
		ConversationID: conv.ConversationID, Sender: alice, Ciphertext: []byte("ct"),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for sender/caller mismatch, got %d", resp.StatusCode)
	}
	if audit.callCount() != before+1 {
		t.Fatalf("expected the HTTP-level mismatch to be audited, count went from %d to %d", before, audit.callCount())
	}
}

func TestHTTP_SendMessage_CallerMatchSucceeds(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv := createTestConversation(t, svc, alice, bob)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/conversations/messages", alice, SendMessageRequest{
		ConversationID: conv.ConversationID, Sender: alice, Ciphertext: []byte("ct"),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

// --- Missing caller header (401) ---

func TestHTTP_MissingCallerHeaderRejected(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv := createTestConversation(t, svc, alice, bob)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	cases := []struct {
		name string
		path string
		body any
	}{
		{"create_conversation", "/conversations/", CreateConversationRequest{Creator: alice, Participant: bob}},
		{"send_message", "/conversations/messages", SendMessageRequest{ConversationID: conv.ConversationID, Sender: alice, Ciphertext: []byte("ct")}},
		{"list_messages", "/conversations/messages/list", ListMessagesRequest{ConversationID: conv.ConversationID, RequestingSubject: alice}},
		{"list_conversations", "/conversations/list", ListConversationsRequest{RequestingSubject: alice}},
		{"get_conversation", "/conversations/get", GetConversationRequest{ConversationID: conv.ConversationID, RequestingSubject: alice}},
		{"export_conversation", "/conversations/export", ExportConversationRequest{ConversationID: conv.ConversationID, RequestingSubject: alice}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := doJSON(t, http.MethodPost, ts.URL+c.path, "", c.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("expected 401 for missing caller header, got %d", resp.StatusCode)
			}
		})
	}
}

// --- requesting_subject mismatch (403), the four participant-gated RPCs ---

func TestHTTP_ListMessages_RequestingSubjectMismatchRejected(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv := createTestConversation(t, svc, alice, bob)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/conversations/messages/list", bob, ListMessagesRequest{ConversationID: conv.ConversationID, RequestingSubject: alice})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestHTTP_GetConversation_RequestingSubjectMismatchRejected(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv := createTestConversation(t, svc, alice, bob)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/conversations/get", bob, GetConversationRequest{ConversationID: conv.ConversationID, RequestingSubject: alice})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestHTTP_ExportConversation_RequestingSubjectMismatchRejected(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv := createTestConversation(t, svc, alice, bob)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	resp := doJSON(t, http.MethodPost, ts.URL+"/conversations/export", bob, ExportConversationRequest{ConversationID: conv.ConversationID, RequestingSubject: alice})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestHTTP_ListConversations_RequestingSubjectMismatchRejected(t *testing.T) {
	svc, _, audit := newTestService(t)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	before := audit.callCount()
	resp := doJSON(t, http.MethodPost, ts.URL+"/conversations/list", bob, ListConversationsRequest{RequestingSubject: alice})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	if audit.callCount() != before+1 {
		t.Fatalf("expected the mismatch to be audited, count went from %d to %d", before, audit.callCount())
	}
}

// --- Enumeration-oracle-safe denial over the real HTTP handler ---
//
// THE merge-gate-critical test set: proves, over the real HTTP handler (not
// the service layer in isolation), that a nonexistent conversation_id and
// an existing-but-not-a-participant one produce a BYTE-FOR-BYTE identical
// HTTP response — same status code, same exact response body bytes.

func TestHTTP_EnumerationOracleClosure_GetConversation(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv := createTestConversation(t, svc, alice, bob)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	respA := doJSON(t, http.MethodPost, ts.URL+"/conversations/get", stranger, GetConversationRequest{ConversationID: conv.ConversationID, RequestingSubject: stranger})
	defer respA.Body.Close()
	bodyA, err := io.ReadAll(respA.Body)
	if err != nil {
		t.Fatalf("read body A: %v", err)
	}

	respB := doJSON(t, http.MethodPost, ts.URL+"/conversations/get", stranger, GetConversationRequest{ConversationID: "conv_does_not_exist_at_all", RequestingSubject: stranger})
	defer respB.Body.Close()
	bodyB, err := io.ReadAll(respB.Body)
	if err != nil {
		t.Fatalf("read body B: %v", err)
	}

	if respA.StatusCode != respB.StatusCode {
		t.Fatalf("expected identical HTTP status, got %d (not-participant) vs %d (nonexistent)", respA.StatusCode, respB.StatusCode)
	}
	if respA.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for both cases, got %d", respA.StatusCode)
	}
	if !bytes.Equal(bodyA, bodyB) {
		t.Fatalf("expected byte-for-byte identical response bodies, got %q (not-participant) vs %q (nonexistent) — this is a real enumeration oracle", bodyA, bodyB)
	}
}

func TestHTTP_EnumerationOracleClosure_ListMessages(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv := createTestConversation(t, svc, alice, bob)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	respA := doJSON(t, http.MethodPost, ts.URL+"/conversations/messages/list", stranger, ListMessagesRequest{ConversationID: conv.ConversationID, RequestingSubject: stranger})
	defer respA.Body.Close()
	bodyA, _ := io.ReadAll(respA.Body)

	respB := doJSON(t, http.MethodPost, ts.URL+"/conversations/messages/list", stranger, ListMessagesRequest{ConversationID: "conv_does_not_exist_at_all", RequestingSubject: stranger})
	defer respB.Body.Close()
	bodyB, _ := io.ReadAll(respB.Body)

	if respA.StatusCode != respB.StatusCode || respA.StatusCode != http.StatusForbidden {
		t.Fatalf("expected identical 403 status, got %d vs %d", respA.StatusCode, respB.StatusCode)
	}
	if !bytes.Equal(bodyA, bodyB) {
		t.Fatalf("expected byte-for-byte identical response bodies, got %q vs %q", bodyA, bodyB)
	}
}

func TestHTTP_EnumerationOracleClosure_ExportConversation(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv := createTestConversation(t, svc, alice, bob)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	respA := doJSON(t, http.MethodPost, ts.URL+"/conversations/export", stranger, ExportConversationRequest{ConversationID: conv.ConversationID, RequestingSubject: stranger})
	defer respA.Body.Close()
	bodyA, _ := io.ReadAll(respA.Body)

	respB := doJSON(t, http.MethodPost, ts.URL+"/conversations/export", stranger, ExportConversationRequest{ConversationID: "conv_does_not_exist_at_all", RequestingSubject: stranger})
	defer respB.Body.Close()
	bodyB, _ := io.ReadAll(respB.Body)

	if respA.StatusCode != respB.StatusCode || respA.StatusCode != http.StatusForbidden {
		t.Fatalf("expected identical 403 status, got %d vs %d", respA.StatusCode, respB.StatusCode)
	}
	if !bytes.Equal(bodyA, bodyB) {
		t.Fatalf("expected byte-for-byte identical response bodies, got %q vs %q", bodyA, bodyB)
	}
}

func TestHTTP_EnumerationOracleClosure_SendMessage(t *testing.T) {
	svc, _, _ := newTestService(t)
	conv := createTestConversation(t, svc, alice, bob)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	respA := doJSON(t, http.MethodPost, ts.URL+"/conversations/messages", stranger, SendMessageRequest{ConversationID: conv.ConversationID, Sender: stranger, Ciphertext: []byte("ct")})
	defer respA.Body.Close()
	bodyA, _ := io.ReadAll(respA.Body)

	respB := doJSON(t, http.MethodPost, ts.URL+"/conversations/messages", stranger, SendMessageRequest{ConversationID: "conv_does_not_exist_at_all", Sender: stranger, Ciphertext: []byte("ct")})
	defer respB.Body.Close()
	bodyB, _ := io.ReadAll(respB.Body)

	if respA.StatusCode != respB.StatusCode || respA.StatusCode != http.StatusForbidden {
		t.Fatalf("expected identical 403 status, got %d vs %d", respA.StatusCode, respB.StatusCode)
	}
	if !bytes.Equal(bodyA, bodyB) {
		t.Fatalf("expected byte-for-byte identical response bodies, got %q vs %q", bodyA, bodyB)
	}
}

// --- End-to-end happy path over real HTTP ---

func TestHTTP_EndToEnd_CreateSendListGetExport(t *testing.T) {
	svc, _, _ := newTestService(t)
	ts := newHTTPTestServer(svc)
	defer ts.Close()

	createResp := doJSON(t, http.MethodPost, ts.URL+"/conversations/", alice, CreateConversationRequest{Creator: alice, Participant: bob})
	defer createResp.Body.Close()
	var created CreateConversationResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	sendResp := doJSON(t, http.MethodPost, ts.URL+"/conversations/messages", alice, SendMessageRequest{ConversationID: created.ConversationID, Sender: alice, Ciphertext: []byte("hello")})
	defer sendResp.Body.Close()
	if sendResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 from SendMessage, got %d", sendResp.StatusCode)
	}

	listResp := doJSON(t, http.MethodPost, ts.URL+"/conversations/messages/list", bob, ListMessagesRequest{ConversationID: created.ConversationID, RequestingSubject: bob})
	defer listResp.Body.Close()
	var lm ListMessagesResponse
	if err := json.NewDecoder(listResp.Body).Decode(&lm); err != nil {
		t.Fatalf("decode list messages: %v", err)
	}
	if len(lm.Messages) != 1 || string(lm.Messages[0].Ciphertext) != "hello" {
		t.Fatalf("unexpected messages: %+v", lm.Messages)
	}

	listConvResp := doJSON(t, http.MethodPost, ts.URL+"/conversations/list", bob, ListConversationsRequest{RequestingSubject: bob})
	defer listConvResp.Body.Close()
	var lc ListConversationsResponse
	if err := json.NewDecoder(listConvResp.Body).Decode(&lc); err != nil {
		t.Fatalf("decode list conversations: %v", err)
	}
	if len(lc.Conversations) != 1 || lc.Conversations[0].ConversationID != created.ConversationID {
		t.Fatalf("unexpected conversations: %+v", lc.Conversations)
	}

	getResp := doJSON(t, http.MethodPost, ts.URL+"/conversations/get", alice, GetConversationRequest{ConversationID: created.ConversationID, RequestingSubject: alice})
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from GetConversation, got %d", getResp.StatusCode)
	}

	exportResp := doJSON(t, http.MethodPost, ts.URL+"/conversations/export", alice, ExportConversationRequest{ConversationID: created.ConversationID, RequestingSubject: alice})
	defer exportResp.Body.Close()
	var exp ExportConversationResponse
	if err := json.NewDecoder(exportResp.Body).Decode(&exp); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if exp.FormatVersion == "" || len(exp.ExportBlob) == 0 {
		t.Fatalf("unexpected export response: %+v", exp)
	}
}
