package audit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func newTestServer(svc *Service) *httptest.Server {
	r := chi.NewRouter()
	Mount(r, svc)
	return httptest.NewServer(r)
}

func TestHTTP_EmitThenQueryThenExplainThenExport(t *testing.T) {
	svc := NewService(NewInMemoryStore(), nil)
	ts := newTestServer(svc)
	defer ts.Close()

	// Emit — this is the network-reachable endpoint a non-Go caller
	// (e.g. apps/mobile's crypto audit stub) would call.
	emitBody, _ := json.Marshal(emitRequestDTO{
		Actor:         "identity:alice",
		Action:        "crypto.key_pair_generated",
		Resource:      ResourceRef{ResourceType: "key", ResourceID: "identity-key"},
		RuleReference: "",
		Metadata:      map[string]string{"purpose": "identity"},
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/audit/events", bytes.NewReader(emitBody))
	req.Header.Set(callerHeader, "identity:alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("emit request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var emitResp emitResponseDTO
	if err := json.NewDecoder(resp.Body).Decode(&emitResp); err != nil {
		t.Fatalf("decode emit response: %v", err)
	}
	if emitResp.EventID == "" {
		t.Fatal("expected non-empty event_id")
	}

	// Query own trail.
	qReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/audit/events?subject=identity:alice", nil)
	qReq.Header.Set(callerHeader, "identity:alice")
	qResp, err := http.DefaultClient.Do(qReq)
	if err != nil {
		t.Fatalf("query request: %v", err)
	}
	defer qResp.Body.Close()
	if qResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", qResp.StatusCode)
	}
	var qBody queryResponseDTO
	if err := json.NewDecoder(qResp.Body).Decode(&qBody); err != nil {
		t.Fatalf("decode query response: %v", err)
	}
	if len(qBody.Events) != 1 || qBody.Events[0].EventID != emitResp.EventID {
		t.Fatalf("unexpected query result: %+v", qBody)
	}

	// Explain.
	eReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/audit/events/"+emitResp.EventID+"/explain", nil)
	eReq.Header.Set(callerHeader, "identity:alice")
	eResp, err := http.DefaultClient.Do(eReq)
	if err != nil {
		t.Fatalf("explain request: %v", err)
	}
	defer eResp.Body.Close()
	if eResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", eResp.StatusCode)
	}
	var explainBody explainResponseDTO
	if err := json.NewDecoder(eResp.Body).Decode(&explainBody); err != nil {
		t.Fatalf("decode explain response: %v", err)
	}
	if explainBody.HumanReadableRationale == "" {
		t.Fatal("expected non-empty rationale")
	}

	// Export.
	xReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/audit/export?identity_ref=identity:alice", nil)
	xReq.Header.Set(callerHeader, "identity:alice")
	xResp, err := http.DefaultClient.Do(xReq)
	if err != nil {
		t.Fatalf("export request: %v", err)
	}
	defer xResp.Body.Close()
	if xResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", xResp.StatusCode)
	}
	if fv := xResp.Header.Get("X-Ascend-Format-Version"); fv != ExportFormatVersion {
		t.Fatalf("expected format version header %q, got %q", ExportFormatVersion, fv)
	}
	var bundle ExportBundle
	if err := json.NewDecoder(xResp.Body).Decode(&bundle); err != nil {
		t.Fatalf("decode export bundle: %v", err)
	}
	if len(bundle.Events) != 1 {
		t.Fatalf("expected 1 event in export bundle, got %d", len(bundle.Events))
	}
}

func TestHTTP_MissingCallerHeaderRejected(t *testing.T) {
	svc := NewService(NewInMemoryStore(), nil)
	ts := newTestServer(svc)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/audit/events?subject=identity:alice")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no caller header, got %d", resp.StatusCode)
	}
}

func TestHTTP_CrossSubjectQueryDeniedByDefault(t *testing.T) {
	svc := NewService(NewInMemoryStore(), nil)
	ts := newTestServer(svc)
	defer ts.Close()

	if _, err := svc.Emit("identity:alice", "file.viewed", ResourceRef{ResourceType: "file", ResourceID: "f1"}, "", nil); err != nil {
		t.Fatalf("emit: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/audit/events?subject=identity:alice", nil)
	req.Header.Set(callerHeader, "identity:bob")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-subject query with no permission checker wired, got %d", resp.StatusCode)
	}
}
