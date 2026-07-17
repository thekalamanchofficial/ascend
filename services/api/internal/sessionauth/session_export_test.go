package sessionauth

import (
	"encoding/json"
	"strings"
	"testing"
)

// session_export_test.go satisfies scripts/constitution/check-export-
// paths.sh's Art. 9 requirement: the persisted-data-marker struct (Session
// — see the `// ascend:persisted` marker directly above it in types.go)
// needs a matching `ExportSession` function, referenced from a
// *_export_test.go file in this package. This test also does real
// verification: the export must round-trip every non-secret field and must
// never contain the session_token.

func TestExportSession_RoundTripsAndExcludesSessionToken(t *testing.T) {
	sess := Session{
		SessionToken:   "super-secret-live-bearer-token",
		IdentityRef:    "id-123",
		DeviceID:       "dev-1",
		IssuedAtUnix:   1_700_000_000,
		ExpiresAtUnix:  1_700_001_800,
		LastUsedAtUnix: 1_700_000_500,
	}

	blob, err := ExportSession(sess)
	if err != nil {
		t.Fatalf("ExportSession: %v", err)
	}

	if strings.Contains(string(blob), sess.SessionToken) {
		t.Fatal("ExportSession output must never contain the raw session_token")
	}

	var parsed exportedSession
	if err := json.Unmarshal(blob, &parsed); err != nil {
		t.Fatalf("export blob did not parse as JSON: %v", err)
	}
	if parsed.IdentityRef != sess.IdentityRef {
		t.Errorf("identityRef mismatch: got %q want %q", parsed.IdentityRef, sess.IdentityRef)
	}
	if parsed.DeviceID != sess.DeviceID {
		t.Errorf("deviceId mismatch: got %q want %q", parsed.DeviceID, sess.DeviceID)
	}
	if parsed.IssuedAtUnix != sess.IssuedAtUnix {
		t.Errorf("issuedAtUnix mismatch: got %d want %d", parsed.IssuedAtUnix, sess.IssuedAtUnix)
	}
	if parsed.ExpiresAtUnix != sess.ExpiresAtUnix {
		t.Errorf("expiresAtUnix mismatch: got %d want %d", parsed.ExpiresAtUnix, sess.ExpiresAtUnix)
	}
	if parsed.LastUsedAtUnix != sess.LastUsedAtUnix {
		t.Errorf("lastUsedAtUnix mismatch: got %d want %d", parsed.LastUsedAtUnix, sess.LastUsedAtUnix)
	}
}

func TestExportSessionsBundle_RoundTripsAndExcludesSessionToken(t *testing.T) {
	sessions := []Session{
		{SessionToken: "secret-1", IdentityRef: "id-9", DeviceID: "dev-a", IssuedAtUnix: 1, ExpiresAtUnix: 2, LastUsedAtUnix: 1},
		{SessionToken: "secret-2", IdentityRef: "id-9", DeviceID: "dev-b", IssuedAtUnix: 3, ExpiresAtUnix: 4, LastUsedAtUnix: 3},
	}

	blob, formatVersion, err := ExportSessionsBundle("id-9", sessions)
	if err != nil {
		t.Fatalf("ExportSessionsBundle: %v", err)
	}
	if formatVersion != ExportFormatVersion {
		t.Fatalf("unexpected format version: %q", formatVersion)
	}
	if strings.Contains(string(blob), "secret-1") || strings.Contains(string(blob), "secret-2") {
		t.Fatal("ExportSessionsBundle output must never contain any session_token value")
	}

	var parsed exportedSessionBundle
	if err := json.Unmarshal(blob, &parsed); err != nil {
		t.Fatalf("export blob did not parse as JSON: %v", err)
	}
	if parsed.IdentityRef != "id-9" {
		t.Errorf("identityRef mismatch: got %q", parsed.IdentityRef)
	}
	if len(parsed.Sessions) != 2 {
		t.Fatalf("expected 2 sessions in bundle, got %d", len(parsed.Sessions))
	}
}
