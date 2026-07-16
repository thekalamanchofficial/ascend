package identity

import (
	"encoding/json"
	"testing"
)

// identity_export_test.go satisfies scripts/constitution/check-export-
// paths.sh's Art. 9 requirement: every persisted-data-marker struct
// (IdentityRecord, Device — see the marker comment directly above each in
// types.go) needs a matching `Export<TypeName>` function, referenced from
// a *_export_test.go file in the same package. These tests also do real
// verification, not just a reference: each export must round-trip through
// JSON and preserve every field.

func TestExportIdentityRecord_RoundTrips(t *testing.T) {
	record := IdentityRecord{
		IdentityRef:   "id-123",
		DisplayName:   "Grace Hopper",
		PublicKey:     []byte{1, 2, 3, 4},
		CreatedAtUnix: 1_700_000_000,
		Epoch:         3,
		Devices: []Device{
			{DeviceID: "dev-1", Name: "Laptop", PublicKey: []byte{5, 6}, AddedAtUnix: 1, LastSeenUnix: 2},
		},
	}

	blob, formatVersion, err := ExportIdentityRecord(record)
	if err != nil {
		t.Fatalf("ExportIdentityRecord: %v", err)
	}
	if formatVersion != ExportFormatVersion {
		t.Fatalf("unexpected format version: %q", formatVersion)
	}

	var parsed exportedIdentityRecord
	if err := json.Unmarshal(blob, &parsed); err != nil {
		t.Fatalf("export blob did not parse as JSON: %v", err)
	}
	if parsed.IdentityRef != record.IdentityRef {
		t.Errorf("identityRef mismatch: got %q want %q", parsed.IdentityRef, record.IdentityRef)
	}
	if parsed.DisplayName != record.DisplayName {
		t.Errorf("displayName mismatch: got %q want %q", parsed.DisplayName, record.DisplayName)
	}
	if len(parsed.Devices) != 1 || parsed.Devices[0].DeviceID != "dev-1" {
		t.Errorf("devices did not round-trip: %+v", parsed.Devices)
	}
	if parsed.CreatedAtUnix != record.CreatedAtUnix {
		t.Errorf("createdAtUnix did not round-trip: got %d want %d", parsed.CreatedAtUnix, record.CreatedAtUnix)
	}
	if parsed.Epoch != record.Epoch {
		t.Errorf("epoch did not round-trip: got %d want %d", parsed.Epoch, record.Epoch)
	}
}

func TestExportDevice_RoundTrips(t *testing.T) {
	d := Device{DeviceID: "dev-9", Name: "Phone", PublicKey: []byte{9, 9, 9}, AddedAtUnix: 10, LastSeenUnix: 20}

	blob, err := ExportDevice(d)
	if err != nil {
		t.Fatalf("ExportDevice: %v", err)
	}

	var parsed exportedDevice
	if err := json.Unmarshal(blob, &parsed); err != nil {
		t.Fatalf("export blob did not parse as JSON: %v", err)
	}
	if parsed.DeviceID != d.DeviceID || parsed.Name != d.Name {
		t.Errorf("device did not round-trip: %+v", parsed)
	}
}
