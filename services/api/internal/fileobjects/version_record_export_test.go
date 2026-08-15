package fileobjects

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestExportVersionRecord satisfies Art. 9's mechanical requirement
// (scripts/constitution/check-export-paths.sh) for VersionRecord, the
// // ascend:persisted-marked struct in types.go: a matching
// ExportVersionRecord function must exist and be referenced by a
// *_export_test.go file in this package. It also proves the function
// honors charter §6 point 8: BlobRef must never appear in the rendered
// output, even though it's a genuine field of the persisted VersionRecord
// this function exports.
func TestExportVersionRecord(t *testing.T) {
	v := VersionRecord{
		VersionRef:    "ver_abc123",
		FileObjectID:  "fobj_def456",
		BlobRef:       "blob_should_never_appear_in_export",
		CreatedAtUnix: 1735689600,
		CreatedBy:     owner,
		SizeBytes:     42,
	}

	blob, err := ExportVersionRecord(v)
	if err != nil {
		t.Fatalf("ExportVersionRecord: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("ExportVersionRecord did not produce valid JSON: %v", err)
	}
	if decoded["versionRef"] != v.VersionRef {
		t.Fatalf("versionRef = %v, want %v", decoded["versionRef"], v.VersionRef)
	}
	if decoded["createdBy"] != v.CreatedBy {
		t.Fatalf("createdBy = %v, want %v", decoded["createdBy"], v.CreatedBy)
	}
	if _, present := decoded["blobRef"]; present {
		t.Fatalf("ExportVersionRecord must never include blobRef (charter §6 point 8)")
	}
	if strings.Contains(string(blob), v.BlobRef) {
		t.Fatalf("ExportVersionRecord's output contains the blob_ref value verbatim")
	}
}
