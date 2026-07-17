package storage

import (
	"encoding/json"
	"fmt"
)

// ExportBlobRecord renders a single BlobRecord as self-describing JSON,
// satisfying Art. 9's per-persisted-type export path requirement for the
// BlobRecord struct (marked ascend:persisted in types.go). It never
// includes blob content or the wrapping key — those are not fields of
// BlobRecord at all (see store.go's doc comment on why they're kept in a
// separate map).
func ExportBlobRecord(r BlobRecord) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// exportDocumentFormatVersion is the format_version returned on every
// ExportAllBlobsResponse. Bumped whenever exportDocument's shape changes
// in a way a consumer parsing the JSON would need to know about.
const exportDocumentFormatVersion = "ascend-storage-export-v1"

// exportedBlob is one blob's entry in ExportAllBlobs' bundle: its full
// metadata, plus its actual decrypted-from-Storage's-perspective bytes
// (still the caller's own end-to-end ciphertext — see charter §3; Storage
// itself never sees real plaintext) for any blob that has not been
// deleted. A deleted blob's entry carries its tombstone metadata but no
// Data field — the whole point of DeleteBlob having run is that the bytes
// are no longer recoverable, so an export produced after deletion must be
// honest about that rather than silently omitting the deleted blob
// entirely (which would look like a gap, not a discloseable fact).
type exportedBlob struct {
	BlobRef           string `json:"blobRef"`
	PolicyID          string `json:"policyId"`
	SizeBytes         int64  `json:"sizeBytes"`
	CreatedAtUnix     int64  `json:"createdAtUnix"`
	Location          string `json:"location"`
	Deleted           bool   `json:"deleted"`
	DeletedAtUnix     int64  `json:"deletedAtUnix,omitempty"`
	DeletionMechanism string `json:"deletionMechanism,omitempty"`
	Data              []byte `json:"data,omitempty"`
}

type exportDocument struct {
	FormatVersion   string         `json:"formatVersion"`
	Owner           string         `json:"owner"`
	GeneratedAtUnix int64          `json:"generatedAtUnix"`
	Blobs           []exportedBlob `json:"blobs"`
}

// ExportAllBlobs returns owner's complete blob inventory — every live
// blob's actual bytes plus every tombstone's metadata — as a single
// versioned, self-describing JSON document (Art. 9): genuinely usable
// outside this module, parseable independently of this service's
// continued existence, matching the bar Permissions'/Identity's own
// export formats already met (docs/DECISION_LOG.md, "ExportKeyMaterial
// format...", "Foundation contracts composition...").
//
// Not marked ascend:mutates (no state change) but still audited — bulk
// disclosure of a user's entire blob inventory is exactly the kind of
// sensitive, important action Art. 5 requires stay discoverable, matching
// Permissions' ExportPermissions/Identity's ExportIdentity precedent.
func (s *Service) ExportAllBlobs(req ExportAllBlobsRequest) (ExportAllBlobsResponse, error) {
	if req.Owner == "" {
		return ExportAllBlobsResponse{}, fmt.Errorf("%w: owner is required", ErrInvalidArgument)
	}

	records := s.store.recordsForOwner(req.Owner)
	blobs := make([]exportedBlob, 0, len(records))
	for _, r := range records {
		eb := exportedBlob{
			BlobRef:           r.BlobRef,
			PolicyID:          r.PolicyID,
			SizeBytes:         r.SizeBytes,
			CreatedAtUnix:     r.CreatedAtUnix,
			Location:          r.Location,
			Deleted:           r.Deleted,
			DeletedAtUnix:     r.DeletedAtUnix,
			DeletionMechanism: r.DeletionMechanism,
		}
		if !r.Deleted {
			policy, ok := s.policies[r.PolicyID]
			if !ok {
				return ExportAllBlobsResponse{}, fmt.Errorf("storage: blob %s references unknown policy %q", r.BlobRef, r.PolicyID)
			}
			sealed, err := policy.Backend.Retrieve(r.BlobRef)
			if err != nil {
				return ExportAllBlobsResponse{}, fmt.Errorf("storage: could not read blob %s for export: %w", r.BlobRef, err)
			}
			key, ok := s.store.wrappingKey(r.BlobRef)
			if !ok {
				return ExportAllBlobsResponse{}, fmt.Errorf("storage: no wrapping key available for blob %s during export", r.BlobRef)
			}
			data, err := openOuterEnvelope(key, sealed)
			if err != nil {
				return ExportAllBlobsResponse{}, fmt.Errorf("storage: could not open blob %s for export: %w", r.BlobRef, err)
			}
			eb.Data = data
		}
		blobs = append(blobs, eb)
	}

	doc := exportDocument{
		FormatVersion:   exportDocumentFormatVersion,
		Owner:           req.Owner,
		GeneratedAtUnix: s.nowUnix(),
		Blobs:           blobs,
	}

	blob, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return ExportAllBlobsResponse{}, err
	}

	resource := ResourceRef{ResourceType: "storage_export", ResourceID: req.Owner}
	// The export blob has already been produced above — same "the
	// disclosure already happened, a failed audit emit must be surfaced
	// loudly" reasoning as RetrieveBlob's success path and Permissions'
	// ExportPermissions precedent.
	if _, err := s.audit.Emit(req.Owner, "storage.export_all_blobs", resource, "user_requested_export", map[string]string{
		"blob_count": fmt.Sprintf("%d", len(blobs)),
	}); err != nil {
		return ExportAllBlobsResponse{}, fmt.Errorf("storage: export produced but audit emit failed: %w", err)
	}

	return ExportAllBlobsResponse{ExportBlob: blob, FormatVersion: exportDocumentFormatVersion}, nil
}
