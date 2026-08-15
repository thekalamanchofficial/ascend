package fileobjects

import "encoding/json"

// exportFormatVersion is the format_version returned on every
// ExportFileResponse. Bumped whenever exportDocument's shape changes in a
// way a consumer parsing the JSON would need to know about.
const exportFormatVersion = "ascend-fileobjects-export-v1"

// exportedVersionSummary is VersionRecord's export-safe projection —
// EVERY field of VersionRecord except BlobRef (charter §6 point 8:
// blob_ref must never appear in any File Objects RPC response, audit
// event, or error message, and an export bundle returned via
// ExportFileResponse is unambiguously a response).
type exportedVersionSummary struct {
	VersionRef    string `json:"versionRef"`
	CreatedAtUnix int64  `json:"createdAtUnix"`
	CreatedBy     string `json:"createdBy"`
	SizeBytes     int64  `json:"sizeBytes"`
}

func toExportedVersionSummary(v VersionRecord) exportedVersionSummary {
	return exportedVersionSummary{
		VersionRef:    v.VersionRef,
		CreatedAtUnix: v.CreatedAtUnix,
		CreatedBy:     v.CreatedBy,
		SizeBytes:     v.SizeBytes,
	}
}

// ExportVersionRecord renders a single VersionRecord as self-describing
// JSON, satisfying Art. 9's per-persisted-type export path requirement for
// VersionRecord (marked ascend:persisted in types.go). It deliberately
// excludes BlobRef — see exportedVersionSummary's doc comment.
func ExportVersionRecord(v VersionRecord) ([]byte, error) {
	return json.MarshalIndent(toExportedVersionSummary(v), "", "  ")
}

// exportedVersion is one version's full entry in ExportFile's bundle:
// its export-safe metadata plus its actual content bytes (retrieved via
// Storage.RetrieveBlob, already permission-gated — charter §6 point 7).
type exportedVersion struct {
	exportedVersionSummary
	Content []byte `json:"content"`
}

// exportedFileEvent is FileEvent's export projection — identical shape,
// named separately so a future divergence between the in-process FileEvent
// type and the exported wire shape doesn't require touching store.go.
type exportedFileEvent struct {
	EventID        string            `json:"eventId"`
	Action         string            `json:"action"`
	Actor          string            `json:"actor"`
	OccurredAtUnix int64             `json:"occurredAtUnix"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// exportDocument is ExportFile's full portable bundle: file metadata, every
// version's content (not just current — Art. 9's "complete artifact"
// promise, charter §3), and File Objects' own full event history (charter
// §6 point 8a — never Permissions'/Storage's own audit trails). No field
// anywhere in this document is ever a blob_ref.
type exportDocument struct {
	FormatVersion   string              `json:"formatVersion"`
	FileObjectID    string              `json:"fileObjectId"`
	Owner           string              `json:"owner"`
	Name            string              `json:"name"`
	MimeType        string              `json:"mimeType"`
	Tags            []string            `json:"tags,omitempty"`
	CreatedAtUnix   int64               `json:"createdAtUnix"`
	Deleted         bool                `json:"deleted"`
	DeletedAtUnix   int64               `json:"deletedAtUnix,omitempty"`
	GeneratedAtUnix int64               `json:"generatedAtUnix"`
	Versions        []exportedVersion   `json:"versions"`
	Events          []exportedFileEvent `json:"events"`
}

func buildExportDocument(fo FileObjectRecord, versions []exportedVersion, events []FileEvent, generatedAtUnix int64) ([]byte, error) {
	exportedEvents := make([]exportedFileEvent, 0, len(events))
	for _, e := range events {
		exportedEvents = append(exportedEvents, exportedFileEvent{
			EventID:        e.EventID,
			Action:         e.Action,
			Actor:          e.Actor,
			OccurredAtUnix: e.OccurredAtUnix,
			Metadata:       e.Metadata,
		})
	}

	doc := exportDocument{
		FormatVersion:   exportFormatVersion,
		FileObjectID:    fo.FileObjectID,
		Owner:           fo.Owner,
		Name:            fo.Name,
		MimeType:        fo.MimeType,
		Tags:            fo.Tags,
		CreatedAtUnix:   fo.CreatedAtUnix,
		Deleted:         fo.Deleted,
		DeletedAtUnix:   fo.DeletedAtUnix,
		GeneratedAtUnix: generatedAtUnix,
		Versions:        versions,
		Events:          exportedEvents,
	}
	return json.MarshalIndent(doc, "", "  ")
}
