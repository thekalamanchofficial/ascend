package identity

import "encoding/json"

// ExportFormatVersion is embedded in every export blob this package
// produces, so a future format change is detectable and rejected cleanly
// rather than silently misparsed — the same discipline Cryptography &
// Keys' ExportKeyMaterial decision established (docs/DECISION_LOG.md,
// 2026-07-16, "ExportKeyMaterial format...").
const ExportFormatVersion = "ascend-identity-export-v1"

// exportedDevice and exportedIdentityRecord are the JSON shapes written to
// export blobs. []byte fields marshal as standard base64 via
// encoding/json, matching how protojson encodes `bytes` fields, so this
// export blob's shape is a superset of what ExportIdentityResponse's
// public_identity/devices already expose over the RPC surface — nothing
// here is a field the user couldn't already see via ResolveIdentity/
// ListDevices, it is simply packaged as one complete, user-readable
// document per Art. 9.
type exportedDevice struct {
	DeviceID     string `json:"deviceId"`
	Name         string `json:"name"`
	PublicKeyB64 []byte `json:"publicKey"`
	AddedAtUnix  int64  `json:"addedAtUnix"`
	LastSeenUnix int64  `json:"lastSeenUnix"`
}

type exportedIdentityRecord struct {
	FormatVersion string           `json:"formatVersion"`
	IdentityRef   string           `json:"identityRef"`
	DisplayName   string           `json:"displayName"`
	PublicKeyB64  []byte           `json:"publicKey"`
	CreatedAtUnix int64            `json:"createdAtUnix"`
	Epoch         int64            `json:"epoch"`
	Devices       []exportedDevice `json:"devices"`
}

// ExportIdentityRecord satisfies the Art. 9 mechanical export-path
// requirement for the IdentityRecord persisted type (scripts/constitution/
// check-export-paths.sh) and backs the ExportIdentity RPC. It produces a
// complete, self-describing, versioned JSON document — parseable by the
// user or any future competing implementation without depending on this
// service's continued existence, per Art. 9's "always able to leave."
func ExportIdentityRecord(record IdentityRecord) (blob []byte, formatVersion string, err error) {
	out := exportedIdentityRecord{
		FormatVersion: ExportFormatVersion,
		IdentityRef:   record.IdentityRef,
		DisplayName:   record.DisplayName,
		PublicKeyB64:  record.PublicKey,
		CreatedAtUnix: record.CreatedAtUnix,
		Epoch:         record.Epoch,
		Devices:       make([]exportedDevice, len(record.Devices)),
	}
	for i, d := range record.Devices {
		out.Devices[i] = exportedDevice{
			DeviceID:     d.DeviceID,
			Name:         d.Name,
			PublicKeyB64: d.PublicKey,
			AddedAtUnix:  d.AddedAtUnix,
			LastSeenUnix: d.LastSeenUnix,
		}
	}

	blob, err = json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, "", err
	}
	return blob, ExportFormatVersion, nil
}

// ExportDevice satisfies the Art. 9 mechanical export-path requirement for
// the Device persisted type independently of IdentityRecord's export path
// above — a device's own record is fully reconstructable on its own from
// this function's output, not only as part of a full identity export.
func ExportDevice(d Device) ([]byte, error) {
	return json.MarshalIndent(exportedDevice{
		DeviceID:     d.DeviceID,
		Name:         d.Name,
		PublicKeyB64: d.PublicKey,
		AddedAtUnix:  d.AddedAtUnix,
		LastSeenUnix: d.LastSeenUnix,
	}, "", "  ")
}
