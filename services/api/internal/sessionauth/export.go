package sessionauth

import "encoding/json"

// ExportFormatVersion is embedded in every export blob this package
// produces, so a future format change is detectable and rejected cleanly
// rather than silently misparsed — the same discipline Identity's
// ExportIdentity and Cryptography & Keys' ExportKeyMaterial already
// established (docs/DECISION_LOG.md).
const ExportFormatVersion = "ascend-sessionauth-export-v1"

// exportedSession is the JSON shape written to export blobs for a single
// session. Deliberately has NO field for session_token — this is a
// structural exclusion, not a call-site omission: even a future engineer
// who forgets the charter's "never export session_token" rule cannot leak
// it by accident through this type, because there is nowhere to put it.
// See charter §3/§6 and DATA_MANIFEST.md: session_token is a live bearer
// credential, not archival data — including it in an export would hand out
// a valid, unrevoked session to whoever holds the export file, which would
// itself violate Art. 7 (security must never reduce ownership), not
// fulfill Art. 9.
type exportedSession struct {
	IdentityRef    string `json:"identityRef"`
	DeviceID       string `json:"deviceId"`
	IssuedAtUnix   int64  `json:"issuedAtUnix"`
	ExpiresAtUnix  int64  `json:"expiresAtUnix"`
	LastUsedAtUnix int64  `json:"lastUsedAtUnix"`
}

func toExportedSession(s Session) exportedSession {
	return exportedSession{
		IdentityRef:    s.IdentityRef,
		DeviceID:       s.DeviceID,
		IssuedAtUnix:   s.IssuedAtUnix,
		ExpiresAtUnix:  s.ExpiresAtUnix,
		LastUsedAtUnix: s.LastUsedAtUnix,
	}
}

// ExportSession satisfies the Art. 9 mechanical export-path requirement
// (scripts/constitution/check-export-paths.sh) for the Session persisted
// type marked `// ascend:persisted` in types.go. A single session's record
// is fully reconstructable on its own from this function's output, not
// only as part of a full ExportSessionsBundle — mirroring
// identity/export.go's ExportDevice precedent (a per-record export
// function independent of the full-collection export path).
func ExportSession(s Session) ([]byte, error) {
	return json.MarshalIndent(toExportedSession(s), "", "  ")
}

// exportedSessionBundle is the full document ExportSessions (the RPC)
// returns as export_blob — one identity's complete set of persisted
// sessions, versioned and self-describing per Art. 9's "independently
// usable" bar (parseable by the user or a future competing implementation
// without depending on this service's continued existence).
type exportedSessionBundle struct {
	FormatVersion string            `json:"formatVersion"`
	IdentityRef   string            `json:"identityRef"`
	Sessions      []exportedSession `json:"sessions"`
}

// ExportSessionsBundle backs the ExportSessions RPC (service.go). It is
// deliberately a separate function from ExportSession above (which
// satisfies the mechanical per-type check): the RPC needs a versioned,
// multi-session document, not just one record's JSON.
func ExportSessionsBundle(identityRef string, sessions []Session) (blob []byte, formatVersion string, err error) {
	out := exportedSessionBundle{
		FormatVersion: ExportFormatVersion,
		IdentityRef:   identityRef,
		Sessions:      make([]exportedSession, len(sessions)),
	}
	for i, sess := range sessions {
		out.Sessions[i] = toExportedSession(sess)
	}

	blob, err = json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, "", err
	}
	return blob, ExportFormatVersion, nil
}
