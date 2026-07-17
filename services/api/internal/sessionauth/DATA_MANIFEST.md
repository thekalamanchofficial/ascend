# Data Manifest — Session / Request Authentication

Per `docs/CONSTITUTION.md` Art. 8 (privacy is the default; minimum data,
documented purpose) and
`docs/capabilities/session-authentication.charter.md` §4. This is the
exhaustive list of fields this capability collects and stores. No other
field is collected at this layer — no IP address, user agent, or device
fingerprinting beyond what Identity's own `Device` record already captures
(this capability does not capture any of that either; it consumes
Identity's device validity via `DeviceResolver`, it does not store a copy).

## Fields

- `session_token`
  Purpose: the opaque bearer credential itself. Random (CSPRNG-sourced, see
  `token.go`), unguessable, and carries no embedded identity data (unlike a
  JWT, deliberately — charter §4/§6). It is the one field on the persisted
  `Session` record that is intentionally excluded from `ExportSessions`'
  output (see `export.go`) — it is a live credential, not archival data;
  including it in an export would hand out a valid, unrevoked session to
  whoever holds the export file.

- `identity_ref`
  Purpose: the minimum needed to answer "which identity does this session
  belong to" — required to scope `RevokeAllSessions`/`ListActiveSessions`/
  `ExportSessions` to only the caller's own resolved identity (charter §3),
  and required for the Art. 5 "who did this" audit metadata on
  `IssueSession`/`RevokeSession`/`RevokeAllSessions`.

- `device_id`
  Purpose: the minimum needed to answer "which bound device is this session
  for" — surfaced on `ListActiveSessions`/`ExportSessions` (via
  `SessionSummary`) as the "Devices screen"-style transparency signal
  charter §5 describes, and used as the resource identifier in this
  capability's audit events.

- `issued_at_unix`
  Purpose: powers the Art. 5 "when was this session created" answer,
  surfaced via `ListActiveSessions`/`ExportSessions`.

- `expires_at_unix`
  Purpose: powers expiry enforcement (`ValidateSession` real, server-side
  lookup — Art. 7) and lets a user see how much longer a session is valid
  for via `ListActiveSessions`/`ExportSessions`.

- `last_used_at_unix`
  Purpose: updated on every successful `ValidateSession` call. Lets a user
  spot a session they don't recognize being actively used — the
  session-level analog of Identity's `device.last_seen`, per charter §4.

- `challenge_nonce` / `challenge_expires_at_unix`
  Purpose: the freshness input `IssueSession` signs over (charter §3/§6),
  closing the same class of replay vulnerability found and fixed in
  Identity's `BindDevice` (`docs/DECISION_LOG.md`, 2026-07-16). Short-lived
  (this implementation: 2 minutes, `DefaultChallengeNonceLifetime` in
  `service.go`) and consumed on first successful use — **not retained once
  consumed or expired** (`store.go`'s `nonceStore.consumeIfValid` deletes
  the record outright on consumption; expired entries are likewise deleted
  on next access rather than kept around). No export path exists for this
  data and none is required — it is transient authentication-protocol
  state, not a durable fact about the user, and the charter is explicit
  that it is not retained.

## Explicitly out of scope (not collected)

- No IP address, geolocation, or device hardware fingerprint of any kind.
- No user agent string.
- No password, email, or any other credential — the only proof of identity
  this capability ever accepts is a fresh Ed25519 signature over the
  canonical `IssueSession` message (`sign.go`), verified against a public
  key resolved from Identity via `DeviceResolver`.
- No private key material of any kind — this capability only ever sees a
  signature (`proof`) and an already-public device key; it never generates,
  transmits, or stores private key material (Cryptography & Keys' exclusive
  responsibility).

## Note on the failure-tracking counter (`anomaly.go`)

`failureTracker` keeps a small in-memory, per-token-fingerprint count of
recent `ValidateSession` failures purely to decide when to emit the
"repeated failures" anomaly-signal audit event (charter §4). It stores a
truncated hash of the token (`tokenFingerprint`, `token.go`), never the raw
token, and the counter itself is not a documented "collected field" in the
Art. 8 sense above — it is transient operational state that never appears
in `ExportSessions`' output and is not part of the persisted `Session`
record. Flagged here for completeness rather than left as an undocumented
implementation detail (Art. 15 — minimize hidden state).
