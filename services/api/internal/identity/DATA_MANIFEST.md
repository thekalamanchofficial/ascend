# Data Manifest — Identity

Per `docs/CONSTITUTION.md` Art. 8 (privacy is the default; minimum data,
documented purpose) and `docs/capabilities/identity.charter.md` §4. This is
the exhaustive list of fields this capability collects and stores. No other
field is collected at this layer — unrelated profile data belongs to a
future profile-composition capability, not Identity.

## Fields

- `display_name`
  Purpose: shown to other users so they know who they're communicating
  with; user-editable, not derived from any other source.

- `public_key` (identity root key, and one per bound device)
  Purpose: the cryptographic material needed to verify device-binding
  authorization proofs and to let other capabilities/users address this
  identity's devices. No corresponding private key material ever reaches
  this service — private keys are generated and held exclusively by
  Cryptography & Keys, on-device.

- `device.name`
  Purpose: lets the user tell their own devices apart on a Devices screen.

- `device.added_at`
  Purpose: powers the Art. 5 "when was this device added" answer, surfaced
  via `ListDevices` and `ExportIdentity`.

- `device.last_seen`
  Purpose: lets the user spot a device they no longer recognize or use, as
  a security signal (charter §6 threat model — device spoofing/lost
  device awareness).

- `created_at_unix` (identity-level)
  Purpose: powers the Art. 5 "when was this identity created" answer,
  surfaced via `ExportIdentity`; also the reference point a user can use
  to reason about their own account history. Persisted on `IdentityRecord`
  and exported by `ExportIdentityRecord` (Constitution Warden merge-gate
  finding, 2026-07-16 — previously persisted/exported but undocumented
  here; fixed in this pass).

- `epoch` (identity-level)
  Purpose: NOT user-supplied data — a server-generated, monotonically
  increasing device-topology version counter, incremented on every
  successful `BindDevice`/`RevokeDevice`. It is the anti-replay input
  bound into every `BindDevice` `authorization_proof` (see `sign.go`),
  closing the replay vulnerability found at the 2026-07-16 Security
  Steward merge-gate veto: without it, a captured, previously-valid
  `authorization_proof` for a device that has since been revoked would
  remain valid forever and could silently re-add that device. Documented
  here per the same "every persisted/exported field is listed" discipline
  applied to `created_at_unix` above, even though it is not a piece of
  data collected *about* the user in the Art. 8 sense.

## Explicitly out of scope (not collected)

- No email, phone number, or other contact identifier.
- No IP address, geolocation, or device hardware fingerprint.
- No private key material of any kind — Identity only ever stores public
  keys handed to it by an already-authenticated client action.

## Notes on `device.last_seen`

This pass's implementation sets `last_seen_unix` at bind time and does not
yet update it on subsequent activity (no session/heartbeat mechanism
exists in this capability's frozen contract — `identity.proto` has no RPC
for "touch device last-seen"). This is a known, documented limitation, not
silent scope creep: the field is reserved and exported correctly today,
and a future contract addition (or a composition-layer call from whichever
capability terminates authenticated sessions) would be required to keep it
live. Flagged for the Chief Architect rather than worked around by adding
an out-of-contract RPC.
