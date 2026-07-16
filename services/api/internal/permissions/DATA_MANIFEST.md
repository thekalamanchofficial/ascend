# Data Manifest — Permissions

Per `docs/CONSTITUTION.md` Art. 8 (privacy is the default; minimum data
necessary, every collected field has a documented purpose) and the
Permissions charter §4. This manifest covers the fields persisted in this
capability's grant/revoke records (`Grant` and `HistoryEntry` in
`types.go`, both marked `// ascend:persisted`).

`Policy` (the `DefinePolicy` record) is intentionally excluded: it is
platform/capability configuration (which resource types exist and their
registered default rule text), not data about an individual user, so it
carries no Art. 8 collection obligation.

## Fields

- `grantor`
  Purpose: identifies who authorized this specific grant or revoke — the
  minimum needed to answer "who gave this access" (Art. 5 explainability)
  and to enforce the grant-chain escalation rule (charter §6).

- `subject`
  Purpose: identifies who the access applies to — the minimum needed to
  answer "who can do this" and to resolve `CheckPermission`.

- `action`
  Purpose: identifies which operation the grant covers (e.g. `read`,
  `write`) — without it, a grant would be all-or-nothing on a resource,
  violating least privilege (Art. 7).

- `resource` (`resource_type` + `resource_id`)
  Purpose: identifies exactly which resource the grant/revoke applies to —
  the minimum needed to scope any access decision to a single object
  rather than a whole class of objects.

- `scope`
  Purpose: bounds a grant to less than full access where the policy
  allows (e.g. read-only vs. full), so grants are never coarser than the
  requester actually needs (Art. 7 — least privilege). Also the field the
  grant-chain escalation rule (charter §6) ranks to decide whether a
  grantor may extend a given scope to someone else.

- `timestamp` (`granted_at_unix` on `Grant`, `at_unix` on `HistoryEntry`)
  Purpose: required for the grant/revoke history itself — when a change
  happened is part of "who can do what, since when" (Art. 5
  explainability, Art. 9 export).

- `event_type` (`HistoryEntry` only; values: `grant`, `revoke`)
  Purpose: distinguishes whether a history record represents a grant or a
  revoke event, needed to reconstruct an accurate grant/revoke history
  (Art. 5, Art. 9) rather than a single ambiguous log of "something
  happened."

- `outcome` / `denial_reason` (`HistoryEntry` only)
  Purpose: records whether a requested grant/revoke was allowed or denied,
  and why, so a denied privilege-escalation attempt is itself explainable
  (Art. 5) and auditable, not silently dropped.

## Retention

Per charter §4: this relationship metadata (who has access to what) is
retained only as long as the underlying resource exists — it must be
deleted when the resource is deleted, not kept as an independent record.
**Known gap, not yet wired:** no capability that owns a resource type
(Storage, File Objects) exists yet to emit a resource-deletion signal this
package can subscribe to, so `Grant`/`HistoryEntry` records are not yet
actually purged on resource deletion. Tracked as a follow-up integration
point once a resource-owning capability comes online — see
`docs/DECISION_LOG.md`.

## Not collected

This capability does not collect or store: display names, contact
information, message content, file content, or any field not listed
above. `subject`/`grantor` are opaque identity-reference strings (see
`types.go`) — this package never resolves them to a real name, email, or
other personal-identity attribute.
