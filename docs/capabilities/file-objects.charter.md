# Capability Charter: File Objects

## 1. Name and one-line purpose

**File Objects** — files as first-class citizens: every file carries identity, ownership, versions, metadata, history, and lifecycle, never a disposable attachment (Art. 2).

## 2. Article 17 answer (asked first)

Yes, directly — this capability exists because Article 2 names files as first-class citizens explicitly. Treating a file as a durable object with its own identity and history (rather than a blob bolted onto a message) is what lets a user actually own their files: know their provenance, control their permissions independent of where they were shared, and see their full history.

## 3. Interface

**Exposes:**
- `CreateFileObject(owner, initial_content) -> file_object` — allocates identity, records owner, creates version 1.
- `CreateVersion(file_object_id, content) -> version_ref` — every edit is a new version, never an overwrite.
- `GetFileHistory(file_object_id) -> [events]` — full lifecycle history (created, versioned, shared, permission-changed, deleted).
- `SetFilePermissions(file_object_id, ...)` — thin pass-through to **Permissions**; File Objects does not reimplement access control.
- `GetFileMetadata(file_object_id)` / `SetFileMetadata(...)` — a fixed field set (`name`, `mime_type`, `tags`, `size`), independent of any one conversation or context the file appears in. Any future field beyond this fixed set requires a charter amendment through this capability's data manifest (§4), not an open-ended schema — this closes off the "other descriptive metadata" bucket that would otherwise let arbitrary fields accrete without Art. 8 review.
- `ExportFile(file_object_id) -> portable_bundle` — file content plus its full metadata/history, in a documented portable format (Art. 9).
- `DeleteFileObject(file_object_id)` — lifecycle termination: calls Storage's `DeleteBlob` (or its crypto-shred fallback) on every version's underlying blob, so "no longer retrievable" is a real guarantee, not just an API-level flag. The file object's identity and history entries remain resolvable in the audit trail per Art. 5, but never the content.

**Consumes:**
- **Storage** — file content (and each version) is stored as one or more blobs.
- **Permissions** — every access check delegates here; File Objects holds no parallel ACL.
- **Identity** — owner and history actor references.
- **Cryptography & Keys** — indirectly, via Storage's encryption boundary.
- **Audit / Explainability** — every mutating operation emits an event, which is also how `GetFileHistory` is largely populated.

## 4. Constitutional obligations

- **Art. 2 (files first-class):** every file object schema must carry identity, owner, and history fields — this is mechanically enforced by `scripts/constitution/check-file-objects.sh` once the Go types exist (mark persisted file-object structs with `// ascend:file-object`).
- **Art. 5 (explainability):** every mutation (`CreateVersion`, `SetFilePermissions`, `DeleteFileObject`) emits an audit event; `GetFileHistory` is the user-facing surface for "why does this file look like this / who touched it."
- **Art. 8 (privacy) — data manifest:** `name` — purpose: user-facing identification; `mime_type` — purpose: correct rendering/handling; `tags` — purpose: user-driven organization (Art. 11); `size` — purpose: display and storage-policy decisions. No other fields; see §3 on closing off open-ended metadata.
- **Art. 9 (export):** `ExportFile` bundles content, metadata, and history — a user leaving the platform gets a complete, self-contained artifact, not just raw bytes stripped of provenance.
- **Art. 10 (modularity):** File Objects composes Storage + Permissions + Identity + Audit through their published contracts only; it adds no independent storage or access-control logic of its own.
- **Art. 16 (consistency):** the same file-object model applies everywhere a file appears (a message attachment, a shared note, etc.) — no per-context reimplementation.

## 5. Experience budget

Zero-config default: attaching a file "just works" and automatically gets identity/history/permissions with no extra steps from the user. "Transparent when curious": a file's history/version list is one tap away from anywhere it's referenced, not a separate hunt through a files app. "Powerful when needed": permission and metadata editing available but not surfaced unless requested.

## 6. Threat model

Largely delegated — File Objects' own logic is not security-sensitive in isolation (it composes chartered primitives), but Security Steward should confirm no bypass:

- File Objects must not cache or duplicate content outside what Storage returns (no shadow plaintext copies for "performance").
- `SetFilePermissions` must not offer a path that skips Permissions' `CheckPermission`/grant model.
- `DeleteFileObject`'s guarantee is only as strong as Storage's `DeleteBlob` — since Storage's charter now commits to atomic deletion or crypto-shred fallback (see Storage charter §3, §6), this guarantee is real rather than aspirational.

N/A beyond the above — no independent cryptographic or storage-boundary design in this charter.

## 7. Open questions / risks

- Version storage strategy (full copy per version vs. delta) is an implementation decision for the capability engineer, constrained by Storage's blob-level contract, not a charter-level decision.
- How file objects interact with a future Search capability (indexing metadata without leaking encrypted content) is out of scope for this charter and flagged for when Search is chartered.

## 8. Guardian gate results

| Guardian | Verdict (✅ pass / 🚫 blocked / N/A) | Notes | Date |
|---|---|---|---|
| Constitution Warden | ✅ pass | No blocking findings; recommended (and now incorporated) bounding the metadata schema to a fixed field set rather than an open-ended bucket. | 2026-07-06 |
| Experience Guardian | ✅ pass | "Model example" of simple-by-default/transparent-when-curious/powerful-when-needed among all six charters — no findings. | 2026-07-06 |
| Security Steward | ✅ pass | Sound delegation to Storage/Permissions/Identity/Audit with no bypass; `DeleteFileObject`'s guarantee is now real rather than aspirational following Storage's `DeleteBlob` addition. | 2026-07-06 |

## 9. Decision log references

See `docs/DECISION_LOG.md`, 2026-07-06 entries for Phase 1 chartering.
