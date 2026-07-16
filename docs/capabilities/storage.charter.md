# Capability Charter: Storage

## 1. Name and one-line purpose

**Storage** — local-first storage abstraction where the user chooses (or knows) where their data physically lives, with no hidden remote copies.

## 2. Article 17 answer (asked first)

Yes. Where data lives, and whether a copy exists somewhere the user didn't choose, is one of the most direct expressions of ownership. Today's platforms silently replicate user data across servers users never see or agreed to; Storage exists to make location an intentional, visible fact (Art. 15) rather than an implementation detail hidden from the user.

## 3. Interface

**Exposes:**
- `StoreBlob(owner, data, policy) -> blob_ref` — persists opaque encrypted blob data under a declared storage policy (e.g. local-device, user's self-hosted endpoint, platform-managed default).
- `RetrieveBlob(blob_ref) -> data`
- `MoveBlob(blob_ref, new_policy)` — an explicit, user-visible relocation, never silent background migration.
- `DeleteBlob(blob_ref)` — permanent removal. Guaranteed atomic and audited, with no residual copy surviving under the blob's storage policy (including any replicas that policy implies). Where a backend cannot guarantee true byte-level erasure (e.g. some object-storage replication models), this operation must instead perform a crypto-shred: the blob's encryption key is destroyed, making the remaining ciphertext permanently unrecoverable — and the charter treats that as an equivalent, explicitly-declared fulfillment of "deleted," not a silent gap.
- `GetStorageLocation(blob_ref) -> human_readable_location` — feeds the "where is my data" experience directly.
- `ListStoragePolicies()` — the set of location choices available to a user (device-local, self-hosted, platform default), so this stays a real choice, not a hidden default with a settings page nobody finds.
- `ExportAllBlobs(owner)` — bulk export path for Art. 9.

**Consumes:**
- **Cryptography & Keys** — every blob is encrypted by Cryptography & Keys before Storage ever receives it, and decrypted only after Cryptography & Keys retrieves it back out. Storage never observes plaintext at any point; it stores and returns ciphertext only.
- **Permissions** — `RetrieveBlob` checks `CheckPermission` before returning data.
- **Audit / Explainability** — store/move/delete operations are audited.

## 4. Constitutional obligations

- **Art. 15 (minimize hidden state):** `GetStorageLocation` must always be answerable for any blob — no data should exist in a location the user cannot query and understand.
- **Art. 1 (ownership):** the user picks (or is told, with an excellent default) where new data lands; moving it is always their action, never a silent platform optimization.
- **Art. 7:** encryption of blob data must not be weakened by a storage-location choice — a "faster" storage tier is not permitted to mean "less encrypted."
- **Art. 9 (export):** `ExportAllBlobs` guarantees no storage-policy choice traps a user's data behind a proprietary access path.
- **Art. 10 (modularity):** Storage is a pure blob substrate — it does not know about "files" as a concept (that's File Objects' layer) or about conversations; it only knows encrypted bytes, an owner, and a policy.
- **Art. 15 / Art. 1 (deletion is real):** `DeleteBlob` ensures a user's belief that they deleted something is never false — either the ciphertext is actually gone, or its key is destroyed and the remaining bytes are permanently unrecoverable. No capability is permitted to bypass this by reaching around Storage's contract to remove bytes directly (Art. 10).

## 5. Experience budget

Zero-config default: new data lands in an excellent platform-managed default location with full encryption — a user does zero setup to get a sound outcome. "Transparent when curious": a "Where is my data" view lists exact locations per item, discoverable but not forced on every save. "Powerful when needed": self-hosted/custom storage endpoints for power users, configured once, not re-prompted per file.

## 6. Threat model

In scope — Storage defines the boundary between "on the user's device/control" and "elsewhere."

- **Location integrity:** a `MoveBlob` must be atomic and auditable — no window where the platform silently holds an extra copy in the old location after claiming a move completed.
- **Policy enforcement:** a blob stored under a "device-local only" policy must never be transparently uploaded as a side effect of an unrelated feature (e.g. search indexing) without that being its own explicitly chartered, permissioned behavior.
- **Encryption boundary:** Storage must reject storing plaintext for any policy — encryption happens before Storage ever sees the bytes (see §3), so a compromised storage backend yields ciphertext only.
- **Deletion integrity:** `DeleteBlob` must not leave a recoverable copy under the blob's declared policy; where physical erasure isn't guaranteed by a backend, crypto-shredding the key is the mandatory fallback (see §3) so "deleted" is never a false claim to the user.

## 7. Open questions / risks

- Exact set of "platform default" storage backends (which S3-compatible provider, self-hosting protocol support) is an implementation decision for the capability engineer, within the constraint that the policy abstraction here must not privilege one backend in a way that's hard to add alternatives to later (Art. 10).
- Interaction with File Objects' "history/versions" (each version is presumably its own blob or delta) is deferred to File Objects' charter — Storage only promises blob-level operations, not versioning semantics.

## 8. Guardian gate results

| Guardian | Verdict (✅ pass / 🚫 blocked / N/A) | Notes | Date |
|---|---|---|---|
| Constitution Warden | ✅ pass | No blocking findings — praised as unusually disciplined self-scoping ("Storage is a pure blob substrate"); freeze sequenced after Permissions/Audit per their own resolution. | 2026-07-06 |
| Experience Guardian | ✅ pass | "Where's my data" is a novel-but-earned mental model; recommended (and now incorporated) an explicit statement that storage-policy selection is never a mandatory step in file/message creation flows. | 2026-07-06 |
| Security Steward | ✅ pass (after amendment) | Initially vetoed for lacking any blob deletion/purge primitive, undermining Art. 1/15 deletion guarantees; resolved by adding `DeleteBlob` with an atomic/audited/crypto-shred-fallback guarantee — see `docs/DECISION_LOG.md`. | 2026-07-06 |

## 9. Decision log references

See `docs/DECISION_LOG.md`, 2026-07-06 entries for Phase 1 chartering.
