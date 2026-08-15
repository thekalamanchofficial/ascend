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
- `GetStorageLocation(blob_ref, requesting_subject) -> human_readable_location` — feeds the "where is my data" experience directly. **`requesting_subject` added 2026-07-17** (closing a tracked gap from the implementation merge gate — the original freeze omitted it): gated on the same `CheckPermission` action as `RetrieveBlob` (`storage.retrieve_blob`) — if a subject can read a blob's content, they may also learn where it lives; there is no separate, narrower "location" grant.
- `ListStoragePolicies()` — the set of location choices available to a user (device-local, self-hosted, platform default), so this stays a real choice, not a hidden default with a settings page nobody finds.
- `ExportAllBlobs(owner, requesting_subject)` — bulk export path for Art. 9. **`requesting_subject` added 2026-07-17** (same tracked gap): unlike the per-blob RPCs, this is not `CheckPermission`-gated per blob — a bulk export of everything an owner has ever stored is a right-to-leave operation, not a shareable read, so it is rejected unless `requesting_subject == owner`. No delegated or collaborator-initiated bulk export exists; a collaborator with a per-blob grant cannot use `ExportAllBlobs` to obtain blobs beyond what they were individually granted.

**Consumes:**
- **Cryptography & Keys** — every blob is encrypted by Cryptography & Keys before Storage ever receives it, and decrypted only after Cryptography & Keys retrieves it back out. Storage never observes plaintext at any point; it stores and returns ciphertext only.
- **Permissions** — `RetrieveBlob`, `MoveBlob`, `DeleteBlob`, and `GetStorageLocation` all check `CheckPermission` before acting; `ExportAllBlobs` checks `requesting_subject == owner` directly (bulk export is a right-to-leave operation, not a shareable grant — see §3). (`MoveBlob`/`DeleteBlob`'s gating was a self-flagged implementation-time extension, 2026-07-17, using a `requesting_subject` field the frozen contract already carried — confirmed sound by both guardians at the merge gate. `GetStorageLocation`/`ExportAllBlobs`'s gating required an actual wire-contract amendment, also 2026-07-17, since neither RPC had a `requesting_subject` field at all until then — see `docs/DECISION_LOG.md`.)
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

- **Location integrity:** a `MoveBlob` must be atomic and auditable — no window where the platform silently holds an extra copy in the old location after claiming a move completed. **Concurrency hardening required, 2026-07-17** (Security Steward, implementation merge gate): `DeleteBlob`/`MoveBlob`'s check-then-act sequence against the in-memory store must be verified `-race`-clean under genuine concurrent duplicate requests for the same `blob_ref`, matching the rigor Session/Request Authentication's nonce-consumption logic received (a 200-iteration concurrent test plus a mutation-tested broken-variant proof). Required before this capability is wired to any real network path, not before this fix specifically — but now being addressed alongside the two gating gaps above. **Closed, 2026-07-17** (see `docs/DECISION_LOG.md`, "Storage: concurrency-harden DeleteBlob/MoveBlob"): `Store` (`store.go`) gained a per-`blob_ref` operation lock (`opLocks sync.Map`), acquired for the full check-then-act sequence in both `DeleteBlob` and `MoveBlob`. No `-race` run was possible (no C compiler in this sandbox, confirmed again); verified instead with the same mutation-testing rigor as Session/Request Authentication's nonce-consumption proof — 200-iteration, 16-concurrent-caller regression tests pass reliably against the real fixed code, and reliably fail (9-10 of 10 full 200-iteration sweeps) against a deliberately lock-removed variant patched into an isolated scratchpad copy, never the real repo.
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

**Implementation merge gate (`services/api/internal/storage`):**

| Guardian | Verdict | Notes | Date |
|---|---|---|---|
| Constitution Warden | ✅ pass | No blocking findings. Confirmed the `StoreBlob`-rolls-back-on-audit-failure divergence from Identity/Permissions' "fail loudly, mutation stands" pattern is deliberate and correct (`blob_ref` is the sole handle to newly-created data — an unaudited-but-committed blob would be permanently unreachable, a worse Art. 15 hazard than a retriable grant failure). Required the self-flagged `CheckPermission` extension to `MoveBlob`/`DeleteBlob` be reflected in this charter's §3 (done, above) and the general precedent recorded in the charter template (done). | 2026-07-17 |
| Security Steward | ✅ pass | Independently verified the crypto-shred guarantee is real (captured the wrapping key pre-delete, proved decryption works, then proved it's destroyed post-delete and the remaining ciphertext is unrecoverable), confirmed the wrapping key is structurally unable to leak through export (no field exists for it), and ruled the `CheckPermission` extension a genuine security improvement, not scope creep. Flagged two pre-existing, frozen-contract-level gaps — `ExportAllBlobsRequest`/`GetStorageLocationRequest` carry no caller-identity field to gate against — required before `Mount` is ever wired to a live network path, not blocking this merge (nothing is wired yet). Also recommended concurrency-hardening `DeleteBlob`/`MoveBlob` with a `-race`-verified test before going live, matching the rigor Session/Request Authentication's nonce consumption got. | 2026-07-17 |

Not wired into `services/api/main.go` — see `docs/CAPABILITY_REGISTRY.md` Notes.

**Follow-up fixes closed (2026-07-17):**

| Guardian | Verdict | Notes | Date |
|---|---|---|---|
| Security Steward | ✅ pass | Confirmed `GetStorageLocation` genuinely gates on the same `CheckPermission` action as `RetrieveBlob`; confirmed `ExportAllBlobs` makes no `CheckPermission` call at all and rejects anyone but the exact owner, even a subject with full per-blob grant coverage — ruled this the correct design, not overly strict, since bulk export is a right-to-leave primitive where grant-based delegation would be a privilege-escalation path disguised as convenience. Independently re-ran the concurrency mutation-testing proof itself (10/10 failures against a broken variant, 10/10 passes against the real fix) rather than trusting the report. Affirmed `MoveBlob`'s "both racing callers get success" behavior as correct, not a hidden-conflict risk — both callers' desired end state is genuinely achieved, and the no-op case is still discoverable via audit metadata. No required changes. | 2026-07-17 |

Both tracked items from the original implementation merge gate are now fully resolved. No open guardian findings remain against Storage's current (still `Mount`-unwired) scope.

## 9. Decision log references

See `docs/DECISION_LOG.md`, 2026-07-06 entries for Phase 1 chartering, and the 2026-07-17 entries for implementation and the merge-gate pass.
