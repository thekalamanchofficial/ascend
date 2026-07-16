# Capability Charter: Identity

## 1. Name and one-line purpose

**Identity** — user-owned identity and device/key binding, with no silent server-side identity authority.

## 2. Article 17 answer (asked first)

Yes. Identity is the root of ownership: if the platform (not the user) is the ultimate authority over "who a user is," every other ownership claim in the Constitution is hollow. This capability exists specifically to make identity something the user creates and controls, not something the server assigns and can unilaterally reissue.

## 3. Interface

**Exposes:**
- `CreateIdentity()` — generates a new user identity locally, backed by a key pair from **Cryptography & Keys**. The server never generates a user's root identity key.
- `BindDevice(identity, device_public_key)` — links a new device to an existing identity, requiring proof of possession from an already-bound device, **or**, in the all-devices-lost path, a binding assertion self-signed by key material derived from the recovery phrase (see Cryptography & Keys' `RestoreFromRecoveryPhrase`). The server only relays and audit-logs this assertion — it never authenticates, approves, or overrides a binding itself, and has no discretionary or support-mediated path to bind a device.
- `RevokeDevice(identity, device_id)` — removes a device's binding.
- `ResolveIdentity(identity_ref) -> public_identity` — read-only lookup of the public-facing identity record (display name, public key, device count) for use by other capabilities (e.g. Permissions' subject resolution).
- `ListDevices(identity)` — enumerates bound devices with metadata (added date, last-seen, name).
- `ExportIdentity(identity)` — produces a complete, user-readable export of the identity record and device list (Art. 9).

**Consumes:**
- **Cryptography & Keys** — for key pair generation, device key binding proofs, and local secure storage of the identity's private material. Identity never implements its own crypto.
- **Audit / Explainability** — every bind/revoke/export emits an audit event.

## 4. Constitutional obligations

- **Art. 1 (ownership):** the identity's private key is generated and held client-side via Cryptography & Keys. The server stores only the public identity record. There is no server-side "reset identity" path that does not go through a user-controlled recovery mechanism.
- **Art. 5 (explainability):** `BindDevice`, `RevokeDevice`, and any change to the public identity record emit audit events — a user can always answer "when was this device added, and by which already-bound device."
- **Art. 7 (security never reduces ownership):** device recovery (lost-all-devices case) must not become a disguised server-side override. See Open Questions.
- **Art. 8 (privacy) — data manifest:**
  - `display_name` — purpose: shown to other users so they know who they're communicating with; user-editable, not derived from any other source.
  - `public_key(s)` — purpose: the cryptographic material needed to bind devices and let others encrypt to this identity; no corresponding private material ever leaves the device.
  - `device.name` — purpose: lets the user tell devices apart in the Devices screen; user-editable.
  - `device.added_at` — purpose: powers the Art. 5 "when was this device added" answer.
  - `device.last_seen` — purpose: lets the user spot a device they no longer recognize or use, as a security signal.
  No other fields are collected at this layer. No collection of unrelated profile data at this layer; that belongs to a future profile-composition feature, not this capability.
- **Art. 9 (export):** `ExportIdentity` is a first-class, always-available operation, not a support-ticket process.
- **Art. 10 (modularity):** depends only on Cryptography & Keys' and Audit's published contracts; does not reach into their internals.

## 5. Experience budget

Zero-config path: identity and a first device key are generated automatically on first launch — no signup form beyond a display name. "Transparent when curious": a Devices screen lists every bound device, when it was added, and by whom (which device authorized it) — discoverable, not front-and-center. Adding a second device is a deliberate, visible pairing flow (e.g. scan/confirm), never silent. `ExportIdentity` lives alongside the Devices screen as an explicit action, not hidden in a settings submenu.

The recovery flow (identity creation) is a single, guided screen shown once: it generates the recovery phrase, states plainly in one sentence that losing it together with all devices means permanent, unrecoverable loss of identity, and requires the user to actively confirm they've saved it before proceeding — mirroring the seriousness of the moment without turning it into a multi-step wizard.

## 6. Threat model

In scope because device binding is a security-sensitive boundary, though the deep cryptographic mechanics are owned by **Cryptography & Keys**.

- **Device spoofing:** binding a new device must require cryptographic proof from an existing device (or the recovery mechanism), not just knowledge of a shared secret transmitted over a channel the server could observe.
- **Server-as-identity-authority risk:** the server must not be able to unilaterally bind a device to a user's identity or reissue an identity without a user-controlled action being provable after the fact (feeds the Art. 5 audit trail).
- **Lost-all-devices recovery:** the hardest open question — see below. Any recovery path is in Security Steward's remit to approve before this charter can freeze.

## 7. Open questions / risks

- **Recovery when all devices are lost — resolved.** Per Cryptography & Keys' committed design (see `docs/DECISION_LOG.md`, 2026-07-06, "Recovery mechanism: deterministic key derivation, no server escrow"), the recovery phrase deterministically derives the identity's key material, and a new device binds itself by self-signed proof from that derivation — the server never verifies or approves it, only relays and audit-logs it (see §3, §6). If the recovery phrase is lost in addition to every bound device, **identity recovery is permanently and intentionally impossible** — there is no support-mediated fallback, by design, because any such fallback would itself be the disguised server override Art. 7 forbids. This tradeoff must be stated plainly to the user at identity creation, not hidden in fine print.
- **Mutual dependency shape with Audit and Permissions — resolved.** Identity, Audit, and Permissions form a three-way contract reference (see each charter's Interface). Per `docs/DECISION_LOG.md`, 2026-07-06 ("Foundation contracts composition: opaque references, no live cycle"), every cross-capability reference among these three (`identity_ref`, `subject`, `actor`) is an opaque contract-level identifier, never a concrete struct owned by one capability crossing into another's package. Audit resolves actor identity and applies permission-gating lazily, at `Query`/`Explain` call time, not as a live dependency required at `Emit` time — so no capability requires the other two to be already-initialized to construct itself. This satisfies Art. 10: the dependency exists only at the published-contract level, never as a circular Go package import.

## 8. Guardian gate results

| Guardian | Verdict (✅ pass / 🚫 blocked / N/A) | Notes | Date |
|---|---|---|---|
| Constitution Warden | ✅ pass (after amendment) | Initially blocked on unresolved Identity/Permissions/Audit contract cycle and thin Art. 8 manifest; resolved via `docs/DECISION_LOG.md` "Foundation contracts composition" entry and a per-field data manifest. | 2026-07-06 |
| Experience Guardian | ✅ pass | Zero-config identity/device creation sound; recommended (and now incorporated) an explicit experience-budget statement for the recovery flow. | 2026-07-06 |
| Security Steward | ✅ pass (after amendment) | Initially vetoed on an underspecified recovery mechanism; resolved via `docs/DECISION_LOG.md` "Recovery mechanism: deterministic key derivation, no server escrow" entry. | 2026-07-06 |

## 9. Decision log references

See `docs/DECISION_LOG.md`, 2026-07-06 entries for Phase 1 chartering.
