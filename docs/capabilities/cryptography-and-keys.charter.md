# Capability Charter: Cryptography & Keys

## 1. Name and one-line purpose

**Cryptography & Keys** — end-to-end encryption primitives, user-owned key generation and storage, the substrate every other security-sensitive capability builds on.

## 2. Article 17 answer (asked first)

Yes, foundationally. Ownership of communication is meaningless if the platform (or anyone who compromises it) can read the content or impersonate the user. This capability is what makes "user-owned keys" (Art. 7) an engineering fact rather than a marketing claim.

## 3. Interface

**Exposes:**
- `GenerateIdentityKeyMaterial() -> (public_key, private_key_handle, recovery_phrase)` — the single generation event for a root identity key pair. The recovery phrase is a mnemonic encoding of the seed that **deterministically derives** the private key; `public_key`/`private_key_handle` are not a second, independently-generated secret. There is exactly one root secret, with two representations: the opaque on-device handle and the human-writable phrase.
- `GenerateKeyPair()` — used for all *non-recovery-bearing* key pairs a capability needs (e.g. per-device session keys). Private key material never leaves this capability's boundary in plaintext; consumers receive an opaque handle backed by OS keychain / secure enclave where available, or an encrypted local store otherwise.
- `Encrypt(recipient_public_keys, plaintext) -> ciphertext`, `Decrypt(private_key_handle, ciphertext) -> plaintext` — E2E primitives used by Messaging, File Objects, etc.
- `DeriveSharedSecret(...)` — for session/channel key agreement, using an AEAD/ratchet construction chosen to provide forward secrecy and post-compromise security (exact construction is an implementation decision within this constraint — see §7).
- `SecureLocalStore(key, value)` / `SecureLocalRetrieve(key)` — encrypted local storage wrapper other capabilities use instead of hand-rolling their own at-rest encryption.
- `RestoreFromRecoveryPhrase(phrase) -> private_key_handle` — re-derives the identity's private key material from the mnemonic on a new device, purely by offline computation. No server involvement, no server-held copy of anything derived from the phrase, at any point.
- `ExportKeyMaterial(user_confirmation)` — explicit, user-initiated export of key material in a portable, documented format (Art. 9) — distinct from routine use, requires deliberate confirmation given the sensitivity.

**Consumes:**
- **Audit / Explainability** — key generation, rotation, and recovery events are audited (the operation succeeding/failing, never the key material itself).

This is a foundation-most capability: it consumes almost nothing and is consumed by nearly everything security-sensitive (Identity, Permissions, Storage, File Objects).

## 4. Constitutional obligations

- **Art. 7 (security never reduces ownership):** no server-side key escrow, ever, under any convenience justification. If a future feature proposes "backup my keys to the cloud for convenience," that is a charter amendment requiring Security Steward veto review, not a default this capability ships with.
- **Art. 1 (ownership):** private keys are generated and remain on-device (or user-controlled secure enclave); the server sees only public keys and ciphertext.
- **Art. 8 (privacy):** no key material, plaintext, or recovery phrase is ever transmitted to or logged by the server. The data manifest for this capability documents exactly zero collected fields beyond public keys.
- **Art. 9 (export):** `ExportKeyMaterial` guarantees the user is never locked out of their own cryptographic identity by the platform.

## 5. Experience budget

Invisible by default — a user never manually manages raw keys during normal use. "Transparent when curious": a "Security" screen shows key fingerprints and device key status for users who want to verify. The recovery phrase is shown once, deliberately, at identity creation, with clear consequence framing (Art. 13 — this is the one place complexity is justified because the stakes are real, not because the default is lazy).

## 6. Threat model

This capability **is** the threat model for the rest of the platform; full rigor required, Security Steward gates hardest here and may spawn an ephemeral crypto red-team specialist.

- **Key generation entropy:** must use a cryptographically secure RNG sourced from the OS; no custom entropy pooling.
- **At-rest protection:** private keys stored via OS keychain/secure enclave/TEE where the platform provides one; falls back to a locally-derived encryption key (e.g. from a device PIN/biometric) where it doesn't — never plaintext on disk.
- **In-transit protection:** only public keys and ciphertext cross the network boundary; the transport layer itself should still be TLS as defense-in-depth, not a substitute for E2E encryption.
- **Recovery phrase handling:** generated client-side, shown once, never persisted by the platform in any form (not even encrypted). The phrase is the sole seed of the identity's key material (deterministic derivation — see §3) — there is no separate encrypted key backup stored anywhere, on the server or otherwise, for the phrase to unlock. Losing the phrase together with every bound device means **permanent, unrecoverable loss of identity**, by design; this is the direct consequence of there being no server-held copy of anything derived from it, and it must be stated plainly to the user at generation time (see Identity charter §5), not hidden.
- **Key rotation:** rotating a device or identity key must not silently break other users' ability to verify who they're talking to. The re-verification signal to conversation partners is a passive, discoverable indicator (e.g. a changed-key badge on the conversation), never an interrupting modal — consistent with "transparent when curious" — and feeds Identity's audit trail.
- **Forward secrecy / post-compromise security:** `DeriveSharedSecret` must use a construction (e.g. a double-ratchet or equivalent) such that compromise of a device's current session state does not expose past session content (forward secrecy) and does not permanently compromise future sessions once the device is secured again (post-compromise security). This is distinct from the "server compromise" item below — it covers a compromised *device's* exposure of session content.
- **Server compromise scenario:** even a fully compromised server must not be able to decrypt past or future E2E content, nor mint a valid key on a user's behalf.

## 7. Open questions / risks

- Exact algorithm choices (e.g. X25519/Ed25519 + AEAD cipher suite) are an implementation decision for the capability engineer once this charter is frozen, not a charter-level decision — but Security Steward should confirm the charter's abstractions (opaque key handles, no plaintext key export outside the explicit `ExportKeyMaterial` path) don't foreclose a secure choice. **Resolved at implementation:** X25519 + XChaCha20-Poly1305 + HKDF-SHA256 (`@noble/*`), see `docs/DECISION_LOG.md` 2026-07-16.
- Multi-device key sync (so a second device can read history) is out of scope for this charter's first freeze — flagged as a follow-up capability question once Identity's device-binding model is built.
- **New, raised by Security Steward at the implementation merge gate (2026-07-16):** `DeriveSharedSecret` as implemented only produces the *initiating* party's half of a handshake — a fresh ephemeral X25519 keypair generated locally, mixed into the root key, but with no mechanism for the responding party to learn that ephemeral public key. The frozen contract has one RPC, not a two-message exchange, and no prekey-bundle concept. This is safe today (nothing consumes it yet; a mismatched session fails loudly at decrypt time rather than leaking anything) but is a real open dependency: whichever capability first needs real two-party session establishment (most likely Messaging) will need either a prekey-bundle mechanism added here, or an equivalent transport for exchanging the ephemeral public key, before `DeriveSharedSecret` can support live conversations. Do not let this be rediscovered silently when Messaging is chartered — check this item first.

## 8. Guardian gate results

| Guardian | Verdict (✅ pass / 🚫 blocked / N/A) | Notes | Date |
|---|---|---|---|
| Constitution Warden | ✅ pass | No blocking findings on first review — strongest Art. 7/8 data-manifest language of the six. | 2026-07-06 |
| Experience Guardian | ✅ pass | Invisible-by-default design sound; recommended (and now incorporated) explicit framing of key-rotation re-verification as a passive, non-interrupting signal. | 2026-07-06 |
| Security Steward | ✅ pass (after amendment) | Initially vetoed for leaving the recovery-phrase/key relationship ambiguous between two designs with opposite security properties; resolved by committing to deterministic derivation (single root secret) — see `docs/DECISION_LOG.md`. | 2026-07-06 |

**Implementation merge gate (first real code, `apps/mobile/src/capabilities/crypto/`):**

| Guardian | Verdict | Notes | Date |
|---|---|---|---|
| Constitution Warden | ✅ pass | One required follow-up (audit-logging didn't cover failure paths) — fixed same pass, verified. Also set a binding condition: manual TS review is a one-capability stopgap, not standing practice — see task "Add TS-side mechanical constitution checks." | 2026-07-16 |
| Security Steward | 🚫 blocked → ✅ pass (after fix) | Initial veto: `DeriveSharedSecret`'s handshake used static-static-only ECDH with no ephemeral contribution, breaking forward secrecy from the first message and creating a key-reuse hazard on repeated calls. Fixed with an X3DH-style ephemeral contribution, re-reviewed and confirmed closed. Left one non-blocking tracked item — see §7 above. | 2026-07-16 |

## 9. Decision log references

See `docs/DECISION_LOG.md`, 2026-07-06 entries for Phase 1 chartering, and the 2026-07-16 entries for implementation, the Security Steward veto, and its fix.
