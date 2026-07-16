# Decision Log

Append-only. Every non-trivial decision made by the Chief Architect, a guardian, or a capability engineer is recorded here, in chronological order. Never edit or delete a past entry — if a decision is reversed, add a new entry that supersedes it and link back.

## Format

```
### YYYY-MM-DD — <short decision title>
**Decision:** what was decided.
**Rationale:** why.
**Article(s) invoked:** e.g. Art. 4, Art. 10.
**Made by:** Chief Architect | Constitution Warden | Experience Guardian | Security Steward | <capability-engineer name>.
**Supersedes:** (optional) link to a prior entry this reverses.
```

---

### 2026-07-06 — Contracts source of truth: Protocol Buffers (via Buf)

**Decision:** `packages/contracts` defines capability interfaces in Protocol Buffers, with Buf for linting, breaking-change detection, and codegen to Go, TypeScript, and Python.

**Rationale:** Ascend has three consumer languages (Go backend, TypeScript mobile client, Python AI service), not two, and the stack already calls for "internal domain events" alongside request/response APIs. Protobuf gives one schema language that covers both RPC-shaped capability interfaces and event payloads, with mature codegen to all three target languages and Buf's breaking-change detection giving Article 10 (modularity — capabilities depend only on published contracts) a mechanical backstop. OpenAPI was considered but is REST/HTTP-shaped only, would need a second schema system for domain events, and Python codegen tooling is comparatively weaker than Go/TS.

**Article(s) invoked:** Art. 10 (modularity — contracts are the only cross-capability dependency surface).

**Made by:** Chief Architect.

---

### 2026-07-06 — Go HTTP routing: Chi over Gin

**Decision:** `services/api` uses `go-chi/chi` for HTTP routing rather than Gin.

**Rationale:** Chi is a thin, idiomatic layer directly on `net/http` — no framework-specific context type, no bundled ORM/rendering opinions. That fits the capability-based architecture: each capability's HTTP surface can be expressed as a plain `http.Handler` composed with stdlib-compatible middleware, mountable and testable in isolation without pulling in framework machinery it doesn't need. Gin's speed and ecosystem are attractive but its custom `gin.Context` and heavier convention set add coupling that works against Article 10 (modularity) at this stage.

**Article(s) invoked:** Art. 10 (modularity).

**Made by:** Chief Architect.

---

### 2026-07-06 — Recovery mechanism: deterministic key derivation, no server escrow

**Decision:** The lost-all-devices recovery mechanism (Identity + Cryptography & Keys) works by deriving a user's identity key material deterministically from a client-side-generated recovery phrase. There is exactly one root secret with two representations (on-device key handle, human-writable phrase) — never a second, server-held encrypted key backup that the phrase merely unlocks. A new device binds itself via a self-signed assertion derived from the phrase; the server only relays and audit-logs that assertion and has no verification or override authority over it. If the phrase is lost together with every bound device, identity recovery is permanently and intentionally impossible — no support-mediated fallback exists, because any such fallback would itself be the disguised server override Article 7 forbids.

**Rationale:** Security Steward vetoed both the Identity and Cryptography & Keys charters because the original "recovery phrase" language was compatible with two designs — deterministic derivation (no server involvement possible) or an encrypted-backup-unlocked-by-phrase model (which, to survive total device loss, would need a durable copy somewhere, and the only realistic "somewhere" is the server — i.e. exactly the escrow Article 7 forbids). Committing explicitly to deterministic derivation closes that ambiguity and makes "no server-side key escrow, ever" a structural guarantee rather than a policy promise that could quietly erode later.

**Article(s) invoked:** Art. 7 (security must never reduce ownership), Art. 1 (ownership), Art. 9 (export/recoverability, bounded honestly rather than promised beyond what the design supports).

**Made by:** Chief Architect, resolving a Security Steward veto on `docs/capabilities/identity.charter.md` and `docs/capabilities/cryptography-and-keys.charter.md`.

---

### 2026-07-06 — Foundation contracts composition: opaque references, no live cycle

**Decision:** Identity, Permissions, and Audit / Explainability form a three-way contract reference (Identity → Audit, Audit → Identity; Audit → Permissions, Permissions → Audit; Permissions → Identity). This is resolved as follows: every cross-capability reference among the three (`identity_ref`, `subject`, `actor`) is an opaque contract-level identifier defined in `packages/contracts`, never a concrete struct owned by one capability crossing into another's package. Audit resolves actor identity and applies permission-gating lazily, at `Query`/`Explain` call time, rather than requiring all three services to be already-initialized to construct one another — so there is no live circular requirement at startup or at `Emit` time, only a contracts-level reference.

**Rationale:** Constitution Warden blocked the Identity, Permissions, and Audit charters because each charter correctly flagged the mutual-dependency risk but none resolved it — a flagged-but-unresolved cycle among three foundation capabilities is exactly the "assertion, not specifics" pattern the charter gate exists to catch. The existing mechanical Art. 10 check (`scripts/constitution/check-modularity.sh`) already anticipates cross-cutting substrates by exempting shared packages like `internal/audit` from the no-cross-import rule; combined with the Protobuf/Buf contracts decision above, opaque contract types plus lazy resolution is a standard, mechanically-checkable way to satisfy Article 10 without collapsing into a real circular package dependency.

**Article(s) invoked:** Art. 10 (modularity — capabilities depend only on published contracts, never each other's internals).

**Made by:** Chief Architect, resolving a Constitution Warden block on `docs/capabilities/identity.charter.md`, `docs/capabilities/permissions.charter.md`, and `docs/capabilities/audit-explainability.charter.md`.

---

### 2026-07-06 — Storage gains an explicit deletion primitive

**Decision:** Storage's interface adds `DeleteBlob(blob_ref)`: atomic, audited, permanent removal with no residual copy under the blob's storage policy. Where a backend can't guarantee true byte-level erasure, `DeleteBlob` must crypto-shred instead (destroy the blob's encryption key, making the remaining ciphertext permanently unrecoverable) — declared explicitly as an equivalent fulfillment of "deleted," not a silent gap. Storage's charter is also reworded so the plaintext boundary is unambiguous: Storage never observes plaintext at any point; encryption/decryption happens entirely within Cryptography & Keys.

**Rationale:** Security Steward vetoed the Storage charter because its original interface had no way to actually remove bytes — every version of every deleted File Object would otherwise either linger indefinitely (an undisclosed retention fact, contradicting Art. 15) or require some capability to bypass Storage's published contract to delete bytes directly (an Art. 10 violation). File Objects' `DeleteFileObject` guarantee ("no longer retrievable") was contingent on this gap being closed.

**Article(s) invoked:** Art. 15 (minimize hidden state), Art. 1 (ownership — deletion must be real), Art. 10 (modularity — no capability bypasses Storage's contract to delete bytes itself).

**Made by:** Chief Architect, resolving a Security Steward veto on `docs/capabilities/storage.charter.md`.

---

### 2026-07-16 — Cryptography & Keys interface frozen; implementation location is apps/mobile, not services/api

**Decision:** `docs/capabilities/cryptography-and-keys.charter.md` §3 is translated into `packages/contracts/proto/ascend/crypto/v1/crypto.proto` and frozen (`buf lint` clean). The capability-engineer spawned against this contract implements it in `apps/mobile` (TypeScript, on-device), **not** `services/api` — the charter's own §4/§6 require private key material to remain on-device and the server to see only public keys and ciphertext, so a Go backend implementation of `Encrypt`/`Decrypt`/`GenerateIdentityKeyMaterial` would itself violate Art. 7/8, not merely be a design choice. The `.proto` service definition is kept as a cross-language type/signature contract (Go, TS, Python codegen all agree on shapes), but its generated Go and Python server bindings are unused by design — only the TS bindings back a real implementation. This is flagged explicitly because the mechanical CI checks (`scripts/constitution/check-audit-events.sh`, `check-export-paths.sh`, etc.) only scan Go under `services/api/internal/`; they do not and currently cannot cover this capability's actual implementation. That is a real gap, not an oversight to hide — logged here as an open follow-up: either a TypeScript-side equivalent of the mechanical checks needs to exist before Art. 5/9 can be mechanically enforced on mobile-implemented capabilities, or Constitution Warden needs to review mobile-side capability code manually at merge gates until one exists.

**Rationale:** Founder approved starting implementation, Crypto-first, per the dependency graph in `docs/CAPABILITY_REGISTRY.md`. Catching the on-device requirement now, before any code was written, avoids building a working implementation that would have had to be thrown away for being unconstitutional by construction.

**Article(s) invoked:** Art. 7 (security must never reduce ownership — no path for the server to ever see plaintext or private keys, structurally not just by policy), Art. 8 (privacy — server collects zero key material), Art. 10 (modularity — contract is the only interface the engineer builds against), Art. 1 (founder/owner approval gate satisfied before implementation began).

**Made by:** Chief Architect, founder approval given 2026-07-16.

---

### 2026-07-16 — Cryptography & Keys algorithm/library choice: @noble/* + @scure/bip39, single audited CSPRNG entry point

**Decision:** Implementation in `apps/mobile/src/capabilities/crypto/` uses X25519 (Diffie-Hellman/ECDH) for all key-agreement and encryption primitives, XChaCha20-Poly1305 as the AEAD cipher, HKDF-SHA256 for key derivation, and BIP-39 (`@scure/bip39`) purely as an entropy<->mnemonic encoding for the recovery phrase — via the `@noble/curves`, `@noble/ciphers`, and `@noble/hashes` pure-TypeScript libraries (all v2.2.0), not `react-native-libsodium` or a custom native binding. Every call site that needs randomness goes through exactly one function, `random.ts`'s `randomBytes()`, which wraps `expo-crypto`'s `getRandomBytes` (native OS CSPRNG binding). No noble/scure API that has its own internal RNG (e.g. `@scure/bip39`'s `generateMnemonic()`, noble's `utils.randomPrivateKey()`) is used anywhere in this module — entropy is always generated by `randomBytes()` first and passed in explicitly (e.g. `entropyToMnemonic(randomBytes(32), wordlist)` instead of `generateMnemonic()`), so there is exactly one audited entropy source in the whole capability, satisfying the charter's "no custom entropy pooling" requirement structurally rather than by convention. `react-native-get-random-values` (a common noble-library companion polyfill) was evaluated and deliberately NOT added as a dependency, precisely because this design never lets any library reach for its own ambient `crypto.getRandomValues` — it would have been a real dependency with nothing in the code path actually calling it.

**Rationale:** `@noble/*` are pure-TypeScript, widely audited (noble-curves/noble-ciphers have had multiple third-party security audits), dependency-free, and work identically across iOS/Android/web/Jest without any native module compilation step — important for a capability with no server component, where "the client is the only implementation" means the crypto library itself carries the full trust burden. `react-native-libsodium` (a native binding) was considered and rejected for this first pass: it would require native module linking/config plugins before any code could even be tested, adds a native-build dependency to a repo that is currently pure-JS/TS scaffolding, and the pure-JS noble libraries are fast enough and audited enough that the native-binding performance argument doesn't outweigh the added build complexity here. X25519 (rather than P-256/NIST curves) and XChaCha20-Poly1305 (rather than AES-GCM) were chosen because they are the modern, constant-time-by-construction, misuse-resistant defaults used by Signal, age, and libsodium's own recommended API (`crypto_box`), and XChaCha20's 24-byte (vs. 12-byte GCM/ChaCha20) nonce removes any practical risk of nonce reuse from random generation — relevant since this module generates a fresh random nonce per encryption rather than maintaining a counter.

**Article(s) invoked:** Art. 7 (security must never reduce ownership — algorithm choice must not create a weaker-than-claimed guarantee), Art. 8 (privacy — CSPRNG sourced only from the OS, no custom entropy pooling, per charter §6 threat model).

**Made by:** Cryptography & Keys capability-engineer.

---

### 2026-07-16 — DeriveSharedSecret construction: symmetric-key ratchet + DH ratchet, X25519-based, session state kept out of the frozen contract's RPC surface

**Decision:** `DeriveSharedSecret` (in `apps/mobile/src/capabilities/crypto/index.ts`, backed by `ratchet.ts`) performs an X25519 ECDH between the caller's local private key and the given remote public key, derives a root key via HKDF-SHA256, and initializes a `RatchetState` (root key, a freshly generated local DH ratchet keypair, and an initial sending chain key) that is stored under the returned `shared_secret_handle` in the same opaque key registry used for private keys. Two internal, non-contract functions are also implemented and directly tested: `deriveNextMessageKey` (the symmetric/chain ratchet — each call derives a message key via HKDF and replaces the chain key with a new HKDF output, so the old chain key cannot be recomputed from the new state) and `ratchetAdvance` (the Diffie-Hellman ratchet — generates a brand-new local DH keypair and mixes a fresh ECDH output into the root key, so a new root key is unpredictable from the old one alone even to an attacker who fully compromised the old state). These two mechanisms together are what a real Double Ratchet combines to provide forward secrecy (chain ratchet) and post-compromise security (DH ratchet) per the charter §6 threat model. `ratchetEncrypt`/`ratchetDecrypt`-style per-message send/receive RPCs are deliberately NOT added to this capability's public surface, because the frozen `crypto.proto` contract only defines `DeriveSharedSecret` returning a handle — no message-level encrypt/decrypt-with-ratchet-state RPC exists in the frozen contract. Wiring per-message ratchet encryption into actual conversations is left as the entry point a future Messaging capability calls (`deriveNextMessageKey`/`ratchetAdvance` are exported from `ratchet.ts` for that purpose), not something this capability-engineer should add speculatively without a corresponding contract change.

**Rationale:** The charter explicitly leaves "double-ratchet or equivalent construction" as the capability engineer's implementation decision, gated only on the FS/PCS properties being real, not on matching Signal's exact wire protocol (X3DH's 3-DH handshake, prekey bundles, etc. — those require a prekey-publishing mechanism that doesn't exist yet since Identity's device-binding model is explicitly out of scope per the charter's §7 open questions). A single-DH handshake (rather than full X3DH) plus a genuine chain+DH ratchet afterward is the smallest construction that (a) is symmetric — both parties independently derive the identical initial root key from public keys they already have, requiring no additional out-of-band exchange the current contract doesn't support, and (b) still provides the two named security properties, tested directly in `__tests__/crypto.test.ts` ("forward secrecy" and "post-compromise security" test cases) rather than merely asserted. Building a full Signal-protocol-compatible X3DH implementation now, without a prekey-bundle contract to back it, would be over-building ahead of the interface that would actually need it — Messaging's eventual contract may shape the handshake differently once it exists.

**Article(s) invoked:** Art. 7 (security — FS/PCS are the concrete engineering guarantee behind "compromise doesn't reduce ownership retroactively or permanently"), Art. 10 (modularity — no RPC added beyond the frozen contract; extension point left for the capability that will actually consume it).

**Made by:** Cryptography & Keys capability-engineer.

---

### 2026-07-16 — Encrypt/Decrypt wire format: versioned multi-recipient sealed envelope (hybrid encryption)

**Decision:** `Encrypt`/`Decrypt` (in `envelope.ts`) implement a self-describing, versioned binary format: a single ephemeral X25519 keypair is generated per call to `Encrypt`; for each recipient public key, the ephemeral private key and that recipient's public key are combined via ECDH + HKDF into a per-recipient wrapping key, which encrypts a single random 32-byte content-encryption key (CEK) under XChaCha20-Poly1305; the CEK then encrypts the actual plaintext once, also under XChaCha20-Poly1305. Each per-recipient block is tagged with a truncated SHA-256 hash of the recipient's public key (not the public key itself) so `Decrypt` can find the block addressed to a given private-key handle without brute-forcing every entry or leaking which public keys were addressed to a passive ciphertext observer. The format has an explicit 1-byte version field so a future format change is detectable and rejected cleanly rather than silently misparsed.

**Rationale:** The frozen contract's `EncryptRequest` takes `repeated bytes recipient_public_keys`, i.e. multi-recipient is part of the interface, not an add-on — a naive design that just picks one recipient or duplicates the whole ciphertext per recipient would either violate the contract or waste bandwidth/storage linearly re-encrypting the same plaintext. The hybrid-encryption pattern (one CEK, wrapped per recipient) is the standard solution or this exact problem, used by age's and PGP's own multi-recipient modes for the same reason. Embedding a format version byte follows the same "documented, versioned format" discipline the charter requires of `ExportKeyMaterial`, applied here too since ciphertext produced by this module may need to remain decryptable by a later version of this same module.

**Article(s) invoked:** Art. 7 (security — recipient authentication is per-key, not an all-or-nothing shared secret), Art. 15 (minimize hidden state — the wire format is explicit and versioned rather than an undocumented internal detail).

**Made by:** Cryptography & Keys capability-engineer.

---

### 2026-07-16 — SecureLocalStore/Retrieve: OS keychain primary, in-memory-by-default software vault fallback, pluggable key-provider hook

**Decision:** `secureStore.ts` tries `expo-secure-store` (iOS Keychain / Android Keystore, checked live via `isAvailableAsync()` rather than assumed) as the primary backend for every `SecureLocalStore`/`SecureLocalRetrieve` call. When that backend genuinely isn't available (e.g. web, or an environment with no native module), it falls back to a "software vault": values are still always encrypted with XChaCha20-Poly1305 before being held in memory — plaintext is never written to disk on any path — but the vault's own symmetric key defaults to a random value that lives only in process memory (lost on restart) unless the app shell calls `setFallbackKeyProvider(...)` to supply a device-PIN/biometric-derived key instead. This provider hook is exported but intentionally left unwired to any real biometric API in this pass, since no UI/biometric-prompt flow exists yet in this scaffold-only mobile app.

**Rationale:** The charter's threat model asks for "a locally-derived encryption key (e.g. from a device PIN/biometric)" as the fallback, but no platform exposes raw PIN/biometric material to application code directly (biometric APIs return a yes/no authentication result, not key bytes) — any real implementation needs a platform-specific key-derivation strategy the app shell controls (e.g. gate a stored key behind `expo-local-authentication`, or a WebAuthn-backed key on web), which is a UI/platform-integration decision outside this capability's boundary, not a cryptographic one. Rather than fabricate a fake "PIN-derived" key that doesn't actually derive from a PIN (which would misrepresent the guarantee), the honest choice was: (1) never weaken the "no plaintext on disk" invariant — the vault always encrypts — and (2) make the weaker default explicit and inspectable (in-memory-only, data lost on restart) rather than silently persisting under a guessable or hardcoded key, with a clearly documented extension seam for the real per-platform key source to be wired in later without changing this module's public shape.

**Article(s) invoked:** Art. 7 (security must never reduce ownership — no silent weakening; the gap is documented, not hidden), Art. 15 (minimize hidden state — the fallback's reduced guarantee is stated in code comments and this entry, not left implicit).

**Made by:** Cryptography & Keys capability-engineer.

---

### 2026-07-16 — ExportKeyMaterial format: versioned JSON blob, recovery phrase deliberately excluded

**Decision:** `ExportKeyMaterial` (gated on `user_confirmation`) produces UTF-8 JSON, `format_version: "ascend-crypto-export-v1"`, containing every currently-registered private-key handle's purpose, base64 public key, and base64 private key, plus an export timestamp. The full JSON schema is documented directly in a comment block above `exportKeyMaterial` in `index.ts`. The recovery phrase itself is NOT included in the export blob — it was already shown once, in full, by the caller at `GenerateIdentityKeyMaterial` time, and this module never persists or re-derives it for re-display; the exported `identity`-purpose private key bytes are sufficient on their own to restore the identity keypair elsewhere, without needing the phrase a second time.

**Rationale:** Art. 9 requires export to guarantee the user is never locked out of their own cryptographic identity by the platform — a raw private-key export achieves that directly, and doing so in a self-describing, versioned JSON format (rather than an opaque proprietary binary blob) means the user (or a future competing implementation) can parse and use it without depending on this module's continued existence, which is the actual substance of "always able to leave" (Art. 1/9) applied to key material specifically. Excluding the recovery phrase from the export blob is a deliberate, documented boundary, not an oversight: re-surfacing the phrase on demand would mean this module retains it somewhere (in memory at minimum) beyond the single generation event, which the charter's §6 threat model explicitly forbids ("never persisted by the platform in any form, not even encrypted"); a private-key export is the constitutionally-required safety net, and it does not require reviving the phrase to provide it.

**Article(s) invoked:** Art. 9 (export always possible, in a documented format), Art. 1 (ownership — the user, not this module, is the durable source of truth for their key material), Art. 8 (privacy — recovery phrase never persisted in any form, including inside an export blob).

**Made by:** Cryptography & Keys capability-engineer.

---

### 2026-07-16 — Security Steward veto: DeriveSharedSecret's initial handshake lacks forward secrecy

**Decision:** Merge of the Cryptography & Keys implementation is blocked. `DeriveSharedSecret`'s initial root-key derivation (`index.ts`) uses a plain static-static X25519 ECDH between the caller's long-term private key and the remote long-term public key, with no ephemeral contribution mixed in before deriving `rootKey`/`sendingChainKey`. This means (a) every message encrypted under the chain before the first `ratchetAdvance()` call is retroactively decryptable by anyone who later obtains either party's long-term private key — the exact scenario charter §6 requires forward secrecy to prevent — and (b) because the derivation is fully deterministic, repeated `DeriveSharedSecret` calls between the same static keypair reproduce identical root/chain keys, a key-reuse hazard. Confirmed independently by Security Steward and an ephemeral crypto red-team specialist it spawned. A secondary, non-blocking finding: `audit.ts`'s `secure_local_store_write` event logs the raw `SecureLocalStoreRequest.key` string, which is safe today (console-log stub) but would leak potentially-identifying metadata if wired to a real Audit backend without first hashing the key.

**Rationale:** The chain-ratchet and DH-ratchet mechanisms implemented (`ratchet.ts`) are real and correctly tested for forward secrecy and post-compromise security *after* the initial root key exists — but the charter's forward-secrecy guarantee was implicitly assumed to hold from session start, and it doesn't: the seed itself is a deterministic function of static keys the engineer's own test suite feeds the identity private key handle into. This is a correctness gap in the specific construction chosen (single static-static DH, no ephemeral), not a flaw in the charter's requirement or the frozen contract — `DeriveSharedSecretResponse` returning only an opaque handle leaves room for an ephemeral public key to be carried alongside it without a contract change.

**Article(s) invoked:** Art. 7 (security must never reduce ownership — a forward-secrecy claim that doesn't hold from the first message is a claim the user can't actually rely on).

**Made by:** Security Steward, vetoing the Cryptography & Keys implementation at the merge gate. Required before re-review: mix a freshly-generated ephemeral contribution into the initial handshake (X3DH-style, no prekey bundle needed) plus a test proving long-term-key compromise does not expose pre-ratchet chain content; tighten `SecureLocalStoreRequest.key` handling in audit logging.

---

### 2026-07-16 — Constitution Warden merge-gate pass, with required follow-up: audit failure paths, and a structural gap flagged for the org

**Decision:** Constitution Warden passes the Cryptography & Keys implementation on Article 17/1/7/8/9/10 grounds (verified by hand: no network/escrow primitive anywhere in the module, audit metadata never contains key material or the recovery phrase, export is genuinely usable — independently re-derives a matching public key from the exported private key bytes in the test suite). One concrete Art. 5 gap found: `logAuditEvent` is only ever called on success paths; `generateKeyPair`, `restoreFromRecoveryPhrase`, and `exportKeyMaterial` all `throw` on rejection/failure before reaching an audit call, contradicting `audit.ts`'s own stated obligation to log "succeeding/failing." Not severe enough to block this merge on its own (on-device threat model; an attacker with local code execution already has stronger access than an audit trail would defend against), but required before the next merge in this capability. Separately, Constitution Warden holds that the audit-logging-stub pattern is acceptable **only** as a one-off interim measure for this first capability, on two conditions treated as binding going forward: (1) the stub must cover failure paths, not just success, from here on; (2) before a second capability lands with a mobile-only (non-Go) implementation under this same pattern, a TypeScript-side mechanical equivalent of `check-audit-events.sh`/`check-export-paths.sh` must exist — manual guardian review at the merge gate does not scale past one or two capabilities.

**Rationale:** Security-relevant obligations stated in a module's own code comments (not just the charter) are real obligations Constitution Warden checks by hand when no CI backstop exists yet — finding the gap here, before it's copied into every subsequent mobile capability, is cheaper than finding it later across many.

**Article(s) invoked:** Art. 5 (explainability — every important action, including failed/rejected ones, must be discoverable), Art. 17 (asked first, answered yes — this is load-bearing security substrate, not complexity for its own sake).

**Made by:** Constitution Warden, merge-gate review of the Cryptography & Keys implementation.

---

### 2026-07-16 — Test infrastructure: plain Jest + scoped Babel config + manual node_modules mocks, not jest-expo

**Decision:** `apps/mobile` gets a minimal `jest.config.js` (testEnvironment `node`, `babel-jest` transform, `transformIgnorePatterns` widened only for the `@noble`/`@scure` scopes since those ship ESM-only with no CommonJS build) and a `babel.config.js` that branches on `api.env("test")`: real Expo/Metro bundling uses `babel-preset-expo` as normal, but Jest runs under `@babel/preset-env` (explicit `modules: "commonjs"`) + `@babel/preset-typescript` instead. `expo-crypto` and `expo-secure-store` — both native-module bindings that throw or fail to parse when required outside a running Expo app — are given manual Jest mocks at `apps/mobile/__mocks__/expo-crypto.ts` and `apps/mobile/__mocks__/expo-secure-store.ts` (Jest auto-applies `__mocks__` files for node_modules packages without an explicit `jest.mock()` call per file). The `expo-crypto` mock is itself backed by Node's own OS CSPRNG (`node:crypto`), preserving the "OS-sourced, no custom entropy pool" property under test rather than substituting something weaker. `jest-environment-node` was pinned as an explicit devDependency at the exact version `jest@30.4.2` expects (`30.4.1`) after discovering `react-native@0.74.0`'s own transitive `jest-environment-node@29.7.0` was winning npm's hoisting and getting resolved at the project root instead, causing a hard `jest-mock` API mismatch (`clearMocksOnScope is not a function`) that failed every test run before any test code executed.

**Rationale:** `jest-expo` (the official Expo Jest preset) was evaluated and rejected for this module specifically: it pulls in a full React Native component-testing environment (NativeModules mocking, RN's own default mock set) that this capability doesn't need — none of this module's code renders a component or touches a React Native API directly, only `expo-crypto`/`expo-secure-store`, which still need hand-written mocks either way since Expo doesn't ship default Jest mocks for every module it publishes. A lighter, fully-understood Jest+Babel config keeps the test suite fast, keeps the exact transform behavior auditable (no inherited preset "magic"), and avoids importing test-environment complexity that belongs to whichever capability first needs to test actual RN components. The `jest-environment-node` pin is recorded here because it was a genuine, non-obvious blocker (silent Node module hoisting conflict, not a code bug) that a future engineer touching this test suite would otherwise waste time rediscovering.

**Article(s) invoked:** Art. 5 (explainability — this module's own test suite must be genuinely verifiable, not aspirational); no direct product-facing constitutional article, but recorded per the general "log every non-trivial choice" instruction since the dependency-resolution root-cause was non-obvious.

**Made by:** Cryptography & Keys capability-engineer.

---

### 2026-07-16 — Fix: DeriveSharedSecret initial handshake forward secrecy (X3DH-style ephemeral contribution)

**Decision:** `initRatchetSession` (`ratchet.ts`) no longer takes a pre-computed shared secret. It now takes the local static private key and remote static public key directly and internally mixes two DH outputs into the root-key HKDF input: `staticStaticDh = X25519(localStaticPrivate, remoteStaticPublic)` (the original computation) and `ephemeralStaticDh = X25519(dhSelfPrivate, remoteStaticPublic)`, where `dhSelfPrivate` is a freshly generated, single-use X25519 private key created on every call. `rootKey = HKDF(staticStaticDh || ephemeralStaticDh)`. The freshly generated ephemeral keypair doubles as the session's initial DH-ratchet keypair (`dhSelfPrivate`/`dhSelfPublic`), so no new field was needed on `RatchetState` — `dhSelfPublic` was already the value later exposed for a future DH ratchet step, and is now also the value a future Messaging capability's key-exchange transport will need to deliver to the counterparty to complete the handshake. `index.ts`'s `deriveSharedSecret` was updated to call `initRatchetSession(entry.privateKey, request.remotePublicKey)` instead of pre-computing `x25519.getSharedSecret(...)` itself. Because two independent `DeriveSharedSecret` calls between the same static keypair now each generate their own fresh ephemeral key, they intentionally no longer produce matching root keys on their own (the previous test asserting Alice's and Bob's independently-derived root keys matched was removed — that property was exactly the key-reuse/no-forward-secrecy symptom being fixed, not a property worth preserving). Two new tests were added to `__tests__/crypto.test.ts`: "derives a fresh root key on every call, even for the exact same static keypair (no key-reuse hazard)" (two calls between the same static keypair produce different root/chain keys and different handles), and "forward secrecy at handshake time: compromising the long-term static private key does not let an attacker recompute the session's chain key derived before any ratchetAdvance() call" (recomputes the *old, vulnerable* static-static-only derivation directly using the real static private key and asserts it does NOT equal the live session's actual root/chain key). `ROOT_INFO`/`CHAIN_INFO` were exported from `ratchet.ts` so the test could perform that comparison without duplicating magic strings.

**Rationale:** Security Steward's veto (2026-07-16, "Security Steward veto: DeriveSharedSecret's initial handshake lacks forward secrecy") was correct: a static-static DH alone is fully determined by two long-term keys, so anyone who later obtains a party's long-term private key (and the counterparty's already-public key) can recompute every root/chain key ever derived from that pair — forward secrecy the charter requires from session start, not just after the first `ratchetAdvance()`. A full X3DH handshake (three DH computations against a signed prekey bundle) was considered and rejected for this pass, consistent with the original design rationale: no prekey-bundle publishing mechanism exists yet (Identity's device-binding model is out of scope per the charter's own §7 open questions), so a two-contribution mix (static-static + ephemeral-static) is the largest forward-secrecy improvement obtainable without inventing a prekey protocol ahead of the capability that would actually need to standardize it. This accepts that, for now, two independently-called `DeriveSharedSecret` invocations do not converge on a shared session by themselves — real convergence requires the ephemeral public key exchange a future Messaging capability's transport will perform, which was already the documented design intent before the fix (this fix does not change that scoping, only closes the concrete vulnerability inside it).

**Article(s) invoked:** Art. 7 (security must never reduce ownership — a forward-secrecy claim must hold from the first message, not just after the first ratchet step).

**Made by:** Cryptography & Keys capability-engineer, resolving the Security Steward veto above.

---

### 2026-07-16 — Fix: hash SecureLocalStore key names before they reach audit metadata

**Decision:** Added `apps/mobile/src/capabilities/crypto/auditHash.ts` exporting `auditFingerprint(input: string | Uint8Array): string` (truncated SHA-256, same construction previously inlined as `index.ts`'s local `fingerprint()` helper for public keys). `secureStore.ts`'s `secureLocalStore` now logs `{ keyFingerprint: auditFingerprint(key) }` instead of `{ key }`. `index.ts`'s local `fingerprint()` function was removed in favor of importing `auditFingerprint` from the same shared module (aliased as `fingerprint` at the import site to avoid touching every call site), so there is now exactly one hashing implementation used everywhere in this capability that audit metadata needs to reference a sensitive value.

**Rationale:** Security Steward's non-blocking finding was correct that a `SecureLocalStoreRequest.key` string is not inherently safe to log verbatim — a caller could reasonably choose a key name that embeds identifying information (e.g. a contact identifier or conversation id), and `audit.ts`'s own documented contract already prohibits raw sensitive values in metadata. Centralizing the hash helper (rather than inlining a second copy in `secureStore.ts`) avoids the two call sites drifting to different hash constructions later.

**Article(s) invoked:** Art. 8 (privacy — minimum data in audit metadata, no incidental collection of potentially-identifying strings).

**Made by:** Cryptography & Keys capability-engineer.

---

### 2026-07-16 — Fix: audit rejected/failed attempts, not just successes

**Decision:** Added `logAuditEvent` calls immediately before the `throw` on the three rejection paths Constitution Warden identified: `generateKeyPair` logs `key_pair_generation_rejected` (`reason: "empty_purpose"`) when `purpose` is empty; `restoreFromRecoveryPhrase` logs `identity_key_restore_failed` (`reason: "invalid_recovery_phrase"`) when the phrase fails BIP-39 validation; `exportKeyMaterial` logs `key_material_export_refused` (`reason: "missing_user_confirmation"`) when `userConfirmation` is false. `restoreFromRecoveryPhrase` now validates the phrase explicitly via `mnemonic.isValidRecoveryPhrase(...)` at the top of the function (rather than relying solely on `mnemonic.deriveIdentityPrivateKeyFromPhrase`'s own internal check further down) so the audit call happens at this operation's boundary, at the point of rejection, rather than depending on exception propagation from a helper module. Four new tests were added ("Audit logging covers rejection paths..." in `__tests__/crypto.test.ts`) that `jest.spyOn` the real `logAuditEvent` export and assert it was called with the expected action/metadata on each of the three rejection paths, plus a fourth test confirming the hashed-key fix above: that `secure_local_store_write`'s metadata contains a `keyFingerprint` and never the raw key string, for a deliberately identifying example key name.

**Rationale:** `audit.ts`'s own doc comment already states the obligation ("the operation succeeding/failing, never the key material itself") — the gap was an inconsistency between that stated contract and three call sites that only ever logged success, which Constitution Warden correctly flagged as required before the next merge given this pattern (mobile capability, no mechanical CI backstop yet) is likely to be copied by future capabilities. Other existing failure paths in this module (`decrypt`'s "not an intended recipient" rejection, `deriveSharedSecret`'s/`encryptEnvelope`'s input-validation throws, `keyRegistry`'s "unknown handle" errors) were deliberately left unaudited in this pass — they were not named in Constitution Warden's finding, and extending audit coverage to every possible throw site in one pass risks logging normal programming-error paths as if they were security events, diluting the signal. Flagged here as a reasonable candidate for a follow-up pass once the real Audit capability exists and a coordinator/guardian can judge which failure paths are actually security-relevant versus ordinary input validation.

**Article(s) invoked:** Art. 5 (explainability — every important action, including failed/rejected ones, must be discoverable).

**Made by:** Cryptography & Keys capability-engineer, resolving the Constitution Warden required-follow-up above.

---

### 2026-07-16 — Cryptography & Keys passes merge gate; capability moves to stable

**Decision:** Security Steward re-reviewed the specific forward-secrecy finding (scoped, not a full re-audit) and confirmed it closed: `initRatchetSession` now mixes a fresh, single-use ephemeral X25519 contribution into the root-key derivation, traced end-to-end to confirm it's never persisted or logged, backed by a regression test that independently recomputes the old vulnerable derivation and asserts it no longer matches. Combined with Constitution Warden's earlier pass (its required follow-up on audit failure-paths was fixed in the same round), both required guardian sign-offs for a keys/encryption surface are now in place. `docs/CAPABILITY_REGISTRY.md` moves Cryptography & Keys from `frozen` to `stable`. Two items are tracked as open follow-ups, not blockers: (1) `docs/capabilities/cryptography-and-keys.charter.md` §7 now records that `DeriveSharedSecret` only produces the initiating party's half of a handshake — a prekey-bundle or equivalent exchange mechanism is a prerequisite for whichever capability (likely Messaging) first needs real two-party session establishment; (2) the task "Add TS-side mechanical constitution checks" tracks Constitution Warden's structural finding that manual guardian review of TypeScript code is a one-capability stopgap, not a scalable practice.

**Rationale:** This is the first capability to move from charter through implementation to a passed merge gate, so the full sequence is recorded here as the reference example for how the next capability's merge gate should run: charter gate (2026-07-06) → contract freeze → implementation → merge-gate veto → fix → scoped re-review → pass.

**Article(s) invoked:** Art. 5 (explainability — the whole sequence, including the veto and fix, is discoverable in one place), Art. 17 (asked first at charter time, reaffirmed at merge gate).

**Made by:** Chief Architect, recording the joint Constitution Warden / Security Steward merge-gate outcome.

---

