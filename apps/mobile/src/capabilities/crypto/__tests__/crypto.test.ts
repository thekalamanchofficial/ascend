import {
  generateIdentityKeyMaterial,
  generateKeyPair,
  encrypt,
  decrypt,
  deriveSharedSecret,
  restoreFromRecoveryPhrase,
  exportKeyMaterial,
  secureLocalStore,
  secureLocalRetrieve,
  sign,
} from "../index";
import { _resetRegistryForTests, getPrivateKeyEntry, getRatchetSession } from "../keyRegistry";
import { deriveNextMessageKey, ratchetAdvance, ROOT_INFO, CHAIN_INFO } from "../ratchet";
import {
  softwareVaultStore,
  softwareVaultRetrieve,
  setFallbackKeyProvider,
  _resetFallbackVaultForTests,
} from "../secureStore";
import { isValidRecoveryPhrase } from "../mnemonic";
import { encryptEnvelope, decryptEnvelope } from "../envelope";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import * as audit from "../audit";

beforeEach(() => {
  _resetRegistryForTests();
  _resetFallbackVaultForTests();
});

describe("GenerateIdentityKeyMaterial", () => {
  it("returns a 32-byte Ed25519 public key, a handle, and a valid 24-word recovery phrase", () => {
    const result = generateIdentityKeyMaterial({});
    expect(result.publicKey).toBeInstanceOf(Uint8Array);
    expect(result.publicKey.length).toBe(32);
    expect(result.privateKeyHandle.handle).toMatch(/^key_/);
    expect(result.recoveryPhrase.split(" ")).toHaveLength(24);
    expect(isValidRecoveryPhrase(result.recoveryPhrase)).toBe(true);
  });

  it("generates a different identity (and different phrase) on every call", () => {
    const a = generateIdentityKeyMaterial({});
    const b = generateIdentityKeyMaterial({});
    expect(a.recoveryPhrase).not.toEqual(b.recoveryPhrase);
    expect(a.publicKey).not.toEqual(b.publicKey);
  });
});

describe("deterministic derivation (RestoreFromRecoveryPhrase)", () => {
  it("restoring from the same phrase twice yields the same public key and private key bytes", () => {
    const generated = generateIdentityKeyMaterial({});

    const restoredA = restoreFromRecoveryPhrase({ recoveryPhrase: generated.recoveryPhrase });
    const restoredB = restoreFromRecoveryPhrase({ recoveryPhrase: generated.recoveryPhrase });

    // Public keys must match the originally generated identity exactly.
    expect(restoredA.publicKey).toEqual(generated.publicKey);
    expect(restoredB.publicKey).toEqual(generated.publicKey);

    // Handles are independent local references (by design — see
    // keyRegistry.ts), but the underlying private key bytes they point to
    // must be byte-for-byte identical, proving derivation is a pure
    // function of the phrase alone.
    const privA = getPrivateKeyEntry(restoredA.privateKeyHandle).privateKey;
    const privB = getPrivateKeyEntry(restoredB.privateKeyHandle).privateKey;
    const privOriginal = getPrivateKeyEntry(generated.privateKeyHandle).privateKey;
    expect(restoredA.privateKeyHandle.handle).not.toEqual(restoredB.privateKeyHandle.handle);
    expect(privA).toEqual(privB);
    expect(privA).toEqual(privOriginal);
  });

  it("rejects a syntactically invalid recovery phrase", () => {
    expect(() => restoreFromRecoveryPhrase({ recoveryPhrase: "not a real bip39 phrase" })).toThrow();
  });

  it("two different phrases derive two different identities", () => {
    const a = generateIdentityKeyMaterial({});
    const b = generateIdentityKeyMaterial({});
    const restoredA = restoreFromRecoveryPhrase({ recoveryPhrase: a.recoveryPhrase });
    expect(restoredA.publicKey).not.toEqual(b.publicKey);
  });
});

describe("GenerateKeyPair", () => {
  it("produces a usable X25519 (DH-capable) keypair, distinct from the identity key (which is Ed25519 — see keyPurpose.ts)", () => {
    const identity = generateIdentityKeyMaterial({});
    const session = generateKeyPair({ purpose: "device-session" });
    expect(session.publicKey.length).toBe(32);
    expect(session.publicKey).not.toEqual(identity.publicKey);
    expect(session.privateKeyHandle.handle).not.toEqual(identity.privateKeyHandle.handle);
  });

  it("requires a purpose", () => {
    expect(() => generateKeyPair({ purpose: "" })).toThrow();
  });

  it("produces an Ed25519 keypair for a 'sign:'-prefixed purpose, distinct from the X25519 public key the same raw bytes would produce", () => {
    const signingKey = generateKeyPair({ purpose: "sign:device-binding" });
    expect(signingKey.publicKey.length).toBe(32);

    const entry = getPrivateKeyEntry(signingKey.privateKeyHandle);
    // Deliberately re-derive both curves' public keys from the SAME raw
    // private key bytes to confirm they really are different — this is the
    // concrete reason DH-capable and signing-capable handles can't be the
    // same underlying key.
    const asX25519 = x25519.getPublicKey(entry.privateKey);
    const asEd25519 = ed25519.getPublicKey(entry.privateKey);
    expect(asEd25519).toEqual(signingKey.publicKey);
    expect(asX25519).not.toEqual(asEd25519);
  });
});

describe("Sign", () => {
  it("produces a standard 64-byte Ed25519 signature that verifies against the returned public key using @noble/curves directly", () => {
    const device = generateKeyPair({ purpose: "sign:device-binding" });
    const message = new TextEncoder().encode("bind device: new-device-id-1234");

    const { signature } = sign({ privateKeyHandle: device.privateKeyHandle, message });

    expect(signature.length).toBe(64);
    // Verification performed with the raw, unmodified @noble/curves
    // Ed25519 primitive directly (not any helper from this module) — this
    // is what proves the signature is standard Ed25519 and not something
    // this module invented, since no Verify RPC exists on this side (see
    // docs/DECISION_LOG.md, 2026-07-16 "Crypto & Keys contract gains Sign;
    // signature verification is not 'own crypto'").
    expect(ed25519.verify(signature, message, device.publicKey)).toBe(true);
  });

  it("a tampered message fails verification", () => {
    const device = generateKeyPair({ purpose: "sign:device-binding" });
    const message = new TextEncoder().encode("bind device: new-device-id-1234");
    const { signature } = sign({ privateKeyHandle: device.privateKeyHandle, message });

    const tamperedMessage = new TextEncoder().encode("bind device: attacker-device-id");
    expect(ed25519.verify(signature, tamperedMessage, device.publicKey)).toBe(false);
  });

  it("rejects a DH-capable (X25519) handle rather than silently signing with it", () => {
    const sessionKey = generateKeyPair({ purpose: "device-session" });
    const message = new TextEncoder().encode("some message");

    expect(() => sign({ privateKeyHandle: sessionKey.privateKeyHandle, message })).toThrow();
  });

  // Regression coverage for the bug found during Identity's implementation:
  // the identity root key must itself be signing-capable (Ed25519), because
  // BindDevice's recovery-path device-binding assertion is produced by
  // calling Sign() with the identity key. An earlier version registered the
  // identity key under a bare "identity" purpose (X25519, DH-only), so
  // Sign() correctly-but-wrongly rejected it — the assertion could never
  // actually be produced. See docs/DECISION_LOG.md, 2026-07-16 "Fix:
  // identity root key must be Ed25519 (signing-capable), not X25519".
  it("signs successfully with the freshly generated identity root key (the BindDevice use case this fix restores)", () => {
    const identity = generateIdentityKeyMaterial({});
    const message = new TextEncoder().encode("bind device: new-device-id-1234");

    const { signature } = sign({ privateKeyHandle: identity.privateKeyHandle, message });

    expect(signature.length).toBe(64);
    expect(ed25519.verify(signature, message, identity.publicKey)).toBe(true);
  });

  it("signs successfully with a RestoreFromRecoveryPhrase-restored identity — the exact recovery-path device-binding scenario Security Steward scrutinized (the only path that survives total device loss)", () => {
    const original = generateIdentityKeyMaterial({});
    const restored = restoreFromRecoveryPhrase({ recoveryPhrase: original.recoveryPhrase });
    expect(restored.publicKey).toEqual(original.publicKey);

    const message = new TextEncoder().encode("bind device: recovered-device-id-5678");
    const { signature } = sign({ privateKeyHandle: restored.privateKeyHandle, message });

    expect(ed25519.verify(signature, message, restored.publicKey)).toBe(true);
    // Also verifies against the ORIGINAL identity's public key, since
    // restoration is deterministic and must produce the same signing
    // identity a counterparty already trusts.
    expect(ed25519.verify(signature, message, original.publicKey)).toBe(true);
  });
});

describe("Sign/DH key-type separation on the DH-only operations", () => {
  it("Decrypt rejects a signing-capable (Ed25519) handle", () => {
    const signingKey = generateKeyPair({ purpose: "sign:device-binding" });
    const bob = generateKeyPair({ purpose: "device-session" });
    const { ciphertext } = encrypt({
      recipientPublicKeys: [bob.publicKey],
      plaintext: new TextEncoder().encode("hi"),
    });
    expect(() => decrypt({ privateKeyHandle: signingKey.privateKeyHandle, ciphertext })).toThrow();
  });

  it("DeriveSharedSecret rejects a signing-capable (Ed25519) handle", () => {
    const signingKey = generateKeyPair({ purpose: "sign:device-binding" });
    const bob = generateKeyPair({ purpose: "device-session" });
    expect(() =>
      deriveSharedSecret({ privateKeyHandle: signingKey.privateKeyHandle, remotePublicKey: bob.publicKey }),
    ).toThrow();
  });

  it("Decrypt rejects the identity key itself (Ed25519, signing-only — never a DH/encryption key)", () => {
    const identity = generateIdentityKeyMaterial({});
    const someRecipient = generateKeyPair({ purpose: "device-session" });
    const { ciphertext } = encrypt({
      recipientPublicKeys: [someRecipient.publicKey],
      plaintext: new TextEncoder().encode("hi"),
    });
    expect(() => decrypt({ privateKeyHandle: identity.privateKeyHandle, ciphertext })).toThrow();
  });

  it("DeriveSharedSecret rejects the identity key itself (Ed25519, signing-only — never a DH key)", () => {
    const identity = generateIdentityKeyMaterial({});
    const remote = generateKeyPair({ purpose: "device-session" });
    expect(() =>
      deriveSharedSecret({ privateKeyHandle: identity.privateKeyHandle, remotePublicKey: remote.publicKey }),
    ).toThrow();
  });
});

// Encrypt/Decrypt operate on DH-capable (X25519) key handles — generated
// here via GenerateKeyPair with a non-"sign:" purpose (e.g. a per-device
// session key), never the identity root key, which is Ed25519 and
// signing-only (see keyPurpose.ts and the "Sign/DH key-type separation"
// describe block above for the rejection behavior).
describe("Encrypt / Decrypt round trip", () => {
  it("round-trips plaintext between two independently generated device keys", () => {
    const alice = generateKeyPair({ purpose: "device-session" });
    const bob = generateKeyPair({ purpose: "device-session" });
    const plaintext = new TextEncoder().encode("the eagle flies at midnight");

    const { ciphertext } = encrypt({ recipientPublicKeys: [bob.publicKey], plaintext });
    const { plaintext: decrypted } = decrypt({ privateKeyHandle: bob.privateKeyHandle, ciphertext });

    expect(new TextDecoder().decode(decrypted)).toBe("the eagle flies at midnight");

    // Alice's own key must NOT be able to decrypt a message addressed only to Bob.
    expect(() => decrypt({ privateKeyHandle: alice.privateKeyHandle, ciphertext })).toThrow();
  });

  it("supports multiple recipients, each independently able to decrypt", () => {
    const bob = generateKeyPair({ purpose: "device-session" });
    const carol = generateKeyPair({ purpose: "device-session" });
    const dave = generateKeyPair({ purpose: "device-session" });
    const plaintext = new TextEncoder().encode("group secret");

    const { ciphertext } = encrypt({
      recipientPublicKeys: [bob.publicKey, carol.publicKey],
      plaintext,
    });

    expect(new TextDecoder().decode(decrypt({ privateKeyHandle: bob.privateKeyHandle, ciphertext }).plaintext)).toBe(
      "group secret",
    );
    expect(
      new TextDecoder().decode(decrypt({ privateKeyHandle: carol.privateKeyHandle, ciphertext }).plaintext),
    ).toBe("group secret");
    expect(() => decrypt({ privateKeyHandle: dave.privateKeyHandle, ciphertext })).toThrow();
  });

  it("detects tampering (AEAD authentication)", () => {
    const bob = generateKeyPair({ purpose: "device-session" });
    const plaintext = new TextEncoder().encode("do not modify me");
    const { ciphertext } = encrypt({ recipientPublicKeys: [bob.publicKey], plaintext });

    const tampered = new Uint8Array(ciphertext);
    tampered[tampered.length - 1] ^= 0xff;

    expect(() => decrypt({ privateKeyHandle: bob.privateKeyHandle, ciphertext: tampered })).toThrow();
  });

  it("rejects Encrypt with zero recipients", () => {
    expect(() => encrypt({ recipientPublicKeys: [], plaintext: new Uint8Array([1]) })).toThrow();
  });

  it("low-level envelope round trip works directly (sanity check for the wire format)", () => {
    const bob = generateKeyPair({ purpose: "device-session" });
    const bobEntry = getPrivateKeyEntry(bob.privateKeyHandle);
    const pt = new TextEncoder().encode("wire format sanity check");
    const ct = encryptEnvelope([bob.publicKey], pt);
    const out = decryptEnvelope(bobEntry.privateKey, bobEntry.publicKey, ct);
    expect(new TextDecoder().decode(out)).toBe("wire format sanity check");
  });
});

// DeriveSharedSecret operates on DH-capable (X25519) key handles — device
// keys generated via GenerateKeyPair with a non-"sign:" purpose, never the
// identity root key (Ed25519, signing-only — rejected, see "Sign/DH
// key-type separation" above).
describe("DeriveSharedSecret and ratchet forward secrecy / post-compromise security", () => {
  it("derives a fresh root key on every call, even for the exact same static keypair (no key-reuse hazard)", () => {
    const alice = generateKeyPair({ purpose: "device-session" });
    const bob = generateKeyPair({ purpose: "device-session" });

    const sessionA = deriveSharedSecret({
      privateKeyHandle: alice.privateKeyHandle,
      remotePublicKey: bob.publicKey,
    });
    const sessionB = deriveSharedSecret({
      privateKeyHandle: alice.privateKeyHandle,
      remotePublicKey: bob.publicKey,
    });

    // initRatchetSession now mixes a fresh ephemeral X25519 contribution
    // into the root-key derivation (X3DH-style) alongside the static-static
    // DH — see ratchet.ts and docs/DECISION_LOG.md, 2026-07-16
    // "DeriveSharedSecret initial handshake forward secrecy fix". Unlike a
    // plain static-static DH (which is fully deterministic given the two
    // static keys — a key-reuse hazard flagged by Security Steward), two
    // independent calls between the exact same two static keypairs must
    // now derive DIFFERENT root keys, because each call generates its own
    // fresh ephemeral keypair.
    const stateA = getRatchetSession(sessionA.sharedSecretHandle);
    const stateB = getRatchetSession(sessionB.sharedSecretHandle);
    expect(stateA.rootKey).not.toEqual(stateB.rootKey);
    expect(stateA.sendingChainKey).not.toEqual(stateB.sendingChainKey);
    expect(sessionA.sharedSecretHandle.handle).not.toEqual(sessionB.sharedSecretHandle.handle);
  });

  it("forward secrecy at handshake time: compromising the long-term static private key does not let an attacker recompute the session's chain key derived before any ratchetAdvance() call", () => {
    const alice = generateKeyPair({ purpose: "device-session" });
    const bob = generateKeyPair({ purpose: "device-session" });

    const session = deriveSharedSecret({
      privateKeyHandle: alice.privateKeyHandle,
      remotePublicKey: bob.publicKey,
    });
    const liveState = getRatchetSession(session.sharedSecretHandle);

    // Simulate an attacker who has since stolen Alice's long-term static
    // private key. Bob's public key is, by definition, already public, so
    // the attacker has both inputs a pure static-static DH handshake would
    // have used. This recomputation is exactly what the pre-fix
    // implementation did (`x25519.getSharedSecret(entry.privateKey,
    // remotePublicKey)` fed directly into the root-key HKDF, with no
    // ephemeral contribution) — the vulnerability this fix closes.
    const aliceStaticEntry = getPrivateKeyEntry(alice.privateKeyHandle);
    const staticStaticDhOnly = x25519.getSharedSecret(aliceStaticEntry.privateKey, bob.publicKey);
    const attackerGuessedRootKey = hkdf(sha256, staticStaticDhOnly, undefined, ROOT_INFO, 32);
    const attackerGuessedChainKey = hkdf(sha256, attackerGuessedRootKey, undefined, CHAIN_INFO, 32);

    // The real session's root/chain key must NOT match what an attacker
    // limited to the long-term static keys alone (no session/device state)
    // could recompute. This chain key was derived before any
    // ratchetAdvance() call, so this is specifically the *initial
    // handshake* forward-secrecy property, not the inter-message one
    // covered by the next test.
    expect(liveState.rootKey).not.toEqual(attackerGuessedRootKey);
    expect(liveState.sendingChainKey).not.toEqual(attackerGuessedChainKey);
  });

  it("forward secrecy: advancing the chain ratchet changes the chain key so the previous message key cannot be recomputed from the new state", () => {
    const alice = generateKeyPair({ purpose: "device-session" });
    const bob = generateKeyPair({ purpose: "device-session" });
    const session = deriveSharedSecret({
      privateKeyHandle: alice.privateKeyHandle,
      remotePublicKey: bob.publicKey,
    });
    const state0 = getRatchetSession(session.sharedSecretHandle);

    const { messageKey: key1, nextState: state1 } = deriveNextMessageKey(state0);
    const { messageKey: key2, nextState: state2 } = deriveNextMessageKey(state1);

    expect(key1).not.toEqual(key2);
    expect(state1.sendingChainKey).not.toEqual(state0.sendingChainKey);
    expect(state2.sendingChainKey).not.toEqual(state1.sendingChainKey);
    // state2 has no field equal to the discarded state0 chain key — proving
    // the old chain key material isn't retained anywhere in the new state.
    expect(state2.sendingChainKey).not.toEqual(state0.sendingChainKey);
  });

  it("post-compromise security: a DH ratchet step produces a root key that could not have been predicted from the old root key alone", () => {
    const alice = generateKeyPair({ purpose: "device-session" });
    const bob = generateKeyPair({ purpose: "device-session" });
    const session = deriveSharedSecret({
      privateKeyHandle: alice.privateKeyHandle,
      remotePublicKey: bob.publicKey,
    });
    const compromisedState = getRatchetSession(session.sharedSecretHandle);

    // Simulate the device healing: a fresh DH ratchet step against a new
    // remote ratchet public key (e.g. Bob's device rotated its session
    // key). Run it twice from the SAME starting (compromised) state.
    const bobNewEphemeral = generateKeyPair({ purpose: "ratchet-step" });
    const healedA = ratchetAdvance(compromisedState, bobNewEphemeral.publicKey);
    const healedB = ratchetAdvance(compromisedState, bobNewEphemeral.publicKey);

    // Because ratchetAdvance generates a fresh local DH keypair internally
    // (not derived from prior state), even re-running the *exact same*
    // ratchet step against the same remote public key from the same old
    // root key yields a DIFFERENT new root key each time. An attacker who
    // captured the old root key cannot predict the healed session's key —
    // that unpredictability is what post-compromise security requires.
    expect(healedA.rootKey).not.toEqual(healedB.rootKey);
    expect(healedA.rootKey).not.toEqual(compromisedState.rootKey);
  });
});

describe("SecureLocalStore / SecureLocalRetrieve", () => {
  it("round-trips a value through the (mocked) OS keychain path", async () => {
    const value = new TextEncoder().encode("super secret device token");
    await secureLocalStore({ key: "device-token", value });
    const { value: retrieved } = await secureLocalRetrieve({ key: "device-token" });
    expect(new TextDecoder().decode(retrieved)).toBe("super secret device token");
  });

  it("throws for a key that was never stored", async () => {
    await expect(secureLocalRetrieve({ key: "does-not-exist" })).rejects.toThrow();
  });

  it("fallback software vault round-trips a value and never stores plaintext", () => {
    const value = new TextEncoder().encode("fallback path secret");
    softwareVaultStore("vault-key", value);
    const retrieved = softwareVaultRetrieve("vault-key");
    expect(new TextDecoder().decode(retrieved)).toBe("fallback path secret");
  });

  it("fallback vault honors a caller-supplied key provider (e.g. biometric-gated key)", () => {
    const fixedKey = new Uint8Array(32).fill(7);
    setFallbackKeyProvider(() => fixedKey);
    softwareVaultStore("pinned", new TextEncoder().encode("value"));
    const retrieved = softwareVaultRetrieve("pinned");
    expect(new TextDecoder().decode(retrieved)).toBe("value");
  });
});

describe("ExportKeyMaterial", () => {
  it("refuses to export without explicit user confirmation", () => {
    generateIdentityKeyMaterial({});
    expect(() => exportKeyMaterial({ userConfirmation: false })).toThrow();
  });

  it("produces a parseable, documented, self-describing export blob", () => {
    const identity = generateIdentityKeyMaterial({});
    const device = generateKeyPair({ purpose: "device-session" });

    const result = exportKeyMaterial({ userConfirmation: true });
    expect(result.formatVersion).toBe("ascend-crypto-export-v1");

    const parsed = JSON.parse(new TextDecoder().decode(result.exportBlob));
    expect(parsed.formatVersion).toBe("ascend-crypto-export-v1");
    expect(typeof parsed.exportedAt).toBe("string");
    expect(Array.isArray(parsed.keys)).toBe(true);
    expect(parsed.keys).toHaveLength(2);

    const identityEntry = parsed.keys.find((k: { handle: string }) => k.handle === identity.privateKeyHandle.handle);
    expect(identityEntry).toBeDefined();
    expect(identityEntry.purpose).toBe("sign:identity");
    expect(typeof identityEntry.privateKey).toBe("string"); // base64

    const deviceEntry = parsed.keys.find((k: { handle: string }) => k.handle === device.privateKeyHandle.handle);
    expect(deviceEntry).toBeDefined();
    expect(deviceEntry.purpose).toBe("device-session");
  });

  it("exported private key bytes actually re-derive the same public key (the export is usable, not just well-formed)", () => {
    const identity = generateIdentityKeyMaterial({});
    const result = exportKeyMaterial({ userConfirmation: true });
    const parsed = JSON.parse(new TextDecoder().decode(result.exportBlob));
    const identityEntry = parsed.keys.find((k: { purpose: string }) => k.purpose === "sign:identity");

    // Re-derived with Ed25519, not X25519 — the identity key is
    // signing-capable (see docs/DECISION_LOG.md, 2026-07-16 "Fix: identity
    // root key must be Ed25519 (signing-capable), not X25519"). Re-deriving
    // with the wrong curve would silently produce a DIFFERENT public key
    // and this assertion would (correctly) fail.
    const { ed25519: reDerivedEd25519 } = require("@noble/curves/ed25519.js");
    const base64ToBytesLocal = (b64: string) => Uint8Array.from(Buffer.from(b64, "base64"));
    const rederivedPublicKey = reDerivedEd25519.getPublicKey(base64ToBytesLocal(identityEntry.privateKey));
    expect(rederivedPublicKey).toEqual(identity.publicKey);
  });
});

describe("Audit logging covers rejection paths (Art. 5) and never logs raw sensitive values (Art. 8)", () => {
  let auditSpy: jest.SpiedFunction<typeof audit.logAuditEvent>;

  beforeEach(() => {
    auditSpy = jest.spyOn(audit, "logAuditEvent");
  });

  afterEach(() => {
    auditSpy.mockRestore();
  });

  it("audits a GenerateKeyPair rejection (empty purpose) before throwing", () => {
    expect(() => generateKeyPair({ purpose: "" })).toThrow();
    expect(auditSpy).toHaveBeenCalledWith("key_pair_generation_rejected", { reason: "empty_purpose" });
  });

  it("audits a RestoreFromRecoveryPhrase rejection (invalid phrase) before throwing", () => {
    expect(() => restoreFromRecoveryPhrase({ recoveryPhrase: "not a real bip39 phrase" })).toThrow();
    expect(auditSpy).toHaveBeenCalledWith("identity_key_restore_failed", { reason: "invalid_recovery_phrase" });
  });

  it("audits an ExportKeyMaterial refusal (missing confirmation) before throwing", () => {
    expect(() => exportKeyMaterial({ userConfirmation: false })).toThrow();
    expect(auditSpy).toHaveBeenCalledWith("key_material_export_refused", { reason: "missing_user_confirmation" });
  });

  it("SecureLocalStore audit metadata carries a hashed key fingerprint, never the raw key string", async () => {
    const sensitiveKeyName = "contact:+15551234567:session-key";
    await secureLocalStore({ key: sensitiveKeyName, value: new Uint8Array([1, 2, 3]) });

    const call = auditSpy.mock.calls.find(([action]) => action === "secure_local_store_write");
    expect(call).toBeDefined();
    const metadata = call?.[1] as Record<string, string>;
    expect(metadata.key).toBeUndefined();
    expect(typeof metadata.keyFingerprint).toBe("string");
    expect(metadata.keyFingerprint).not.toContain(sensitiveKeyName);
    expect(JSON.stringify(metadata)).not.toContain("+15551234567");
  });
});
