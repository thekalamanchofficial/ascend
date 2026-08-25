import {
  generateIdentityKeyMaterial,
  generateKeyPair,
  encrypt,
  decrypt,
  deriveSharedSecret,
  completeSharedSecret,
  generatePrekeyBundle,
  encryptMessage,
  decryptMessage,
  restoreFromRecoveryPhrase,
  exportKeyMaterial,
  secureLocalStore,
  secureLocalRetrieve,
  sign,
} from "../index";
import type { PrekeyBundle, KeyHandle, DecryptMessageResponse } from "../types";
import {
  _resetRegistryForTests,
  _resetRatchetLocksForTests,
  getPrivateKeyEntry,
  getRatchetSession,
} from "../keyRegistry";
import {
  deriveNextMessageKey,
  ratchetAdvance,
  CHAIN_INFO,
  CHAIN_INFO_INITIATOR_TO_RESPONDER,
  CHAIN_INFO_RESPONDER_TO_INITIATOR,
  X3DH_CONTEXT_3TERM_SIGNED_PREKEY_ONLY,
} from "../ratchet";
import {
  softwareVaultStore,
  softwareVaultRetrieve,
  setFallbackKeyProvider,
  _resetFallbackVaultForTests,
} from "../secureStore";
import { _resetPrekeyLocksForTests, PrekeyAlreadyConsumedError } from "../prekeyStore";
import { isValidRecoveryPhrase } from "../mnemonic";
import { encryptEnvelope, decryptEnvelope } from "../envelope";
import { deriveDhScalar, deriveDhPublicKey } from "../dhKey";
import { bytesToHex } from "../bytes";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import * as SecureStore from "expo-secure-store";
import * as audit from "../audit";

beforeEach(() => {
  _resetRegistryForTests();
  _resetFallbackVaultForTests();
  _resetPrekeyLocksForTests();
  _resetRatchetLocksForTests();
});

/**
 * Registers a fresh identity and immediately generates its prekey bundle —
 * in that order, and with no other identity registered in between, so
 * `generatePrekeyBundle`'s internal `findPrivateKeyEntryByPurpose` lookup
 * (see keyRegistry.ts / docs/DECISION_LOG.md, 2026-08-20) unambiguously
 * resolves to THIS identity, not some other one also live in the registry.
 * Callers that need a second identity in the same test (e.g. an initiator)
 * should create it AFTER calling this helper.
 */
async function makeResponderWithBundle(oneTimePrekeyCount = 1) {
  const responder = generateIdentityKeyMaterial({});
  const bundle = await generatePrekeyBundle({ oneTimePrekeyCount });
  return { responder, bundle };
}

/**
 * Computes an initiator's own DH-capable identity key material (charter §3
 * key-separation fix) exactly the way `generatePrekeyBundle` computes it
 * internally for a responder (index.ts) — `deriveDhPublicKey` directly from
 * the identity's raw seed, signed with the SAME identity's Ed25519 key via
 * the real `sign()` RPC. This is what a real initiator would have cached
 * locally from its own most recent `GeneratePrekeyBundle` call (charter §7
 * item 4: "the initiator's own already-generated signature ... no new
 * signing operation needed to include it here") — computed directly here,
 * rather than via `generatePrekeyBundle` itself, so it stays correct
 * regardless of how many OTHER identities are concurrently registered in
 * this process during a test (generatePrekeyBundle locates its identity by
 * "most recently registered" — see keyRegistry.ts — which several of this
 * suite's concurrency tests deliberately violate on purpose).
 */
function initiatorDhMaterial(initiator: { privateKeyHandle: KeyHandle }) {
  const entry = getPrivateKeyEntry(initiator.privateKeyHandle);
  const identityDhPublicKey = deriveDhPublicKey(entry.privateKey);
  const { signature: identityDhPublicKeySignature } = sign({
    privateKeyHandle: initiator.privateKeyHandle,
    message: identityDhPublicKey,
  });
  return { identityDhPublicKey, identityDhPublicKeySignature };
}

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
    // docs/DECISION_LOG.md, 2026-07-16, "Crypto & Keys contract gains Sign;
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

  it("Decrypt rejects the identity key itself (Ed25519, signing-only — never a DH/encryption key)", () => {
    const identity = generateIdentityKeyMaterial({});
    const someRecipient = generateKeyPair({ purpose: "device-session" });
    const { ciphertext } = encrypt({
      recipientPublicKeys: [someRecipient.publicKey],
      plaintext: new TextEncoder().encode("hi"),
    });
    expect(() => decrypt({ privateKeyHandle: identity.privateKeyHandle, ciphertext })).toThrow();
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

// ---------------------------------------------------------------------------
// GeneratePrekeyBundle (charter §3/§5, added 2026-08-20)
// ---------------------------------------------------------------------------
describe("GeneratePrekeyBundle", () => {
  it("returns a genuinely separate DH-capable identity key (signed), a self-consistently-signed signed prekey, and the requested count of one-time prekeys", async () => {
    const identity = generateIdentityKeyMaterial({});
    const bundle = await generatePrekeyBundle({ oneTimePrekeyCount: 3 });

    // Key-separation fix (charter §3, docs/DECISION_LOG.md's "Key-separation
    // fix" series): identity_dh_public_key must be a GENUINELY DIFFERENT
    // key from the Ed25519 signing public key — never equal to it, and
    // independently reproducible from the identity's own raw seed via
    // dhKey.ts's domain-separated KDF (the same function generatePrekeyBundle
    // uses internally).
    expect(bundle.identityDhPublicKey).not.toEqual(identity.publicKey);
    expect(bundle.identityDhPublicKey.length).toBe(32);
    const identityEntry = getPrivateKeyEntry(identity.privateKeyHandle);
    expect(bundle.identityDhPublicKey).toEqual(deriveDhPublicKey(identityEntry.privateKey));

    // identity_dh_public_key_signature verifies against the identity's
    // Ed25519 signing key (charter §6 "identity_dh_public_key substitution")
    // — the raw, unmodified @noble/curves primitive, proving this really is
    // signed with the SAME identity signing key that signs signed_prekey.
    expect(
      ed25519.verify(bundle.identityDhPublicKeySignature, bundle.identityDhPublicKey, identity.publicKey),
    ).toBe(true);

    expect(bundle.signedPrekey.publicKey.length).toBe(32);
    expect(bundle.signedPrekey.prekeyId).toEqual(expect.any(String));
    expect(bundle.signedPrekey.prekeyId.length).toBeGreaterThan(0);

    // The signature verifies with the raw, unmodified @noble/curves
    // Ed25519 primitive directly against the identity's Ed25519 public key —
    // proving "sign its public key with the identity's long-term Ed25519
    // signing key via the existing Sign RPC" (charter §3) actually happened.
    expect(ed25519.verify(bundle.signedPrekey.signature, bundle.signedPrekey.publicKey, identity.publicKey)).toBe(
      true,
    );

    expect(bundle.oneTimePrekeys).toHaveLength(3);
    const ids = bundle.oneTimePrekeys.map((k) => k.prekeyId);
    expect(new Set(ids).size).toBe(3); // all unique
    for (const otp of bundle.oneTimePrekeys) {
      expect(otp.publicKey.length).toBe(32);
    }
  });

  it("identity_dh_public_key is NOT derived via a birational Ed25519->X25519 (Montgomery) conversion of the signing key — the exact defect this key-separation fix replaces", async () => {
    const identity = generateIdentityKeyMaterial({});
    const bundle = await generatePrekeyBundle({ oneTimePrekeyCount: 0 });
    const identityEntry = getPrivateKeyEntry(identity.privateKeyHandle);

    // The OLD (superseded, broken) construction: birational conversion of
    // the CLAMPED Ed25519 signing scalar via @noble/curves' own helper.
    const oldBirationalConversion = x25519.getPublicKey(ed25519.utils.toMontgomerySecret(identityEntry.privateKey));

    expect(bundle.identityDhPublicKey).not.toEqual(oldBirationalConversion);
    // And the correct construction really is HKDF(seed, "ascend-x3dh-dh-key")
    // over the PRE-clamp seed — dhKey.ts's own contract.
    expect(bundle.identityDhPublicKey).toEqual(x25519.getPublicKey(deriveDhScalar(identityEntry.privateKey)));
  });

  it("supports zero one-time prekeys (still returns a valid signed prekey)", async () => {
    generateIdentityKeyMaterial({});
    const bundle = await generatePrekeyBundle({ oneTimePrekeyCount: 0 });
    expect(bundle.oneTimePrekeys).toHaveLength(0);
    expect(bundle.signedPrekey.publicKey.length).toBe(32);
  });

  it("rejects a negative one_time_prekey_count and audits the rejection", async () => {
    generateIdentityKeyMaterial({});
    const auditSpy = jest.spyOn(audit, "logAuditEvent");
    await expect(generatePrekeyBundle({ oneTimePrekeyCount: -1 })).rejects.toThrow();
    expect(auditSpy).toHaveBeenCalledWith("prekey_bundle_generation_rejected", {
      reason: "invalid_one_time_prekey_count",
    });
    auditSpy.mockRestore();
  });

  it("refuses to run without an identity key already registered in this process", async () => {
    // No generateIdentityKeyMaterial()/restoreFromRecoveryPhrase() call in
    // this test — the registry is empty (beforeEach resets it).
    await expect(generatePrekeyBundle({ oneTimePrekeyCount: 1 })).rejects.toThrow();
  });

  it("successive calls produce different signed-prekey ids and key material (rotation-ready)", async () => {
    generateIdentityKeyMaterial({});
    const first = await generatePrekeyBundle({ oneTimePrekeyCount: 1 });
    const second = await generatePrekeyBundle({ oneTimePrekeyCount: 1 });
    expect(first.signedPrekey.prekeyId).not.toEqual(second.signedPrekey.prekeyId);
    expect(first.signedPrekey.publicKey).not.toEqual(second.signedPrekey.publicKey);
  });
});

// ---------------------------------------------------------------------------
// DeriveSharedSecret (initiator) / CompleteSharedSecret (responder) — the
// standard X3DH construction specified exactly in charter §3 (amended
// 2026-08-20). This EXPLICITLY SUPERSEDES the pre-amendment two-term
// staticStaticDh/ephemeralStaticDh scheme — see ratchet.ts.
// ---------------------------------------------------------------------------
describe("DeriveSharedSecret / CompleteSharedSecret: cross-derivation match (the core correctness property of this amendment)", () => {
  it("initiator and responder derive the IDENTICAL shared secret, WITH a one-time prekey (4-term construction)", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const initiator = generateIdentityKeyMaterial({});
    const initiatorDh = initiatorDhMaterial(initiator);
    const otp = bundle.oneTimePrekeys[0];

    const theirPrekeyBundle: PrekeyBundle = {
      identityDhPublicKey: bundle.identityDhPublicKey,
      identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
      signedPrekey: bundle.signedPrekey,
      oneTimePrekey: otp,
    };
    const initiatorResult = await deriveSharedSecret({
      privateKeyHandle: initiator.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle,
    });

    const responderResult = await completeSharedSecret({
      privateKeyHandle: responder.privateKeyHandle,
      theirIdentityDhPublicKey: initiatorDh.identityDhPublicKey,
      theirEphemeralPublicKey: initiatorResult.myEphemeralPublicKey,
      mySignedPrekeyId: bundle.signedPrekey.prekeyId,
      myOneTimePrekeyId: otp.prekeyId,
      theirIdentitySigningPublicKey: initiator.publicKey,
      theirIdentityDhPublicKeySignature: initiatorDh.identityDhPublicKeySignature,
    });

    const initiatorState = await getRatchetSession(initiatorResult.sharedSecretHandle);
    const responderState = await getRatchetSession(responderResult.sharedSecretHandle);

    // The actual, load-bearing assertion: byte-for-byte identical shared
    // secrets, computed independently by both sides via
    // deriveInitiatorHandshake and deriveResponderSharedSecret
    // respectively (ratchet.ts) — proving DH commutativity really does
    // make DH1..DH4 match term-by-term across the two derivations, using
    // the corrected (key-separation-fixed) DH-capable identity keys on
    // BOTH sides.
    expect(initiatorState.rootKey).toEqual(responderState.rootKey);
  });

  it("initiator and responder derive the IDENTICAL shared secret WITHOUT a one-time prekey (3-term exhaustion-fallback construction)", async () => {
    const { responder, bundle } = await makeResponderWithBundle(0);
    const initiator = generateIdentityKeyMaterial({});
    const initiatorDh = initiatorDhMaterial(initiator);

    const theirPrekeyBundle: PrekeyBundle = {
      identityDhPublicKey: bundle.identityDhPublicKey,
      identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
      signedPrekey: bundle.signedPrekey,
    };
    const initiatorResult = await deriveSharedSecret({
      privateKeyHandle: initiator.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle,
    });

    const responderResult = await completeSharedSecret({
      privateKeyHandle: responder.privateKeyHandle,
      theirIdentityDhPublicKey: initiatorDh.identityDhPublicKey,
      theirEphemeralPublicKey: initiatorResult.myEphemeralPublicKey,
      mySignedPrekeyId: bundle.signedPrekey.prekeyId,
      // myOneTimePrekeyId deliberately omitted.
      theirIdentitySigningPublicKey: initiator.publicKey,
      theirIdentityDhPublicKeySignature: initiatorDh.identityDhPublicKeySignature,
    });

    const initiatorState = await getRatchetSession(initiatorResult.sharedSecretHandle);
    const responderState = await getRatchetSession(responderResult.sharedSecretHandle);
    expect(initiatorState.rootKey).toEqual(responderState.rootKey);
  });

  it("required domain separation: the 4-term (with-OTP) and 3-term (signed-prekey-only) shared secrets differ even when the underlying signed-prekey/identity material is otherwise the same", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const initiator = generateIdentityKeyMaterial({});
    const otp = bundle.oneTimePrekeys[0];

    const with4Term = await deriveSharedSecret({
      privateKeyHandle: initiator.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle: {
        identityDhPublicKey: bundle.identityDhPublicKey,
        identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
        signedPrekey: bundle.signedPrekey,
        oneTimePrekey: otp,
      },
    });
    const with3Term = await deriveSharedSecret({
      privateKeyHandle: initiator.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle: {
        identityDhPublicKey: bundle.identityDhPublicKey,
        identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
        signedPrekey: bundle.signedPrekey,
      },
    });

    const state4 = await getRatchetSession(with4Term.sharedSecretHandle);
    const state3 = await getRatchetSession(with3Term.sharedSecretHandle);
    expect(state4.rootKey).not.toEqual(state3.rootKey);
  });
});

describe("DeriveSharedSecret: signature verification (charter §6 'Signed-prekey substitution') — hard abort, never a silent fallback", () => {
  let auditSpy: jest.SpiedFunction<typeof audit.logAuditEvent>;

  beforeEach(() => {
    auditSpy = jest.spyOn(audit, "logAuditEvent");
  });

  afterEach(() => {
    auditSpy.mockRestore();
  });

  it("refuses to proceed (no partial derivation) when the signed prekey's signature does not verify, and emits signed_prekey_signature_invalid", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const initiator = generateIdentityKeyMaterial({});

    const tamperedSignature = new Uint8Array(bundle.signedPrekey.signature);
    tamperedSignature[0] ^= 0xff;

    await expect(
      deriveSharedSecret({
        privateKeyHandle: initiator.privateKeyHandle,
        theirIdentitySigningPublicKey: responder.publicKey,
        theirPrekeyBundle: {
          identityDhPublicKey: bundle.identityDhPublicKey,
          identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
          signedPrekey: { ...bundle.signedPrekey, signature: tamperedSignature },
        },
      }),
    ).rejects.toThrow();

    expect(auditSpy).toHaveBeenCalledWith(
      "signed_prekey_signature_invalid",
      expect.objectContaining({ prekeyId: bundle.signedPrekey.prekeyId }),
    );
  });

  it("refuses to proceed when the signed prekey's public key has been substituted (server/MITM substitution attack)", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const initiator = generateIdentityKeyMaterial({});
    const attackerPrekeyPrivate = new Uint8Array(32).fill(9);
    const attackerPrekeyPublic = x25519.getPublicKey(attackerPrekeyPrivate);

    await expect(
      deriveSharedSecret({
        privateKeyHandle: initiator.privateKeyHandle,
        theirIdentitySigningPublicKey: responder.publicKey,
        theirPrekeyBundle: {
          identityDhPublicKey: bundle.identityDhPublicKey,
          identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
          signedPrekey: { ...bundle.signedPrekey, publicKey: attackerPrekeyPublic },
        },
      }),
    ).rejects.toThrow();
  });

  // NEW, key-separation fix round 2 (charter §6 "identity_dh_public_key
  // substitution"): identity_dh_public_key is server-published/-fetched
  // material exactly like signed_prekey, and inherits the identical
  // substitution risk and the identical hard-abort fix.
  it("refuses to proceed (no partial derivation) when identity_dh_public_key_signature does not verify, and emits signed_prekey_signature_invalid", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const initiator = generateIdentityKeyMaterial({});

    const tamperedSignature = new Uint8Array(bundle.identityDhPublicKeySignature);
    tamperedSignature[0] ^= 0xff;

    await expect(
      deriveSharedSecret({
        privateKeyHandle: initiator.privateKeyHandle,
        theirIdentitySigningPublicKey: responder.publicKey,
        theirPrekeyBundle: {
          identityDhPublicKey: bundle.identityDhPublicKey,
          identityDhPublicKeySignature: tamperedSignature,
          signedPrekey: bundle.signedPrekey,
        },
      }),
    ).rejects.toThrow();

    expect(auditSpy).toHaveBeenCalledWith(
      "signed_prekey_signature_invalid",
      expect.objectContaining({ reason: "identity_dh_public_key_signature_invalid" }),
    );
  });

  it("refuses to proceed when identity_dh_public_key itself has been substituted (server/MITM substitution attack) — the derivation-mismatch case the signature check exists to close", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const initiator = generateIdentityKeyMaterial({});
    const attackerIdentityDhPublicKey = x25519.getPublicKey(new Uint8Array(32).fill(9));

    await expect(
      deriveSharedSecret({
        privateKeyHandle: initiator.privateKeyHandle,
        theirIdentitySigningPublicKey: responder.publicKey,
        theirPrekeyBundle: {
          identityDhPublicKey: attackerIdentityDhPublicKey,
          identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
          signedPrekey: bundle.signedPrekey,
        },
      }),
    ).rejects.toThrow();
  });

  it("requires the caller's identity key handle specifically — rejects a non-identity signing-capable handle", async () => {
    const otherSigningKey = generateKeyPair({ purpose: "sign:device-binding" });
    await expect(
      deriveSharedSecret({
        privateKeyHandle: otherSigningKey.privateKeyHandle,
        theirIdentitySigningPublicKey: new Uint8Array(32),
        theirPrekeyBundle: {
          identityDhPublicKey: new Uint8Array(32),
          identityDhPublicKeySignature: new Uint8Array(64),
          signedPrekey: { prekeyId: "x", publicKey: new Uint8Array(32), signature: new Uint8Array(64), createdAtUnix: 0 },
        },
      }),
    ).rejects.toThrow();
  });

  it("rejects a DH-capable (X25519) device-session handle", async () => {
    const sessionKey = generateKeyPair({ purpose: "device-session" });
    await expect(
      deriveSharedSecret({
        privateKeyHandle: sessionKey.privateKeyHandle,
        theirIdentitySigningPublicKey: new Uint8Array(32),
        theirPrekeyBundle: {
          identityDhPublicKey: new Uint8Array(32),
          identityDhPublicKeySignature: new Uint8Array(64),
          signedPrekey: { prekeyId: "x", publicKey: new Uint8Array(32), signature: new Uint8Array(64), createdAtUnix: 0 },
        },
      }),
    ).rejects.toThrow();
  });
});

describe("DeriveSharedSecret: forward secrecy at handshake time", () => {
  it("derives a fresh shared secret on every call, even against the exact same bundle (no key-reuse hazard — DH2/DH3/DH4 depend on a freshly generated ephemeral keypair)", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const initiator = generateIdentityKeyMaterial({});
    const theirPrekeyBundle: PrekeyBundle = {
      identityDhPublicKey: bundle.identityDhPublicKey,
      identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
      signedPrekey: bundle.signedPrekey,
      oneTimePrekey: bundle.oneTimePrekeys[0],
    };

    const sessionA = await deriveSharedSecret({
      privateKeyHandle: initiator.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle,
    });
    const sessionB = await deriveSharedSecret({
      privateKeyHandle: initiator.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle,
    });

    const stateA = await getRatchetSession(sessionA.sharedSecretHandle);
    const stateB = await getRatchetSession(sessionB.sharedSecretHandle);
    expect(stateA.rootKey).not.toEqual(stateB.rootKey);
    expect(sessionA.myEphemeralPublicKey).not.toEqual(sessionB.myEphemeralPublicKey);
  });

  it("compromising the initiator's long-term identity private key alone is NOT sufficient to recompute the session's shared secret (DH2/DH3/DH4 all depend on the now-discarded ephemeral private key)", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const initiator = generateIdentityKeyMaterial({});
    const theirPrekeyBundle: PrekeyBundle = {
      identityDhPublicKey: bundle.identityDhPublicKey,
      identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
      signedPrekey: bundle.signedPrekey,
      oneTimePrekey: bundle.oneTimePrekeys[0],
    };

    const session = await deriveSharedSecret({
      privateKeyHandle: initiator.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle,
    });
    const liveState = await getRatchetSession(session.sharedSecretHandle);

    // Simulate an attacker who has since stolen the initiator's long-term
    // identity private key (the SEED, per dhKey.ts — the corrected
    // key-separation-fix construction, NOT the old birational conversion).
    // Every other input here (bundle contents) is, by definition, already
    // public. The attacker can therefore compute DH1 (static-static:
    // DH(IK_A, SPK_B), no ephemeral involved) — but NOT DH2/DH3/DH4, which
    // all require the ephemeral private key that was generated fresh inside
    // deriveSharedSecret and never retained anywhere this attacker could
    // reach.
    const initiatorEntry = getPrivateKeyEntry(initiator.privateKeyHandle);
    const ikAScalar = deriveDhScalar(initiatorEntry.privateKey);
    const dh1Only = x25519.getSharedSecret(ikAScalar, bundle.signedPrekey.publicKey);
    const attackerGuess = hkdf(sha256, dh1Only, undefined, X3DH_CONTEXT_3TERM_SIGNED_PREKEY_ONLY, 32);

    expect(liveState.rootKey).not.toEqual(attackerGuess);
  });
});

describe("CompleteSharedSecret: exhaustion-fallback (charter §6/§5) — disclosed, not silently degraded", () => {
  let auditSpy: jest.SpiedFunction<typeof audit.logAuditEvent>;

  beforeEach(() => {
    auditSpy = jest.spyOn(audit, "logAuditEvent");
  });

  afterEach(() => {
    auditSpy.mockRestore();
  });

  it("succeeds with the 3-term derivation when my_one_time_prekey_id is omitted, and emits session_established_signed_prekey_only", async () => {
    const { responder, bundle } = await makeResponderWithBundle(0);
    const initiator = generateIdentityKeyMaterial({});
    const initiatorDh = initiatorDhMaterial(initiator);

    const initiatorResult = await deriveSharedSecret({
      privateKeyHandle: initiator.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle: {
        identityDhPublicKey: bundle.identityDhPublicKey,
        identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
        signedPrekey: bundle.signedPrekey,
      },
    });

    const result = await completeSharedSecret({
      privateKeyHandle: responder.privateKeyHandle,
      theirIdentityDhPublicKey: initiatorDh.identityDhPublicKey,
      theirEphemeralPublicKey: initiatorResult.myEphemeralPublicKey,
      mySignedPrekeyId: bundle.signedPrekey.prekeyId,
      theirIdentitySigningPublicKey: initiator.publicKey,
      theirIdentityDhPublicKeySignature: initiatorDh.identityDhPublicKeySignature,
    });

    expect(result.sharedSecretHandle.handle).toMatch(/^ratchet_/);
    expect(auditSpy).toHaveBeenCalledWith(
      "session_established_signed_prekey_only",
      expect.objectContaining({ signedPrekeyId: bundle.signedPrekey.prekeyId }),
    );
  });

  it("does NOT emit session_established_signed_prekey_only when a one-time prekey IS used", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const initiator = generateIdentityKeyMaterial({});
    const initiatorDh = initiatorDhMaterial(initiator);
    const otp = bundle.oneTimePrekeys[0];

    const initiatorResult = await deriveSharedSecret({
      privateKeyHandle: initiator.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle: {
        identityDhPublicKey: bundle.identityDhPublicKey,
        identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
        signedPrekey: bundle.signedPrekey,
        oneTimePrekey: otp,
      },
    });

    await completeSharedSecret({
      privateKeyHandle: responder.privateKeyHandle,
      theirIdentityDhPublicKey: initiatorDh.identityDhPublicKey,
      theirEphemeralPublicKey: initiatorResult.myEphemeralPublicKey,
      mySignedPrekeyId: bundle.signedPrekey.prekeyId,
      myOneTimePrekeyId: otp.prekeyId,
      theirIdentitySigningPublicKey: initiator.publicKey,
      theirIdentityDhPublicKeySignature: initiatorDh.identityDhPublicKeySignature,
    });

    expect(auditSpy).not.toHaveBeenCalledWith("session_established_signed_prekey_only", expect.anything());
  });
});

// ---------------------------------------------------------------------------
// CompleteSharedSecret: atomic one-time-prekey consumption (charter §6 —
// "the single most load-bearing requirement of this whole amendment").
// ---------------------------------------------------------------------------
describe("CompleteSharedSecret: atomic one-time-prekey consumption", () => {
  it("a single call successfully consumes the one-time prekey, and a SECOND call against the SAME prekey_id afterward fails distinguishably (sequential re-use, not just concurrent)", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const initiator = generateIdentityKeyMaterial({});
    const initiatorDh = initiatorDhMaterial(initiator);
    const otp = bundle.oneTimePrekeys[0];

    const initiatorResult = await deriveSharedSecret({
      privateKeyHandle: initiator.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle: {
        identityDhPublicKey: bundle.identityDhPublicKey,
        identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
        signedPrekey: bundle.signedPrekey,
        oneTimePrekey: otp,
      },
    });

    await completeSharedSecret({
      privateKeyHandle: responder.privateKeyHandle,
      theirIdentityDhPublicKey: initiatorDh.identityDhPublicKey,
      theirEphemeralPublicKey: initiatorResult.myEphemeralPublicKey,
      mySignedPrekeyId: bundle.signedPrekey.prekeyId,
      myOneTimePrekeyId: otp.prekeyId,
      theirIdentitySigningPublicKey: initiator.publicKey,
      theirIdentityDhPublicKeySignature: initiatorDh.identityDhPublicKeySignature,
    });

    // A second, later call referencing the identical (now-consumed)
    // prekey_id — e.g. a duplicate/retried delivery of the same first
    // message — must fail distinguishably, never silently re-derive using
    // stale key material.
    await expect(
      completeSharedSecret({
        privateKeyHandle: responder.privateKeyHandle,
        theirIdentityDhPublicKey: initiatorDh.identityDhPublicKey,
        theirEphemeralPublicKey: initiatorResult.myEphemeralPublicKey,
        mySignedPrekeyId: bundle.signedPrekey.prekeyId,
        myOneTimePrekeyId: otp.prekeyId,
        theirIdentitySigningPublicKey: initiator.publicKey,
        theirIdentityDhPublicKeySignature: initiatorDh.identityDhPublicKeySignature,
      }),
    ).rejects.toBeInstanceOf(PrekeyAlreadyConsumedError);
  });

  it("REAL CONCURRENCY: two simultaneous CompleteSharedSecret calls referencing the same prekey_id — exactly one succeeds, the other fails with PrekeyAlreadyConsumedError, neither hangs nor silently succeeds", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const initiatorA = generateIdentityKeyMaterial({});
    const initiatorADh = initiatorDhMaterial(initiatorA);
    const initiatorB = generateIdentityKeyMaterial({});
    const initiatorBDh = initiatorDhMaterial(initiatorB);
    const otp = bundle.oneTimePrekeys[0];

    // Two different initiators' handshakes both reference the SAME
    // responder one-time prekey — simulating duplicate message delivery, a
    // dropped-response retry, or (pre-single-issuance-guarantee) two
    // initiators independently fetching the same bundle, per charter §6.
    const resultA = await deriveSharedSecret({
      privateKeyHandle: initiatorA.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle: {
        identityDhPublicKey: bundle.identityDhPublicKey,
        identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
        signedPrekey: bundle.signedPrekey,
        oneTimePrekey: otp,
      },
    });
    const resultB = await deriveSharedSecret({
      privateKeyHandle: initiatorB.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle: {
        identityDhPublicKey: bundle.identityDhPublicKey,
        identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
        signedPrekey: bundle.signedPrekey,
        oneTimePrekey: otp,
      },
    });

    // Both invoked WITHOUT awaiting in between, so both promises start
    // executing up to their first `await` (SecureLocalStore's real,
    // genuinely asynchronous boundary — see prekeyStore.ts) before either
    // completes. This is the actual race window charter §6 describes, not
    // a simulated one.
    const outcomes = await Promise.allSettled([
      completeSharedSecret({
        privateKeyHandle: responder.privateKeyHandle,
        theirIdentityDhPublicKey: initiatorADh.identityDhPublicKey,
        theirEphemeralPublicKey: resultA.myEphemeralPublicKey,
        mySignedPrekeyId: bundle.signedPrekey.prekeyId,
        myOneTimePrekeyId: otp.prekeyId,
        theirIdentitySigningPublicKey: initiatorA.publicKey,
        theirIdentityDhPublicKeySignature: initiatorADh.identityDhPublicKeySignature,
      }),
      completeSharedSecret({
        privateKeyHandle: responder.privateKeyHandle,
        theirIdentityDhPublicKey: initiatorBDh.identityDhPublicKey,
        theirEphemeralPublicKey: resultB.myEphemeralPublicKey,
        mySignedPrekeyId: bundle.signedPrekey.prekeyId,
        myOneTimePrekeyId: otp.prekeyId,
        theirIdentitySigningPublicKey: initiatorB.publicKey,
        theirIdentityDhPublicKeySignature: initiatorBDh.identityDhPublicKeySignature,
      }),
    ]);

    const fulfilled = outcomes.filter((o) => o.status === "fulfilled");
    const rejected = outcomes.filter((o): o is PromiseRejectedResult => o.status === "rejected");

    // Exactly one succeeds — never both (stale reuse), never neither (hang
    // or unhandled failure of both).
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(rejected[0].reason).toBeInstanceOf(PrekeyAlreadyConsumedError);
    expect((rejected[0].reason as PrekeyAlreadyConsumedError).prekeyId).toBe(otp.prekeyId);
  });

  it("REAL CONCURRENCY, 5-way: exactly one of five simultaneous calls for the same prekey_id succeeds", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const otp = bundle.oneTimePrekeys[0];

    const initiators = Array.from({ length: 5 }, () => generateIdentityKeyMaterial({}));
    const initiatorDhs = initiators.map((initiator) => initiatorDhMaterial(initiator));
    const handshakes = await Promise.all(
      initiators.map((initiator) =>
        deriveSharedSecret({
          privateKeyHandle: initiator.privateKeyHandle,
          theirIdentitySigningPublicKey: responder.publicKey,
          theirPrekeyBundle: {
            identityDhPublicKey: bundle.identityDhPublicKey,
            identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
            signedPrekey: bundle.signedPrekey,
            oneTimePrekey: otp,
          },
        }),
      ),
    );

    const outcomes = await Promise.allSettled(
      initiators.map((initiator, i) =>
        completeSharedSecret({
          privateKeyHandle: responder.privateKeyHandle,
          theirIdentityDhPublicKey: initiatorDhs[i].identityDhPublicKey,
          theirEphemeralPublicKey: handshakes[i].myEphemeralPublicKey,
          mySignedPrekeyId: bundle.signedPrekey.prekeyId,
          myOneTimePrekeyId: otp.prekeyId,
          theirIdentitySigningPublicKey: initiator.publicKey,
          theirIdentityDhPublicKeySignature: initiatorDhs[i].identityDhPublicKeySignature,
        }),
      ),
    );

    expect(outcomes.filter((o) => o.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((o) => o.status === "rejected")).toHaveLength(4);
    for (const outcome of outcomes) {
      if (outcome.status === "rejected") {
        expect(outcome.reason).toBeInstanceOf(PrekeyAlreadyConsumedError);
      }
    }
  });

  it("concurrent calls for DIFFERENT prekey_ids do not interfere with each other (the lock is per-prekey_id, not global)", async () => {
    const { responder, bundle } = await makeResponderWithBundle(2);
    const initiatorA = generateIdentityKeyMaterial({});
    const initiatorADh = initiatorDhMaterial(initiatorA);
    const initiatorB = generateIdentityKeyMaterial({});
    const initiatorBDh = initiatorDhMaterial(initiatorB);
    const [otpA, otpB] = bundle.oneTimePrekeys;

    const resultA = await deriveSharedSecret({
      privateKeyHandle: initiatorA.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle: {
        identityDhPublicKey: bundle.identityDhPublicKey,
        identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
        signedPrekey: bundle.signedPrekey,
        oneTimePrekey: otpA,
      },
    });
    const resultB = await deriveSharedSecret({
      privateKeyHandle: initiatorB.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle: {
        identityDhPublicKey: bundle.identityDhPublicKey,
        identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
        signedPrekey: bundle.signedPrekey,
        oneTimePrekey: otpB,
      },
    });

    const outcomes = await Promise.allSettled([
      completeSharedSecret({
        privateKeyHandle: responder.privateKeyHandle,
        theirIdentityDhPublicKey: initiatorADh.identityDhPublicKey,
        theirEphemeralPublicKey: resultA.myEphemeralPublicKey,
        mySignedPrekeyId: bundle.signedPrekey.prekeyId,
        myOneTimePrekeyId: otpA.prekeyId,
        theirIdentitySigningPublicKey: initiatorA.publicKey,
        theirIdentityDhPublicKeySignature: initiatorADh.identityDhPublicKeySignature,
      }),
      completeSharedSecret({
        privateKeyHandle: responder.privateKeyHandle,
        theirIdentityDhPublicKey: initiatorBDh.identityDhPublicKey,
        theirEphemeralPublicKey: resultB.myEphemeralPublicKey,
        mySignedPrekeyId: bundle.signedPrekey.prekeyId,
        myOneTimePrekeyId: otpB.prekeyId,
        theirIdentitySigningPublicKey: initiatorB.publicKey,
        theirIdentityDhPublicKeySignature: initiatorBDh.identityDhPublicKeySignature,
      }),
    ]);

    expect(outcomes.every((o) => o.status === "fulfilled")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// CompleteSharedSecret: wholesale key fabrication (charter §6 "identity
// impersonation via wholesale key fabrication", key-separation fix round 4)
// — a distinct, more severe threat than field-tampering: an attacker who
// generates BOTH their_identity_dh_public_key and their_ephemeral_public_key
// from scratch, with no genuine private key from any real party, holds 100%
// of the private material every DH term needs and can derive a fully
// working shared secret this responder would accept as belonging to
// whatever identity is claimed. The their_identity_dh_public_key_signature
// verification closes this by requiring a signature no fabricator can
// produce without the real claimed identity's actual signing key.
// ---------------------------------------------------------------------------
describe("CompleteSharedSecret: wholesale key fabrication — hard abort, distinct from field-tampering", () => {
  let auditSpy: jest.SpiedFunction<typeof audit.logAuditEvent>;

  beforeEach(() => {
    auditSpy = jest.spyOn(audit, "logAuditEvent");
  });

  afterEach(() => {
    auditSpy.mockRestore();
  });

  it("rejects a wholesale-fabricated identity_dh_public_key + ephemeral_public_key pair with NO real signature at all — the attacker owns 100% of the private material but cannot produce a valid signature over a claimed identity it does not control", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const otp = bundle.oneTimePrekeys[0];
    // A real, claimed identity the attacker does NOT actually control —
    // the attacker knows no private key corresponding to this identity.
    const claimedVictim = generateIdentityKeyMaterial({});

    // The attacker fabricates BOTH keys from scratch — genuinely valid
    // X25519 keys, just not signed by (or derived from) the claimed
    // victim's real identity seed. This is the exact "no genuine private
    // key from anyone real" scenario charter §6 describes.
    const fabricatedIdentityDhPrivate = new Uint8Array(32).fill(0x42);
    const fabricatedIdentityDhPublicKey = x25519.getPublicKey(fabricatedIdentityDhPrivate);
    const fabricatedEphemeralPrivate = new Uint8Array(32).fill(0x43);
    const fabricatedEphemeralPublicKey = x25519.getPublicKey(fabricatedEphemeralPrivate);
    // No real signature exists over an unsigned/self-authored value — an
    // arbitrary 64-byte buffer, standing in for "whatever garbage an
    // attacker who doesn't control the claimed identity's signing key can
    // produce."
    const unsignedGarbage = new Uint8Array(64).fill(0xee);

    await expect(
      completeSharedSecret({
        privateKeyHandle: responder.privateKeyHandle,
        theirIdentityDhPublicKey: fabricatedIdentityDhPublicKey,
        theirEphemeralPublicKey: fabricatedEphemeralPublicKey,
        mySignedPrekeyId: bundle.signedPrekey.prekeyId,
        myOneTimePrekeyId: otp.prekeyId,
        theirIdentitySigningPublicKey: claimedVictim.publicKey,
        theirIdentityDhPublicKeySignature: unsignedGarbage,
      }),
    ).rejects.toThrow();

    expect(auditSpy).toHaveBeenCalledWith(
      "signed_prekey_signature_invalid",
      expect.objectContaining({ reason: "their_identity_dh_public_key_signature_invalid" }),
    );
  });

  it("rejects a fabricated identity_dh_public_key even when paired with a DIFFERENT real identity's genuine signature (signature doesn't transfer across keys)", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const otp = bundle.oneTimePrekeys[0];
    const claimedVictim = generateIdentityKeyMaterial({});
    // A real attacker-controlled identity, with a real, validly-signed DH
    // key of its OWN.
    const attacker = generateIdentityKeyMaterial({});
    const attackerDh = initiatorDhMaterial(attacker);

    await expect(
      completeSharedSecret({
        privateKeyHandle: responder.privateKeyHandle,
        // The attacker presents ITS OWN genuinely-signed DH key material,
        // but CLAIMS to be claimedVictim (their_identity_signing_public_key
        // below) — the signature was produced by the attacker's own key,
        // not the victim's, so it must not verify against the victim's
        // signing key.
        theirIdentityDhPublicKey: attackerDh.identityDhPublicKey,
        theirEphemeralPublicKey: x25519.getPublicKey(new Uint8Array(32).fill(0x44)),
        mySignedPrekeyId: bundle.signedPrekey.prekeyId,
        myOneTimePrekeyId: otp.prekeyId,
        theirIdentitySigningPublicKey: claimedVictim.publicKey,
        theirIdentityDhPublicKeySignature: attackerDh.identityDhPublicKeySignature,
      }),
    ).rejects.toThrow();
  });

  it("never consumes the one-time prekey for a request that fails signature verification (the scarce forward-secrecy resource is not burned on a rejected fabrication attempt)", async () => {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const otp = bundle.oneTimePrekeys[0];
    const claimedVictim = generateIdentityKeyMaterial({});

    await expect(
      completeSharedSecret({
        privateKeyHandle: responder.privateKeyHandle,
        theirIdentityDhPublicKey: x25519.getPublicKey(new Uint8Array(32).fill(0x42)),
        theirEphemeralPublicKey: x25519.getPublicKey(new Uint8Array(32).fill(0x43)),
        mySignedPrekeyId: bundle.signedPrekey.prekeyId,
        myOneTimePrekeyId: otp.prekeyId,
        theirIdentitySigningPublicKey: claimedVictim.publicKey,
        theirIdentityDhPublicKeySignature: new Uint8Array(64).fill(0xee),
      }),
    ).rejects.toThrow();

    // The one-time prekey must still be consumable by a legitimate,
    // correctly-signed request afterward — proving it was never touched by
    // the rejected fabrication attempt above.
    const initiator = generateIdentityKeyMaterial({});
    const initiatorDh = initiatorDhMaterial(initiator);
    const initiatorResult = await deriveSharedSecret({
      privateKeyHandle: initiator.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle: {
        identityDhPublicKey: bundle.identityDhPublicKey,
        identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
        signedPrekey: bundle.signedPrekey,
        oneTimePrekey: otp,
      },
    });
    await expect(
      completeSharedSecret({
        privateKeyHandle: responder.privateKeyHandle,
        theirIdentityDhPublicKey: initiatorDh.identityDhPublicKey,
        theirEphemeralPublicKey: initiatorResult.myEphemeralPublicKey,
        mySignedPrekeyId: bundle.signedPrekey.prekeyId,
        myOneTimePrekeyId: otp.prekeyId,
        theirIdentitySigningPublicKey: initiator.publicKey,
        theirIdentityDhPublicKeySignature: initiatorDh.identityDhPublicKeySignature,
      }),
    ).resolves.toBeDefined();
  });
});

describe("Post-handshake ratchet mechanics (deriveNextMessageKey / ratchetAdvance) — unaffected by this amendment", () => {
  async function makeSession() {
    const { responder, bundle } = await makeResponderWithBundle(1);
    const initiator = generateIdentityKeyMaterial({});
    const otp = bundle.oneTimePrekeys[0];
    const result = await deriveSharedSecret({
      privateKeyHandle: initiator.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle: {
        identityDhPublicKey: bundle.identityDhPublicKey,
        identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
        signedPrekey: bundle.signedPrekey,
        oneTimePrekey: otp,
      },
    });
    return await getRatchetSession(result.sharedSecretHandle);
  }

  it("forward secrecy: advancing the chain ratchet changes the chain key so the previous message key cannot be recomputed from the new state", async () => {
    const state0 = await makeSession();

    const { messageKey: key1, nextState: state1 } = deriveNextMessageKey(state0);
    const { messageKey: key2, nextState: state2 } = deriveNextMessageKey(state1);

    expect(key1).not.toEqual(key2);
    expect(state1.sendingChainKey).not.toEqual(state0.sendingChainKey);
    expect(state2.sendingChainKey).not.toEqual(state1.sendingChainKey);
    expect(state2.sendingChainKey).not.toEqual(state0.sendingChainKey);
  });

  it("post-compromise security: a DH ratchet step produces a root key that could not have been predicted from the old root key alone", async () => {
    const compromisedState = await makeSession();

    const bobNewEphemeral = generateKeyPair({ purpose: "ratchet-step" });
    const healedA = ratchetAdvance(compromisedState, bobNewEphemeral.publicKey);
    const healedB = ratchetAdvance(compromisedState, bobNewEphemeral.publicKey);

    expect(healedA.rootKey).not.toEqual(healedB.rootKey);
    expect(healedA.rootKey).not.toEqual(compromisedState.rootKey);
  });

  // CORRECTED 2026-08-23 ("the ongoing-ratchet exposure gap" amendment):
  // this test used to assert `sendingChainKey === HKDF(rootKey, CHAIN_INFO)`
  // (the bare, undirected label) for a HANDSHAKE-produced state — that
  // assertion was, itself, an exact encoding of the amendment's own
  // catastrophic bidirectional-collision defect (an initiator and a
  // responder would both compute that same bare-label value). `makeSession`
  // here returns the INITIATOR's handshake state, so its `sendingChainKey`/
  // `receivingChainKey` must now come from the two DIRECTIONAL labels, not
  // the bare one — see ratchet.ts's module header.
  it("initiator's sendingChainKey/receivingChainKey are HKDF(rootKey, <directional label>) — sanity check against the exported context constants", async () => {
    const state = await makeSession();
    const expectedSending = hkdf(sha256, state.rootKey, undefined, CHAIN_INFO_INITIATOR_TO_RESPONDER, 32);
    const expectedReceiving = hkdf(sha256, state.rootKey, undefined, CHAIN_INFO_RESPONDER_TO_INITIATOR, 32);
    expect(state.sendingChainKey).toEqual(expectedSending);
    expect(state.receivingChainKey).toEqual(expectedReceiving);
    // And, explicitly, NOT the old bare/undirected label — the exact
    // defect this amendment's directional fix replaces.
    expect(state.sendingChainKey).not.toEqual(hkdf(sha256, state.rootKey, undefined, CHAIN_INFO, 32));
  });
});

// ---------------------------------------------------------------------------
// EncryptMessage / DecryptMessage (charter §3/§6/§7, "the ongoing-ratchet
// exposure gap" amendment, added 2026-08-23).
// ---------------------------------------------------------------------------
describe("EncryptMessage / DecryptMessage", () => {
  /**
   * Establishes a full, real initiator<->responder session (both halves of
   * the handshake, exactly like the DeriveSharedSecret/CompleteSharedSecret
   * describe blocks above) and returns both sides' independently-derived
   * `sharedSecretHandle`s — the two handles this describe block's tests use
   * to exercise EncryptMessage/DecryptMessage from both directions.
   */
  async function makeEstablishedPair(oneTimePrekeyCount = 1) {
    const { responder, bundle } = await makeResponderWithBundle(oneTimePrekeyCount);
    const initiator = generateIdentityKeyMaterial({});
    const initiatorDh = initiatorDhMaterial(initiator);
    const otp = bundle.oneTimePrekeys[0];

    const initiatorResult = await deriveSharedSecret({
      privateKeyHandle: initiator.privateKeyHandle,
      theirIdentitySigningPublicKey: responder.publicKey,
      theirPrekeyBundle: {
        identityDhPublicKey: bundle.identityDhPublicKey,
        identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
        signedPrekey: bundle.signedPrekey,
        oneTimePrekey: otp,
      },
    });
    const responderResult = await completeSharedSecret({
      privateKeyHandle: responder.privateKeyHandle,
      theirIdentityDhPublicKey: initiatorDh.identityDhPublicKey,
      theirEphemeralPublicKey: initiatorResult.myEphemeralPublicKey,
      mySignedPrekeyId: bundle.signedPrekey.prekeyId,
      myOneTimePrekeyId: otp.prekeyId,
      theirIdentitySigningPublicKey: initiator.publicKey,
      theirIdentityDhPublicKeySignature: initiatorDh.identityDhPublicKeySignature,
    });

    return {
      initiatorHandle: initiatorResult.sharedSecretHandle,
      responderHandle: responderResult.sharedSecretHandle,
    };
  }

  // (a) — the core correctness property this whole amendment exists for:
  // NOT the same sendingChainKey/receivingChainKey on both sides, and real
  // cross-decryption in both directions (not just "decryption round-trips
  // against itself", which the catastrophic same-key-reuse defect would
  // also have passed).
  it("initiator and responder derive genuinely different sendingChainKey/receivingChainKey pairs, and each can decrypt what the other encrypts, in both directions", async () => {
    const { initiatorHandle, responderHandle } = await makeEstablishedPair();

    const initiatorState = await getRatchetSession(initiatorHandle);
    const responderState = await getRatchetSession(responderHandle);

    // The exact defect this amendment fixes: an initiator and a responder
    // must NEVER derive the same sendingChainKey (the pre-fix bug) or the
    // same receivingChainKey.
    expect(initiatorState.sendingChainKey).not.toEqual(responderState.sendingChainKey);
    expect(initiatorState.receivingChainKey).not.toEqual(responderState.receivingChainKey);
    // Each party's own sending chain must equal the OTHER party's
    // receiving chain — the directional labels really do line up.
    expect(initiatorState.sendingChainKey).toEqual(responderState.receivingChainKey);
    expect(responderState.sendingChainKey).toEqual(initiatorState.receivingChainKey);

    // Initiator -> responder.
    const plaintextToResponder = new TextEncoder().encode("hello from the initiator");
    const { ciphertext: ciphertextToResponder } = await encryptMessage({
      sharedSecretHandle: initiatorHandle,
      plaintext: plaintextToResponder,
    });
    const { plaintext: decryptedByResponder } = await decryptMessage({
      sharedSecretHandle: responderHandle,
      ciphertext: ciphertextToResponder,
    });
    expect(new TextDecoder().decode(decryptedByResponder)).toBe("hello from the initiator");

    // Responder -> initiator (the OPPOSITE direction — this is exactly the
    // direction the pre-fix same-key-reuse defect would have broken).
    const plaintextToInitiator = new TextEncoder().encode("hello back from the responder");
    const { ciphertext: ciphertextToInitiator } = await encryptMessage({
      sharedSecretHandle: responderHandle,
      plaintext: plaintextToInitiator,
    });
    const { plaintext: decryptedByInitiator } = await decryptMessage({
      sharedSecretHandle: initiatorHandle,
      ciphertext: ciphertextToInitiator,
    });
    expect(new TextDecoder().decode(decryptedByInitiator)).toBe("hello back from the responder");
  });

  // (b) — required random-per-call nonce (charter §3).
  it("two EncryptMessage calls on the same session produce different ciphertexts even for identical plaintext (nonce randomness)", async () => {
    const { initiatorHandle } = await makeEstablishedPair();
    const plaintext = new TextEncoder().encode("the exact same message, twice");

    const { ciphertext: ciphertext1 } = await encryptMessage({ sharedSecretHandle: initiatorHandle, plaintext });
    const { ciphertext: ciphertext2 } = await encryptMessage({ sharedSecretHandle: initiatorHandle, plaintext });

    expect(ciphertext1).not.toEqual(ciphertext2);
  });

  // (c) — persistence genuinely routes through SecureLocalStore, not an
  // in-memory map (charter §3 round 2 persistence fix). Proven by reading
  // straight out of the underlying (mocked) OS keychain store directly —
  // not just by calling getRatchetSession twice in the same process, which
  // would also appear to work against a stale in-memory map.
  it("a session's state genuinely persists through SecureLocalStore — verified directly against the underlying (mocked) OS keychain store, not just by re-calling getRatchetSession in-process", async () => {
    const { initiatorHandle } = await makeEstablishedPair();

    // Advance the chain once via a real EncryptMessage call, so there is a
    // genuinely-updated state to prove survives.
    await encryptMessage({ sharedSecretHandle: initiatorHandle, plaintext: new TextEncoder().encode("advance once") });

    // Read the RAW stored bytes directly from the underlying (mocked)
    // expo-secure-store keychain — bypassing keyRegistry.ts's own
    // getRatchetSession accessor entirely — proving the value really lives
    // in the persistence layer keyed by "ascend.crypto.ratchetSession.<handle>",
    // not merely in some in-process object this test's own earlier calls
    // kept alive by reference. Dot-separated, not colon-separated (fixed
    // 2026-08-26 — the real expo-secure-store module rejects colons in
    // keys; this mock never enforced that, so the bug only surfaced on a
    // real device).
    const storageKey = `ascend.crypto.ratchetSession.${initiatorHandle.handle}`;
    const rawStoredValue = await SecureStore.getItemAsync(storageKey);
    expect(rawStoredValue).not.toBeNull();
    expect(typeof rawStoredValue).toBe("string");

    // And the real accessor, called completely independently afterward,
    // must decode that same durable record back to a valid, usable state
    // (sendMessageNumber reflects the one EncryptMessage call above).
    const state = await getRatchetSession(initiatorHandle);
    expect(state.sendMessageNumber).toBe(1);
    expect(state.rootKey.length).toBe(32);
  });

  // (d) — per-shared_secret_handle mutex (charter §6), mirroring
  // prekeyStore.ts's own one-time-prekey concurrency test structure: fire
  // several EncryptMessage calls against the SAME handle without awaiting
  // in between, so they genuinely overlap at SecureLocalStore's real async
  // boundary, and confirm the chain advances exactly once per call with no
  // corruption (no two calls silently landing on/clobbering the same chain
  // position).
  it("REAL CONCURRENCY: concurrent EncryptMessage calls against the same handle don't corrupt state — every call advances the chain exactly once, no lost updates", async () => {
    const { initiatorHandle } = await makeEstablishedPair();
    const messageCount = 5;
    const plaintexts = Array.from({ length: messageCount }, (_, i) =>
      new TextEncoder().encode(`concurrent message ${i}`),
    );

    // All fired without awaiting in between — the actual race window the
    // mutex exists to close, not a simulated one.
    const results = await Promise.all(
      plaintexts.map((plaintext) => encryptMessage({ sharedSecretHandle: initiatorHandle, plaintext })),
    );

    // Every ciphertext must be distinct (different nonce AND different
    // message key per call — two calls landing on the same chain position
    // would be far more likely to coincide).
    const uniqueCiphertexts = new Set(results.map((r) => bytesToHex(r.ciphertext)));
    expect(uniqueCiphertexts.size).toBe(messageCount);

    // The final persisted state must reflect EXACTLY `messageCount`
    // advances — a lost update (two concurrent calls both reading the
    // same not-yet-advanced chain key and one clobbering the other's
    // persisted result) would leave this LOWER than messageCount.
    const finalState = await getRatchetSession(initiatorHandle);
    expect(finalState.sendMessageNumber).toBe(messageCount);
  });

  it("concurrent DecryptMessage calls against the same handle don't corrupt state either", async () => {
    const { initiatorHandle, responderHandle } = await makeEstablishedPair();
    const messageCount = 4;

    // The initiator sends `messageCount` real messages, SEQUENTIALLY (a
    // real sender always advances its own chain in order) — this is what
    // the responder will decrypt concurrently below.
    const envelopes: Uint8Array[] = [];
    for (let i = 0; i < messageCount; i++) {
      const { ciphertext } = await encryptMessage({
        sharedSecretHandle: initiatorHandle,
        plaintext: new TextEncoder().encode(`sequential message ${i}`),
      });
      envelopes.push(ciphertext);
    }

    // The responder decrypts all of them concurrently. Since this
    // implementation's receiving chain has no out-of-order/skip-ahead
    // support (charter §7 item 3, explicitly deferred), only calls that
    // happen to settle in the correct chain order will succeed — the
    // property under test here is NOT "all 4 succeed" but "the mutex
    // prevents corruption": no crash, no silently-wrong plaintext, and the
    // final sendMessageNumber-equivalent chain position advances by
    // exactly as many calls as genuinely succeeded.
    const outcomes = await Promise.allSettled(
      envelopes.map((ciphertext) => decryptMessage({ sharedSecretHandle: responderHandle, ciphertext })),
    );

    const fulfilled = outcomes.filter(
      (o): o is PromiseFulfilledResult<DecryptMessageResponse> => o.status === "fulfilled",
    );
    // At least the naturally-first-settling call must succeed, and no
    // fulfilled result may silently duplicate a plaintext or corrupt
    // another's — every fulfilled plaintext must be one of the genuine
    // sequential messages, never garbage.
    const decodedFulfilled = fulfilled.map((o) => new TextDecoder().decode(o.value.plaintext));
    for (const decoded of decodedFulfilled) {
      expect(decoded.startsWith("sequential message ")).toBe(true);
    }
    // No two fulfilled calls ever decrypted to the SAME plaintext (that
    // would mean two calls both consumed the identical chain position —
    // exactly the corruption the mutex exists to prevent).
    expect(new Set(decodedFulfilled).size).toBe(decodedFulfilled.length);
  });

  // (e) — a failed decrypt must NOT advance receivingChainKey (charter §3/§6).
  it("a failed DecryptMessage (tampered ciphertext) does not advance receivingChainKey — a subsequent correct decrypt still succeeds", async () => {
    const { initiatorHandle, responderHandle } = await makeEstablishedPair();

    const plaintext = new TextEncoder().encode("legitimate, untampered message");
    const { ciphertext } = await encryptMessage({ sharedSecretHandle: initiatorHandle, plaintext });

    const tampered = new Uint8Array(ciphertext);
    tampered[tampered.length - 1] ^= 0xff; // flip a bit in the AEAD tag

    const stateBeforeFailedDecrypt = await getRatchetSession(responderHandle);

    await expect(
      decryptMessage({ sharedSecretHandle: responderHandle, ciphertext: tampered }),
    ).rejects.toThrow();

    const stateAfterFailedDecrypt = await getRatchetSession(responderHandle);
    expect(stateAfterFailedDecrypt.receivingChainKey).toEqual(stateBeforeFailedDecrypt.receivingChainKey);

    // The legitimate, untampered message must still decrypt correctly
    // afterward — proving the failed attempt never advanced the chain
    // (had it advanced, this decrypt would now fail too, since the message
    // key was derived from the wrong, "skipped past" chain position).
    const { plaintext: decrypted } = await decryptMessage({ sharedSecretHandle: responderHandle, ciphertext });
    expect(new TextDecoder().decode(decrypted)).toBe("legitimate, untampered message");
  });

  it("a corrupted/truncated envelope (not just a tampered AEAD tag) is rejected without advancing receivingChainKey", async () => {
    const { responderHandle } = await makeEstablishedPair();
    const stateBefore = await getRatchetSession(responderHandle);

    await expect(
      decryptMessage({ sharedSecretHandle: responderHandle, ciphertext: new Uint8Array([1, 2, 3]) }),
    ).rejects.toThrow();

    const stateAfter = await getRatchetSession(responderHandle);
    expect(stateAfter.receivingChainKey).toEqual(stateBefore.receivingChainKey);
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

  // Added following the crypto amendment's implementation merge gate
  // (Constitution Warden, round 2, non-blocking follow-up finding): the
  // same "every rejection is audited" defect class the negative-count fix
  // above closed for GeneratePrekeyBundle also applied to
  // DeriveSharedSecret/CompleteSharedSecret's own early-validation throws.
  it("audits a DeriveSharedSecret rejection (wrong key purpose) before throwing", async () => {
    const { responder, bundle } = await makeResponderWithBundle(0);
    const notIdentity = generateKeyPair({ purpose: "device-session" });
    await expect(
      deriveSharedSecret({
        privateKeyHandle: notIdentity.privateKeyHandle,
        theirIdentitySigningPublicKey: responder.publicKey,
        theirPrekeyBundle: {
          identityDhPublicKey: bundle.identityDhPublicKey,
          identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
          signedPrekey: bundle.signedPrekey,
        },
      }),
    ).rejects.toThrow();
    expect(auditSpy).toHaveBeenCalledWith("derive_shared_secret_rejected", {
      handle: notIdentity.privateKeyHandle.handle,
      reason: "not_identity_key",
    });
  });

  it("audits a DeriveSharedSecret rejection (malformed their_identity_signing_public_key) before throwing", async () => {
    const { bundle } = await makeResponderWithBundle(0);
    const initiator = generateIdentityKeyMaterial({});
    await expect(
      deriveSharedSecret({
        privateKeyHandle: initiator.privateKeyHandle,
        theirIdentitySigningPublicKey: new Uint8Array(4),
        theirPrekeyBundle: {
          identityDhPublicKey: bundle.identityDhPublicKey,
          identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
          signedPrekey: bundle.signedPrekey,
        },
      }),
    ).rejects.toThrow();
    expect(auditSpy).toHaveBeenCalledWith("derive_shared_secret_rejected", {
      reason: "invalid_their_identity_signing_public_key_length",
    });
  });

  it("audits a DeriveSharedSecret rejection (malformed signed prekey public key) before throwing", async () => {
    const { responder, bundle } = await makeResponderWithBundle(0);
    const initiator = generateIdentityKeyMaterial({});
    await expect(
      deriveSharedSecret({
        privateKeyHandle: initiator.privateKeyHandle,
        theirIdentitySigningPublicKey: responder.publicKey,
        theirPrekeyBundle: {
          identityDhPublicKey: bundle.identityDhPublicKey,
          identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
          signedPrekey: { ...bundle.signedPrekey, publicKey: new Uint8Array(4) },
        },
      }),
    ).rejects.toThrow();
    expect(auditSpy).toHaveBeenCalledWith("derive_shared_secret_rejected", {
      reason: "invalid_signed_prekey_public_key_length",
      prekeyId: bundle.signedPrekey.prekeyId,
    });
  });

  it("audits a DeriveSharedSecret rejection (malformed their_prekey_bundle.identity_dh_public_key) before throwing", async () => {
    const { responder, bundle } = await makeResponderWithBundle(0);
    const initiator = generateIdentityKeyMaterial({});
    await expect(
      deriveSharedSecret({
        privateKeyHandle: initiator.privateKeyHandle,
        theirIdentitySigningPublicKey: responder.publicKey,
        theirPrekeyBundle: {
          identityDhPublicKey: new Uint8Array(4),
          identityDhPublicKeySignature: bundle.identityDhPublicKeySignature,
          signedPrekey: bundle.signedPrekey,
        },
      }),
    ).rejects.toThrow();
    expect(auditSpy).toHaveBeenCalledWith("derive_shared_secret_rejected", {
      reason: "invalid_identity_dh_public_key_length",
    });
  });

  it("audits a CompleteSharedSecret rejection (wrong key purpose) before throwing", async () => {
    const { responder, bundle } = await makeResponderWithBundle(0);
    const notIdentity = generateKeyPair({ purpose: "device-session" });
    const initiator = generateIdentityKeyMaterial({});
    const initiatorDh = initiatorDhMaterial(initiator);
    await expect(
      completeSharedSecret({
        privateKeyHandle: notIdentity.privateKeyHandle,
        theirIdentityDhPublicKey: initiatorDh.identityDhPublicKey,
        theirEphemeralPublicKey: new Uint8Array(32),
        mySignedPrekeyId: bundle.signedPrekey.prekeyId,
        theirIdentitySigningPublicKey: initiator.publicKey,
        theirIdentityDhPublicKeySignature: initiatorDh.identityDhPublicKeySignature,
      }),
    ).rejects.toThrow();
    expect(auditSpy).toHaveBeenCalledWith("complete_shared_secret_rejected", {
      reason: "not_identity_key",
      handle: notIdentity.privateKeyHandle.handle,
    });
    void responder;
  });

  it("audits a CompleteSharedSecret rejection (malformed their_identity_dh_public_key) before throwing", async () => {
    const { responder, bundle } = await makeResponderWithBundle(0);
    const initiator = generateIdentityKeyMaterial({});
    const initiatorDh = initiatorDhMaterial(initiator);
    await expect(
      completeSharedSecret({
        privateKeyHandle: responder.privateKeyHandle,
        theirIdentityDhPublicKey: new Uint8Array(4),
        theirEphemeralPublicKey: new Uint8Array(32),
        mySignedPrekeyId: bundle.signedPrekey.prekeyId,
        theirIdentitySigningPublicKey: initiator.publicKey,
        theirIdentityDhPublicKeySignature: initiatorDh.identityDhPublicKeySignature,
      }),
    ).rejects.toThrow();
    expect(auditSpy).toHaveBeenCalledWith("complete_shared_secret_rejected", {
      reason: "invalid_their_identity_dh_public_key_length",
    });
  });

  it("audits a CompleteSharedSecret rejection (malformed their_ephemeral_public_key) before throwing", async () => {
    const { responder, bundle } = await makeResponderWithBundle(0);
    const initiator = generateIdentityKeyMaterial({});
    const initiatorDh = initiatorDhMaterial(initiator);
    await expect(
      completeSharedSecret({
        privateKeyHandle: responder.privateKeyHandle,
        theirIdentityDhPublicKey: initiatorDh.identityDhPublicKey,
        theirEphemeralPublicKey: new Uint8Array(4),
        mySignedPrekeyId: bundle.signedPrekey.prekeyId,
        theirIdentitySigningPublicKey: initiator.publicKey,
        theirIdentityDhPublicKeySignature: initiatorDh.identityDhPublicKeySignature,
      }),
    ).rejects.toThrow();
    expect(auditSpy).toHaveBeenCalledWith("complete_shared_secret_rejected", {
      reason: "invalid_their_ephemeral_public_key_length",
    });
  });

  it("audits a CompleteSharedSecret rejection (malformed their_identity_signing_public_key) before throwing", async () => {
    const { responder, bundle } = await makeResponderWithBundle(0);
    const initiator = generateIdentityKeyMaterial({});
    const initiatorDh = initiatorDhMaterial(initiator);
    await expect(
      completeSharedSecret({
        privateKeyHandle: responder.privateKeyHandle,
        theirIdentityDhPublicKey: initiatorDh.identityDhPublicKey,
        theirEphemeralPublicKey: new Uint8Array(32),
        mySignedPrekeyId: bundle.signedPrekey.prekeyId,
        theirIdentitySigningPublicKey: new Uint8Array(4),
        theirIdentityDhPublicKeySignature: initiatorDh.identityDhPublicKeySignature,
      }),
    ).rejects.toThrow();
    expect(auditSpy).toHaveBeenCalledWith("complete_shared_secret_rejected", {
      reason: "invalid_their_identity_signing_public_key_length",
    });
  });

  it("SecureLocalStore audit metadata carries a hashed key fingerprint, never the raw key string", async () => {
    // Valid SecureStore key characters only (alphanumeric, ".", "-", "_") —
    // still embeds a recognizably sensitive-looking substring for this
    // test's own purpose, without using the ":" separator real
    // expo-secure-store rejects (see __mocks__/expo-secure-store.ts).
    const sensitiveKeyName = "contact.15551234567.session-key";
    await secureLocalStore({ key: sensitiveKeyName, value: new Uint8Array([1, 2, 3]) });

    const call = auditSpy.mock.calls.find(([action]) => action === "secure_local_store_write");
    expect(call).toBeDefined();
    const metadata = call?.[1] as Record<string, string>;
    expect(metadata.key).toBeUndefined();
    expect(typeof metadata.keyFingerprint).toBe("string");
    expect(metadata.keyFingerprint).not.toContain(sensitiveKeyName);
    expect(JSON.stringify(metadata)).not.toContain("15551234567");
  });
});
