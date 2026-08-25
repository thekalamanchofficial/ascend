// X3DH handshake + Double-Ratchet-style session construction.
//
// Charter §3/§6 requirement: session/channel key agreement must provide
// forward secrecy and post-compromise security ("e.g. a double-ratchet or
// equivalent construction"). This module implements two distinct pieces:
//
//   1. THE INITIAL HANDSHAKE (`deriveInitiatorHandshake` /
//      `deriveResponderSharedSecret`, below): the exact, charter-specified,
//      standard X3DH four-term (or three-term exhaustion-fallback)
//      construction. AMENDED 2026-08-20 (responder-side prekey completion —
//      docs/capabilities/cryptography-and-keys.charter.md §3/§6/§7, gated
//      2026-08-19): this EXPLICITLY SUPERSEDES, not reparameterizes, the
//      prior two-term `staticStaticDh`/`ephemeralStaticDh` scheme this file
//      used to implement via a single `initRatchetSession` function. That
//      function is gone; `DH2` below is the closest analogue to what
//      `ephemeralStaticDh` computed, but `DH1`/`DH3`/`DH4` are new terms
//      with no prior equivalent, and the two-term scheme provided no
//      responder-side forward secrecy at all (the defect this amendment
//      exists to fix — charter §6's dedicated bullet).
//
//   2. THE ONGOING RATCHET (`deriveNextMessageKey` / `ratchetAdvance`,
//      unchanged by this amendment): a symmetric-key ("chain") ratchet and
//      a Diffie-Hellman ratchet step, exactly as before. These operate on
//      whatever `RatchetState.rootKey` the handshake produced — they are
//      agnostic to how that root key was derived, so this amendment does
//      not need to touch them.
//
// ---------------------------------------------------------------------------
// AMENDED 2026-08-23 ("the ongoing-ratchet exposure gap" —
// docs/capabilities/cryptography-and-keys.charter.md §3/§6, gated
// 2026-08-23): a real, catastrophic same-key-reuse defect was found in
// section 1 above, not section 2. `deriveInitiatorHandshake` and
// `deriveResponderSharedSecret` both used to derive a SINGLE
// `sendingChainKey = HKDF(sharedSecret, CHAIN_INFO)` — and because X3DH's
// own DH-commutativity property guarantees both parties compute the
// IDENTICAL `sharedSecret`, both sides derived the IDENTICAL
// `sendingChainKey`. The initiator's first outgoing message and the
// responder's first outgoing message (opposite directions, different
// plaintexts) would have been encrypted under the same derived message key
// — a catastrophic AEAD key-reuse condition, not a theoretical gap.
//
// Required fix (charter §3): `RatchetState` gains a second field,
// `receivingChainKey`, alongside `sendingChainKey`. Both are derived
// DIRECTIONALLY at handshake time via role-labeled HKDF info strings —
// `CHAIN_INFO_INITIATOR_TO_RESPONDER` / `CHAIN_INFO_RESPONDER_TO_INITIATOR`
// below — with the initiator assigning the first to its own
// `sendingChainKey` and the second to `receivingChainKey`, and the responder
// assigning them the opposite way. Both parties can compute both labels
// locally (each already knows its own role from which half of the handshake
// it ran) — no new wire field, no new round-trip. `EncryptMessage` always
// advances `sendingChainKey`; `DecryptMessage` always advances
// `receivingChainKey` — the two chains never collide because they are never
// the same derived value again.
//
// `CHAIN_INFO` (the old, bare, undirected label) is NOT removed — it still
// backs `ratchetAdvance`'s own chain-key derivation (unaffected by this fix,
// per charter §6's explicit scope discipline: `ratchetAdvance` is not wired
// into anything yet, and carries the identical, not-yet-fixed defect,
// tracked as required follow-up work whenever it IS wired in — see this
// module's own `ratchetAdvance` doc comment below).
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// 1. The initial handshake: standard X3DH, charter §3's exact specification
// ---------------------------------------------------------------------------
//
// Given the initiator's identity keypair IK_A and fresh ephemeral keypair
// EK_A, and the responder's published identity key IK_B, signed prekey
// SPK_B, and (if available) one-time prekey OPK_B:
//
//   DH1 = DH(IK_A, SPK_B)
//   DH2 = DH(EK_A, IK_B)
//   DH3 = DH(EK_A, SPK_B)
//   DH4 = DH(EK_A, OPK_B)  — only when a one-time prekey was available
//   shared_secret = HKDF(DH1 || DH2 || DH3 [|| DH4], context)
//
// `context` is a fixed, distinct literal string per case
// (X3DH_CONTEXT_4TERM_WITH_OTP vs X3DH_CONTEXT_3TERM_SIGNED_PREKEY_ONLY),
// mixed into the HKDF info parameter — required domain separation (charter
// §3), not optional hygiene: it ensures the two cases (and any other
// construction this capability might use elsewhere) can never be confused
// with one another even if inputs overlapped.
//
// IK_A/IK_B here are a genuinely separate, DH-only X25519 keypair — NOT the
// identity's Ed25519 signing key, and NOT a birational conversion of it.
// CORRECTED 2026-08-21 (key-separation fix, docs/DECISION_LOG.md's
// "Key-separation fix" series; charter §3 "Required fix", the outcome of an
// eight-round guardian-gate correction): an earlier version of this module
// reused the identity's existing Ed25519 signing scalar for IK_A/IK_B via a
// birational Ed25519->X25519 (Montgomery) conversion
// (`ed25519.utils.toMontgomerySecret`/`toMontgomery`), citing Signal's
// XEdDSA as precedent. Security Steward's implementation-merge-gate veto
// found that precedent factually inaccurate and the underlying design a
// real NIST SP 800-57 key-separation violation against the platform's
// highest-blast-radius key: reusing one long-term scalar for both standard
// EdDSA signing AND raw X25519 DH against network-facing, attacker-
// influenced public values, with none of XEdDSA's own compensating
// nonce-derivation engineering. See dhKey.ts's module header for the full
// corrected construction: `IK_A`/`IK_B`'s private form is
// `dh_scalar = HKDF(seed, "ascend-x3dh-dh-key")`, where `seed` is the raw,
// pre-RFC-8032-clamp bytes behind the identity's Ed25519 key — a genuinely
// separate key-usage domain, deterministically derived from the same
// recovery-phrase seed (no new secret to generate, back up, or lose). The
// Ed25519 (signing) form of the SAME seed is what `Sign`/`ed25519.verify`
// use directly elsewhere (e.g. signing the signed prekey and
// `identity_dh_public_key`, and verifying those signatures in index.ts) —
// this module performs no signature check of its own; callers must have
// already verified both the signed prekey's signature AND the counterparty
// identity_dh_public_key's signature (charter §6 "Signed-prekey
// substitution" / "identity_dh_public_key substitution" /
// "wholesale fabrication") before calling `deriveInitiatorHandshake` or
// `deriveResponderSharedSecret`.
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes } from "./bytes";
import { randomBytes } from "./random";
import { deriveDhScalar } from "./dhKey";

/** HKDF info/context literals — charter §3's required domain separation between the two X3DH cases. */
export const X3DH_CONTEXT_4TERM_WITH_OTP = new TextEncoder().encode("x3dh-4term-with-otp");
export const X3DH_CONTEXT_3TERM_SIGNED_PREKEY_ONLY = new TextEncoder().encode("x3dh-3term-signed-prekey-only");

// Used only by ratchetAdvance (section 2 below, unfixed — see this module's
// header comment and ratchetAdvance's own doc comment) — NOT by the X3DH
// handshake above, which uses the two DIRECTIONAL context literals below
// instead. Exported so the test suite can assert domain separation directly.
export const ROOT_INFO = new TextEncoder().encode("ascend-crypto-v1:ratchet-root");
export const CHAIN_INFO = new TextEncoder().encode("ascend-crypto-v1:ratchet-chain");
const MESSAGE_KEY_INFO = new TextEncoder().encode("ascend-crypto-v1:ratchet-message-key");
const CHAIN_ADVANCE_INFO = new TextEncoder().encode("ascend-crypto-v1:ratchet-chain-advance");

/**
 * Directional, role-labeled HKDF info strings — charter §3's required fix
 * for the bidirectional chain-key collision (see this module's header
 * comment). Exact literal strings, load-bearing (charter §3): both parties
 * derive BOTH labels locally from the identical `sharedSecret` and assign
 * them to `sendingChainKey`/`receivingChainKey` according to their own role
 * (structural, not self-reported — each party knows which half of the
 * handshake it ran), so the two sides can never disagree on labeling.
 */
export const CHAIN_INFO_INITIATOR_TO_RESPONDER = new TextEncoder().encode(
  "ascend-crypto-v1:ratchet-chain-initiator-to-responder",
);
export const CHAIN_INFO_RESPONDER_TO_INITIATOR = new TextEncoder().encode(
  "ascend-crypto-v1:ratchet-chain-responder-to-initiator",
);

export interface RatchetState {
  rootKey: Uint8Array;
  /** Current local DH ratchet keypair — regenerated on every DH ratchet step. */
  dhSelfPrivate: Uint8Array;
  dhSelfPublic: Uint8Array;
  /** Most recently known remote DH ratchet public key, if any. */
  dhRemotePublic: Uint8Array | null;
  /** Chain key for THIS party's own outgoing messages. `EncryptMessage` always advances this (charter §3). */
  sendingChainKey: Uint8Array;
  /**
   * Chain key for messages received FROM the counterparty. `DecryptMessage`
   * always advances this (charter §3) — added 2026-08-23, the ongoing-
   * ratchet exposure amendment's required fix. Directionally derived at
   * handshake time (see this module's header comment) so it is never the
   * same value as `sendingChainKey`, on either side.
   */
  receivingChainKey: Uint8Array;
  sendMessageNumber: number;
}

function computeSharedSecret(dh1: Uint8Array, dh2: Uint8Array, dh3: Uint8Array, dh4: Uint8Array | null): Uint8Array {
  const ikm = dh4 ? concatBytes(dh1, dh2, dh3, dh4) : concatBytes(dh1, dh2, dh3);
  const context = dh4 ? X3DH_CONTEXT_4TERM_WITH_OTP : X3DH_CONTEXT_3TERM_SIGNED_PREKEY_ONLY;
  return hkdf(sha256, ikm, undefined, context, 32);
}

export interface X3dhInitiatorHandshake {
  ratchetState: RatchetState;
  /** EK_A's public key — the caller's transport carries this to the responder (charter §3). */
  myEphemeralPublic: Uint8Array;
}

/**
 * Initiator's half of the X3DH handshake. Generates a fresh, single-use
 * ephemeral keypair (EK_A) and computes DH1..DH3 (and DH4, if
 * `theirOneTimePrekeyPublic` is provided) exactly as specified above.
 *
 * `myIdentitySeed` is the raw, pre-RFC-8032-clamp 32-byte seed behind this
 * process's "sign:identity" key handle — NEVER the clamped Ed25519 signing
 * scalar (see dhKey.ts's module header) — from which `IK_A` (this
 * function's own genuinely separate DH-capable scalar) is deterministically
 * derived. `theirIdentityDhPublicKey` is the counterparty's own DH-capable
 * public key (`PrekeyBundle.identity_dh_public_key`), NOT their Ed25519
 * signing public key. index.ts is responsible for resolving the identity
 * key handle and verifying BOTH `their_prekey_bundle.signed_prekey`'s
 * signature AND `their_prekey_bundle.identity_dh_public_key_signature`
 * BEFORE calling this function — this function trusts its inputs and
 * performs no verification of its own.
 */
export function deriveInitiatorHandshake(
  myIdentitySeed: Uint8Array,
  theirIdentityDhPublicKey: Uint8Array,
  theirSignedPrekeyPublic: Uint8Array,
  theirOneTimePrekeyPublic: Uint8Array | null,
): X3dhInitiatorHandshake {
  const ikAScalar = deriveDhScalar(myIdentitySeed);

  const ekAPrivate = randomBytes(32);
  const ekAPublic = x25519.getPublicKey(ekAPrivate);

  const dh1 = x25519.getSharedSecret(ikAScalar, theirSignedPrekeyPublic); // DH(IK_A, SPK_B)
  const dh2 = x25519.getSharedSecret(ekAPrivate, theirIdentityDhPublicKey); // DH(EK_A, IK_B)
  const dh3 = x25519.getSharedSecret(ekAPrivate, theirSignedPrekeyPublic); // DH(EK_A, SPK_B)
  const dh4 = theirOneTimePrekeyPublic ? x25519.getSharedSecret(ekAPrivate, theirOneTimePrekeyPublic) : null; // DH(EK_A, OPK_B)

  const sharedSecret = computeSharedSecret(dh1, dh2, dh3, dh4);
  // Directional fix (charter §3): the initiator's OWN outgoing chain is
  // "initiator-to-responder"; what it RECEIVES is "responder-to-initiator".
  const sendingChainKey = hkdf(sha256, sharedSecret, undefined, CHAIN_INFO_INITIATOR_TO_RESPONDER, 32);
  const receivingChainKey = hkdf(sha256, sharedSecret, undefined, CHAIN_INFO_RESPONDER_TO_INITIATOR, 32);

  return {
    ratchetState: {
      rootKey: sharedSecret,
      dhSelfPrivate: ekAPrivate,
      dhSelfPublic: ekAPublic,
      dhRemotePublic: theirSignedPrekeyPublic,
      sendingChainKey,
      receivingChainKey,
      sendMessageNumber: 0,
    },
    myEphemeralPublic: ekAPublic,
  };
}

/**
 * Responder's half of the X3DH handshake (`CompleteSharedSecret`, charter
 * §3/§6). Computes the identical DH1..DH3(/DH4) terms from the responder's
 * side of each pairing — `DH(SPK_B_private, IK_A_public)` equals
 * `DH(IK_A_private, SPK_B_public)` by Diffie-Hellman commutativity, and so
 * on for each term (independently verified byte-for-byte against
 * `deriveInitiatorHandshake` above — see
 * `__tests__/crypto.test.ts`, "initiator and responder derive the identical
 * shared secret").
 *
 * `myIdentitySeed` is the raw, pre-RFC-8032-clamp seed behind this
 * process's "sign:identity" key handle (see dhKey.ts) — from which `IK_B`
 * is deterministically derived, exactly mirroring `deriveInitiatorHandshake`
 * above. `theirIdentityDhPublicKey` is the initiator's own DH-capable
 * public key (`CompleteSharedSecretRequest.their_identity_dh_public_key`) —
 * index.ts is responsible for verifying it against
 * `their_identity_signing_public_key` via
 * `their_identity_dh_public_key_signature` BEFORE calling this function
 * (charter §6 "identity impersonation via wholesale key fabrication") —
 * this function trusts its inputs and performs no verification of its own.
 *
 * `myOneTimePrekeyPrivate` must already have been atomically consumed
 * (retrieved-and-deleted) by the caller — see prekeyStore.ts — before this
 * function is called; this function only performs the DH algebra, not the
 * consumption itself.
 */
export function deriveResponderSharedSecret(
  myIdentitySeed: Uint8Array,
  theirIdentityDhPublicKey: Uint8Array,
  theirEphemeralPublic: Uint8Array,
  mySignedPrekeyPrivate: Uint8Array,
  myOneTimePrekeyPrivate: Uint8Array | null,
): RatchetState {
  const ikBScalar = deriveDhScalar(myIdentitySeed);

  const dh1 = x25519.getSharedSecret(mySignedPrekeyPrivate, theirIdentityDhPublicKey); // DH(SPK_B, IK_A) == DH1
  const dh2 = x25519.getSharedSecret(ikBScalar, theirEphemeralPublic); // DH(IK_B, EK_A) == DH2
  const dh3 = x25519.getSharedSecret(mySignedPrekeyPrivate, theirEphemeralPublic); // DH(SPK_B, EK_A) == DH3
  const dh4 = myOneTimePrekeyPrivate
    ? x25519.getSharedSecret(myOneTimePrekeyPrivate, theirEphemeralPublic) // DH(OPK_B, EK_A) == DH4
    : null;

  const sharedSecret = computeSharedSecret(dh1, dh2, dh3, dh4);
  // Directional fix (charter §3): the responder's OWN outgoing chain is
  // "responder-to-initiator" — the OPPOSITE assignment from the initiator's
  // side above, computed from the identical `sharedSecret` (DH commutativity)
  // but never landing on the same field on both sides. What the responder
  // RECEIVES is "initiator-to-responder".
  const sendingChainKey = hkdf(sha256, sharedSecret, undefined, CHAIN_INFO_RESPONDER_TO_INITIATOR, 32);
  const receivingChainKey = hkdf(sha256, sharedSecret, undefined, CHAIN_INFO_INITIATOR_TO_RESPONDER, 32);
  const mySignedPrekeyPublic = x25519.getPublicKey(mySignedPrekeyPrivate);

  return {
    rootKey: sharedSecret,
    dhSelfPrivate: mySignedPrekeyPrivate,
    dhSelfPublic: mySignedPrekeyPublic,
    dhRemotePublic: theirEphemeralPublic,
    sendingChainKey,
    receivingChainKey,
    sendMessageNumber: 0,
  };
}

// ---------------------------------------------------------------------------
// 2. The ongoing ratchet. `deriveNextMessageKey` (sending) and
//    `ratchetAdvance` (DH ratchet) are themselves unchanged by the
//    2026-08-23 amendment. `deriveNextReceivingMessageKey` is NEW (the
//    amendment's own addition) — the receiving-side mirror of
//    `deriveNextMessageKey`, required now that `RatchetState` carries a
//    genuinely distinct `receivingChainKey`.
// ---------------------------------------------------------------------------

/**
 * Symmetric-key ("chain") ratchet step: derives the next message key from
 * the current chain key, then advances the chain key in place. Returns a
 * new RatchetState (state is treated as immutable to make the
 * forward-secrecy property easy to test: the caller's old reference still
 * has the old chain key in memory only until it is discarded, but nothing
 * in this module ever hands back a way to regenerate it).
 */
export function deriveNextMessageKey(state: RatchetState): { messageKey: Uint8Array; nextState: RatchetState } {
  const messageKey = hkdf(sha256, state.sendingChainKey, undefined, MESSAGE_KEY_INFO, 32);
  const nextChainKey = hkdf(sha256, state.sendingChainKey, undefined, CHAIN_ADVANCE_INFO, 32);
  return {
    messageKey,
    nextState: {
      ...state,
      sendingChainKey: nextChainKey,
      sendMessageNumber: state.sendMessageNumber + 1,
    },
  };
}

/**
 * The mirror of `deriveNextMessageKey` for the RECEIVING chain — added
 * 2026-08-23, "the ongoing-ratchet exposure gap" amendment (charter §3).
 * `DecryptMessage` (index.ts) always advances `receivingChainKey`, never
 * `sendingChainKey` — the two chains are directionally distinct from
 * handshake time onward (see this module's header comment), so a
 * `DecryptMessage` call can never consume the same derived message key an
 * `EncryptMessage` call on this same session already used or will use.
 *
 * Identical HKDF construction to `deriveNextMessageKey` (same
 * `MESSAGE_KEY_INFO`/`CHAIN_ADVANCE_INFO` literals) — only which chain key
 * field is read from/written to differs, since `messageKey`'s domain
 * separation already comes from `sendingChainKey`/`receivingChainKey`
 * themselves being distinct values (directional HKDF labels at handshake
 * time), not from a second pair of advance-step literals.
 *
 * Charter §3/§6 requirement, enforced by the CALLER (index.ts), not here:
 * a failed decrypt must NOT result in this function's `nextState` being
 * persisted — this function is a pure derivation with no knowledge of
 * whether the resulting `messageKey` will successfully decrypt anything.
 */
export function deriveNextReceivingMessageKey(state: RatchetState): { messageKey: Uint8Array; nextState: RatchetState } {
  const messageKey = hkdf(sha256, state.receivingChainKey, undefined, MESSAGE_KEY_INFO, 32);
  const nextChainKey = hkdf(sha256, state.receivingChainKey, undefined, CHAIN_ADVANCE_INFO, 32);
  return {
    messageKey,
    nextState: {
      ...state,
      receivingChainKey: nextChainKey,
    },
  };
}

/**
 * DH ratchet step: mixes a fresh local keypair and the counterparty's new
 * public key into the root key, producing a new root key and a reset chain
 * key. This is what provides post-compromise security — even full
 * knowledge of the previous root key does not let an attacker predict the
 * new one, because `dhSelfPrivate` here is freshly and independently
 * generated (never derived from prior state).
 *
 * NOT touched by the 2026-08-23 "ongoing-ratchet exposure gap" amendment,
 * deliberately (charter §6/§7 — named explicitly so it is not silently
 * rediscovered later): this still derives a single, bare, undirected
 * `sendingChainKey = HKDF(newRootKey, CHAIN_INFO)` — the IDENTICAL defect
 * class the amendment fixed for the initial handshake above (`newRootKey`
 * is identical on both sides by the same DH-commutativity property). Since
 * nothing calls `ratchetAdvance` today (confirmed by direct search) and
 * this amendment does not wire it into `EncryptMessage`/`DecryptMessage`
 * either, the identical bidirectional-collision defect would silently
 * resurface at every DH-ratchet step the moment someone DOES wire this in
 * — whoever does that next must ALSO give this function the identical
 * directional/role-labeled `sendingChainKey`/`receivingChainKey`
 * derivation from `newRootKey` this amendment gave the initial
 * handshake-produced state (`ROOT_INFO`'s own use, advancing `rootKey`
 * itself, is unaffected and correct as-is; only the chain-key derivation
 * that follows it needs the fix). `receivingChainKey` below is set to the
 * SAME (still-undirected) value as `sendingChainKey`, purely so this
 * function keeps returning a structurally valid `RatchetState` — not a
 * real fix, just satisfying the type until this function is actually wired
 * in and fixed for real.
 */
export function ratchetAdvance(state: RatchetState, remotePublicKey: Uint8Array): RatchetState {
  const dhSelfPrivate = randomBytes(32);
  const dhSelfPublic = x25519.getPublicKey(dhSelfPrivate);
  const dhOutput = x25519.getSharedSecret(dhSelfPrivate, remotePublicKey);
  const newRootKey = hkdf(sha256, concatBytes(state.rootKey, dhOutput), undefined, ROOT_INFO, 32);
  const chainKey = hkdf(sha256, newRootKey, undefined, CHAIN_INFO, 32);
  return {
    rootKey: newRootKey,
    dhSelfPrivate,
    dhSelfPublic,
    dhRemotePublic: remotePublicKey,
    sendingChainKey: chainKey,
    receivingChainKey: chainKey,
    sendMessageNumber: 0,
  };
}
