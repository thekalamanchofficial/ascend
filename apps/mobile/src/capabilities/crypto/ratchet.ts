// Double-Ratchet-style session construction for `DeriveSharedSecret`.
//
// Charter §3/§6 requirement: session/channel key agreement must provide
// forward secrecy (a compromised device's *current* session state must not
// expose *past* session content) and post-compromise security (future
// sessions must recover once the device is secured again), "e.g. a
// double-ratchet or equivalent construction."
//
// This module implements the two mechanisms a real Double Ratchet (Signal)
// combines:
//
//   1. A symmetric-key KDF chain ("chain ratchet"): each message key is
//      derived from the current chain key via HKDF, and the chain key is
//      then replaced by a new HKDF output. The old chain key is never
//      retained, so it cannot be recomputed from the new one (HKDF is a
//      one-way function) — this is what gives forward secrecy between
//      messages within a session.
//
//   2. A Diffie-Hellman ratchet step: whenever a fresh DH exchange happens
//      (e.g. the other party rotates their session key), a brand new local
//      X25519 keypair is generated and combined with the counterparty's new
//      public key to produce a new root key, mixed with the *old* root key.
//      Because the new root key depends on freshly generated randomness the
//      previous root key could not have predicted, compromising the old
//      state does not compromise sessions derived after a DH ratchet step —
//      this is post-compromise security ("healing").
//
// `DeriveSharedSecret` (in index.ts) performs the *initial* handshake via
// `initRatchetSession` below. This is an X3DH-style two-contribution mix,
// not a plain static-static ECDH: the root key is derived from BOTH (a) a
// static-static X25519 DH between the caller's long-term private key and
// the remote's long-term public key, AND (b) an ephemeral-static X25519 DH
// using a freshly generated, single-use local keypair against the same
// remote public key. Mixing in (b) is what gives the *initial* handshake
// forward secrecy: an attacker who later compromises only the long-term
// static private key (and already knows the remote's public key — it's
// public) still cannot reproduce the ephemeral contribution, because the
// ephemeral private key is freshly random on every call and is never
// derivable from the static key. Without it, a pure static-static DH would
// be fully deterministic given the two static keys (a key-reuse hazard) and
// would make every message encrypted before the first `ratchetAdvance()`
// retroactively decryptable by anyone who later obtains a static private
// key — see docs/DECISION_LOG.md, 2026-07-16, "DeriveSharedSecret initial
// handshake forward secrecy fix", for the finding this closes.
//
// The ephemeral keypair generated for the handshake doubles as the
// session's initial DH-ratchet keypair (`dhSelfPrivate`/`dhSelfPublic`) —
// the same way Signal's X3DH ephemeral key becomes the first Double Ratchet
// key. `dhSelfPublic` is exactly the value a future Messaging capability's
// key-exchange transport needs to deliver to the counterparty so they can
// complete their side of the handshake (via `ratchetAdvance`) and converge
// on matching session keys; that transport doesn't exist yet (no prekey
// bundle / Messaging capability), so two independent `DeriveSharedSecret`
// calls from either side of a conversation will NOT yet produce matching
// root keys on their own — this capability's job ends at making the
// ephemeral public key available on the registered session, not at
// delivering it. `ratchetAdvance`/`deriveNextMessageKey` below are exported
// for direct use (and are exercised in the test suite proving the FS/PCS
// properties above) and are the wiring point that future exchange will use
// — the contract only requires `DeriveSharedSecret` to return an opaque
// handle backed by a real ratchet session, not a message-send/receive RPC,
// so those aren't part of this capability's frozen interface yet.
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes } from "./bytes";
import { randomBytes } from "./random";

// Exported (not just module-local) so the test suite can independently
// recompute the *vulnerable* static-static-only derivation an attacker
// armed with just a stolen long-term private key would be limited to, and
// assert it does NOT match the real session's keys — see
// __tests__/crypto.test.ts, "forward secrecy at handshake time".
export const ROOT_INFO = new TextEncoder().encode("ascend-crypto-v1:ratchet-root");
export const CHAIN_INFO = new TextEncoder().encode("ascend-crypto-v1:ratchet-chain");
const MESSAGE_KEY_INFO = new TextEncoder().encode("ascend-crypto-v1:ratchet-message-key");
const CHAIN_ADVANCE_INFO = new TextEncoder().encode("ascend-crypto-v1:ratchet-chain-advance");

export interface RatchetState {
  rootKey: Uint8Array;
  /** Current local DH ratchet keypair — regenerated on every DH ratchet step. */
  dhSelfPrivate: Uint8Array;
  dhSelfPublic: Uint8Array;
  /** Most recently known remote DH ratchet public key, if any. */
  dhRemotePublic: Uint8Array | null;
  sendingChainKey: Uint8Array;
  sendMessageNumber: number;
}

/**
 * Initializes a ratchet session from the local party's long-term static
 * private key and the remote party's long-term static public key.
 *
 * Performs an X3DH-style two-contribution handshake rather than a plain
 * static-static ECDH — see the module header comment for the full
 * rationale. Concretely:
 *
 *   staticStaticDh    = X25519(localStaticPrivate, remoteStaticPublic)
 *   (dhSelfPrivate, dhSelfPublic) = fresh, single-use X25519 keypair
 *   ephemeralStaticDh = X25519(dhSelfPrivate, remoteStaticPublic)
 *   rootKey           = HKDF(staticStaticDh || ephemeralStaticDh)
 *
 * `localStaticPrivate` itself is never mixed into the HKDF input directly
 * and is not retained in the returned state — only its DH *outputs* are —
 * so nothing here creates a new way to reconstruct the static private key
 * from session state.
 */
export function initRatchetSession(localStaticPrivate: Uint8Array, remoteStaticPublic: Uint8Array): RatchetState {
  const staticStaticDh = x25519.getSharedSecret(localStaticPrivate, remoteStaticPublic);

  const dhSelfPrivate = randomBytes(32);
  const dhSelfPublic = x25519.getPublicKey(dhSelfPrivate);
  const ephemeralStaticDh = x25519.getSharedSecret(dhSelfPrivate, remoteStaticPublic);

  const rootKey = hkdf(sha256, concatBytes(staticStaticDh, ephemeralStaticDh), undefined, ROOT_INFO, 32);
  const sendingChainKey = hkdf(sha256, rootKey, undefined, CHAIN_INFO, 32);

  return {
    rootKey,
    dhSelfPrivate,
    dhSelfPublic,
    dhRemotePublic: remoteStaticPublic,
    sendingChainKey,
    sendMessageNumber: 0,
  };
}

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
 * DH ratchet step: mixes a fresh local keypair and the counterparty's new
 * public key into the root key, producing a new root key and a reset chain
 * key. This is what provides post-compromise security — even full
 * knowledge of the previous root key does not let an attacker predict the
 * new one, because `dhSelfPrivate` here is freshly and independently
 * generated (never derived from prior state).
 */
export function ratchetAdvance(state: RatchetState, remotePublicKey: Uint8Array): RatchetState {
  const dhSelfPrivate = randomBytes(32);
  const dhSelfPublic = x25519.getPublicKey(dhSelfPrivate);
  const dhOutput = x25519.getSharedSecret(dhSelfPrivate, remotePublicKey);
  const newRootKey = hkdf(sha256, concatBytes(state.rootKey, dhOutput), undefined, ROOT_INFO, 32);
  const sendingChainKey = hkdf(sha256, newRootKey, undefined, CHAIN_INFO, 32);
  return {
    rootKey: newRootKey,
    dhSelfPrivate,
    dhSelfPublic,
    dhRemotePublic: remotePublicKey,
    sendingChainKey,
    sendMessageNumber: 0,
  };
}
