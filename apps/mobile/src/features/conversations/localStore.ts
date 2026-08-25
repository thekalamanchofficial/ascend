// Conversations' feature-composition-layer local persistence.
//
// Per CLAUDE.md's "capabilities vs. features," this directory
// (apps/mobile/src/features/conversations/) is NOT a capability — it is the
// thin composition layer that wires Cryptography & Keys, Identity, and the
// Conversations capability client together into a real send/receive flow,
// mirroring apps/mobile/src/features/onboarding/'s own established role and
// discipline (its onboarding.ts/localSession.ts are the direct precedent
// this file follows).
//
// *** Binding charter requirement this file exists to satisfy
// (conversations.charter.md §4 Art. 9 / §6 "Local plaintext at rest"),
// found and fixed one layer down for exactly this shape of bug on
// 2026-08-23 (see docs/DECISION_LOG.md's "ongoing-ratchet exposure gap"
// entries) — read before touching this file: ***
//
// This module's job is to hold TWO categories of data that would silently
// break every conversation on an ordinary app restart if held only in a
// Zustand store or a plain in-memory variable, reproducing the identical
// defect class the crypto amendment above was chartered to fix one layer
// down:
//
//   1. The `conversationId -> sharedSecretHandle` mapping. Crypto's own
//      `RatchetState` is now durable (SecureLocalStore-backed) once you HAVE
//      a `shared_secret_handle` — but if THIS module's own knowledge of
//      which handle belongs to which conversation is lost on restart, the
//      durable ratchet state becomes unreachable orphaned data: every
//      conversation would silently re-run session establishment (consuming
//      a fresh one-time prekey, discarding a REACHABLE existing ratchet
//      state) or, worse, simply appear broken.
//   2. This device's own cached `identityDhPublicKey`/
//      `identityDhPublicKeySignature` (crypto.generatePrekeyBundle's
//      output) — needed to re-include, unchanged, in every
//      session_establishment_payload this device builds as an initiator
//      (cryptography-and-keys.charter.md §7 item 4), without re-calling
//      GeneratePrekeyBundle (and therefore re-publishing a brand new signed
//      prekey / burning a fresh one-time-prekey pool) on every single first
//      message sent.
//
// BOTH are held via Cryptography & Keys' `secureLocalStore`/
// `secureLocalRetrieve` (the same at-rest-encrypted primitive
// `keyRegistry.ts`'s own ratchet-session-persistence fix uses) — never
// AsyncStorage, never a plain in-memory Map, never a Zustand store with no
// persistence middleware.
import { secureLocalStore, secureLocalRetrieve } from "../../capabilities/crypto/secureStore";
import { bytesToBase64, base64ToBytes } from "../../capabilities/crypto/bytes";
import type { KeyHandle } from "../../capabilities/crypto";
import { withKeyLock } from "./mutex";

// ---------------------------------------------------------------------------
// conversationId -> sharedSecretHandle
//
// LOCKING, required (Security Steward implementation-merge-gate veto,
// 2026-08-25 — see docs/DECISION_LOG.md): this is a single shared JSON blob
// (SESSION_MAP_KEY) read, mutated in JS, and written back by BOTH
// getCachedSessionHandle's callers (none — it's read-only) and, critically,
// setCachedSessionHandle. Two concurrent setCachedSessionHandle calls (a
// concretely reachable race: the Send button isn't disabled during an
// in-flight background syncThreadHistory, and navigating away mid-sync
// doesn't cancel the in-flight promise chain) previously raced a real
// secureLocalRetrieve -> mutate -> secureLocalStore sequence with a genuine
// `await` boundary in between and NO locking — the loser's write would
// silently clobber the winner's, permanently orphaning an already-
// established (possibly one-time-prekey-consuming) ratchet session with no
// error, no audit event, no user-visible sign. `withKeyLock` (mirroring
// keyRegistry.ts's `withRatchetSessionLock`/prekeyStore.ts's
// `withOneTimePrekeyLock` exactly) now serializes every read-modify-write
// against this one shared blob under a single fixed lock key — sufficient
// per Security Steward's own fix specification, since all writes share one
// blob (unlike history.ts's per-conversationId storage below, which needs
// its own lock per conversationId instead).
// ---------------------------------------------------------------------------

const SESSION_MAP_KEY = "ascend.conversations.sessionHandleMap";
const SESSION_MAP_LOCK_KEY = "session-map";

async function loadSessionMap(): Promise<Record<string, string>> {
  try {
    const raw = await secureLocalRetrieve(SESSION_MAP_KEY);
    return JSON.parse(new TextDecoder().decode(raw)) as Record<string, string>;
  } catch {
    return {};
  }
}

async function saveSessionMap(map: Record<string, string>): Promise<void> {
  await secureLocalStore(SESSION_MAP_KEY, new TextEncoder().encode(JSON.stringify(map)));
}

/**
 * Returns the cached `sharedSecretHandle` for `conversationId`, or `null` if
 * no session is cached yet (a fresh conversation, or one whose cache was
 * lost/never established on this device — charter §5's disclosed gap).
 * Locked too (not just the write below) — a read racing a concurrent
 * in-flight write could otherwise observe a torn intermediate state.
 */
export async function getCachedSessionHandle(conversationId: string): Promise<KeyHandle | null> {
  return withKeyLock(SESSION_MAP_LOCK_KEY, async () => {
    const map = await loadSessionMap();
    const handle = map[conversationId];
    return handle ? { handle } : null;
  });
}

/** Persists `conversationId -> sharedSecretHandle` durably (SecureLocalStore-backed) — required after EVERY successful DeriveSharedSecret/CompleteSharedSecret, per this module's own header comment. Locked (see module header) — the full retrieve-mutate-store sequence runs inside one critical section, never interleaved with a concurrent call's own sequence. */
export async function setCachedSessionHandle(conversationId: string, handle: KeyHandle): Promise<void> {
  await withKeyLock(SESSION_MAP_LOCK_KEY, async () => {
    const map = await loadSessionMap();
    map[conversationId] = handle.handle;
    await saveSessionMap(map);
  });
}

// ---------------------------------------------------------------------------
// This device's own cached identityDhPublicKey / identityDhPublicKeySignature
// (crypto.generatePrekeyBundle's output) — scoped by deviceId so a single
// process that (in principle) ever handled more than one device's identity
// never cross-contaminates the two.
// ---------------------------------------------------------------------------

interface CachedOwnPrekeyIdentity {
  identityDhPublicKey: string; // base64
  identityDhPublicKeySignature: string; // base64
}

function ownPrekeyIdentityKey(deviceId: string): string {
  return `ascend.conversations.ownPrekeyIdentity.${deviceId}`;
}

export async function loadOwnPrekeyIdentity(
  deviceId: string,
): Promise<{ identityDhPublicKey: Uint8Array; identityDhPublicKeySignature: Uint8Array } | null> {
  try {
    const raw = await secureLocalRetrieve(ownPrekeyIdentityKey(deviceId));
    const parsed = JSON.parse(new TextDecoder().decode(raw)) as CachedOwnPrekeyIdentity;
    return {
      identityDhPublicKey: base64ToBytes(parsed.identityDhPublicKey),
      identityDhPublicKeySignature: base64ToBytes(parsed.identityDhPublicKeySignature),
    };
  } catch {
    return null;
  }
}

export async function saveOwnPrekeyIdentity(
  deviceId: string,
  value: { identityDhPublicKey: Uint8Array; identityDhPublicKeySignature: Uint8Array },
): Promise<void> {
  const encoded: CachedOwnPrekeyIdentity = {
    identityDhPublicKey: bytesToBase64(value.identityDhPublicKey),
    identityDhPublicKeySignature: bytesToBase64(value.identityDhPublicKeySignature),
  };
  await secureLocalStore(ownPrekeyIdentityKey(deviceId), new TextEncoder().encode(JSON.stringify(encoded)));
}

// ---------------------------------------------------------------------------
// Passive key-rotation/change indicator — cryptography-and-keys.charter.md
// §5/§6's "passive, discoverable indicator (e.g. a changed-key badge on the
// conversation), never an interrupting modal" commitment, made real for the
// first time here (conversations.charter.md §5 cross-reference: "this is
// the first capability where that commitment becomes a real, renderable
// thing"). Deliberately narrow, per this pass's scope decision — see
// ConversationThreadScreen.tsx's own header comment for what this does and
// does NOT cover.
//
// Stores the last-seen Ed25519 SIGNING public key (identity.PublicIdentity's
// own `publicKey` — already-public material, ResolveIdentity's normal
// response, not a secret) per `identityRef`, so a LATER, DIFFERENT value for
// the same identityRef is detectable. No key material beyond an
// already-public key is ever involved.
// ---------------------------------------------------------------------------

function lastSeenIdentityKeyStorageKey(identityRef: string): string {
  return `ascend.conversations.lastSeenIdentityKey.${identityRef}`;
}

export async function getLastSeenIdentitySigningPublicKey(identityRef: string): Promise<Uint8Array | null> {
  try {
    const raw = await secureLocalRetrieve(lastSeenIdentityKeyStorageKey(identityRef));
    return base64ToBytes(new TextDecoder().decode(raw));
  } catch {
    return null;
  }
}

export async function setLastSeenIdentitySigningPublicKey(identityRef: string, publicKey: Uint8Array): Promise<void> {
  await secureLocalStore(lastSeenIdentityKeyStorageKey(identityRef), new TextEncoder().encode(bytesToBase64(publicKey)));
}
