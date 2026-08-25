// In-process, in-memory registry mapping opaque KeyHandle strings to actual
// PRIVATE-KEY material. This is the enforcement point for the charter's
// "private key material never leaves this module's boundary in plaintext"
// guarantee for GenerateKeyPair/GenerateIdentityKeyMaterial: callers (other
// capabilities, UI code) only ever receive a `KeyHandle` (`{ handle: string
// }`), never the bytes.
//
// Private-key entries below remain intentionally volatile (cleared on
// process restart) — that part of this module's original design was never
// wrong. Handle strings are prefixed by kind purely for local
// debuggability (e.g. distinguishing a private-key handle from a
// ratchet-session handle in logs or error messages) — never encode any key
// material or derivable secret into the handle string itself.
//
// RATCHET-SESSION storage, CORRECTED 2026-08-23 ("the ongoing-ratchet
// exposure gap" amendment — docs/capabilities/cryptography-and-keys.charter.md
// §3, round 2; docs/DECISION_LOG.md's 2026-08-23 entries): this module used
// to also hold `RatchetState` in this same volatile in-memory `Map`, with a
// header comment explicitly (and, as Constitution Warden's gate found,
// WRONGLY for the amendment's own draft claims) calling that "intentionally
// volatile... a DeriveSharedSecret ratchet session handle may be ephemeral
// by design." That was never true once real conversations exist: an
// ordinary app backgrounding/relaunch would silently destroy every active
// session's ratchet state, with no repair path (a consumed one-time prekey
// cannot be re-derived). `registerRatchetSession`/`getRatchetSession`/
// `updateRatchetSession` are now backed by `secureLocalStore`/
// `secureLocalRetrieve` (secureStore.ts) instead — the SAME at-rest-
// encrypted primitive already governing prekey/identity private material —
// keyed by `"ascend.crypto.ratchetSession." + handle` (originally
// colon-separated — `"ratchet-session:" + handle` — fixed 2026-08-26 after
// a live founder report: the real native expo-secure-store module rejects
// colons in keys, a constraint the Jest mock doesn't enforce, so this only
// surfaced running on an actual device; see docs/DECISION_LOG.md). This is
// a necessary, disclosed consequence, not incidental: `secureLocalStore`/
// `secureLocalRetrieve` are asynchronous (real OS-keychain `await`
// boundaries), so all three functions are now `async`, which in turn
// requires `DeriveSharedSecret` itself (index.ts) to become `async` — a
// calling-convention change, not a wire-contract change (the frozen
// `crypto.proto` RPC shape is unaffected).
import { randomBytes } from "./random";
import { bytesToHex, bytesToBase64, base64ToBytes } from "./bytes";
import { secureLocalStore, secureLocalRetrieve } from "./secureStore";
import type { KeyHandle } from "./types";
import type { RatchetState } from "./ratchet";

interface PrivateKeyEntry {
  kind: "private-key";
  purpose: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

const registry = new Map<string, PrivateKeyEntry>();

function newHandleId(prefix: string): string {
  return `${prefix}_${bytesToHex(randomBytes(16))}`;
}

export function registerPrivateKey(
  purpose: string,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): KeyHandle {
  const handle = newHandleId("key");
  registry.set(handle, { kind: "private-key", purpose, privateKey, publicKey });
  return { handle };
}

export function getPrivateKeyEntry(handle: KeyHandle): PrivateKeyEntry {
  const entry = registry.get(handle.handle);
  if (!entry) {
    throw new Error(`Unknown or invalid private key handle: "${handle.handle}".`);
  }
  return entry;
}

// ---------------------------------------------------------------------------
// Ratchet-session persistence (SecureLocalStore-backed — see module header).
// ---------------------------------------------------------------------------

// Dot-separated, NOT colon-separated — matching prekeyStore.ts's/
// history.ts's own established key-naming convention
// ("ascend.crypto.prekey.signed.<id>", "ascend.conversations.history.<id>").
// A colon here (this function's original form) is REJECTED by the real,
// native expo-secure-store module ("Invalid key provided to SecureStore" —
// only alphanumeric, ".", "-", "_" are accepted), even though the Jest
// mock (__mocks__/expo-secure-store.ts) has no such validation and so never
// caught this — this bug only surfaced on a real device/emulator (2026-08-26,
// founder report; see docs/DECISION_LOG.md).
function ratchetSessionStorageKey(handle: string): string {
  return `ascend.crypto.ratchetSession.${handle}`;
}

/**
 * Serializes a `RatchetState` to bytes for `secureLocalStore`. Mirrors
 * prekeyStore.ts's own base64-JSON encode/decode convention for storing
 * structured key material through a byte-oriented store.
 */
function encodeRatchetState(state: RatchetState): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      rootKey: bytesToBase64(state.rootKey),
      dhSelfPrivate: bytesToBase64(state.dhSelfPrivate),
      dhSelfPublic: bytesToBase64(state.dhSelfPublic),
      dhRemotePublic: state.dhRemotePublic ? bytesToBase64(state.dhRemotePublic) : null,
      sendingChainKey: bytesToBase64(state.sendingChainKey),
      receivingChainKey: bytesToBase64(state.receivingChainKey),
      sendMessageNumber: state.sendMessageNumber,
    }),
  );
}

function decodeRatchetState(bytes: Uint8Array): RatchetState {
  const parsed = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, string | number | null>;
  return {
    rootKey: base64ToBytes(parsed.rootKey as string),
    dhSelfPrivate: base64ToBytes(parsed.dhSelfPrivate as string),
    dhSelfPublic: base64ToBytes(parsed.dhSelfPublic as string),
    dhRemotePublic: parsed.dhRemotePublic ? base64ToBytes(parsed.dhRemotePublic as string) : null,
    sendingChainKey: base64ToBytes(parsed.sendingChainKey as string),
    receivingChainKey: base64ToBytes(parsed.receivingChainKey as string),
    sendMessageNumber: parsed.sendMessageNumber as number,
  };
}

export async function registerRatchetSession(state: RatchetState): Promise<KeyHandle> {
  const handle = newHandleId("ratchet");
  await secureLocalStore(ratchetSessionStorageKey(handle), encodeRatchetState(state));
  return { handle };
}

export async function getRatchetSession(handle: KeyHandle): Promise<RatchetState> {
  let raw: Uint8Array;
  try {
    raw = await secureLocalRetrieve(ratchetSessionStorageKey(handle.handle));
  } catch {
    throw new Error(`Unknown or invalid shared-secret handle: "${handle.handle}".`);
  }
  return decodeRatchetState(raw);
}

export async function updateRatchetSession(handle: KeyHandle, state: RatchetState): Promise<void> {
  // Preserve the original "unknown handle" behavior (must already be
  // registered) rather than letting a typo'd/forged handle silently create
  // a brand-new session record.
  try {
    await secureLocalRetrieve(ratchetSessionStorageKey(handle.handle));
  } catch {
    throw new Error(`Unknown or invalid shared-secret handle: "${handle.handle}".`);
  }
  await secureLocalStore(ratchetSessionStorageKey(handle.handle), encodeRatchetState(state));
}

// ---------------------------------------------------------------------------
// Per-shared_secret_handle mutex (charter §6, "the ongoing-ratchet exposure
// gap" amendment) — mirrors prekeyStore.ts's `withOneTimePrekeyLock` exactly
// (`Map<shared_secret_handle, Promise>`; React Native's single-threaded JS
// execution makes this sufficient, no OS-level locking required). Required
// so concurrent `EncryptMessage`/`DecryptMessage` calls against the same
// `shared_secret_handle` (a realistic retry/resend/offline-queue-flush
// scenario) cannot both read the same not-yet-advanced chain key and both
// derive/persist independently — the second `updateRatchetSession` call
// would otherwise silently clobber the first, reintroducing this
// amendment's own core same-key-reuse defect via a different mechanism.
// ---------------------------------------------------------------------------

const ratchetSessionLocks = new Map<string, Promise<void>>();

export async function withRatchetSessionLock<T>(handle: string, fn: () => Promise<T>): Promise<T> {
  const prior = ratchetSessionLocks.get(handle) ?? Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>((resolve) => {
    release = resolve;
  });
  // Publish `mine` as the new lock slot BEFORE awaiting `prior`, so a
  // concurrent caller arriving between now and when we finish sees `mine`
  // (not `prior`) as what it must wait on — this is what actually
  // serializes the two calls rather than letting them both read `prior`
  // and both proceed once it resolves. Identical structure to
  // prekeyStore.ts's `withOneTimePrekeyLock` — see that function's own
  // comment for the full TOCTOU-avoidance rationale.
  ratchetSessionLocks.set(handle, mine);
  await prior;
  try {
    return await fn();
  } finally {
    release();
    if (ratchetSessionLocks.get(handle) === mine) {
      ratchetSessionLocks.delete(handle);
    }
  }
}

/**
 * Finds the most recently registered private-key handle for a given
 * purpose, if one is currently registered in this process. Used internally
 * by `generatePrekeyBundle` (index.ts) — that RPC's frozen request shape
 * (`GeneratePrekeyBundleRequest { one_time_prekey_count }`) deliberately
 * carries no key handle, so it must locate this process's own identity key
 * itself rather than have one handed to it (see docs/DECISION_LOG.md,
 * 2026-08-20, "GeneratePrekeyBundle locates the identity key from the
 * in-process registry rather than a caller-supplied handle" for the full
 * reasoning, including the residual limitation this inherits from
 * apps/mobile/src/features/onboarding/localSession.ts's own already-
 * disclosed choice not to persist private key material across restarts).
 *
 * Deliberately NOT exported from index.ts's public API — same rationale as
 * `debugListPrivateKeyEntries` below: handing out private key bytes (or a
 * way to enumerate them by purpose) outside this module's own
 * implementation would defeat the whole point of KeyHandle opacity.
 */
export function findPrivateKeyEntryByPurpose(
  purpose: string,
): { handle: string; purpose: string; privateKey: Uint8Array; publicKey: Uint8Array } | undefined {
  let found: { handle: string; purpose: string; privateKey: Uint8Array; publicKey: Uint8Array } | undefined;
  for (const [handle, entry] of registry.entries()) {
    if (entry.purpose === purpose) {
      // Keep overwriting so the LAST (most recently registered) match wins
      // — Map iteration order is insertion order in JS.
      found = { handle, purpose: entry.purpose, privateKey: entry.privateKey, publicKey: entry.publicKey };
    }
  }
  return found;
}

/**
 * Test/debug-only accessor. Deliberately NOT exported from index.ts's
 * public API surface — the whole point of KeyHandle is that private key
 * bytes never leave this module through the normal contract. Only two
 * legitimate callers exist: ExportKeyMaterial (an explicit,
 * user-confirmed, in-module operation — see index.ts) and this capability's
 * own test suite (which needs to assert on raw derived key bytes to prove
 * deterministic derivation).
 */
export function debugListPrivateKeyEntries(): Array<{
  handle: string;
  purpose: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}> {
  const out: Array<{ handle: string; purpose: string; privateKey: Uint8Array; publicKey: Uint8Array }> = [];
  for (const [handle, entry] of registry.entries()) {
    out.push({ handle, purpose: entry.purpose, privateKey: entry.privateKey, publicKey: entry.publicKey });
  }
  return out;
}

/** Test-only: clears all registered private-key handles between test cases. Ratchet sessions live in SecureLocalStore now — see secureStore.ts's own test reset helpers. */
export function _resetRegistryForTests(): void {
  registry.clear();
}

/** Test-only: clears in-process ratchet-session lock state between test cases. */
export function _resetRatchetLocksForTests(): void {
  ratchetSessionLocks.clear();
}
