// Local persistence + atomic consumption for GeneratePrekeyBundle's signed-
// prekey and one-time-prekey PRIVATE material.
//
// Charter §3 ("GeneratePrekeyBundle... All private halves are stored
// locally via SecureLocalStore, indexed by prekey_id so CompleteSharedSecret
// can retrieve them later") and charter §6's "Atomic one-time-prekey
// consumption" bullet — the single most load-bearing requirement of this
// entire amendment — are both implemented in this one module, so
// index.ts's `completeSharedSecret` stays a straightforward orchestration
// of already-atomic operations rather than re-implementing locking inline.
//
// Uses secureStore.ts's internal (non-RPC) `secureLocalDelete` — see that
// function's own doc comment for why this is safe: it is not part of this
// capability's frozen 9-RPC contract surface.
import { bytesToBase64, base64ToBytes } from "./bytes";
import {
  secureLocalStore as storeSecureLocal,
  secureLocalRetrieve as retrieveSecureLocal,
  secureLocalDelete,
} from "./secureStore";

const SIGNED_PREKEY_KEY_PREFIX = "ascend.crypto.prekey.signed.";
const ONE_TIME_PREKEY_KEY_PREFIX = "ascend.crypto.prekey.onetime.";

function signedPrekeyStorageKey(prekeyId: string): string {
  return `${SIGNED_PREKEY_KEY_PREFIX}${prekeyId}`;
}

function oneTimePrekeyStorageKey(prekeyId: string): string {
  return `${ONE_TIME_PREKEY_KEY_PREFIX}${prekeyId}`;
}

export interface StoredSignedPrekeyRecord {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  signature: Uint8Array;
  /** The identity public key this signature was produced under — stored alongside for self-verification (see index.ts's completeSharedSecret). */
  identityPublicKey: Uint8Array;
  createdAtUnix: number;
}

export interface StoredOneTimePrekeyRecord {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

function encodeSignedPrekeyRecord(record: StoredSignedPrekeyRecord): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      privateKey: bytesToBase64(record.privateKey),
      publicKey: bytesToBase64(record.publicKey),
      signature: bytesToBase64(record.signature),
      identityPublicKey: bytesToBase64(record.identityPublicKey),
      createdAtUnix: record.createdAtUnix,
    }),
  );
}

function decodeSignedPrekeyRecord(bytes: Uint8Array): StoredSignedPrekeyRecord {
  const parsed = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, string | number>;
  return {
    privateKey: base64ToBytes(parsed.privateKey as string),
    publicKey: base64ToBytes(parsed.publicKey as string),
    signature: base64ToBytes(parsed.signature as string),
    identityPublicKey: base64ToBytes(parsed.identityPublicKey as string),
    createdAtUnix: parsed.createdAtUnix as number,
  };
}

function encodeOneTimePrekeyRecord(record: StoredOneTimePrekeyRecord): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      privateKey: bytesToBase64(record.privateKey),
      publicKey: bytesToBase64(record.publicKey),
    }),
  );
}

function decodeOneTimePrekeyRecord(bytes: Uint8Array): StoredOneTimePrekeyRecord {
  const parsed = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, string>;
  return { privateKey: base64ToBytes(parsed.privateKey), publicKey: base64ToBytes(parsed.publicKey) };
}

export async function storeSignedPrekey(prekeyId: string, record: StoredSignedPrekeyRecord): Promise<void> {
  await storeSecureLocal(signedPrekeyStorageKey(prekeyId), encodeSignedPrekeyRecord(record));
}

/** Not single-use — the signed prekey is retrieved (never deleted) until it next rotates. */
export async function retrieveSignedPrekey(prekeyId: string): Promise<StoredSignedPrekeyRecord> {
  let raw: Uint8Array;
  try {
    raw = await retrieveSecureLocal(signedPrekeyStorageKey(prekeyId));
  } catch {
    throw new Error(`Unknown signed prekey id "${prekeyId}".`);
  }
  return decodeSignedPrekeyRecord(raw);
}

export async function storeOneTimePrekey(prekeyId: string, record: StoredOneTimePrekeyRecord): Promise<void> {
  await storeSecureLocal(oneTimePrekeyStorageKey(prekeyId), encodeOneTimePrekeyRecord(record));
}

/**
 * Thrown by `consumeOneTimePrekey` for the losing side of a concurrent race
 * (or any call referencing an already-used/unknown prekey_id) — charter
 * §6's required "specific, distinguishable error", never a silent success,
 * never a hang, never a silent fallback to a weaker derivation. Exported as
 * a real class (not a generic Error) so callers/tests can assert on it
 * with `instanceof` rather than string-matching a message.
 */
export class PrekeyAlreadyConsumedError extends Error {
  readonly prekeyId: string;
  constructor(prekeyId: string) {
    super(
      `One-time prekey "${prekeyId}" was already consumed (or never existed) — likely a duplicate message delivery.`,
    );
    this.name = "PrekeyAlreadyConsumedError";
    this.prekeyId = prekeyId;
  }
}

// Per-prekey_id in-process mutex (charter §6: "a per-prekey_id in-process
// lock — concretely, a Map<prekey_id, Promise>-based mutex serializing
// concurrent calls for the same prekey_id is sufficient" given React
// Native's single-threaded JS execution). Scope is deliberately this one JS
// runtime instance only — charter §7 item 5 names the residual,
// non-blocking cross-JS-context risk (e.g. a future headless-JS background
// task), not reachable today (no such capability exists in this codebase).
const oneTimePrekeyLocks = new Map<string, Promise<void>>();

async function withOneTimePrekeyLock<T>(prekeyId: string, fn: () => Promise<T>): Promise<T> {
  const prior = oneTimePrekeyLocks.get(prekeyId) ?? Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>((resolve) => {
    release = resolve;
  });
  // Publish `mine` as the new lock slot BEFORE awaiting `prior`, so a
  // concurrent caller arriving between now and when we finish sees `mine`
  // (not `prior`) as what it must wait on — this is what actually
  // serializes the two calls rather than letting them both read `prior`
  // and both proceed once it resolves.
  oneTimePrekeyLocks.set(prekeyId, mine);
  await prior;
  try {
    return await fn();
  } finally {
    release();
    // Clean up only if nobody chained after us, to avoid unbounded map growth.
    if (oneTimePrekeyLocks.get(prekeyId) === mine) {
      oneTimePrekeyLocks.delete(prekeyId);
    }
  }
}

/**
 * Atomically retrieves AND permanently deletes a one-time prekey's private
 * material — charter §6's single most load-bearing requirement of this
 * whole amendment, and the mechanism that gives `CompleteSharedSecret`
 * genuine responder-side forward secrecy (the defect §6's dedicated bullet
 * exists to fix). The lookup and delete happen inside the same critical
 * section, serialized per prekey_id by `withOneTimePrekeyLock` above — two
 * concurrent calls for the same prekey_id can never both observe the
 * private key still present. The loser acquires the lock only after the
 * winner has already deleted the entry underneath it, and fails with
 * `PrekeyAlreadyConsumedError` rather than silently succeeding, hanging, or
 * falling back to a weaker derivation.
 */
export async function consumeOneTimePrekey(prekeyId: string): Promise<StoredOneTimePrekeyRecord> {
  return withOneTimePrekeyLock(prekeyId, async () => {
    const storageKey = oneTimePrekeyStorageKey(prekeyId);
    let raw: Uint8Array;
    try {
      raw = await retrieveSecureLocal(storageKey);
    } catch {
      throw new PrekeyAlreadyConsumedError(prekeyId);
    }
    await secureLocalDelete(storageKey);
    return decodeOneTimePrekeyRecord(raw);
  });
}

/** Test-only: clears in-process lock state between test cases. */
export function _resetPrekeyLocksForTests(): void {
  oneTimePrekeyLocks.clear();
}
