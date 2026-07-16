// In-process, in-memory registry mapping opaque KeyHandle strings to actual
// key material. This is the enforcement point for the charter's "private
// key material never leaves this module's boundary in plaintext" guarantee
// for GenerateKeyPair/GenerateIdentityKeyMaterial/DeriveSharedSecret:
// callers (other capabilities, UI code) only ever receive a `KeyHandle`
// (`{ handle: string }`), never the bytes.
//
// This registry is intentionally volatile (cleared on process restart).
// Persisted key material goes through SecureLocalStore instead — see
// secureStore.ts — which is a deliberate separation: not every handle
// needs to survive a restart (e.g. a `DeriveSharedSecret` ratchet session
// handle may be ephemeral by design), and mixing "opaque runtime reference"
// with "at-rest persistence" into one mechanism would make the handle
// format harder to evolve later (charter §6: rotation must remain
// possible).
//
// Handle strings are prefixed by kind purely for local debuggability (e.g.
// distinguishing a private-key handle from a ratchet-session handle in logs
// or error messages) — never encode any key material or derivable secret
// into the handle string itself.
import { randomBytes } from "./random";
import { bytesToHex } from "./bytes";
import type { KeyHandle } from "./types";
import type { RatchetState } from "./ratchet";

interface PrivateKeyEntry {
  kind: "private-key";
  purpose: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

interface RatchetSessionEntry {
  kind: "ratchet-session";
  state: RatchetState;
}

type RegistryEntry = PrivateKeyEntry | RatchetSessionEntry;

const registry = new Map<string, RegistryEntry>();

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
  if (!entry || entry.kind !== "private-key") {
    throw new Error(`Unknown or invalid private key handle: "${handle.handle}".`);
  }
  return entry;
}

export function registerRatchetSession(state: RatchetState): KeyHandle {
  const handle = newHandleId("ratchet");
  registry.set(handle, { kind: "ratchet-session", state });
  return { handle };
}

export function getRatchetSession(handle: KeyHandle): RatchetState {
  const entry = registry.get(handle.handle);
  if (!entry || entry.kind !== "ratchet-session") {
    throw new Error(`Unknown or invalid shared-secret handle: "${handle.handle}".`);
  }
  return entry.state;
}

export function updateRatchetSession(handle: KeyHandle, state: RatchetState): void {
  const entry = registry.get(handle.handle);
  if (!entry || entry.kind !== "ratchet-session") {
    throw new Error(`Unknown or invalid shared-secret handle: "${handle.handle}".`);
  }
  entry.state = state;
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
    if (entry.kind === "private-key") {
      out.push({ handle, purpose: entry.purpose, privateKey: entry.privateKey, publicKey: entry.publicKey });
    }
  }
  return out;
}

/** Test-only: clears all registered handles between test cases. */
export function _resetRegistryForTests(): void {
  registry.clear();
}
