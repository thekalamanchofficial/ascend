// SecureLocalStore / SecureLocalRetrieve: encrypted local storage wrapper.
//
// Charter §6 threat model: "private keys stored via OS keychain/secure
// enclave/TEE where the platform provides one; falls back to a
// locally-derived encryption key (e.g. from a device PIN/biometric) where
// it doesn't — never plaintext on disk."
//
// Primary path: expo-secure-store, which wraps iOS Keychain / Android
// Keystore — hardware-backed where the device supports it. This is checked
// at call time via `isAvailableAsync()` rather than assumed, since it can
// be unavailable (web, some emulators).
//
// Fallback path ("software vault"): used only when the OS store genuinely
// isn't available. Values are still always encrypted (XChaCha20-Poly1305)
// before being held — the "never plaintext on disk" line is never crossed
// — but the vault key's own protection is weaker than hardware-backed
// storage. By default (no `fallbackKeyProvider` registered) the vault key
// is a random value that lives only in process memory: it disappears on
// restart, which loses fallback-stored data but never leaks it. The charter
// calls for the fallback key to be derived from a device PIN/biometric;
// deriving one directly from a raw OS PIN generally isn't exposed to
// application code on any platform, so this module instead exposes
// `setFallbackKeyProvider`, a hook the app shell can wire to whatever
// biometric/passcode-gated key material it can obtain on a given platform
// (e.g. an `expo-local-authentication` gate guarding a key held in
// `localStorage`/IndexedDB on web). Until that's wired in by the app layer,
// the in-memory-only default is the honest, documented behavior — see
// docs/DECISION_LOG.md for the trade-off this represents.
import * as SecureStore from "expo-secure-store";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { bytesToBase64, base64ToBytes, concatBytes } from "./bytes";
import { randomBytes } from "./random";
import { logAuditEvent } from "./audit";
import { auditFingerprint } from "./auditHash";

const FALLBACK_NONCE_LEN = 24;

let fallbackKeyProvider: (() => Uint8Array) | null = null;
let inMemoryFallbackKey: Uint8Array | null = null;
const softwareVault = new Map<string, Uint8Array>();

/**
 * Lets the app shell supply a device-PIN/biometric-derived 32-byte key for
 * the software-vault fallback, instead of the in-memory-only default. Not
 * part of the frozen contract's 9 RPCs (this is a platform-integration
 * seam, not a capability operation) — safe to leave unset; the fallback
 * degrades to memory-only storage rather than ever writing plaintext.
 */
export function setFallbackKeyProvider(provider: (() => Uint8Array) | null): void {
  fallbackKeyProvider = provider;
}

function getFallbackVaultKey(): Uint8Array {
  if (fallbackKeyProvider) return fallbackKeyProvider();
  if (!inMemoryFallbackKey) inMemoryFallbackKey = randomBytes(32);
  return inMemoryFallbackKey;
}

async function isOsSecureStoreAvailable(): Promise<boolean> {
  try {
    return await SecureStore.isAvailableAsync();
  } catch {
    return false;
  }
}

/** Exported directly for the fallback-path test — see __tests__/crypto.test.ts. */
export function softwareVaultStore(key: string, value: Uint8Array): void {
  const vaultKey = getFallbackVaultKey();
  const nonce = randomBytes(FALLBACK_NONCE_LEN);
  const sealed = xchacha20poly1305(vaultKey, nonce).encrypt(value);
  softwareVault.set(key, concatBytes(nonce, sealed));
}

/** Exported directly for the fallback-path test — see __tests__/crypto.test.ts. */
export function softwareVaultRetrieve(key: string): Uint8Array {
  const stored = softwareVault.get(key);
  if (!stored) throw new Error(`No value stored for key "${key}".`);
  const vaultKey = getFallbackVaultKey();
  const nonce = stored.slice(0, FALLBACK_NONCE_LEN);
  const ciphertext = stored.slice(FALLBACK_NONCE_LEN);
  return xchacha20poly1305(vaultKey, nonce).decrypt(ciphertext);
}

export async function secureLocalStore(key: string, value: Uint8Array): Promise<void> {
  if (await isOsSecureStoreAvailable()) {
    await SecureStore.setItemAsync(key, bytesToBase64(value), {
      keychainAccessible: SecureStore.WHEN_UNLOCKED,
    });
  } else {
    softwareVaultStore(key, value);
  }
  // Log a fingerprint of the storage key, never the raw key string — a
  // local-storage key name can itself be identifying metadata (e.g. it
  // might embed a contact identifier or conversation id). See auditHash.ts.
  logAuditEvent("secure_local_store_write", { keyFingerprint: auditFingerprint(key) });
}

export async function secureLocalRetrieve(key: string): Promise<Uint8Array> {
  if (await isOsSecureStoreAvailable()) {
    const stored = await SecureStore.getItemAsync(key);
    if (stored === null) throw new Error(`No value stored for key "${key}".`);
    return base64ToBytes(stored);
  }
  return softwareVaultRetrieve(key);
}

/** Test-only: clears in-memory fallback vault state between test cases. */
export function _resetFallbackVaultForTests(): void {
  softwareVault.clear();
  inMemoryFallbackKey = null;
  fallbackKeyProvider = null;
}
