// Jest manual mock for `expo-secure-store`.
//
// Same rationale as __mocks__/expo-crypto.ts: the real module is a native
// Keychain (iOS) / Keystore (Android) binding unavailable outside a running
// app. This mock simulates an *available, working* secure store so tests
// exercise the primary (OS-keychain-backed) SecureLocalStore/Retrieve code
// path exactly as a real device would. The software-vault fallback path
// (used when the OS store is genuinely unavailable, e.g. web) is tested
// directly against secureStore.ts's exported fallback-vault functions
// rather than by forcing this mock to report unavailability.
const store = new Map<string, string>();

export const WHEN_UNLOCKED = "WHEN_UNLOCKED";

// Real expo-secure-store rejects any key outside this character set (only
// alphanumeric, ".", "-", "_") — a constraint this mock did NOT originally
// enforce, which is exactly how `ratchetSessionStorageKey`'s colon-
// separated key format (fixed 2026-08-26, see docs/DECISION_LOG.md) shipped
// with a passing test suite yet threw "Invalid key provided to SecureStore"
// on a real device. Enforced here now so this defect class fails fast in
// tests going forward, not only on a live device.
const VALID_KEY_PATTERN = /^[\w.-]+$/;

function assertValidKey(key: string): void {
  if (!VALID_KEY_PATTERN.test(key)) {
    throw new Error(
      `Invalid key provided to SecureStore. Keys must not be empty and can only contain alphanumeric characters, '.', '-', and '_'. Received: "${key}"`,
    );
  }
}

export async function isAvailableAsync(): Promise<boolean> {
  return true;
}

export async function setItemAsync(
  key: string,
  value: string,
  _options?: Record<string, unknown>,
): Promise<void> {
  assertValidKey(key);
  store.set(key, value);
}

export async function getItemAsync(key: string): Promise<string | null> {
  assertValidKey(key);
  return store.has(key) ? (store.get(key) as string) : null;
}

export async function deleteItemAsync(key: string): Promise<void> {
  assertValidKey(key);
  store.delete(key);
}

// Test-only helper, not part of the real expo-secure-store API.
export function __reset(): void {
  store.clear();
}
