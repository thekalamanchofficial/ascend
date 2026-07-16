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

export async function isAvailableAsync(): Promise<boolean> {
  return true;
}

export async function setItemAsync(
  key: string,
  value: string,
  _options?: Record<string, unknown>,
): Promise<void> {
  store.set(key, value);
}

export async function getItemAsync(key: string): Promise<string | null> {
  return store.has(key) ? (store.get(key) as string) : null;
}

export async function deleteItemAsync(key: string): Promise<void> {
  store.delete(key);
}

// Test-only helper, not part of the real expo-secure-store API.
export function __reset(): void {
  store.clear();
}
