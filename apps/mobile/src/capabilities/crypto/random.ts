// Single audited CSPRNG entry point for this capability.
//
// Threat model requirement (charter §6): "must use a cryptographically
// secure RNG sourced from the OS; no custom entropy pooling." Every other
// module in this capability that needs randomness (key generation, nonces,
// ephemeral keys, recovery-phrase entropy) MUST go through this function
// rather than calling a library's own internal RNG, so there is exactly one
// place that sources entropy and exactly one place to audit.
//
// In a real Expo/React Native runtime this calls straight into
// expo-crypto's native binding (iOS SecRandomCopyBytes / Android
// SecureRandom under the hood). Under Jest, expo-crypto's native module
// isn't available, so `__mocks__/expo-crypto.ts` transparently substitutes
// Node's own OS-backed CSPRNG (`node:crypto`) — still OS-sourced, just via
// a different native binding, never a userspace/software entropy pool.
import * as ExpoCrypto from "expo-crypto";

export function randomBytes(length: number): Uint8Array {
  if (length <= 0) {
    throw new Error("randomBytes: length must be a positive integer.");
  }
  return ExpoCrypto.getRandomBytes(length);
}
